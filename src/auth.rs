use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use anyhow::{bail, Result};
use rand::RngCore;
use serde::Serialize;

const SESSION_TTL: Duration = Duration::from_secs(8 * 3600);

#[cfg_attr(target_env = "gnu", link(name = "crypt"))]
extern "C" {
    fn crypt(key: *const c_char, salt: *const c_char) -> *mut c_char;
}

fn crypt_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

/// crypt(3) is not reentrant; serialise access. musl provides it in libc, so
/// the static build has no external libcrypt dependency.
fn crypt_password(password: &str, salt: &str) -> Option<String> {
    let ckey = CString::new(password).ok()?;
    let csalt = CString::new(salt).ok()?;
    let _guard = crypt_lock().lock().unwrap();
    let ptr = unsafe { crypt(ckey.as_ptr(), csalt.as_ptr()) };
    if ptr.is_null() {
        return None;
    }
    let out = unsafe { CStr::from_ptr(ptr) }.to_string_lossy().to_string();
    if out.starts_with("*") {
        None
    } else {
        Some(out)
    }
}

pub fn shadow_path() -> String {
    std::env::var("ROUTERD_SHADOW").unwrap_or_else(|_| "/etc/shadow".to_string())
}

pub fn data_dir() -> String {
    std::env::var("ROUTERD_DATA_DIR").unwrap_or_else(|_| "/etc/routerd".to_string())
}

fn shadow_hash(user: &str) -> Option<String> {
    let text = std::fs::read_to_string(shadow_path()).ok()?;
    for line in text.lines() {
        let fields: Vec<&str> = line.split(':').collect();
        if fields.len() > 1 && fields[0] == user {
            return Some(fields[1].to_string());
        }
    }
    None
}

/// Verify a login against /etc/shadow. Empty hash means "no password set".
pub fn verify_password(user: &str, password: &str) -> bool {
    let Some(hash) = shadow_hash(user) else {
        return false;
    };
    if hash.is_empty() {
        return password.is_empty();
    }
    if hash.starts_with('!') || hash.starts_with('*') {
        return false;
    }
    match crypt_password(password, &hash) {
        Some(computed) => crate::util::ct_eq(computed.as_bytes(), hash.as_bytes()),
        None => false,
    }
}

fn random_salt() -> String {
    const ALPHABET: &[u8] = b"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    let mut raw = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut raw);
    raw.iter()
        .map(|b| ALPHABET[(*b as usize) % ALPHABET.len()] as char)
        .collect()
}

pub fn hash_password(password: &str) -> Result<String> {
    let salt = format!("$6${}$", random_salt());
    crypt_password(password, &salt).ok_or_else(|| anyhow::anyhow!("crypt failed"))
}

/// Replace the password hash for `user`, preserving the rest of the line.
pub fn set_password(user: &str, password: &str) -> Result<()> {
    let hash = hash_password(password)?;
    let path = shadow_path();
    let text = std::fs::read_to_string(&path)?;
    let mut found = false;
    let mut out = String::with_capacity(text.len() + 16);
    for line in text.lines() {
        let mut fields: Vec<String> = line.split(':').map(|s| s.to_string()).collect();
        if fields.len() > 1 && fields[0] == user {
            fields[1] = hash.clone();
            found = true;
        }
        out.push_str(&fields.join(":"));
        out.push('\n');
    }
    if !found {
        bail!("shadow entry for {user} not found");
    }
    crate::util::write_atomic(&path, out.as_bytes(), 0o600)?;
    clear_must_change();
    Ok(())
}

pub fn must_change_path() -> String {
    format!("{}/must_change", data_dir())
}

pub fn must_change() -> bool {
    std::path::Path::new(&must_change_path()).exists()
}

pub fn clear_must_change() {
    let _ = std::fs::remove_file(must_change_path());
}

pub fn new_token(bytes: usize) -> String {
    use base64::Engine;
    let mut raw = vec![0u8; bytes];
    rand::thread_rng().fill_bytes(&mut raw);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw)
}

#[derive(Debug, Clone, Serialize)]
pub struct Session {
    pub user: String,
    pub csrf: String,
    pub ip: String,
    #[serde(skip)]
    pub last_seen: Instant,
}

impl Session {
    pub fn new(user: &str, ip: &str) -> Self {
        let now = Instant::now();
        Self {
            user: user.to_string(),
            csrf: new_token(24),
            ip: ip.to_string(),
            last_seen: now,
        }
    }

    pub fn expired(&self) -> bool {
        self.last_seen.elapsed() > SESSION_TTL
    }
}

pub type SessionStore = std::sync::Arc<std::sync::RwLock<HashMap<String, Session>>>;

pub fn cleanup(store: &SessionStore) {
    let mut map = store.write().unwrap();
    map.retain(|_, s| !s.expired());
    // Hard cap so a bug cannot grow memory without bound.
    if map.len() > 64 {
        let mut keys: Vec<(Instant, String)> = map
            .iter()
            .map(|(k, v)| (v.last_seen, k.clone()))
            .collect();
        keys.sort_by_key(|(t, _)| *t);
        for (_, k) in keys.into_iter().take(map.len() - 64) {
            map.remove(&k);
        }
    }
}

/// Auth information attached to a protected request.
#[derive(Debug, Clone)]
pub struct CurrentSession(pub Session);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha512_hashes_verify() {
        let hash = hash_password("s3cret!pass").unwrap();
        assert!(hash.starts_with("$6$"));
        assert_eq!(crypt_password("s3cret!pass", &hash).unwrap(), hash);
        assert_ne!(crypt_password("wrong", &hash).unwrap(), hash);
    }
}
