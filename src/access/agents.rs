use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use anyhow::Result;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::util;

pub const SCOPE_READ: &str = "devices:read";
pub const SCOPE_WRITE: &str = "devices:write";

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentToken {
    pub id: String,
    pub name: String,
    /// SHA-256 of the bearer token; the plaintext is shown only once.
    pub hash: String,
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(default)]
    pub created: u64,
    #[serde(default)]
    pub last_used: u64,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

impl AgentToken {
    pub fn view(&self) -> Value {
        json!({
            "id": self.id,
            "name": self.name,
            "scopes": self.scopes,
            "created": self.created,
            "last_used": self.last_used,
            "enabled": self.enabled,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TokenStore {
    #[serde(default)]
    pub tokens: Vec<AgentToken>,
}

pub fn normalize_scopes(input: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for scope in input {
        let s = scope.trim();
        if (s == SCOPE_READ || s == SCOPE_WRITE) && !out.iter().any(|x| x == s) {
            out.push(s.to_string());
        }
    }
    if out.is_empty() {
        out.push(SCOPE_READ.to_string());
    }
    out
}

pub fn can_read(scopes: &[String]) -> bool {
    scopes
        .iter()
        .any(|s| s == SCOPE_READ || s == SCOPE_WRITE)
}

pub fn can_write(scopes: &[String]) -> bool {
    scopes.iter().any(|s| s == SCOPE_WRITE)
}

fn sha256_hex(data: &str) -> String {
    hex::encode(openssl::sha::sha256(data.as_bytes()))
}

impl TokenStore {
    pub fn load(path: &str) -> Self {
        std::fs::read_to_string(path)
            .ok()
            .and_then(|text| serde_json::from_str(&text).ok())
            .unwrap_or_default()
    }

    pub fn save(&self, path: &str) -> Result<()> {
        let data = serde_json::to_vec(self)?;
        util::write_atomic(path, &data, 0o600)?;
        Ok(())
    }

    /// Returns the plaintext token exactly once.
    pub fn create(&mut self, name: &str, scopes: &[String]) -> (String, AgentToken) {
        let mut id_bytes = [0u8; 6];
        rand::thread_rng().fill_bytes(&mut id_bytes);
        let id = hex::encode(id_bytes);
        let secret = crate::auth::new_token(32);
        let token = format!("rd_{secret}");
        let entry = AgentToken {
            id,
            name: if name.trim().is_empty() {
                "AI agent".to_string()
            } else {
                name.trim().to_string()
            },
            hash: sha256_hex(&token),
            scopes: normalize_scopes(scopes),
            created: super::devices::now_unix(),
            last_used: 0,
            enabled: true,
        };
        self.tokens.push(entry.clone());
        (token, entry)
    }

    pub fn verify(&mut self, raw: &str) -> Option<AgentToken> {
        let raw = raw.trim();
        if raw.is_empty() {
            return None;
        }
        let hash = sha256_hex(raw);
        let now = super::devices::now_unix();
        let token = self
            .tokens
            .iter_mut()
            .find(|t| t.enabled && util::ct_eq(t.hash.as_bytes(), hash.as_bytes()))?;
        token.last_used = now;
        Some(token.clone())
    }

    pub fn revoke(&mut self, id: &str) -> bool {
        let before = self.tokens.len();
        self.tokens.retain(|t| t.id != id);
        self.tokens.len() != before
    }

    pub fn views(&self) -> Vec<Value> {
        self.tokens.iter().map(|t| t.view()).collect()
    }
}

/// Anonymous per-token request limiter: 120 requests per minute.
#[derive(Default)]
pub struct RateLimiter {
    inner: Mutex<HashMap<String, (Instant, u32)>>,
}

impl RateLimiter {
    pub fn check(&self, key: &str) -> bool {
        let mut map = self.inner.lock().unwrap();
        let now = Instant::now();
        let entry = map.entry(key.to_string()).or_insert((now, 0));
        if now.duration_since(entry.0) > Duration::from_secs(60) {
            *entry = (now, 0);
        }
        if entry.1 >= 120 {
            return false;
        }
        entry.1 += 1;
        true
    }

    pub fn cleanup(&self) {
        let mut map = self.inner.lock().unwrap();
        map.retain(|_, (seen, _)| seen.elapsed() <= Duration::from_secs(600));
    }
}

/// Append one line to the access audit log; rotates at 1 MiB.
pub fn audit(data_dir: &str, actor: &str, action: &str, target: &str, result: &str, ip: &str) {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let _ = std::fs::create_dir_all(data_dir);
    let path = format!("{data_dir}/audit.log");
    if let Ok(meta) = std::fs::metadata(&path) {
        if meta.len() > 1024 * 1024 {
            let _ = std::fs::rename(&path, format!("{data_dir}/audit.log.1"));
        }
    }
    let line = json!({
        "ts": super::devices::now_unix(),
        "actor": actor,
        "action": action,
        "target": target,
        "result": result,
        "ip": ip,
    });
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(&path)
    {
        let _ = writeln!(file, "{line}");
    }
}

pub fn read_audit(data_dir: &str, limit: usize) -> String {
    let Ok(text) = std::fs::read_to_string(format!("{data_dir}/audit.log")) else {
        return String::new();
    };
    let lines: Vec<&str> = text.lines().collect();
    let start = lines.len().saturating_sub(limit.clamp(1, 1000));
    lines[start..].join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_lifecycle() {
        let mut store = TokenStore::default();
        let (raw, entry) = store.create("Claude", &[SCOPE_READ.to_string(), SCOPE_WRITE.to_string()]);
        assert!(raw.starts_with("rd_"));
        assert!(can_read(&entry.scopes) && can_write(&entry.scopes));
        let verified = store.verify(&raw).expect("token verifies");
        assert_eq!(verified.id, entry.id);
        assert!(store.verify("rd_wrong").is_none());
        assert!(store.revoke(&entry.id));
        assert!(store.verify(&raw).is_none());
    }

    #[test]
    fn scopes_are_normalized() {
        let scopes = normalize_scopes(&["devices:write".into(), "bogus".into()]);
        assert_eq!(scopes, vec!["devices:write"]);
        assert!(can_read(&scopes));
        let read_only = normalize_scopes(&[SCOPE_READ.into()]);
        assert!(!can_write(&read_only));
    }
}
