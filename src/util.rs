use std::path::Path;
use std::process::{Command, Stdio};

use anyhow::{bail, Context, Result};

/// Run a command and return trimmed stdout. Fails on non-zero exit.
pub fn run(cmd: &str, args: &[&str]) -> Result<String> {
    let out = Command::new(cmd)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .with_context(|| format!("spawn {cmd}"))?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        bail!("{} exited with {}: {}", cmd, out.status, err.trim());
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim_end().to_string())
}

/// Run a command with stdin data (used for nft -f -).
pub fn run_input(cmd: &str, args: &[&str], input: &str) -> Result<String> {
    use std::io::Write;
    let mut child = Command::new(cmd)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("spawn {cmd}"))?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(input.as_bytes())?;
    }
    let out = child.wait_with_output()?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        bail!("{} exited with {}: {}", cmd, out.status, err.trim());
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim_end().to_string())
}

/// Run a command, returning stdout only when it succeeds.
pub fn run_ok(cmd: &str, args: &[&str]) -> Option<String> {
    run(cmd, args).ok()
}

pub fn read(path: &str) -> String {
    std::fs::read_to_string(path).unwrap_or_default()
}

pub fn read_trim(path: &str) -> String {
    read(path).trim().to_string()
}

/// Write a file atomically (same-directory temp + rename), with an explicit mode.
pub fn write_atomic(path: &str, data: &[u8], mode: u32) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let path = Path::new(path);
    let dir = path.parent().context("path has no parent")?;
    std::fs::create_dir_all(dir).ok();
    let tmp = dir.join(format!(
        ".{}.tmp.{}",
        path.file_name().and_then(|s| s.to_str()).unwrap_or("routerd"),
        std::process::id()
    ));
    {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(mode)
            .open(&tmp)
            .with_context(|| format!("open {}", tmp.display()))?;
        f.write_all(data)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path).with_context(|| format!("rename to {}", path.display()))?;
    Ok(())
}

/// Validate an OpenWrt config section name before it is passed to uci/init.d.
pub fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
}

/// Quote a value for `uci set` argv: we never use a shell, so no escaping is
/// required beyond rejecting NUL bytes (which cannot appear in a Command arg).
pub fn clean_value(value: &str) -> Result<&str> {
    if value.contains('\0') {
        bail!("value contains NUL");
    }
    Ok(value)
}

/// Constant-time byte comparison for secrets.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Parse "key=value" lines where value is single-quoted UCI output.
pub fn parse_shell_kv(text: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        out.push((k.to_string(), unquote_uci(v)));
    }
    out
}

fn unquote_uci(v: &str) -> String {
    let v = v.trim();
    if v.len() >= 2 && v.starts_with('\'') && v.ends_with('\'') {
        let inner = &v[1..v.len() - 1];
        // uci escapes a single quote as '\'' inside single quotes.
        inner.replace("'\\''", "'").replace("\\\\", "\\")
    } else {
        v.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constant_time_eq() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"ab"));
    }

    #[test]
    fn parses_uci_output() {
        let text = "network.lan=interface\nnetwork.lan.proto='static'\nnetwork.lan.ipaddr='192.168.1.1'\n";
        let kv = parse_shell_kv(text);
        assert_eq!(kv[0], ("network.lan".into(), "interface".into()));
        assert_eq!(kv[1], ("network.lan.proto".into(), "static".into()));
        assert_eq!(kv[2].1, "192.168.1.1");
    }

    #[test]
    fn unescapes_single_quote() {
        let text = "x.y='it'\\''s'";
        let kv = parse_shell_kv(text);
        assert_eq!(kv[0].1, "it's");
    }
}
