use std::sync::Mutex;

use anyhow::{bail, Context, Result};

use crate::access::devices::DeviceStore;
use crate::openwrt::uci;
use crate::util;

const TABLE_SEC: &str = "routerd_auth_table";
const RULE_SEC: &str = "routerd_auth_rule";
const TABLE_FILE: &str = "auth-table.nft";
const RULE_FILE: &str = "auth-forward.nft";

fn lock() -> &'static Mutex<()> {
    static LOCK: std::sync::OnceLock<Mutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

pub fn available() -> bool {
    nft_bin().is_some()
}

fn nft_bin() -> Option<&'static str> {
    ["/usr/sbin/nft", "/sbin/nft", "/usr/bin/nft"]
        .into_iter()
        .find(|path| std::path::Path::new(path).exists())
}

fn lan_iface() -> String {
    let device = uci::load("network")
        .ok()
        .and_then(|cfg| cfg.section("lan").cloned())
        .and_then(|s| s.get("device").map(|d| d.to_string()))
        .unwrap_or_else(|| "br-lan".to_string());
    if !device.is_empty()
        && device
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | ':'))
    {
        device
    } else {
        "br-lan".to_string()
    }
}

pub fn write_files(store: &DeviceStore, data_dir: &str) -> Result<()> {
    let iface = lan_iface();
    let macs = store.allowed_macs();

    let mut table = String::from("set routerd_authorized {\n\ttype ether_addr\n");
    if !macs.is_empty() {
        table.push_str("\telements = { ");
        for (i, mac) in macs.iter().enumerate() {
            if i > 0 {
                table.push_str(", ");
            }
            table.push_str(&mac.to_ascii_lowercase());
        }
        table.push_str(" }\n");
    }
    table.push_str("}\n");

    let rule = format!(
        "iifname \"{iface}\" ether saddr != @routerd_authorized drop comment \"routerd: unauthorized device\"\n"
    );

    util::write_atomic(&format!("{data_dir}/{TABLE_FILE}"), table.as_bytes(), 0o644)?;
    util::write_atomic(&format!("{data_dir}/{RULE_FILE}"), rule.as_bytes(), 0o644)?;
    Ok(())
}

fn include_state(data_dir: &str) -> (bool, bool) {
    let cfg = uci::load("firewall").unwrap_or_default();
    let table_path = format!("{data_dir}/{TABLE_FILE}");
    let rule_path = format!("{data_dir}/{RULE_FILE}");
    let table_ok = cfg
        .section(TABLE_SEC)
        .map(|s| {
            s.kind == "include"
                && s.get("type") == Some("nftables")
                && s.get("path") == Some(table_path.as_str())
                && s.get("position") == Some("table-prepend")
                && !matches!(s.get("enabled"), Some("0"))
        })
        .unwrap_or(false);
    let rule_ok = cfg
        .section(RULE_SEC)
        .map(|s| {
            s.kind == "include"
                && s.get("type") == Some("nftables")
                && s.get("path") == Some(rule_path.as_str())
                && s.get("position") == Some("chain-prepend")
                && s.get("chain") == Some("forward")
                && !matches!(s.get("enabled"), Some("0"))
        })
        .unwrap_or(false);
    (table_ok, rule_ok)
}

fn ensure_include(
    sec: &str,
    data_dir: &str,
    file: &str,
    position: &str,
    chain: Option<&str>,
) -> Result<()> {
    let bin = uci::bin();
    let cfg = uci::load("firewall").unwrap_or_default();
    if let Some(section) = cfg.section(sec) {
        if section.kind != "include" {
            let _ = util::run_ok(bin, &["-q", "delete", &format!("firewall.{sec}")]);
        }
    }
    util::run(bin, &["set", &format!("firewall.{sec}=include")])?;
    let base = format!("firewall.{sec}");
    util::run(bin, &["set", &format!("{base}.type=nftables")])?;
    util::run(
        bin,
        &["set", &format!("{base}.path={data_dir}/{file}")],
    )?;
    util::run(bin, &["set", &format!("{base}.position={position}")])?;
    util::run(bin, &["set", &format!("{base}.enabled=1")])?;
    if let Some(chain) = chain {
        util::run(bin, &["set", &format!("{base}.chain={chain}")])?;
    }
    Ok(())
}

fn ensure_includes(data_dir: &str) -> Result<bool> {
    let (table_ok, rule_ok) = include_state(data_dir);
    if table_ok && rule_ok {
        return Ok(false);
    }
    if !table_ok {
        ensure_include(TABLE_SEC, data_dir, TABLE_FILE, "table-prepend", None)?;
    }
    if !rule_ok {
        ensure_include(RULE_SEC, data_dir, RULE_FILE, "chain-prepend", Some("forward"))?;
    }
    util::run(uci::bin(), &["commit", "firewall"])?;
    Ok(true)
}

fn remove_includes() -> Result<bool> {
    let cfg = uci::load("firewall").unwrap_or_default();
    if cfg.section(TABLE_SEC).is_none() && cfg.section(RULE_SEC).is_none() {
        return Ok(false);
    }
    for sec in [TABLE_SEC, RULE_SEC] {
        let _ = util::run_ok(
            uci::bin(),
            &["-q", "delete", &format!("firewall.{sec}")],
        );
    }
    util::run(uci::bin(), &["commit", "firewall"])?;
    Ok(true)
}

fn reload_fw4() -> Result<()> {
    util::run("/etc/init.d/firewall", &["reload"])?;
    Ok(())
}

fn nft_sync(store: &DeviceStore) -> Result<()> {
    let bin = nft_bin().context("nft binary not found")?;
    let macs = store.allowed_macs();
    let mut script = String::from("flush set inet fw4 routerd_authorized\n");
    if !macs.is_empty() {
        script.push_str("add element inet fw4 routerd_authorized { ");
        for (i, mac) in macs.iter().enumerate() {
            if i > 0 {
                script.push_str(", ");
            }
            script.push_str(&mac.to_ascii_lowercase());
        }
        script.push_str(" }\n");
    }
    util::run_input(bin, &["-f", "-"], &script)?;
    Ok(())
}

fn sync_locked(store: &DeviceStore, data_dir: &str, sim: bool) -> Result<()> {
    if sim || !store.enforcement {
        return Ok(());
    }
    write_files(store, data_dir)?;
    if ensure_includes(data_dir)? {
        reload_fw4()?;
        return Ok(());
    }
    match nft_sync(store) {
        Ok(()) => Ok(()),
        Err(first) => {
            tracing::warn!("nft sync failed ({first:#}), reloading fw4 and retrying");
            reload_fw4()?;
            nft_sync(store)
        }
    }
}

/// Fast path used on authorize/revoke/expiry while enforcement is active.
pub fn sync(store: &DeviceStore, data_dir: &str, sim: bool) -> Result<()> {
    let _guard = lock().lock().unwrap();
    sync_locked(store, data_dir, sim)
}

/// Enable enforcement: persist rules, install fw4 includes and reload once.
pub fn enable(store: &DeviceStore, data_dir: &str, sim: bool) -> Result<()> {
    if sim {
        return Ok(());
    }
    let _guard = lock().lock().unwrap();
    write_files(store, data_dir)?;
    ensure_includes(data_dir)?;
    reload_fw4()?;
    Ok(())
}

/// Disable enforcement: remove includes and reload fw4.
pub fn disable(_data_dir: &str, sim: bool) -> Result<()> {
    if sim {
        return Ok(());
    }
    let _guard = lock().lock().unwrap();
    if remove_includes()? {
        reload_fw4()?;
    }
    Ok(())
}

/// Startup reconciliation.
pub fn bootstrap(store: &DeviceStore, data_dir: &str, sim: bool) -> Result<()> {
    if sim {
        return Ok(());
    }
    let _guard = lock().lock().unwrap();
    if !store.enforcement {
        if remove_includes()? {
            reload_fw4()?;
        }
        return Ok(());
    }
    if nft_bin().is_none() {
        bail!("nft binary not found");
    }
    write_files(store, data_dir)?;
    let changed = ensure_includes(data_dir)?;
    if changed {
        reload_fw4()?;
        return Ok(());
    }
    match nft_sync(store) {
        Ok(()) => Ok(()),
        Err(_) => {
            reload_fw4()?;
            nft_sync(store)
        }
    }
}
