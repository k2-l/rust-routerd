use std::collections::HashSet;
use std::sync::Mutex;

use anyhow::{bail, Context, Result};

use crate::access::devices::DeviceStore;
use crate::openwrt::uci;
use crate::util;

const TABLE_SEC: &str = "routerd_auth_table";
const RULE_SEC: &str = "routerd_auth_rule";
const INPUT_SEC: &str = "routerd_auth_input";
const TABLE_FILE: &str = "auth-table.nft";
const RULE_FILE: &str = "auth-forward.nft";
const INPUT_FILE: &str = "auth-input.nft";

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

fn conntrack_bin() -> Option<&'static str> {
    ["/usr/sbin/conntrack", "/sbin/conntrack", "/usr/bin/conntrack"]
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

    let fwd_rule = format!(
        "iifname \"{iface}\" ether saddr != @routerd_authorized drop comment \"routerd: unauthorized forward\"\n"
    );

    // Block unauthorized LAN clients from probing SSH (22) or local router ports while permitting DHCP & DNS
    let input_rule = format!(
        "iifname \"{iface}\" ether saddr != @routerd_authorized udp dport {{ 53, 67 }} accept comment \"routerd: allow unauth dhcp/dns\"\n\
         iifname \"{iface}\" ether saddr != @routerd_authorized tcp dport {{ 22, 53 }} reject comment \"routerd: block unauth ssh\"\n"
    );

    util::write_atomic(&format!("{data_dir}/{TABLE_FILE}"), table.as_bytes(), 0o644)?;
    util::write_atomic(&format!("{data_dir}/{RULE_FILE}"), fwd_rule.as_bytes(), 0o644)?;
    util::write_atomic(&format!("{data_dir}/{INPUT_FILE}"), input_rule.as_bytes(), 0o644)?;
    Ok(())
}

fn include_state(data_dir: &str) -> (bool, bool, bool) {
    let cfg = uci::load("firewall").unwrap_or_default();
    let check = |sec: &str, file: &str, pos: &str, chain: Option<&str>| -> bool {
        let path = format!("{data_dir}/{file}");
        cfg.section(sec)
            .map(|s| {
                s.kind == "include"
                    && s.get("type") == Some("nftables")
                    && s.get("path") == Some(path.as_str())
                    && s.get("position") == Some(pos)
                    && s.get("chain") == chain
                    && !matches!(s.get("enabled"), Some("0"))
            })
            .unwrap_or(false)
    };
    (
        check(TABLE_SEC, TABLE_FILE, "table-prepend", None),
        check(RULE_SEC, RULE_FILE, "chain-prepend", Some("forward")),
        check(INPUT_SEC, INPUT_FILE, "chain-prepend", Some("input")),
    )
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
    util::run(bin, &["set", &format!("{base}.path={data_dir}/{file}")])?;
    util::run(bin, &["set", &format!("{base}.position={position}")])?;
    util::run(bin, &["set", &format!("{base}.enabled=1")])?;
    if let Some(chain) = chain {
        util::run(bin, &["set", &format!("{base}.chain={chain}")])?;
    }
    Ok(())
}

fn ensure_includes(data_dir: &str) -> Result<bool> {
    let (table_ok, rule_ok, input_ok) = include_state(data_dir);
    if table_ok && rule_ok && input_ok {
        return Ok(false);
    }
    if !table_ok {
        ensure_include(TABLE_SEC, data_dir, TABLE_FILE, "table-prepend", None)?;
    }
    if !rule_ok {
        ensure_include(RULE_SEC, data_dir, RULE_FILE, "chain-prepend", Some("forward"))?;
    }
    if !input_ok {
        ensure_include(INPUT_SEC, data_dir, INPUT_FILE, "chain-prepend", Some("input"))?;
    }
    util::run(uci::bin(), &["commit", "firewall"])?;
    Ok(true)
}

fn remove_includes() -> Result<bool> {
    let cfg = uci::load("firewall").unwrap_or_default();
    if cfg.section(TABLE_SEC).is_none()
        && cfg.section(RULE_SEC).is_none()
        && cfg.section(INPUT_SEC).is_none()
    {
        return Ok(false);
    }
    for sec in [TABLE_SEC, RULE_SEC, INPUT_SEC] {
        let _ = util::run_ok(uci::bin(), &["-q", "delete", &format!("firewall.{sec}")]);
    }
    util::run(uci::bin(), &["commit", "firewall"])?;
    Ok(true)
}

fn reload_fw4() -> Result<()> {
    util::run("/etc/init.d/firewall", &["reload"])?;
    Ok(())
}

fn flush_unauthorized_conntrack(store: &DeviceStore) {
    let Some(ct) = conntrack_bin() else {
        return;
    };
    let allowed: HashSet<String> = store
        .allowed_macs()
        .into_iter()
        .map(|m| m.to_ascii_lowercase())
        .collect();

    let mut target_ips: HashSet<String> = HashSet::new();
    for a in crate::openwrt::net::arp_table() {
        let mac = a["mac"].as_str().unwrap_or("").to_ascii_lowercase();
        let ip = a["ip"].as_str().unwrap_or("");
        let dev = a["device"].as_str().unwrap_or("");
        if !mac.is_empty()
            && !ip.is_empty()
            && (dev.starts_with("br-") || dev.starts_with("lan") || dev.starts_with("eth"))
            && !allowed.contains(&mac)
        {
            target_ips.insert(ip.to_string());
        }
    }
    for l in crate::openwrt::net::leases() {
        let mac = l["mac"].as_str().unwrap_or("").to_ascii_lowercase();
        let ip = l["ip"].as_str().unwrap_or("");
        if !mac.is_empty() && !ip.is_empty() && !allowed.contains(&mac) {
            target_ips.insert(ip.to_string());
        }
    }

    for ip in target_ips {
        let _ = util::run_ok(ct, &["-D", "-s", &ip]);
        let _ = util::run_ok(ct, &["-D", "-d", &ip]);
    }
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
    flush_unauthorized_conntrack(store);
    Ok(())
}

fn sync_locked(store: &DeviceStore, data_dir: &str, sim: bool) -> Result<()> {
    if sim || !store.enforcement {
        return Ok(());
    }
    write_files(store, data_dir)?;
    if ensure_includes(data_dir)? {
        reload_fw4()?;
        flush_unauthorized_conntrack(store);
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

pub fn sync(store: &DeviceStore, data_dir: &str, sim: bool) -> Result<()> {
    let _guard = lock().lock().unwrap();
    sync_locked(store, data_dir, sim)
}

pub fn enable(store: &DeviceStore, data_dir: &str, sim: bool) -> Result<()> {
    if sim {
        return Ok(());
    }
    let _guard = lock().lock().unwrap();
    write_files(store, data_dir)?;
    ensure_includes(data_dir)?;
    reload_fw4()?;
    flush_unauthorized_conntrack(store);
    Ok(())
}

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
        flush_unauthorized_conntrack(store);
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
