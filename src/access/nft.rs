use std::collections::HashSet;
use std::sync::Mutex;

use anyhow::{bail, Context, Result};

use crate::access::devices::DeviceStore;
use crate::openwrt::uci;
use crate::util;

const TABLE_SEC: &str = "routerd_auth_table";
const RULE_SEC: &str = "routerd_auth_rule";
const INPUT_SEC: &str = "routerd_auth_input";
const QOS_SEC: &str = "routerd_qos_forward";
const TABLE_FILE: &str = "auth-table.nft";
const RULE_FILE: &str = "auth-forward.nft";
const INPUT_FILE: &str = "auth-input.nft";
const QOS_FILE: &str = "qos-forward.nft";

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

fn format_mac_set(name: &str, macs: &[String]) -> String {
    let mut table = format!("set {name} {{\n\ttype ether_addr\n");
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
    table
}

pub(crate) fn render_auth_files(
    store: &DeviceStore,
    iface: &str,
) -> Option<(String, String, String)> {
    if store.enforcement {
        let macs = store.allowed_macs();
        let table = format_mac_set("routerd_authorized", &macs);
        let fwd_rule = format!(
            "iifname \"{iface}\" ether saddr != @routerd_authorized drop comment \"routerd: unauthorized forward\"\n"
        );
        // Block unauthorized LAN clients from probing SSH (22) or local router ports while permitting DHCP & DNS
        let input_rule = format!(
            "iifname \"{iface}\" ether saddr != @routerd_authorized udp dport {{ 53, 67 }} accept comment \"routerd: allow unauth dhcp/dns\"\n\
             iifname \"{iface}\" ether saddr != @routerd_authorized tcp dport {{ 22, 53 }} reject comment \"routerd: block unauth ssh\"\n"
        );
        return Some((table, fwd_rule, input_rule));
    }

    let blocked = store.blocked_macs();
    if blocked.is_empty() {
        return None;
    }
    let table = format_mac_set("routerd_blocked", &blocked);
    let fwd_rule = format!(
        "iifname \"{iface}\" ether saddr @routerd_blocked drop comment \"routerd: blocked forward\"\n"
    );
    let input_rule = format!(
        "iifname \"{iface}\" ether saddr @routerd_blocked udp dport {{ 53, 67 }} accept comment \"routerd: allow blocked dhcp/dns\"\n\
         iifname \"{iface}\" ether saddr @routerd_blocked tcp dport {{ 22, 53 }} reject comment \"routerd: block blocked ssh\"\n"
    );
    Some((table, fwd_rule, input_rule))
}

fn remove_auth_files(data_dir: &str) {
    for file in [TABLE_FILE, RULE_FILE, INPUT_FILE] {
        let _ = std::fs::remove_file(format!("{data_dir}/{file}"));
    }
}

pub fn write_files(store: &DeviceStore, data_dir: &str) -> Result<()> {
    let iface = lan_iface();
    let Some((table, fwd_rule, input_rule)) = render_auth_files(store, &iface) else {
        remove_auth_files(data_dir);
        return Ok(());
    };
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
    let cfg = uci::load("firewall").unwrap_or_default();
    if let Some(section) = cfg.section(sec) {
        if section.kind != "include" {
            let _ = uci::delete(&format!("firewall.{sec}"));
        }
    }
    uci::set(&format!("firewall.{sec}"), "include")?;
    let mut ops = vec![
        (sec.into(), "type".into(), Some("nftables".into())),
        (sec.into(), "path".into(), Some(format!("{data_dir}/{file}"))),
        (sec.into(), "position".into(), Some(position.into())),
        (sec.into(), "enabled".into(), Some("1".into())),
    ];
    if let Some(chain) = chain {
        ops.push((sec.into(), "chain".into(), Some(chain.into())));
    }
    uci::apply("firewall", &ops)?;
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
        let _ = uci::delete(&format!("firewall.{sec}"));
    }
    Ok(true)
}

fn reload_fw4() -> Result<()> {
    util::run("/etc/init.d/firewall", &["reload"])?;
    Ok(())
}

fn flush_unauthorized_conntrack(store: &DeviceStore) {
    let should_flush = |mac: &str, set: &HashSet<String>| -> bool {
        if store.enforcement {
            !set.contains(mac)
        } else {
            set.contains(mac)
        }
    };

    let mac_set: HashSet<String> = if store.enforcement {
        store
            .allowed_macs()
            .into_iter()
            .map(|m| m.to_ascii_lowercase())
            .collect()
    } else {
        let blocked: HashSet<String> = store
            .blocked_macs()
            .into_iter()
            .map(|m| m.to_ascii_lowercase())
            .collect();
        if blocked.is_empty() {
            return;
        }
        blocked
    };

    let lan_wan = crate::openwrt::net::lan_wan_devs();
    let mut target_ips: HashSet<std::net::Ipv4Addr> = HashSet::new();
    for a in crate::openwrt::net::arp_table() {
        let mac = a["mac"].as_str().unwrap_or("").to_ascii_lowercase();
        let ip = a["ip"].as_str().unwrap_or("");
        let dev = a["device"].as_str().unwrap_or("");
        if !mac.is_empty()
            && crate::openwrt::net::is_lan_arp_device_with(dev, &lan_wan)
            && should_flush(&mac, &mac_set)
        {
            if let Ok(addr) = ip.parse::<std::net::Ipv4Addr>() {
                target_ips.insert(addr);
            }
        }
    }
    for l in crate::openwrt::net::leases() {
        let mac = l["mac"].as_str().unwrap_or("").to_ascii_lowercase();
        let ip = l["ip"].as_str().unwrap_or("");
        if !mac.is_empty() && should_flush(&mac, &mac_set) {
            if let Ok(addr) = ip.parse::<std::net::Ipv4Addr>() {
                target_ips.insert(addr);
            }
        }
    }

    if !target_ips.is_empty() {
        if let Err(e) = crate::openwrt::conntrack::flush_ips(&target_ips) {
            tracing::warn!("ctnetlink flush unauthorized failed: {e:#}");
        }
    }
}

fn nft_sync(store: &DeviceStore) -> Result<()> {
    let bin = nft_bin().context("nft binary not found")?;
    let (set_name, macs) = if store.enforcement {
        ("routerd_authorized", store.allowed_macs())
    } else {
        ("routerd_blocked", store.blocked_macs())
    };
    let mut script = format!("flush set inet fw4 {set_name}\n");
    if !macs.is_empty() {
        script.push_str(&format!("add element inet fw4 {set_name} {{ "));
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
    if sim {
        return Ok(());
    }
    if !store.enforcement && store.blocked_macs().is_empty() {
        remove_auth_files(data_dir);
        if remove_includes()? {
            reload_fw4()?;
        }
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

pub fn reconfigure(store: &DeviceStore, data_dir: &str, sim: bool) -> Result<()> {
    if sim {
        return Ok(());
    }
    let _guard = lock().lock().unwrap();
    if !store.enforcement && store.blocked_macs().is_empty() {
        remove_auth_files(data_dir);
        if remove_includes()? {
            reload_fw4()?;
        }
        return Ok(());
    }
    write_files(store, data_dir)?;
    ensure_includes(data_dir)?;
    reload_fw4()?;
    flush_unauthorized_conntrack(store);
    Ok(())
}

pub fn bootstrap(store: &DeviceStore, data_dir: &str, sim: bool) -> Result<()> {
    if sim {
        return Ok(());
    }
    let _guard = lock().lock().unwrap();
    if !store.enforcement && store.blocked_macs().is_empty() {
        remove_auth_files(data_dir);
        if remove_includes()? {
            reload_fw4()?;
        }
        return Ok(());
    }
    if nft_bin().is_none() {
        bail!("nft binary not found");
    }
    sync_locked(store, data_dir, sim)
}

pub fn apply_qos(store: &DeviceStore, data_dir: &str, sim: bool) -> Result<()> {
    if sim {
        return Ok(());
    }
    let _guard = lock().lock().unwrap();
    let iface = lan_iface();
    let limits = store.rate_limited_devices();
    let qos_path = format!("{data_dir}/{QOS_FILE}");

    let mut rules = String::new();
    for (mac, rx_kbps, tx_kbps) in &limits {
        let m = mac.to_ascii_lowercase();
        if *tx_kbps > 0 {
            let kbytes = (*tx_kbps / 8).max(1);
            let burst = (kbytes / 2).max(4);
            rules.push_str(&format!(
                "iifname \"{iface}\" ether saddr {m} limit rate over {kbytes} kbytes/second burst {burst} kbytes drop comment \"routerd: tx limit {m}\"\n"
            ));
        }
        if *rx_kbps > 0 {
            let kbytes = (*rx_kbps / 8).max(1);
            let burst = (kbytes / 2).max(4);
            rules.push_str(&format!(
                "oifname \"{iface}\" ether daddr {m} limit rate over {kbytes} kbytes/second burst {burst} kbytes drop comment \"routerd: rx limit {m}\"\n"
            ));
        }
    }

    let cfg = uci::load("firewall").unwrap_or_default();
    if limits.is_empty() {
        let _ = std::fs::remove_file(&qos_path);
        if cfg.section(QOS_SEC).is_some() {
            let _ = uci::delete(&format!("firewall.{QOS_SEC}"));
            reload_fw4()?;
        }
        return Ok(());
    }

    util::write_atomic(&qos_path, rules.as_bytes(), 0o644)?;
    let needs_uci = cfg
        .section(QOS_SEC)
        .map(|s| {
            s.kind != "include"
                || s.get("path") != Some(qos_path.as_str())
                || s.get("chain") != Some("forward")
        })
        .unwrap_or(true);
    if needs_uci {
        ensure_include(QOS_SEC, data_dir, QOS_FILE, "chain-prepend", Some("forward"))?;
    }
    reload_fw4()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::access::devices::Device;

    #[test]
    fn render_auth_files_covers_whitelist_blacklist_and_empty_free_mode() {
        let mut store = DeviceStore::default();
        store.devices.insert(
            "AA:BB:CC:DD:EE:01".into(),
            Device {
                mac: "AA:BB:CC:DD:EE:01".into(),
                authorized: true,
                ..Device::default()
            },
        );
        store.devices.insert(
            "AA:BB:CC:DD:EE:02".into(),
            Device {
                mac: "AA:BB:CC:DD:EE:02".into(),
                blocked: true,
                ..Device::default()
            },
        );

        // 1. Whitelist enforcement enabled
        store.enforcement = true;
        let (tbl, fwd, inp) = render_auth_files(&store, "br-lan").expect("whitelist rules");
        assert!(tbl.contains("set routerd_authorized"));
        assert!(tbl.contains("aa:bb:cc:dd:ee:01"));
        assert!(!tbl.contains("aa:bb:cc:dd:ee:02"));
        assert!(fwd.contains("ether saddr != @routerd_authorized drop"));
        assert!(inp.contains("ether saddr != @routerd_authorized"));

        // 2. Free mode with blocked MACs -> blacklist rules active
        store.enforcement = false;
        let (tbl, fwd, inp) = render_auth_files(&store, "br-lan").expect("blacklist rules");
        assert!(tbl.contains("set routerd_blocked"));
        assert!(tbl.contains("aa:bb:cc:dd:ee:02"));
        assert!(!tbl.contains("aa:bb:cc:dd:ee:01"));
        assert!(fwd.contains("ether saddr @routerd_blocked drop"));
        assert!(inp.contains("ether saddr @routerd_blocked"));

        // 3. Free mode with no blocked MACs -> None
        store.unblock("AA:BB:CC:DD:EE:02");
        assert!(render_auth_files(&store, "br-lan").is_none());
    }
}
