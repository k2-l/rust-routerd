use anyhow::{bail, Result};
use serde_json::{json, Value};

use crate::openwrt::uci;
use crate::util;

fn reload() {
    let _ = util::run_ok("/etc/init.d/firewall", &["reload"]);
}

pub fn zones() -> Vec<Value> {
    let cfg = uci::load("firewall").unwrap_or_default();
    cfg.by_kind("zone")
        .map(|z| {
            json!({
                "name": z.get_or("name", ""),
                "input": z.get_or("input", "REJECT"),
                "output": z.get_or("output", "ACCEPT"),
                "forward": z.get_or("forward", "REJECT"),
                "masq": z.bool("masq"),
                "networks": z.get_or("network", ""),
            })
        })
        .collect()
}

pub fn redirects() -> Vec<Value> {
    let cfg = uci::load("firewall").unwrap_or_default();
    cfg.by_kind("redirect")
        .map(|r| {
            json!({
                "section": r.name,
                "name": r.get_or("name", "未命名规则"),
                "enabled": !matches!(r.get("enabled"), Some("0")),
                "target": r.get_or("target", "DNAT"),
                "proto": r.get_or("proto", "tcp"),
                "src": r.get_or("src", "wan"),
                "dest": r.get_or("dest", "lan"),
                "src_dport": r.get_or("src_dport", ""),
                "dest_ip": r.get_or("dest_ip", ""),
                "dest_port": r.get_or("dest_port", ""),
            })
        })
        .collect()
}

pub fn rules() -> Vec<Value> {
    let cfg = uci::load("firewall").unwrap_or_default();
    cfg.by_kind("rule")
        .map(|r| {
            json!({
                "section": r.name,
                "name": r.get_or("name", ""),
                "enabled": !matches!(r.get("enabled"), Some("0")),
                "target": r.get_or("target", ""),
                "src": r.get_or("src", ""),
                "dest": r.get_or("dest", ""),
                "proto": r.get_or("proto", ""),
                "dest_port": r.get_or("dest_port", ""),
                "src_ip": r.get_or("src_ip", ""),
            })
        })
        .collect()
}

fn field(payload: &Value, key: &str) -> String {
    payload
        .get(key)
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_string()
}

pub fn add_redirect(payload: &Value) -> Result<String> {
    let name = field(payload, "name");
    let src_dport = field(payload, "src_dport");
    let dest_ip = field(payload, "dest_ip");
    let dest_port = field(payload, "dest_port");
    let proto = field(payload, "proto");
    if name.is_empty() {
        bail!("规则名称不能为空");
    }
    if !src_dport.parse::<u16>().is_ok() {
        bail!("外部端口必须是 1-65535");
    }
    if !dest_port.parse::<u16>().is_ok() {
        bail!("内部端口必须是 1-65535");
    }
    if dest_ip.parse::<std::net::Ipv4Addr>().is_err() {
        bail!("内部 IP 地址无效");
    }
    if !["tcp", "udp", "tcp udp", "icmp"].contains(&proto.as_str()) {
        bail!("协议无效");
    }
    let section = uci::add("firewall", "redirect")?;
    let path = format!("firewall.{section}");
    uci::apply(
        "firewall",
        &[
            (section.clone(), "name".into(), Some(name)),
            (section.clone(), "target".into(), Some("DNAT".into())),
            (section.clone(), "src".into(), Some(field_or(payload, "src", "wan"))),
            (section.clone(), "dest".into(), Some(field_or(payload, "dest", "lan"))),
            (section.clone(), "proto".into(), Some(proto)),
            (section.clone(), "src_dport".into(), Some(src_dport)),
            (section.clone(), "dest_ip".into(), Some(dest_ip)),
            (section.clone(), "dest_port".into(), Some(dest_port)),
            (section.clone(), "enabled".into(), Some("1".into())),
        ],
    )?;
    tracing::info!("added redirect {path}");
    reload();
    Ok(section)
}

fn field_or(payload: &Value, key: &str, default: &str) -> String {
    let v = field(payload, key);
    if v.is_empty() {
        default.to_string()
    } else {
        v
    }
}

pub fn delete_redirect(section: &str) -> Result<()> {
    if !util::valid_name(section) {
        bail!("无效的规则 ID");
    }
    let cfg = uci::load("firewall")?;
    if cfg.section(section).is_none() {
        bail!("规则不存在");
    }
    uci::delete(&format!("firewall.{section}"))?;
    uci::commit("firewall")?;
    reload();
    Ok(())
}

pub fn set_redirect_enabled(section: &str, enabled: bool) -> Result<()> {
    if !util::valid_name(section) {
        bail!("无效的规则 ID");
    }
    uci::set_opt("firewall", section, "enabled", if enabled { "1" } else { "0" })?;
    uci::commit("firewall")?;
    reload();
    Ok(())
}
