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

struct ValidatedRedirect {
    name: String,
    src: String,
    dest: String,
    proto: String,
    src_dport: String,
    dest_ip: String,
    dest_port: String,
}

fn validate_redirect(payload: &Value) -> Result<ValidatedRedirect> {
    let name = field(payload, "name");
    let src_dport = field(payload, "src_dport");
    let dest_ip = field(payload, "dest_ip");
    let dest_port = field(payload, "dest_port");
    let proto = field(payload, "proto");
    if name.is_empty() {
        bail!("规则名称不能为空");
    }
    if src_dport.parse::<u16>().is_err() {
        bail!("外部端口必须是 1-65535");
    }
    if dest_port.parse::<u16>().is_err() {
        bail!("内部端口必须是 1-65535");
    }
    if dest_ip.parse::<std::net::Ipv4Addr>().is_err() {
        bail!("内部 IP 地址无效");
    }
    if !["tcp", "udp", "tcp udp", "icmp"].contains(&proto.as_str()) {
        bail!("协议无效");
    }
    Ok(ValidatedRedirect {
        name,
        src: field_or(payload, "src", "wan"),
        dest: field_or(payload, "dest", "lan"),
        proto,
        src_dport,
        dest_ip,
        dest_port,
    })
}

fn apply_redirect_fields(section: &str, r: ValidatedRedirect, enabled: Option<&str>) -> Result<()> {
    let mut ops = vec![
        (section.to_string(), "name".into(), Some(r.name)),
        (section.to_string(), "target".into(), Some("DNAT".into())),
        (section.to_string(), "src".into(), Some(r.src)),
        (section.to_string(), "dest".into(), Some(r.dest)),
        (section.to_string(), "proto".into(), Some(r.proto)),
        (section.to_string(), "src_dport".into(), Some(r.src_dport)),
        (section.to_string(), "dest_ip".into(), Some(r.dest_ip)),
        (section.to_string(), "dest_port".into(), Some(r.dest_port)),
    ];
    if let Some(en) = enabled {
        ops.push((section.to_string(), "enabled".into(), Some(en.to_string())));
    }
    uci::apply("firewall", &ops)
}

pub fn add_redirect(payload: &Value) -> Result<String> {
    let validated = validate_redirect(payload)?;
    let section = uci::add("firewall", "redirect")?;
    apply_redirect_fields(&section, validated, Some("1"))?;
    tracing::info!("added redirect firewall.{section}");
    reload();
    Ok(section)
}

pub fn update_redirect(section: &str, payload: &Value) -> Result<()> {
    if !util::valid_name(section) {
        bail!("无效的规则 ID");
    }
    let cfg = uci::load("firewall")?;
    if cfg.section(section).is_none() {
        bail!("规则不存在");
    }
    let validated = validate_redirect(payload)?;
    let enabled = payload.get("enabled").and_then(|v| v.as_bool()).map(|b| if b { "1" } else { "0" });
    apply_redirect_fields(section, validated, enabled)?;
    tracing::info!("updated redirect firewall.{section}");
    reload();
    Ok(())
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

struct ValidatedRule {
    name: String,
    src: String,
    dest: String,
    proto: String,
    dest_port: String,
    src_ip: String,
    target: String,
}

fn validate_rule(payload: &Value) -> Result<ValidatedRule> {
    let name = field(payload, "name");
    let target = field_or(payload, "target", "ACCEPT").to_ascii_uppercase();
    let proto = field_or(payload, "proto", "tcp");
    let dest_port = field(payload, "dest_port");
    let src_ip = field(payload, "src_ip");
    if name.is_empty() {
        bail!("规则名称不能为空");
    }
    if !["ACCEPT", "DROP", "REJECT"].contains(&target.as_str()) {
        bail!("动作必须是 ACCEPT / DROP / REJECT");
    }
    if !["all", "tcp", "udp", "tcp udp", "icmp"].contains(&proto.as_str()) {
        bail!("协议无效");
    }
    if !dest_port.is_empty() {
        for p in dest_port.split(|c: char| c == ',' || c == '-' || c.is_whitespace()).filter(|s| !s.is_empty()) {
            if p.parse::<u16>().is_err() {
                bail!("目标端口无效: {p}");
            }
        }
    }
    if !src_ip.is_empty() {
        let ip_part = src_ip.split('/').next().unwrap_or("");
        if ip_part.parse::<std::net::Ipv4Addr>().is_err() {
            bail!("源 IP/CIDR 无效");
        }
    }
    Ok(ValidatedRule {
        name,
        src: field_or(payload, "src", "wan"),
        dest: field(payload, "dest"),
        proto,
        dest_port,
        src_ip,
        target,
    })
}

fn apply_rule_fields(section: &str, r: ValidatedRule, enabled: Option<&str>) -> Result<()> {
    let mut ops = vec![
        (section.to_string(), "name".into(), Some(r.name)),
        (section.to_string(), "src".into(), if r.src.is_empty() { None } else { Some(r.src) }),
        (section.to_string(), "dest".into(), if r.dest.is_empty() { None } else { Some(r.dest) }),
        (section.to_string(), "proto".into(), Some(r.proto)),
        (section.to_string(), "dest_port".into(), if r.dest_port.is_empty() { None } else { Some(r.dest_port) }),
        (section.to_string(), "src_ip".into(), if r.src_ip.is_empty() { None } else { Some(r.src_ip) }),
        (section.to_string(), "target".into(), Some(r.target)),
    ];
    if let Some(en) = enabled {
        ops.push((section.to_string(), "enabled".into(), Some(en.to_string())));
    }
    uci::apply("firewall", &ops)
}

pub fn add_rule(payload: &Value) -> Result<String> {
    let validated = validate_rule(payload)?;
    let section = uci::add("firewall", "rule")?;
    apply_rule_fields(&section, validated, Some("1"))?;
    tracing::info!("added firewall rule firewall.{section}");
    reload();
    Ok(section)
}

pub fn update_rule(section: &str, payload: &Value) -> Result<()> {
    if !util::valid_name(section) {
        bail!("无效的规则 ID");
    }
    let cfg = uci::load("firewall")?;
    if cfg.section(section).is_none() {
        bail!("规则不存在");
    }
    let validated = validate_rule(payload)?;
    let enabled = payload.get("enabled").and_then(|v| v.as_bool()).map(|b| if b { "1" } else { "0" });
    apply_rule_fields(section, validated, enabled)?;
    tracing::info!("updated firewall rule firewall.{section}");
    reload();
    Ok(())
}

pub fn delete_rule(section: &str) -> Result<()> {
    delete_redirect(section)
}

pub fn set_rule_enabled(section: &str, enabled: bool) -> Result<()> {
    set_redirect_enabled(section, enabled)
}
