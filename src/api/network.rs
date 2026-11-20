use std::net::Ipv4Addr;
use std::time::Duration;

use axum::extract::{Query, State};
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};
use crate::state::AppState;

use super::{ok, ApiError, ApiResult};
use crate::openwrt::{net, uci};
use crate::util;

fn wan_value() -> Value {
    let cfg = uci::load("network").unwrap_or_default();
    let s = cfg
        .section("wan")
        .or_else(|| cfg.first_of("interface"))
        .cloned()
        .unwrap_or_default();
    json!({
        "section": if s.name.is_empty() { "wan".to_string() } else { s.name.clone() },
        "proto": s.get_or("proto", "dhcp"),
        "ipaddr": s.get_or("ipaddr", ""),
        "netmask": s.get_or("netmask", ""),
        "gateway": s.get_or("gateway", ""),
        "dns": s.get_or("dns", ""),
        "username": s.get_or("username", ""),
        "password": s.get_or("password", ""),
        "mtu": s.get_or("mtu", ""),
        "disabled": s.bool("disabled"),
    })
}

fn lan_value() -> Value {
    let cfg = uci::load("network").unwrap_or_default();
    let s = cfg.section("lan").cloned().unwrap_or_default();
    let dhcp = uci::load("dhcp").unwrap_or_default();
    let d = dhcp.section("lan").cloned().unwrap_or_default();
    json!({
        "section": if s.name.is_empty() { "lan".to_string() } else { s.name.clone() },
        "ipaddr": s.get_or("ipaddr", "192.168.1.1"),
        "netmask": s.get_or("netmask", "255.255.255.0"),
        "proto": s.get_or("proto", "static"),
        "device": s.get_or("device", "br-lan"),
        "dhcp": {
            "start": d.get_or("start", "100"),
            "limit": d.get_or("limit", "150"),
            "leasetime": d.get_or("leasetime", "12h"),
            "ignore": d.bool("ignore"),
        },
        "dns": d.get_or("dns", ""),
    })
}

pub async fn get() -> ApiResult<Json<Value>> {
    let data = tokio::task::spawn_blocking(|| {
        json!({
            "wan": wan_value(),
            "lan": lan_value(),
            "wan_status": net::wan_summary(),
            "interfaces": net::interfaces(),
            "routes": net::routes(),
            "devices": net::physical_devices(),
            "dns": net::dns_servers(),
        })
    })
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;
    Ok(ok(data))
}

fn valid_ip(value: &str) -> bool {
    value.parse::<Ipv4Addr>().is_ok()
}

fn valid_mask(value: &str) -> bool {
    value
        .parse::<Ipv4Addr>()
        .map(|m| {
            let bits = u32::from(m);
            let inv = !bits;
            inv == 0 || (inv & (inv.wrapping_add(1))) == 0
        })
        .unwrap_or(false)
}

fn schedule_reload(services: &[&'static str]) {
    let services: Vec<&'static str> = services.to_vec();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(900)).await;
        let _ = tokio::task::spawn_blocking(move || {
            for s in services {
                let _ = uci::reload_service(s);
            }
        })
        .await;
    });
}

pub async fn update_wan(Json(body): Json<Value>) -> ApiResult<Json<Value>> {
    let proto = body
        .get("proto")
        .and_then(|v| v.as_str())
        .unwrap_or("dhcp")
        .to_string();
    if !["dhcp", "static", "pppoe", "none"].contains(&proto.as_str()) {
        return Err(ApiError::bad("不支持的 WAN 协议"));
    }
    let ipaddr = body.get("ipaddr").and_then(|v| v.as_str()).unwrap_or("");
    let netmask = body.get("netmask").and_then(|v| v.as_str()).unwrap_or("");
    let gateway = body.get("gateway").and_then(|v| v.as_str()).unwrap_or("");
    let username = body.get("username").and_then(|v| v.as_str()).unwrap_or("");
    let password = body.get("password").and_then(|v| v.as_str()).unwrap_or("");
    let dns = body.get("dns").and_then(|v| v.as_str()).unwrap_or("");
    let mtu = body.get("mtu").and_then(|v| v.as_str()).unwrap_or("");

    let mut changes: Vec<(String, String, Option<String>)> =
        vec![("wan".into(), "proto".into(), Some(proto.clone()))];

    match proto.as_str() {
        "static" => {
            if !valid_ip(ipaddr) || !valid_mask(netmask) {
                return Err(ApiError::bad("IP 地址或子网掩码无效"));
            }
            if !gateway.is_empty() && !valid_ip(gateway) {
                return Err(ApiError::bad("网关地址无效"));
            }
            changes.extend([
                ("wan".into(), "ipaddr".into(), Some(ipaddr.into())),
                ("wan".into(), "netmask".into(), Some(netmask.into())),
                ("wan".into(), "gateway".into(), Some(gateway.into())),
                ("wan".into(), "username".into(), None),
                ("wan".into(), "password".into(), None),
            ]);
        }
        "pppoe" => {
            if username.is_empty() || password.is_empty() {
                return Err(ApiError::bad("PPPoE 账号和密码不能为空"));
            }
            changes.extend([
                ("wan".into(), "username".into(), Some(username.into())),
                ("wan".into(), "password".into(), Some(password.into())),
                ("wan".into(), "ipaddr".into(), None),
                ("wan".into(), "netmask".into(), None),
                ("wan".into(), "gateway".into(), None),
            ]);
        }
        _ => {
            changes.extend([
                ("wan".into(), "ipaddr".into(), None),
                ("wan".into(), "netmask".into(), None),
                ("wan".into(), "gateway".into(), None),
                ("wan".into(), "username".into(), None),
                ("wan".into(), "password".into(), None),
            ]);
        }
    }

    if !dns.trim().is_empty() {
        let servers: Vec<&str> = dns.split_whitespace().collect();
        if !servers.iter().all(|s| valid_ip(s)) {
            return Err(ApiError::bad("DNS 地址无效"));
        }
        changes.push(("wan".into(), "dns".into(), Some(servers.join(" "))));
    } else {
        changes.push(("wan".into(), "dns".into(), None));
    }
    if !mtu.is_empty() {
        if mtu.parse::<u16>().map(|v| v < 576).unwrap_or(true) {
            return Err(ApiError::bad("MTU 无效"));
        }
        changes.push(("wan".into(), "mtu".into(), Some(mtu.into())));
    }

    let changes2 = changes.clone();
    tokio::task::spawn_blocking(move || uci::apply("network", &changes2))
        .await
        .map_err(|e| ApiError::internal(e.to_string()))??;
    schedule_reload(&["network"]);

    Ok(ok(json!({"applied": true, "proto": proto})))
}

pub async fn update_lan(Json(body): Json<Value>) -> ApiResult<Json<Value>> {
    let ipaddr = body
        .get("ipaddr")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim();
    let netmask = body
        .get("netmask")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim();
    if !valid_ip(ipaddr) || !valid_mask(netmask) {
        return Err(ApiError::bad("LAN IP 地址或子网掩码无效"));
    }
    let start = body
        .get("dhcp_start")
        .and_then(|v| v.as_u64())
        .unwrap_or(100);
    let limit = body
        .get("dhcp_limit")
        .and_then(|v| v.as_u64())
        .unwrap_or(150);
    if !(2..=254).contains(&start) || !(1..=253).contains(&limit) || start + limit > 255 {
        return Err(ApiError::bad("DHCP 地址池超出范围"));
    }
    let leasetime = body
        .get("leasetime")
        .and_then(|v| v.as_str())
        .unwrap_or("12h");
    if !leasetime
        .chars()
        .all(|c| c.is_ascii_digit() || c == 'h' || c == 'm' || c == 'd')
    {
        return Err(ApiError::bad("租期格式无效"));
    }
    let ignore = body.get("ignore").and_then(|v| v.as_bool()).unwrap_or(false);

    let net_changes = vec![
        ("lan".to_string(), "proto".into(), Some("static".into())),
        ("lan".to_string(), "ipaddr".into(), Some(ipaddr.into())),
        ("lan".to_string(), "netmask".into(), Some(netmask.into())),
    ];
    let dhcp_changes = vec![
        ("lan".to_string(), "start".into(), Some(start.to_string())),
        ("lan".to_string(), "limit".into(), Some(limit.to_string())),
        ("lan".to_string(), "leasetime".into(), Some(leasetime.to_string())),
        (
            "lan".to_string(),
            "ignore".into(),
            Some(if ignore { "1" } else { "0" }.into()),
        ),
    ];

    tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
        uci::apply("network", &net_changes)?;
        uci::apply("dhcp", &dhcp_changes)?;
        Ok(())
    })
    .await
    .map_err(|e| ApiError::internal(e.to_string()))??;

    // Remove persisted self-signed cert so next boot/restart generates one with the new LAN IP SAN
    let _ = std::fs::remove_file("/etc/routerd/cert.pem");
    let _ = std::fs::remove_file("/etc/routerd/key.pem");

    schedule_reload(&["network", "dnsmasq"]);
    Ok(ok(json!({
        "applied": true,
        "ipaddr": ipaddr,
        "reconnect": true,
    })))
}

pub async fn reload() -> ApiResult<Json<Value>> {
    tokio::task::spawn_blocking(|| {
        let _ = uci::reload_service("network");
        let _ = uci::reload_service("dnsmasq");
    })
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;
    Ok(ok(json!({"reloaded": true})))
}


pub async fn hardware(State(state): State<AppState>) -> ApiResult<Json<Value>> {
    if state.sim {
        return Ok(ok(json!({
            "ports": [
                { "name": "eth1", "label": "WAN 口 (2.5G)", "role": "WAN", "link_up": true, "speed_mbps": 2500, "duplex": "full", "rx_bytes": 1849201408u64, "tx_bytes": 342190208u64 },
                { "name": "eth0", "label": "LAN 口 (1G)", "role": "LAN", "link_up": true, "speed_mbps": 1000, "duplex": "full", "rx_bytes": 329104896u64, "tx_bytes": 1820418048u64 }
            ],
            "hw_offload": true,
            "sw_offload": true,
        })));
    }
    let (ports, (hw_offload, sw_offload)) = tokio::task::spawn_blocking(|| {
        (net::get_physical_ports(), net::check_offload_status())
    })
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;

    Ok(ok(json!({
        "ports": ports,
        "hw_offload": hw_offload,
        "sw_offload": sw_offload,
    })))
}

pub async fn redial() -> ApiResult<Json<Value>> {
    tokio::task::spawn_blocking(net::redial_wan)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?
        .map_err(|e| ApiError::internal(e.to_string()))?;
    Ok(ok(json!({ "restarted": true })))
}

#[derive(Deserialize)]
pub struct LogQuery {
    pub lines: Option<usize>,
}

pub async fn pppoe_log(
    State(state): State<AppState>,
    Query(q): Query<LogQuery>,
) -> ApiResult<Json<Value>> {
    if state.sim {
        return Ok(ok(json!({
            "log": "[sim] daemon.info pppd[1024]: Plugin pppoe.so loaded.\n[sim] daemon.info pppd[1024]: PPP session is 0x1a4f\n[sim] daemon.info pppd[1024]: PAP authentication succeeded\n[sim] daemon.notice netifd: Interface 'wan' is now up"
        })));
    }
    let lines = q.lines.unwrap_or(40).min(200);
    let log = tokio::task::spawn_blocking(move || net::get_pppoe_logs(lines))
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;
    Ok(ok(json!({ "log": log })))
}


pub async fn get_mode() -> ApiResult<Json<Value>> {
    let mode = tokio::task::spawn_blocking(|| {
        let cfg = uci::load("network").unwrap_or_default();
        let wan_proto = cfg
            .section("wan")
            .and_then(|s| s.get("proto"))
            .unwrap_or("dhcp");
        let lan_proto = cfg
            .section("lan")
            .and_then(|s| s.get("proto"))
            .unwrap_or("static");
        if wan_proto == "none" && lan_proto == "dhcp" {
            "ap"
        } else {
            "router"
        }
    })
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;
    Ok(ok(json!({ "mode": mode })))
}

pub async fn set_mode(Json(body): Json<Value>) -> ApiResult<Json<Value>> {
    let mode = body
        .get("mode")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim();
    if mode != "router" && mode != "ap" {
        return Err(ApiError::bad("模式必须是 router（路由模式）或 ap（无线中继模式）"));
    }

    let mode_owned = mode.to_string();
    tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
        if mode_owned == "ap" {
            // AP mode: WAN disabled, LAN gets DHCP from upstream main router, local DHCP server disabled
            uci::apply(
                "network",
                &[
                    ("wan".into(), "proto".into(), Some("none".into())),
                    ("wan".into(), "disabled".into(), Some("1".into())),
                    ("lan".into(), "proto".into(), Some("dhcp".into())),
                    ("lan".into(), "ipaddr".into(), None),
                    ("lan".into(), "netmask".into(), None),
                ],
            )?;
            uci::apply(
                "dhcp",
                &[("lan".into(), "ignore".into(), Some("1".into()))],
            )?;
        } else {
            // Router mode: WAN DHCP, LAN static 192.168.1.1, local DHCP enabled
            uci::apply(
                "network",
                &[
                    ("wan".into(), "proto".into(), Some("dhcp".into())),
                    ("wan".into(), "disabled".into(), Some("0".into())),
                    ("lan".into(), "proto".into(), Some("static".into())),
                    ("lan".into(), "ipaddr".into(), Some("192.168.1.1".into())),
                    ("lan".into(), "netmask".into(), Some("255.255.255.0".into())),
                ],
            )?;
            uci::apply(
                "dhcp",
                &[("lan".into(), "ignore".into(), Some("0".into()))],
            )?;
        }
        Ok(())
    })
    .await
    .map_err(|e| ApiError::internal(e.to_string()))??;

    schedule_reload(&["network", "dnsmasq", "firewall"]);
    Ok(ok(json!({ "applied": true, "mode": mode })))
}

pub async fn swap_ports(State(state): State<AppState>) -> ApiResult<Json<Value>> {
    if state.sim {
        return Err(ApiError::Forbidden("演示模式禁止修改物理网口绑定".into()));
    }
    let new_wan = tokio::task::spawn_blocking(|| -> anyhow::Result<String> {
        let cfg = uci::load("network")?;
        let cur_wan = cfg
            .section("wan")
            .and_then(|s| s.get("device"))
            .unwrap_or("eth1")
            .to_string();
        let (next_wan, next_lan_port) = if cur_wan == "eth1" {
            ("eth0", "eth1")
        } else {
            ("eth1", "eth0")
        };

        uci::set_opt("network", "wan", "device", next_wan)?;
        if let Some(br) = cfg.by_kind("device").find(|s| s.get("name") == Some("br-lan")) {
            let sec = br.name.clone();
            let _ = uci::delete(&format!("network.{sec}.ports"));
            util::run(
                uci::bin(),
                &["add_list", &format!("network.{sec}.ports={next_lan_port}")],
            )?;
        }
        uci::commit("network")?;
        Ok(next_wan.to_string())
    })
    .await
    .map_err(|e| ApiError::internal(e.to_string()))??;

    schedule_reload(&["network", "firewall"]);
    Ok(ok(json!({ "swapped": true, "wan_device": new_wan })))
}

#[derive(Deserialize)]
pub struct DiagRequest {
    tool: String,
    host: String,
}

pub async fn diag(
    State(state): State<AppState>,
    Json(req): Json<DiagRequest>,
) -> ApiResult<Json<Value>> {
    let host = req.host.trim();
    if host.is_empty()
        || host.len() > 128
        || host.starts_with('-')
        || !host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':'))
    {
        return Err(ApiError::bad("目标主机名或 IP 格式无效"));
    }
    let tool = req.tool.trim().to_string();
    if !matches!(tool.as_str(), "ping" | "traceroute" | "nslookup") {
        return Err(ApiError::bad("仅支持 ping / traceroute / nslookup 诊断工具"));
    }
    if state.sim {
        return Ok(ok(json!({
            "output": format!("[sim] {tool} {host}\n64 bytes from {host}: seq=0 ttl=56 time=11.4 ms\n64 bytes from {host}: seq=1 ttl=56 time=11.2 ms\n--- {host} statistics --- 0% packet loss")
        })));
    }
    let host_owned = host.to_string();
    let output = tokio::task::spawn_blocking(move || -> String {
        let res = match tool.as_str() {
            "ping" => std::process::Command::new("ping")
                .args(["-c", "4", "-W", "2", &host_owned])
                .output(),
            "traceroute" => std::process::Command::new("traceroute")
                .args(["-n", "-w", "2", "-m", "15", &host_owned])
                .output(),
            "nslookup" => std::process::Command::new("nslookup")
                .args([&host_owned])
                .output(),
            _ => unreachable!(),
        };
        match res {
            Ok(o) => {
                let mut text = String::from_utf8_lossy(&o.stdout).to_string();
                let err = String::from_utf8_lossy(&o.stderr);
                if !err.trim().is_empty() {
                    if !text.is_empty() {
                        text.push('\n');
                    }
                    text.push_str(err.trim());
                }
                if text.trim().is_empty() {
                    "命令执行完成，无输出".into()
                } else {
                    text
                }
            }
            Err(e) => format!("执行失败: {e}"),
        }
    })
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;

    Ok(ok(json!({ "output": output })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_validation() {
        assert!(valid_ip("192.168.1.1"));
        assert!(!valid_ip("192.168.1.256"));
        assert!(!valid_ip(""));
    }

    #[test]
    fn contiguous_masks() {
        assert!(valid_mask("255.255.255.0"));
        assert!(valid_mask("255.255.255.255"));
        assert!(!valid_mask("255.0.255.0"));
        assert!(!valid_mask("255.255.255.1"));
        assert!(!valid_mask("nope"));
    }
}
