use std::net::Ipv4Addr;
use std::time::Duration;

use axum::Json;
use serde_json::{json, Value};

use super::{ok, ApiError, ApiResult};
use crate::openwrt::{net, uci};

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
