use serde_json::{json, Value};

use crate::openwrt::ubus;
use crate::util;

fn sysfs_u64(path: String) -> u64 {
    util::read(&path).trim().parse().unwrap_or(0)
}

fn iface_stats(dev: &str) -> Value {
    let base = format!("/sys/class/net/{dev}/statistics");
    json!({
        "rx_bytes": sysfs_u64(format!("{base}/rx_bytes")),
        "tx_bytes": sysfs_u64(format!("{base}/tx_bytes")),
        "rx_packets": sysfs_u64(format!("{base}/rx_packets")),
        "tx_packets": sysfs_u64(format!("{base}/tx_packets")),
        "rx_errors": sysfs_u64(format!("{base}/rx_errors")),
        "tx_errors": sysfs_u64(format!("{base}/tx_errors")),
    })
}

fn ipv4_list(value: Option<&Value>) -> Vec<Value> {
    value
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .map(|a| {
                    json!({
                        "address": a.get("address").cloned().unwrap_or(Value::Null),
                        "mask": a.get("mask").cloned().unwrap_or(Value::Null),
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

fn ipv6_list(value: Option<&Value>) -> Vec<Value> {
    value
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .map(|a| {
                    json!({
                        "address": a.get("address").cloned().unwrap_or(Value::Null),
                        "mask": a.get("mask").cloned().unwrap_or(Value::Null),
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Logical interfaces as reported by netifd, normalized for the UI.
pub fn interfaces() -> Vec<Value> {
    let dump = ubus::call_ok("network.interface", "dump", None);
    let Some(dump) = dump else {
        return Vec::new();
    };
    let Some(arr) = dump.get("interface").and_then(|v| v.as_array()) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for it in arr {
        let name = it.get("interface").and_then(|v| v.as_str()).unwrap_or("");
        let device = it.get("device").and_then(|v| v.as_str()).unwrap_or("");
        let l3 = it.get("l3_device").and_then(|v| v.as_str()).unwrap_or(device);
        let routes = it.get("route").and_then(|v| v.as_array());
        let gateway = routes.and_then(|rs| {
            rs.iter()
                .find(|r| {
                    r.get("target").and_then(|t| t.as_str()) == Some("0.0.0.0")
                        && r.get("mask").and_then(|m| m.as_u64()) == Some(0)
                })
                .and_then(|r| r.get("nexthop").and_then(|n| n.as_str()))
        });
        let dns: Vec<String> = it
            .get("dns-server")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default();
        let uptime = it
            .get("data")
            .and_then(|d| d.get("uptime"))
            .and_then(|v| v.as_u64());
        let stats = it
            .get("statistics")
            .cloned()
            .unwrap_or_else(|| iface_stats(device));
        out.push(json!({
            "name": name,
            "up": it.get("up").and_then(|v| v.as_bool()).unwrap_or(false),
            "pending": it.get("pending").and_then(|v| v.as_bool()).unwrap_or(false),
            "available": it.get("available").and_then(|v| v.as_bool()).unwrap_or(true),
            "autostart": it.get("autostart").and_then(|v| v.as_bool()).unwrap_or(false),
            "proto": it.get("proto").and_then(|v| v.as_str()).unwrap_or("none"),
            "device": device,
            "l3_device": l3,
            "metric": it.get("metric").cloned().unwrap_or(Value::Null),
            "uptime": uptime,
            "ipv4": ipv4_list(it.get("ipv4-address")),
            "ipv6": ipv6_list(it.get("ipv6-address")),
            "dns": dns,
            "gateway": gateway,
            "mac": util::read_trim(&format!("/sys/class/net/{l3}/address")).to_uppercase(),
            "statistics": stats,
            "errors": it.get("errors").cloned().unwrap_or_else(|| json!([])),
        }));
    }
    out
}

pub fn wan_summary() -> Value {
    let ifaces = interfaces();
    let wan = ifaces
        .iter()
        .find(|i| i["name"] == "wan")
        .or_else(|| ifaces.iter().find(|i| i["name"] == "wan6"))
        .cloned()
        .unwrap_or(Value::Null);
    if wan.is_null() {
        return json!({"up": false, "proto": "none", "ipv4": []});
    }
    let mut extra = wan.clone();
    if let Some(obj) = extra.as_object_mut() {
        obj.insert("internet".into(), json!(wan["up"].as_bool().unwrap_or(false)));
    }
    extra
}

pub fn routes() -> Vec<Value> {
    let out = util::run_ok("ip", &["-4", "route", "show"]).unwrap_or_default();
    let mut result = Vec::new();
    for line in out.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.is_empty() {
            continue;
        }
        let mut r = json!({"target": f[0], "gateway": "", "device": "", "metric": 0, "proto": "", "source": ""});
        let mut i = 1;
        while i + 1 < f.len() {
            match f[i] {
                "via" => r["gateway"] = json!(f[i + 1]),
                "dev" => r["device"] = json!(f[i + 1]),
                "metric" => r["metric"] = json!(f[i + 1].parse::<u32>().unwrap_or(0)),
                "proto" => r["proto"] = json!(f[i + 1]),
                "src" => r["source"] = json!(f[i + 1]),
                _ => {}
            }
            i += 2;
        }
        result.push(r);
    }
    result
}

pub fn arp_table() -> Vec<Value> {
    let text = util::read("/proc/net/arp");
    let mut out = Vec::new();
    for line in text.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 6 {
            continue;
        }
        if f[2] != "0x2" || f[3] == "00:00:00:00:00:00" {
            continue;
        }
        out.push(json!({"ip": f[0], "mac": f[3].to_uppercase(), "device": f[5]}));
    }
    out
}

pub fn leases() -> Vec<Value> {
    let text = util::read("/tmp/dhcp.leases");
    let mut out = Vec::new();
    for line in text.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 4 {
            continue;
        }
        let hostname = if f[3] == "*" { "" } else { f[3] };
        out.push(json!({
            "expires": f[0].parse::<u64>().unwrap_or(0),
            "mac": f[1].to_uppercase(),
            "ip": f[2],
            "hostname": hostname,
        }));
    }
    out
}

/// Physical devices present on the system.
pub fn physical_devices() -> Vec<Value> {
    let mut out = Vec::new();
    if let Ok(dir) = std::fs::read_dir("/sys/class/net") {
        for entry in dir.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name == "lo" {
                continue;
            }
            let base = entry.path();
            let operstate = std::fs::read_to_string(base.join("operstate"))
                .unwrap_or_default()
                .trim()
                .to_string();
            let mac = std::fs::read_to_string(base.join("address"))
                .unwrap_or_default()
                .trim()
                .to_uppercase();
            let mtu = std::fs::read_to_string(base.join("mtu"))
                .unwrap_or_default()
                .trim()
                .parse::<u64>()
                .unwrap_or(0);
            out.push(json!({
                "name": name,
                "operstate": operstate,
                "up": operstate == "up",
                "mac": mac,
                "mtu": mtu,
                "statistics": iface_stats(&name),
            }));
        }
    }
    out.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
    out
}

pub fn dns_servers() -> Vec<String> {
    let resolv = util::read("/tmp/resolv.conf.d/resolv.conf.auto");
    let resolv = if resolv.is_empty() {
        util::read("/etc/resolv.conf")
    } else {
        resolv
    };
    resolv
        .lines()
        .filter_map(|l| {
            let l = l.trim();
            l.strip_prefix("nameserver")
                .map(|s| s.trim().to_string())
        })
        .filter(|s| !s.is_empty())
        .collect()
}
