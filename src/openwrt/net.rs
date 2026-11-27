use serde::{Deserialize, Serialize};
use std::fs;
use std::process::Command;
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
            .get("uptime")
            .and_then(|v| v.as_u64())
            .or_else(|| it.get("data").and_then(|d| d.get("uptime")).and_then(|v| v.as_u64()));
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
    crate::openwrt::rtnetlink::list_ipv4_routes()
        .unwrap_or_default()
        .into_iter()
        .map(|r| {
            json!({
                "target": r.target,
                "gateway": r.gateway,
                "device": r.device,
                "metric": r.metric,
                "proto": r.proto,
                "source": r.source,
            })
        })
        .collect()
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

/// Read `(lan_dev, wan_dev)` from `/etc/config/network` once for batch ARP filtering.
pub fn lan_wan_devs() -> (String, String) {
    let cfg = crate::openwrt::uci::load("network").unwrap_or_default();
    let lan_dev = cfg
        .section("lan")
        .and_then(|s| s.get("device"))
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("br-lan")
        .to_string();
    let wan_dev = cfg
        .section("wan")
        .and_then(|s| s.get("device"))
        .map(str::trim)
        .unwrap_or("")
        .to_string();
    (lan_dev, wan_dev)
}

/// Return true if `dev` is the router's LAN bridge/interface using preloaded `(lan_dev, wan_dev)`.
pub fn is_lan_arp_device_with(dev: &str, devs: &(String, String)) -> bool {
    if dev.is_empty() {
        return false;
    }
    let (lan_dev, wan_dev) = devs;
    if !wan_dev.is_empty() && dev == wan_dev {
        return false;
    }
    dev == lan_dev || dev.starts_with("br-") || dev == "lan"
}

/// Return true if `dev` is the router's LAN bridge/interface (excluding WAN such as `eth1` / `wan`).
pub fn is_lan_arp_device(dev: &str) -> bool {
    is_lan_arp_device_with(dev, &lan_wan_devs())
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

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PhysicalPort {
    pub name: String,
    pub label: String,
    pub role: String,
    pub link_up: bool,
    pub speed_mbps: i32,
    pub duplex: String,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

pub fn get_physical_ports() -> Vec<PhysicalPort> {
    let cfg = crate::openwrt::uci::load("network").unwrap_or_default();
    let wan_dev = cfg
        .section("wan")
        .and_then(|s| {
            s.get("device")
                .map(str::trim)
                .filter(|v| !v.is_empty())
                .or_else(|| s.get("ifname").map(str::trim).filter(|v| !v.is_empty()))
        })
        .unwrap_or("eth1")
        .to_string();

    let candidates = ["eth1", "eth0", "wan", "lan1", "lan2", "lan3", "lan4"];
    let mut ports = Vec::new();

    for dev in candidates {
        let sys_path = format!("/sys/class/net/{}", dev);
        if !std::path::Path::new(&sys_path).exists() {
            continue;
        }
        let carrier = fs::read_to_string(format!("{}/carrier", sys_path))
            .unwrap_or_default()
            .trim()
            == "1";
        let speed_mbps = fs::read_to_string(format!("{}/speed", sys_path))
            .unwrap_or_else(|_| "-1".into())
            .trim()
            .parse::<i32>()
            .unwrap_or(-1);
        let duplex = fs::read_to_string(format!("{}/duplex", sys_path))
            .unwrap_or_else(|_| "unknown".into())
            .trim()
            .to_string();
        let rx_bytes = fs::read_to_string(format!("{}/statistics/rx_bytes", sys_path))
            .unwrap_or_default()
            .trim()
            .parse::<u64>()
            .unwrap_or(0);
        let tx_bytes = fs::read_to_string(format!("{}/statistics/tx_bytes", sys_path))
            .unwrap_or_default()
            .trim()
            .parse::<u64>()
            .unwrap_or(0);

        let is_wan = dev == wan_dev;
        let label = if is_wan {
            "WAN 口".to_string()
        } else if dev == "eth0" || dev == "eth1" {
            "LAN 口".to_string()
        } else {
            dev.to_uppercase()
        };

        ports.push(PhysicalPort {
            name: dev.to_string(),
            label,
            role: if is_wan { "WAN".into() } else { "LAN".into() },
            link_up: carrier,
            speed_mbps: if carrier { speed_mbps } else { 0 },
            duplex,
            rx_bytes,
            tx_bytes,
        });
    }
    ports
}

pub fn check_offload_status() -> (bool, bool) {
    let fw = fs::read_to_string("/etc/config/firewall").unwrap_or_default();
    let sw = fw.contains("option flow_offloading '1'") || fw.contains("option flow_offloading \"1\"");
    let hw = fw.contains("option flow_offloading_hw '1'") || fw.contains("option flow_offloading_hw \"1\"");
    (hw, sw)
}

pub fn get_pppoe_logs(lines: usize) -> String {
    let out = Command::new("logread")
        .args(["-e", "pppd\\|pppoe\\|netifd"])
        .output();
    match out {
        Ok(o) => {
            let text = String::from_utf8_lossy(&o.stdout);
            let all: Vec<&str> = text.lines().collect();
            let start = all.len().saturating_sub(lines);
            all[start..].join("\n")
        }
        Err(_) => "无法读取系统拨号日志".into(),
    }
}

pub fn redial_wan() -> anyhow::Result<()> {
    let _ = ubus::call("network.interface.wan", "down", None);
    std::thread::sleep(std::time::Duration::from_millis(800));
    ubus::call("network.interface.wan", "up", None)
        .map(|_| ())
        .map_err(|e| anyhow::anyhow!("ubus up 调用失败: {e:#}"))
}
