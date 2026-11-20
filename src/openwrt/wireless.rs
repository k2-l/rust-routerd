use std::fs;
use serde_json::{json, Value};

use crate::openwrt::ubus;
use crate::util;

fn iwinfo_devices() -> Vec<String> {
    ubus::call_ok("iwinfo", "devices", None)
        .and_then(|v| v.get("devices").and_then(|d| d.as_array()).cloned())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default()
}

fn iwinfo_info(dev: &str) -> Option<Value> {
    ubus::call_ok("iwinfo", "info", Some(&json!({"device": dev}).to_string()))
}

fn iwinfo_assoc(dev: &str) -> Vec<Value> {
    ubus::call_ok(
        "iwinfo",
        "assoclist",
        Some(&json!({"device": dev}).to_string()),
    )
    .and_then(|v| v.get("results").and_then(|r| r.as_array()).cloned())
    .unwrap_or_default()
}

fn infer_live_band(info: &Value) -> &'static str {
    if let Some(freq) = info.get("frequency").and_then(|v| v.as_u64()) {
        if freq >= 5925 {
            return "6g";
        } else if freq >= 4900 {
            return "5g";
        } else if freq >= 2400 {
            return "2g";
        }
    }
    if let Some(ch) = info.get("channel").and_then(|v| v.as_u64()) {
        if ch > 14 {
            return "5g";
        } else if ch >= 1 {
            return "2g";
        }
    }
    ""
}

/// Check if ARP entry is genuinely reachable (flags != 0x0) via /proc/net/arp
fn is_arp_reachable(ip: &str) -> bool {
    let Ok(content) = fs::read_to_string("/proc/net/arp") else {
        return true;
    };
    for line in content.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() >= 3 && cols[0] == ip {
            return cols[2] != "0x0";
        }
    }
    false
}

pub fn live() -> Vec<Value> {
    let mut out = Vec::new();
    for dev in iwinfo_devices() {
        let info = iwinfo_info(&dev).unwrap_or(Value::Null);
        let assoc = iwinfo_assoc(&dev);
        let band = infer_live_band(&info);
        out.push(json!({
            "device": dev,
            "band": band,
            "ssid": info.get("ssid").cloned().unwrap_or(Value::Null),
            "bssid": info.get("bssid").cloned().unwrap_or(Value::Null),
            "mode": info.get("mode").cloned().unwrap_or(Value::Null),
            "channel": info.get("channel").cloned().unwrap_or(Value::Null),
            "frequency": info.get("frequency").cloned().unwrap_or(Value::Null),
            "txpower": info.get("txpower").cloned().unwrap_or(Value::Null),
            "signal": info.get("signal").cloned().unwrap_or(Value::Null),
            "noise": info.get("noise").cloned().unwrap_or(Value::Null),
            "bitrate": info.get("bitrate").cloned().unwrap_or(Value::Null),
            "encryption": info.get("encryption").cloned().unwrap_or(Value::Null),
            "quality": info.get("quality").cloned().unwrap_or(Value::Null),
            "quality_max": info.get("quality_max").cloned().unwrap_or(Value::Null),
            "assoc_count": assoc.len(),
            "stations": assoc,
        }));
    }
    out
}

pub fn overview() -> Value {
    let cfg = crate::openwrt::uci::load("wireless").unwrap_or_default();
    let live_list = live();
    let mut radios = Vec::new();

    for r in cfg.by_kind("wifi-device") {
        let disabled = r.bool("disabled");
        let radio_band = r.get_or("band", "").to_ascii_lowercase();
        let ifaces: Vec<&crate::openwrt::uci::Section> = cfg
            .by_kind("wifi-iface")
            .filter(|i| i.get("device") == Some(r.name.as_str()))
            .collect();

        let mut live_ifaces = Vec::new();
        for i in &ifaces {
            let ssid = i.get_or("ssid", "");
            let key = i.get_or("key", "");
            let match_live = live_list
                .iter()
                .find(|l| {
                    l["ssid"].as_str().unwrap_or("") == ssid
                        && l["mode"].as_str().unwrap_or("") != "Client"
                        && (!radio_band.is_empty() && l["band"].as_str().unwrap_or("") == radio_band)
                })
                .or_else(|| {
                    live_list.iter().find(|l| {
                        l["ssid"].as_str().unwrap_or("") == ssid
                            && l["mode"].as_str().unwrap_or("") != "Client"
                    })
                });

            live_ifaces.push(json!({
                "section": i.name,
                "ssid": ssid,
                "mode": i.get_or("mode", "ap"),
                "network": i.get_or("network", "lan"),
                "encryption": i.get_or("encryption", "none"),
                "has_key": !key.is_empty(),
                "hidden": i.bool("hidden"),
                "disabled": i.bool("disabled"),
                "isolate": i.bool("isolate"),
                "device": match_live.and_then(|l| l.get("device")).cloned().unwrap_or(Value::Null),
                "assoc_count": match_live.and_then(|l| l.get("assoc_count")).cloned().unwrap_or(json!(0)),
                "channel": match_live.and_then(|l| l.get("channel")).cloned().unwrap_or(Value::Null),
                "txpower": match_live.and_then(|l| l.get("txpower")).cloned().unwrap_or(Value::Null),
            }));
        }

        radios.push(json!({
            "name": r.name,
            "band": r.get_or("band", ""),
            "hwmode": r.get_or("hwmode", ""),
            "channel": r.get_or("channel", "auto"),
            "htmode": r.get_or("htmode", ""),
            "txpower": r.get_or("txpower", ""),
            "country": r.get_or("country", ""),
            "disabled": disabled,
            "path": r.get_or("path", ""),
            "ifaces": live_ifaces,
        }));
    }
    json!({"radios": radios, "live": live_list})
}

pub fn clients() -> Vec<Value> {
    let leases = crate::openwrt::net::leases();
    let arp = crate::openwrt::net::arp_table();
    let mut out = Vec::new();

    for dev in live() {
        let iface = dev["device"].as_str().unwrap_or("");
        let ssid = dev["ssid"].as_str().unwrap_or("");
        let Some(stations) = dev["stations"].as_array() else {
            continue;
        };
        for s in stations {
            let mac = s
                .get("mac")
                .and_then(|m| m.as_str())
                .unwrap_or("")
                .to_ascii_uppercase();
            if mac.is_empty() {
                continue;
            }
            let lease = leases
                .iter()
                .find(|l| l["mac"].as_str().unwrap_or("").eq_ignore_ascii_case(&mac));
            let arp_entry = arp
                .iter()
                .find(|a| a["mac"].as_str().unwrap_or("").eq_ignore_ascii_case(&mac));

            out.push(json!({
                "mac": mac,
                "signal": s.get("signal").cloned().unwrap_or(Value::Null),
                "noise": s.get("noise").cloned().unwrap_or(Value::Null),
                "rx": s.get("rx").cloned().unwrap_or(Value::Null),
                "tx": s.get("tx").cloned().unwrap_or(Value::Null),
                "inactive": s.get("inactive").cloned().unwrap_or(Value::Null),
                "iface": iface,
                "ssid": ssid,
                "ip": lease.and_then(|l| l["ip"].as_str()).or_else(|| arp_entry.and_then(|a| a["ip"].as_str())).unwrap_or(""),
                "hostname": lease.and_then(|l| l["hostname"].as_str()).unwrap_or(""),
                "wireless": true,
            }));
        }
    }

    for a in &arp {
        let mac = a["mac"].as_str().unwrap_or("").to_ascii_uppercase();
        let ip = a["ip"].as_str().unwrap_or("");
        if mac.is_empty() || ip.is_empty() {
            continue;
        }
        if out.iter().any(|c| c["mac"].as_str().unwrap_or("").eq_ignore_ascii_case(&mac)) {
            continue;
        }
        let dev = a["device"].as_str().unwrap_or("");
        if !(dev.starts_with("br-") || dev.starts_with("eth") || dev.starts_with("lan")) {
            continue;
        }
        // Filter out stale/unplugged ARP entries (flags == 0x0)
        if !is_arp_reachable(ip) {
            continue;
        }
        let lease = leases
            .iter()
            .find(|l| l["mac"].as_str().unwrap_or("").eq_ignore_ascii_case(&mac));
        out.push(json!({
            "mac": mac,
            "ip": ip,
            "hostname": lease.and_then(|l| l["hostname"].as_str()).unwrap_or(""),
            "iface": dev,
            "signal": Value::Null,
            "rx": json!({"bytes": 0}),
            "tx": json!({"bytes": 0}),
            "wireless": false,
            "inactive": Value::Null,
        }));
    }
    out
}

pub fn apply(payload: &Value) -> anyhow::Result<()> {
    use crate::openwrt::uci;

    let cfg = uci::load("wireless").unwrap_or_default();
    let Some(radios) = payload.get("radios").and_then(|v| v.as_array()) else {
        anyhow::bail!("missing radios");
    };
    let mut changes: Vec<(String, String, Option<String>)> = Vec::new();
    for r in radios {
        let Some(name) = r.get("name").and_then(|v| v.as_str()) else {
            continue;
        };
        if !util::valid_name(name) {
            anyhow::bail!("invalid radio name");
        }
        let band = cfg
            .section(name)
            .and_then(|s| s.get("band"))
            .unwrap_or("")
            .to_ascii_lowercase();

        if let Some(v) = r.get("channel").and_then(|v| v.as_str()) {
            if v != "auto" {
                let ch: u16 = v.parse().map_err(|_| anyhow::anyhow!("信道必须是 auto 或数字"))?;
                if band == "2g" && !(1..=14).contains(&ch) {
                    anyhow::bail!("2.4GHz 频段信道必须在 1-14 之间");
                }
                if band == "5g" && ch < 36 {
                    anyhow::bail!("5GHz 频段信道必须大于等于 36");
                }
            }
            changes.push((name.into(), "channel".into(), Some(v.to_string())));
        }
        if let Some(v) = r.get("htmode").and_then(|v| v.as_str()) {
            if !v.is_empty() {
                let valid_modes = ["HT20", "HT40", "VHT20", "VHT40", "VHT80", "VHT160", "HE20", "HE40", "HE80", "HE160", "EHT20", "EHT40", "EHT80", "EHT160", "EHT320"];
                if !valid_modes.contains(&v) {
                    anyhow::bail!("不支持的频宽模式: {v}");
                }
                if band == "2g" && (v.contains("80") || v.contains("160") || v.contains("320")) {
                    anyhow::bail!("2.4GHz 频段不支持 {v} 频宽");
                }
                changes.push((name.into(), "htmode".into(), Some(v.to_string())));
            }
        }
        if let Some(v) = r.get("txpower").and_then(|v| v.as_str()) {
            if !v.is_empty() {
                if v != "auto" {
                    let pwr: i16 = v.parse().map_err(|_| anyhow::anyhow!("发射功率无效"))?;
                    if !(0..=30).contains(&pwr) {
                        anyhow::bail!("发射功率必须在 0-30 dBm 之间");
                    }
                }
                changes.push((name.into(), "txpower".into(), Some(v.to_string())));
            }
        }
        if let Some(v) = r.get("disabled").and_then(|v| v.as_bool()) {
            changes.push((name.into(), "disabled".into(), Some(bool_str(v))));
        }
        if let Some(ifaces) = r.get("ifaces").and_then(|v| v.as_array()) {
            for i in ifaces {
                let Some(sec) = i.get("section").and_then(|v| v.as_str()) else {
                    continue;
                };
                if !util::valid_name(sec) {
                    anyhow::bail!("invalid wifi-iface name");
                }
                if let Some(v) = i.get("ssid").and_then(|v| v.as_str()) {
                    if v.is_empty() || v.len() > 32 {
                        anyhow::bail!("SSID 长度必须在 1-32 字节之间");
                    }
                    changes.push((sec.into(), "ssid".into(), Some(v.to_string())));
                }
                if let Some(v) = i.get("encryption").and_then(|v| v.as_str()) {
                    if !["none", "psk2", "psk", "sae", "sae-mixed", "psk-mixed"].contains(&v) {
                        anyhow::bail!("不支持的加密方式");
                    }
                    changes.push((sec.into(), "encryption".into(), Some(v.to_string())));
                    if v == "none" {
                        changes.push((sec.into(), "key".into(), None));
                    }
                }
                if let Some(v) = i.get("key").and_then(|v| v.as_str()) {
                    if !v.is_empty() {
                        if v.len() < 8 || v.len() > 63 {
                            anyhow::bail!("Wi-Fi 密码长度必须在 8-63 位之间");
                        }
                        changes.push((sec.into(), "key".into(), Some(v.to_string())));
                    }
                }
                if let Some(v) = i.get("hidden").and_then(|v| v.as_bool()) {
                    changes.push((sec.into(), "hidden".into(), Some(bool_str(v))));
                }
                if let Some(v) = i.get("disabled").and_then(|v| v.as_bool()) {
                    changes.push((sec.into(), "disabled".into(), Some(bool_str(v))));
                }
            }
        }
    }
    uci::apply("wireless", &changes)?;
    Ok(())
}

pub fn bool_str(v: bool) -> String {
    if v { "1".into() } else { "0".into() }
}

/// Disconnect a client by MAC across all active `hostapd.*` interfaces (and optionally flush conntrack/ARP).
pub fn kick_client(mac: &str, ip: Option<&str>, ban_ms: u64) -> (bool, bool) {
    let mut wifi_deauth = false;
    if let Some(list) = util::run_ok("ubus", &["list", "hostapd.*"]) {
        let payload = json!({
            "addr": mac,
            "reason": 5,
            "deauth": true,
            "ban_time": ban_ms,
        })
        .to_string();
        for obj in list.lines().map(str::trim).filter(|l| l.starts_with("hostapd.")) {
            if ubus::call_ok(obj, "del_client", Some(&payload)).is_some() {
                wifi_deauth = true;
            }
        }
    }

    let mut conntrack_flushed = false;
    if let Some(client_ip) = ip.filter(|s| !s.is_empty()) {
        if util::run_ok("conntrack", &["-D", "-s", client_ip]).is_some() {
            conntrack_flushed = true;
        }
        if util::run_ok("conntrack", &["-D", "-d", client_ip]).is_some() {
            conntrack_flushed = true;
        }
        let _ = util::run_ok("ip", &["neigh", "del", client_ip, "dev", "br-lan"]);
    }
    (wifi_deauth, conntrack_flushed)
}
