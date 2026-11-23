use std::fs;
use serde_json::{json, Value};

use crate::openwrt::ubus;
use crate::util;

fn infer_live_band(frequency: Option<u32>, channel: Option<u32>) -> &'static str {
    if let Some(freq) = frequency {
        if freq >= 5925 {
            return "6g";
        } else if freq >= 4900 {
            return "5g";
        } else if freq >= 2400 {
            return "2g";
        }
    }
    if let Some(ch) = channel {
        if ch > 14 {
            return "5g";
        } else if ch >= 1 {
            return "2g";
        }
    }
    ""
}

fn rate_to_json(r: &crate::openwrt::nl80211::RateInfo) -> Value {
    json!({
        "rate": r.rate_kbps,
        "mcs": r.mcs,
        "nss": r.nss,
        "mhz": r.mhz,
        "short_gi": r.short_gi,
        "ht": r.ht,
        "vht": r.vht,
        "he": r.he,
    })
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
    let ifaces = match crate::openwrt::nl80211::query_live() {
        Ok(list) => list,
        Err(e) => {
            tracing::debug!("nl80211 query_live failed: {e:#}");
            return Vec::new();
        }
    };

    let mut out = Vec::with_capacity(ifaces.len());
    for iface in ifaces {
        let band = infer_live_band(iface.frequency, iface.channel);
        let stations: Vec<Value> = iface
            .stations
            .iter()
            .map(|s| {
                let mut rx = rate_to_json(&s.rx_rate);
                if let Some(obj) = rx.as_object_mut() {
                    obj.insert("bytes".into(), json!(s.rx_bytes));
                    obj.insert("packets".into(), json!(s.rx_packets));
                    obj.insert("drop_misc".into(), json!(s.rx_drop_misc));
                }
                let mut tx = rate_to_json(&s.tx_rate);
                if let Some(obj) = tx.as_object_mut() {
                    obj.insert("bytes".into(), json!(s.tx_bytes));
                    obj.insert("packets".into(), json!(s.tx_packets));
                    obj.insert("retries".into(), json!(s.tx_retries));
                    obj.insert("failed".into(), json!(s.tx_failed));
                }
                json!({
                    "mac": s.mac,
                    "signal": s.signal,
                    "signal_avg": s.signal_avg,
                    "noise": s.noise,
                    "inactive": s.inactive_ms,
                    "connected_time": s.connected_time,
                    "rx": rx,
                    "tx": tx,
                })
            })
            .collect();

        let sigs: Vec<i32> = iface.stations.iter().filter_map(|s| s.signal).collect();
        let signal = if sigs.is_empty() {
            None
        } else {
            Some((sigs.iter().map(|&v| i64::from(v)).sum::<i64>() / sigs.len() as i64) as i32)
        };
        let quality = signal.map(|sig| (sig + 110).clamp(0, 70));
        let quality_max = signal.map(|_| 70);

        let rates: Vec<u32> = iface
            .stations
            .iter()
            .filter_map(|s| s.tx_rate.rate_kbps)
            .collect();
        let bitrate = if rates.is_empty() {
            None
        } else {
            Some((rates.iter().map(|&v| u64::from(v)).sum::<u64>() / rates.len() as u64) as u32)
        };

        out.push(json!({
            "device": iface.device,
            "band": band,
            "ssid": iface.ssid,
            "bssid": iface.bssid,
            "mode": iface.mode,
            "channel": iface.channel,
            "frequency": iface.frequency,
            "txpower": iface.txpower,
            "signal": signal,
            "noise": iface.noise,
            "bitrate": bitrate,
            "encryption": Value::Null,
            "quality": quality,
            "quality_max": quality_max,
            "assoc_count": stations.len(),
            "stations": stations,
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
        if !crate::openwrt::net::is_lan_arp_device(dev) {
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
    if let Ok(objs) = ubus::list(Some("hostapd.*")) {
        let payload = json!({
            "addr": mac,
            "reason": 5,
            "deauth": true,
            "ban_time": ban_ms,
        })
        .to_string();
        for obj in objs.into_iter().filter(|l| l.starts_with("hostapd.")) {
            if ubus::call_ok(&obj, "del_client", Some(&payload)).is_some() {
                wifi_deauth = true;
            }
        }
    }

    let mut conntrack_flushed = false;
    if let Some(client_ip) = ip.filter(|s| !s.is_empty()) {
        if let Ok(addr) = client_ip.parse::<std::net::Ipv4Addr>() {
            conntrack_flushed =
                matches!(crate::openwrt::conntrack::flush_ip(addr), Ok(n) if n > 0);
            let lan_dev = crate::openwrt::uci::load("network")
                .ok()
                .and_then(|cfg| {
                    cfg.section("lan")
                        .and_then(|s| s.get("device").map(str::to_string))
                })
                .filter(|d| !d.is_empty())
                .unwrap_or_else(|| "br-lan".to_string());
            let _ = crate::openwrt::rtnetlink::delete_ipv4_neigh(addr, &lan_dev);
        }
    }
    (wifi_deauth, conntrack_flushed)
}
