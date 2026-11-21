use std::collections::BTreeMap;

use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::openwrt::{net, uci};
use crate::util;

pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Accept `aa:bb:cc:dd:ee:ff`, `aa-bb-...`, `aabb.ccdd.eeff` or `aabbccddeeff`.
pub fn normalize_mac(input: &str) -> Option<String> {
    let cleaned: String = input
        .chars()
        .filter(|c| !matches!(c, ':' | '-' | '.' | ' '))
        .collect();
    if cleaned.len() != 12 || !cleaned.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let upper = cleaned.to_ascii_uppercase();
    Some(
        upper
            .as_bytes()
            .chunks(2)
            .map(|c| std::str::from_utf8(c).unwrap_or(""))
            .collect::<Vec<_>>()
            .join(":"),
    )
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Device {
    pub mac: String,
    #[serde(default)]
    pub ip: String,
    #[serde(default)]
    pub hostname: String,
    /// User/AI supplied label, kept separate from the DHCP hostname.
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub note: String,
    #[serde(default)]
    pub first_seen: u64,
    #[serde(default)]
    pub last_seen: u64,
    #[serde(default)]
    pub authorized: bool,
    #[serde(default)]
    pub blocked: bool,
    /// 0 = permanent.
    #[serde(default)]
    pub expires_at: u64,
    /// Download rate limit in Kbps (0 = unlimited).
    #[serde(default)]
    pub rx_limit_kbps: u64,
    /// Upload rate limit in Kbps (0 = unlimited).
    #[serde(default)]
    pub tx_limit_kbps: u64,
    #[serde(skip)]
    pub online: bool,
}

impl Device {
    pub fn status(&self, now: u64) -> &'static str {
        if self.blocked {
            "blocked"
        } else if self.authorized && (self.expires_at == 0 || self.expires_at > now) {
            "authorized"
        } else {
            "pending"
        }
    }

    pub fn allowed(&self, now: u64) -> bool {
        !self.blocked && self.authorized && (self.expires_at == 0 || self.expires_at > now)
    }

    pub fn view(&self, now: u64) -> Value {
        json!({
            "mac": self.mac,
            "ip": self.ip,
            "hostname": self.hostname,
            "name": if self.name.is_empty() { self.hostname.clone() } else { self.name.clone() },
            "label": self.name,
            "note": self.note,
            "online": self.online,
            "status": self.status(now),
            "authorized": self.authorized,
            "blocked": self.blocked,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "expires_at": self.expires_at,
            "rx_limit_kbps": self.rx_limit_kbps,
            "tx_limit_kbps": self.tx_limit_kbps,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DeviceStore {
    #[serde(default)]
    pub enforcement: bool,
    #[serde(default)]
    pub devices: BTreeMap<String, Device>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct Selector {
    #[serde(default)]
    pub mac: Option<String>,
    #[serde(default)]
    pub ip: Option<String>,
    #[serde(default)]
    pub hostname: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
}

pub enum ResolveError {
    NotFound,
    Ambiguous(Vec<String>),
}

impl DeviceStore {
    pub fn load(path: &str) -> Self {
        std::fs::read_to_string(path)
            .ok()
            .and_then(|text| serde_json::from_str(&text).ok())
            .unwrap_or_default()
    }

    pub fn save(&self, path: &str) -> Result<()> {
        let data = serde_json::to_vec(self)?;
        util::write_atomic(path, &data, 0o600)?;
        Ok(())
    }

    /// Look up the device MAC address currently associated with `ip` (preferring online devices).
    pub fn mac_by_ip(&self, ip: &str) -> Option<&str> {
        let mut fallback = None;
        for d in self.devices.values() {
            if d.ip == ip {
                if d.online {
                    return Some(&d.mac);
                }
                if fallback.is_none() {
                    fallback = Some(d.mac.as_str());
                }
            }
        }
        fallback
    }

    /// Merge DHCP leases and ARP into the store. Online flags are runtime-only.
    /// Returns true when persistent state changed.
    pub fn scan(&mut self) -> bool {
        let now = now_unix();
        let mut seen: BTreeMap<String, (String, String)> = BTreeMap::new();

        for lease in net::leases() {
            let Some(mac) = lease["mac"].as_str().and_then(normalize_mac) else {
                continue;
            };
            let expires = lease["expires"].as_u64().unwrap_or(0);
            if expires != 0 && expires <= now {
                continue;
            }
            let ip = lease["ip"].as_str().unwrap_or("").to_string();
            let hostname = lease["hostname"].as_str().unwrap_or("").to_string();
            seen.insert(mac, (ip, hostname));
        }
        let mut non_lan_macs: Vec<String> = Vec::new();
        for arp in net::arp_table() {
            let Some(mac) = arp["mac"].as_str().and_then(normalize_mac) else {
                continue;
            };
            let dev = arp["device"].as_str().unwrap_or("");
            if !net::is_lan_arp_device(dev) {
                if !seen.contains_key(&mac) {
                    non_lan_macs.push(mac);
                }
                continue;
            }
            let ip = arp["ip"].as_str().unwrap_or("").to_string();
            let entry = seen.entry(mac).or_default();
            if entry.0.is_empty() {
                entry.0 = ip;
            }
        }

        let mut changed = false;
        for mac in non_lan_macs {
            if let Some(d) = self.devices.get(&mac) {
                if !d.authorized && !d.blocked {
                    self.devices.remove(&mac);
                    changed = true;
                }
            }
        }
        for (mac, (ip, hostname)) in &seen {
            let device = self.devices.entry(mac.clone()).or_insert_with(|| {
                changed = true;
                Device {
                    mac: mac.clone(),
                    first_seen: now,
                    last_seen: now,
                    online: true,
                    ..Device::default()
                }
            });
            if !ip.is_empty() && device.ip != *ip {
                device.ip = ip.clone();
                changed = true;
            }
            if !hostname.is_empty() && device.hostname != *hostname {
                device.hostname = hostname.clone();
                changed = true;
            }
            if device.last_seen != now {
                device.last_seen = now;
            }
            device.online = true;
        }
        for device in self.devices.values_mut() {
            if !seen.contains_key(&device.mac) {
                device.online = false;
            }
            if device.authorized && device.expires_at > 0 && device.expires_at <= now {
                device.authorized = false;
                device.expires_at = 0;
                changed = true;
            }
        }
        if self.prune() {
            changed = true;
        }
        changed
    }

    fn prune(&mut self) -> bool {
        const MAX: usize = 512;
        if self.devices.len() <= MAX {
            return false;
        }
        let mut removable: Vec<(u64, String)> = self
            .devices
            .values()
            .filter(|d| !d.authorized && !d.blocked)
            .map(|d| (d.last_seen, d.mac.clone()))
            .collect();
        removable.sort_unstable();
        let mut removed = false;
        for (_, mac) in removable {
            if self.devices.len() <= MAX {
                break;
            }
            self.devices.remove(&mac);
            removed = true;
        }
        removed
    }

    pub fn get(&self, mac: &str) -> Option<&Device> {
        self.devices.get(mac)
    }

    pub fn authorize(
        &mut self,
        mac: &str,
        name: &str,
        note: &str,
        expires_in: u64,
    ) -> Device {
        let now = now_unix();
        let device = self.devices.entry(mac.to_string()).or_insert_with(|| Device {
            mac: mac.to_string(),
            first_seen: now,
            last_seen: now,
            ..Device::default()
        });
        device.authorized = true;
        device.blocked = false;
        device.expires_at = if expires_in > 0 {
            now.saturating_add(expires_in)
        } else {
            0
        };
        if !name.trim().is_empty() {
            device.name = name.trim().to_string();
        }
        if !note.trim().is_empty() {
            device.note = note.trim().to_string();
        }
        device.clone()
    }

    pub fn revoke(&mut self, mac: &str) -> Option<Device> {
        let device = self.devices.get_mut(mac)?;
        device.authorized = false;
        device.expires_at = 0;
        Some(device.clone())
    }

    pub fn block(&mut self, mac: &str) -> Device {
        let now = now_unix();
        let device = self.devices.entry(mac.to_string()).or_insert_with(|| Device {
            mac: mac.to_string(),
            first_seen: now,
            last_seen: now,
            ..Device::default()
        });
        device.blocked = true;
        device.authorized = false;
        device.expires_at = 0;
        device.clone()
    }

    pub fn unblock(&mut self, mac: &str) -> Option<Device> {
        let device = self.devices.get_mut(mac)?;
        device.blocked = false;
        Some(device.clone())
    }

    pub fn set_rate_limit(
        &mut self,
        mac: &str,
        rx_limit_kbps: u64,
        tx_limit_kbps: u64,
        name: Option<&str>,
    ) -> Device {
        let now = now_unix();
        let device = self.devices.entry(mac.to_string()).or_insert_with(|| Device {
            mac: mac.to_string(),
            first_seen: now,
            last_seen: now,
            ..Device::default()
        });
        device.rx_limit_kbps = rx_limit_kbps;
        device.tx_limit_kbps = tx_limit_kbps;
        if let Some(n) = name {
            device.name = n.trim().to_string();
        }
        device.clone()
    }

    pub fn rate_limited_devices(&self) -> Vec<(String, u64, u64)> {
        self.devices
            .values()
            .filter(|d| !d.blocked && (d.rx_limit_kbps > 0 || d.tx_limit_kbps > 0))
            .map(|d| (d.mac.clone(), d.rx_limit_kbps, d.tx_limit_kbps))
            .collect()
    }

    pub fn set_enforcement(&mut self, enabled: bool, authorize_current: bool) -> bool {
        let was = self.enforcement;
        self.enforcement = enabled;
        if enabled && authorize_current {
            let now = now_unix();
            for device in self.devices.values_mut() {
                if device.online && !device.blocked {
                    device.authorized = true;
                    device.expires_at = 0;
                    device.last_seen = now;
                }
            }
        }
        was != enabled
    }

    pub fn allowed_macs(&self) -> Vec<String> {
        let now = now_unix();
        self.devices
            .values()
            .filter(|d| d.allowed(now))
            .map(|d| d.mac.clone())
            .collect()
    }

    pub fn summary(&self) -> Value {
        let now = now_unix();
        let mut pending = 0;
        let mut authorized = 0;
        let mut blocked = 0;
        let mut online = 0;
        for d in self.devices.values() {
            if d.online {
                online += 1;
            }
            match d.status(now) {
                "authorized" => authorized += 1,
                "blocked" => blocked += 1,
                _ => pending += 1,
            }
        }
        json!({
            "enforcement": self.enforcement,
            "online": online,
            "pending": pending,
            "authorized": authorized,
            "blocked": blocked,
            "known": self.devices.len(),
        })
    }

    pub fn views(&self, filter: &str, limit: usize) -> Vec<Value> {
        let now = now_unix();
        let mut list: Vec<&Device> = self
            .devices
            .values()
            .filter(|d| match filter {
                "pending" => d.status(now) == "pending",
                "authorized" => d.status(now) == "authorized",
                "blocked" => d.blocked,
                "online" => d.online,
                _ => true,
            })
            .collect();
        if filter == "pending" {
            list.sort_by_key(|d| std::cmp::Reverse(d.first_seen));
        } else {
            list.sort_by(|a, b| a.mac.cmp(&b.mac));
        }
        list.into_iter()
            .take(limit.clamp(1, 500))
            .map(|d| d.view(now))
            .collect()
    }

    pub fn resolve(&self, sel: &Selector, allow_new_mac: bool) -> Result<String, ResolveError> {
        if let Some(raw) = sel.mac.as_deref().filter(|s| !s.trim().is_empty()) {
            let mac = normalize_mac(raw).ok_or(ResolveError::NotFound)?;
            if self.devices.contains_key(&mac) || allow_new_mac {
                return Ok(mac);
            }
            return Err(ResolveError::NotFound);
        }
        if let Some(ip) = sel.ip.as_deref().filter(|s| !s.trim().is_empty()) {
            let ip = ip.trim();
            return self
                .devices
                .values()
                .find(|d| d.ip == ip)
                .map(|d| d.mac.clone())
                .ok_or(ResolveError::NotFound);
        }
        let needle = sel
            .hostname
            .as_deref()
            .or(sel.name.as_deref())
            .map(|s| s.trim().to_lowercase())
            .filter(|s| !s.is_empty())
            .ok_or(ResolveError::NotFound)?;

        let exact: Vec<String> = self
            .devices
            .values()
            .filter(|d| {
                d.hostname.to_lowercase() == needle || d.name.to_lowercase() == needle
            })
            .map(|d| d.mac.clone())
            .collect();
        if exact.len() == 1 {
            return Ok(exact[0].clone());
        }
        if exact.len() > 1 {
            return Err(ResolveError::Ambiguous(exact));
        }
        let fuzzy: Vec<String> = self
            .devices
            .values()
            .filter(|d| {
                d.hostname.to_lowercase().contains(&needle)
                    || d.name.to_lowercase().contains(&needle)
            })
            .map(|d| d.mac.clone())
            .collect();
        match fuzzy.len() {
            0 => Err(ResolveError::NotFound),
            1 => Ok(fuzzy[0].clone()),
            _ => Err(ResolveError::Ambiguous(fuzzy)),
        }
    }

    pub fn lan_hint(&self) -> String {
        uci::load("network")
            .ok()
            .and_then(|cfg| cfg.section("lan").cloned())
            .and_then(|s| s.get("device").map(|d| d.to_string()))
            .filter(|d| !d.is_empty())
            .unwrap_or_else(|| "br-lan".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_mac_formats() {
        assert_eq!(normalize_mac("aa:bb:cc:dd:ee:ff").as_deref(), Some("AA:BB:CC:DD:EE:FF"));
        assert_eq!(normalize_mac("aabb.ccdd.eeff").as_deref(), Some("AA:BB:CC:DD:EE:FF"));
        assert_eq!(normalize_mac("AA-BB-CC-DD-EE-FF").as_deref(), Some("AA:BB:CC:DD:EE:FF"));
        assert_eq!(normalize_mac("zz:bb:cc:dd:ee:ff"), None);
        assert_eq!(normalize_mac("aa:bb"), None);
    }

    #[test]
    fn authorization_lifecycle() {
        let mut store = DeviceStore::default();
        store.devices.insert(
            "AA:BB:CC:DD:EE:01".into(),
            Device {
                mac: "AA:BB:CC:DD:EE:01".into(),
                hostname: "tv".into(),
                online: true,
                ..Device::default()
            },
        );
        assert_eq!(store.views("pending", 10).len(), 1);
        let d = store.authorize("AA:BB:CC:DD:EE:01", "客厅电视", "", 0);
        assert!(d.authorized);
        assert_eq!(store.views("authorized", 10).len(), 1);
        assert_eq!(store.allowed_macs(), vec!["AA:BB:CC:DD:EE:01"]);
        assert!(store.revoke("AA:BB:CC:DD:EE:01").is_some());
        assert!(store.allowed_macs().is_empty());
    }

    #[test]
    fn resolves_by_hostname_and_reports_ambiguity() {
        let mut store = DeviceStore::default();
        for (mac, name) in [("AA:BB:CC:DD:EE:01", "living-tv"), ("AA:BB:CC:DD:EE:02", "bedroom-tv")] {
            store.devices.insert(mac.into(), Device { mac: mac.into(), hostname: name.into(), ..Device::default() });
        }
        let sel = Selector { hostname: Some("living".into()), ..Selector::default() };
        assert_eq!(store.resolve(&sel, false).ok().as_deref(), Some("AA:BB:CC:DD:EE:01"));
        let sel = Selector { hostname: Some("tv".into()), ..Selector::default() };
        match store.resolve(&sel, false) {
            Err(ResolveError::Ambiguous(v)) => assert_eq!(v.len(), 2),
            _ => panic!("expected ambiguous"),
        }
    }
}
