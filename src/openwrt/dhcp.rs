use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::os::unix::io::{FromRawFd, RawFd};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use tokio::net::UdpSocket;
use tokio::sync::{watch, Mutex};
use tokio::task::JoinHandle;

use crate::openwrt::uci;
use crate::util;

const DHCP_SERVER_PORT: u16 = 67;
const DHCP_CLIENT_PORT: u16 = 68;
const DHCP_MAGIC_COOKIE: [u8; 4] = [99, 130, 83, 99];
const BOOTP_HEADER_LEN: usize = 236;
const BOOTREQUEST: u8 = 1;
const BOOTREPLY: u8 = 2;

const DHCP_DISCOVER: u8 = 1;
const DHCP_OFFER: u8 = 2;
const DHCP_REQUEST: u8 = 3;
const DHCP_DECLINE: u8 = 4;
const DHCP_ACK: u8 = 5;
const DHCP_NAK: u8 = 6;
const DHCP_RELEASE: u8 = 7;
const DHCP_INFORM: u8 = 8;

const OPT_SUBNET_MASK: u8 = 1;
const OPT_ROUTER: u8 = 3;
const OPT_DNS: u8 = 6;
const OPT_HOSTNAME: u8 = 12;
const OPT_DOMAIN_NAME: u8 = 15;
const OPT_BROADCAST: u8 = 28;
const OPT_REQUESTED_IP: u8 = 50;
const OPT_LEASE_TIME: u8 = 51;
const OPT_MSG_TYPE: u8 = 53;
const OPT_SERVER_ID: u8 = 54;
const OPT_RENEWAL_T1: u8 = 58;
const OPT_REBIND_T2: u8 = 59;
const OPT_CLIENT_ID: u8 = 61;
const OPT_END: u8 = 255;

const DEFAULT_LEASES_PATH: &str = "/tmp/dhcp.leases";
const DECLINE_QUARANTINE_SECS: u64 = 600;
const OFFER_HOLD_SECS: u64 = 120;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum DhcpEngine {
    Dnsmasq,
    #[default]
    Routerd,
}

impl DhcpEngine {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Dnsmasq => "dnsmasq",
            Self::Routerd => "routerd",
        }
    }

    pub fn from_str_lossy(s: &str) -> Self {
        if s.trim().eq_ignore_ascii_case("dnsmasq") {
            Self::Dnsmasq
        } else {
            Self::Routerd
        }
    }
}

pub fn dnsmasq_installed() -> bool {
    std::path::Path::new("/etc/init.d/dnsmasq").exists()
}

pub fn read_configured_engine() -> DhcpEngine {
    let cfg = uci::load("routerd").unwrap_or_default();
    let val = cfg
        .section("main")
        .and_then(|s| s.get("dhcp_engine"))
        .unwrap_or("routerd");
    DhcpEngine::from_str_lossy(val)
}

pub fn write_configured_engine(engine: DhcpEngine) -> Result<()> {
    uci::set_opt("routerd", "main", "dhcp_engine", engine.as_str())
}

pub fn read_user_disabled() -> bool {
    let cfg = uci::load("routerd").unwrap_or_default();
    if let Some(v) = cfg.section("main").and_then(|s| s.get("dhcp_disabled")) {
        return v == "1" || v.eq_ignore_ascii_case("true");
    }
    false
}

pub fn write_user_disabled(disabled: bool) -> Result<()> {
    uci::set_opt(
        "routerd",
        "main",
        "dhcp_disabled",
        if disabled { "1" } else { "0" },
    )
}

pub fn parse_leasetime(s: &str) -> u32 {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return 43200;
    }
    if trimmed.eq_ignore_ascii_case("infinite") {
        return 86400;
    }
    let (num_str, mult) = if let Some(n) = trimmed.strip_suffix(['s', 'S']) {
        (n, 1u64)
    } else if let Some(n) = trimmed.strip_suffix(['m', 'M']) {
        (n, 60u64)
    } else if let Some(n) = trimmed.strip_suffix(['h', 'H']) {
        (n, 3600u64)
    } else if let Some(n) = trimmed.strip_suffix(['d', 'D']) {
        (n, 86400u64)
    } else {
        (trimmed, 1u64)
    };
    match num_str.trim().parse::<u64>() {
        Ok(v) => {
            let secs = v.saturating_mul(mult).clamp(120, 31_536_000);
            secs as u32
        }
        Err(_) => 43200,
    }
}

#[derive(Debug, Clone)]
pub struct StaticHost {
    pub mac: [u8; 6],
    pub ip: Ipv4Addr,
    pub name: String,
}

#[derive(Debug, Clone)]
pub struct DhcpPoolConfig {
    pub interface: String,
    pub server_ip: Ipv4Addr,
    pub netmask: Ipv4Addr,
    pub broadcast: Ipv4Addr,
    pub pool_start: Ipv4Addr,
    pub pool_end: Ipv4Addr,
    pub lease_secs: u32,
    pub domain: String,
    pub ap_mode: bool,
    pub user_disabled: bool,
    pub static_hosts: Vec<StaticHost>,
}

impl Default for DhcpPoolConfig {
    fn default() -> Self {
        Self {
            interface: "br-lan".to_string(),
            server_ip: Ipv4Addr::new(192, 168, 1, 1),
            netmask: Ipv4Addr::new(255, 255, 255, 0),
            broadcast: Ipv4Addr::new(192, 168, 1, 255),
            pool_start: Ipv4Addr::new(192, 168, 1, 100),
            pool_end: Ipv4Addr::new(192, 168, 1, 249),
            lease_secs: 43200,
            domain: "lan".to_string(),
            ap_mode: false,
            user_disabled: false,
            static_hosts: Vec::new(),
        }
    }
}

pub fn parse_mac_bytes(s: &str) -> Option<[u8; 6]> {
    let parts: Vec<&str> = s.trim().split(':').collect();
    if parts.len() != 6 {
        return None;
    }
    let mut mac = [0u8; 6];
    for (i, p) in parts.iter().enumerate() {
        mac[i] = u8::from_str_radix(p, 16).ok()?;
    }
    Some(mac)
}

pub fn format_mac(mac: &[u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

pub fn load_pool_config() -> DhcpPoolConfig {
    let net_cfg = uci::load("network").unwrap_or_default();
    let dhcp_cfg = uci::load("dhcp").unwrap_or_default();

    let lan_net = net_cfg.section("lan").cloned().unwrap_or_default();
    let wan_net = net_cfg.section("wan").cloned().unwrap_or_default();
    let lan_dhcp = dhcp_cfg.section("lan").cloned().unwrap_or_default();

    let lan_proto = lan_net.get_or("proto", "static");
    let wan_proto = wan_net.get_or("proto", "dhcp");
    let ap_mode = lan_proto == "dhcp" && wan_proto == "none";

    let interface = {
        let dev = lan_net.get_or("device", "br-lan");
        if dev.is_empty() {
            "br-lan".to_string()
        } else {
            dev.to_string()
        }
    };
    let server_ip: Ipv4Addr = lan_net
        .get_or("ipaddr", "192.168.1.1")
        .parse()
        .unwrap_or(Ipv4Addr::new(192, 168, 1, 1));
    let netmask: Ipv4Addr = lan_net
        .get_or("netmask", "255.255.255.0")
        .parse()
        .unwrap_or(Ipv4Addr::new(255, 255, 255, 0));

    let ip_u32 = u32::from(server_ip);
    let mask_u32 = u32::from(netmask);
    let net_u32 = ip_u32 & mask_u32;
    let bcast_u32 = net_u32 | !mask_u32;

    let start_off: u32 = lan_dhcp.get_or("start", "100").parse().unwrap_or(100);
    let limit: u32 = lan_dhcp.get_or("limit", "150").parse().unwrap_or(150).max(1);

    let raw_start = net_u32.saturating_add(start_off).max(net_u32.saturating_add(1));
    let max_host = bcast_u32.saturating_sub(1);
    let pool_start_u32 = raw_start.min(max_host);
    let pool_end_u32 = raw_start
        .saturating_add(limit.saturating_sub(1))
        .min(max_host)
        .max(pool_start_u32);

    let lease_secs = parse_leasetime(&lan_dhcp.get_or("leasetime", "12h"));
    let domain = dhcp_cfg
        .first_of("dnsmasq")
        .and_then(|s| s.get("domain"))
        .filter(|d| !d.is_empty())
        .unwrap_or("lan")
        .to_string();

    let mut static_hosts = Vec::new();
    for h in dhcp_cfg.by_kind("host") {
        let Some(mac) = h.get("mac").and_then(parse_mac_bytes) else {
            continue;
        };
        let Ok(ip) = h.get_or("ip", "").parse::<Ipv4Addr>() else {
            continue;
        };
        static_hosts.push(StaticHost {
            mac,
            ip,
            name: h.get_or("name", "").to_string(),
        });
    }

    let user_disabled = read_user_disabled()
        || (read_configured_engine() == DhcpEngine::Dnsmasq && lan_dhcp.bool("ignore"));

    DhcpPoolConfig {
        interface,
        server_ip,
        netmask,
        broadcast: Ipv4Addr::from(bcast_u32),
        pool_start: Ipv4Addr::from(pool_start_u32),
        pool_end: Ipv4Addr::from(pool_end_u32),
        lease_secs,
        domain,
        ap_mode,
        user_disabled,
        static_hosts,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaseEntry {
    pub expiry: u64,
    pub mac: [u8; 6],
    pub ip: Ipv4Addr,
    pub hostname: String,
    pub client_id: String,
}

pub fn load_leases_file(path: &str, now: u64) -> Vec<LeaseEntry> {
    let text = std::fs::read_to_string(path).unwrap_or_default();
    let mut out = Vec::new();
    for line in text.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 4 {
            continue;
        }
        let Ok(expiry) = parts[0].parse::<u64>() else {
            continue;
        };
        if expiry > 0 && expiry <= now {
            continue;
        }
        let Some(mac) = parse_mac_bytes(parts[1]) else {
            continue;
        };
        let Ok(ip) = parts[2].parse::<Ipv4Addr>() else {
            continue;
        };
        let hostname = if parts[3] == "*" {
            String::new()
        } else {
            parts[3].to_string()
        };
        let client_id = parts
            .get(4)
            .filter(|&&s| s != "*")
            .map(|s| (*s).to_string())
            .unwrap_or_default();
        out.push(LeaseEntry {
            expiry,
            mac,
            ip,
            hostname,
            client_id,
        });
    }
    out
}

pub fn save_leases_file(path: &str, leases: &[LeaseEntry]) -> Result<()> {
    let mut buf = String::new();
    for l in leases {
        let host = if l.hostname.trim().is_empty() {
            "*"
        } else {
            l.hostname.trim()
        };
        let cid = if l.client_id.trim().is_empty() {
            "*"
        } else {
            l.client_id.trim()
        };
        buf.push_str(&format!(
            "{} {} {} {} {}\n",
            l.expiry,
            format_mac(&l.mac),
            l.ip,
            host,
            cid
        ));
    }
    util::write_atomic(path, buf.as_bytes(), 0o644)
}

#[derive(Debug, Clone)]
struct PendingOffer {
    ip: Ipv4Addr,
    expires_at: u64,
    hostname: String,
}

#[derive(Debug)]
struct DhcpPacket {
    xid: [u8; 4],
    flags: [u8; 2],
    ciaddr: Ipv4Addr,
    giaddr: Ipv4Addr,
    chaddr: [u8; 16],
    mac: [u8; 6],
    msg_type: u8,
    requested_ip: Option<Ipv4Addr>,
    server_id: Option<Ipv4Addr>,
    hostname: String,
    client_id: String,
}

fn sanitize_lease_field(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_ascii_graphic())
        .take(64)
        .collect()
}

fn format_client_id(raw: &[u8]) -> String {
    if raw.is_empty() {
        return String::new();
    }
    raw.iter()
        .take(32)
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

fn parse_packet(buf: &[u8]) -> Option<DhcpPacket> {
    if buf.len() < BOOTP_HEADER_LEN + 4 {
        return None;
    }
    if buf[0] != BOOTREQUEST || buf[1] != 1 || buf[2] != 6 {
        return None;
    }
    if buf[BOOTP_HEADER_LEN..BOOTP_HEADER_LEN + 4] != DHCP_MAGIC_COOKIE {
        return None;
    }

    let xid = [buf[4], buf[5], buf[6], buf[7]];
    let flags = [buf[10], buf[11]];
    let ciaddr = Ipv4Addr::new(buf[12], buf[13], buf[14], buf[15]);
    let giaddr = Ipv4Addr::new(buf[24], buf[25], buf[26], buf[27]);
    let mut chaddr = [0u8; 16];
    chaddr.copy_from_slice(&buf[28..44]);
    let mac = [buf[28], buf[29], buf[30], buf[31], buf[32], buf[33]];

    let mut msg_type = 0u8;
    let mut requested_ip = None;
    let mut server_id = None;
    let mut hostname = String::new();
    let mut client_id = String::new();

    let mut i = BOOTP_HEADER_LEN + 4;
    while i < buf.len() {
        let code = buf[i];
        i += 1;
        if code == 0 {
            continue;
        }
        if code == OPT_END {
            break;
        }
        if i >= buf.len() {
            break;
        }
        let len = buf[i] as usize;
        i += 1;
        if i + len > buf.len() {
            break;
        }
        let val = &buf[i..i + len];
        i += len;

        match code {
            OPT_MSG_TYPE if len == 1 => msg_type = val[0],
            OPT_REQUESTED_IP if len == 4 => {
                requested_ip = Some(Ipv4Addr::new(val[0], val[1], val[2], val[3]));
            }
            OPT_SERVER_ID if len == 4 => {
                server_id = Some(Ipv4Addr::new(val[0], val[1], val[2], val[3]));
            }
            OPT_HOSTNAME => {
                hostname = sanitize_lease_field(&String::from_utf8_lossy(val));
            }
            OPT_CLIENT_ID => {
                client_id = format_client_id(val);
            }
            _ => {}
        }
    }

    if msg_type == 0 {
        return None;
    }

    Some(DhcpPacket {
        xid,
        flags,
        ciaddr,
        giaddr,
        chaddr,
        mac,
        msg_type,
        requested_ip,
        server_id,
        hostname,
        client_id,
    })
}

fn push_opt_ip(out: &mut Vec<u8>, code: u8, ip: Ipv4Addr) {
    out.push(code);
    out.push(4);
    out.extend_from_slice(&ip.octets());
}

fn push_opt_u32(out: &mut Vec<u8>, code: u8, val: u32) {
    out.push(code);
    out.push(4);
    out.extend_from_slice(&val.to_be_bytes());
}

fn build_reply(
    req: &DhcpPacket,
    msg_type: u8,
    yiaddr: Ipv4Addr,
    cfg: &DhcpPoolConfig,
) -> Vec<u8> {
    let mut out = vec![0u8; BOOTP_HEADER_LEN];
    out[0] = BOOTREPLY;
    out[1] = 1;
    out[2] = 6;
    out[4..8].copy_from_slice(&req.xid);
    out[10..12].copy_from_slice(&req.flags);
    // Per RFC 2131, ciaddr is 0 except in DHCPACK to INFORM or as echoed.
    if req.msg_type == DHCP_INFORM {
        out[12..16].copy_from_slice(&req.ciaddr.octets());
    }
    if msg_type != DHCP_NAK {
        out[16..20].copy_from_slice(&yiaddr.octets());
        out[20..24].copy_from_slice(&cfg.server_ip.octets());
    }
    out[24..28].copy_from_slice(&req.giaddr.octets());
    out[28..44].copy_from_slice(&req.chaddr);
    out.extend_from_slice(&DHCP_MAGIC_COOKIE);

    out.push(OPT_MSG_TYPE);
    out.push(1);
    out.push(msg_type);
    push_opt_ip(&mut out, OPT_SERVER_ID, cfg.server_ip);

    if msg_type != DHCP_NAK {
        if req.msg_type != DHCP_INFORM {
            let lease = cfg.lease_secs;
            push_opt_u32(&mut out, OPT_LEASE_TIME, lease);
            push_opt_u32(&mut out, OPT_RENEWAL_T1, lease / 2);
            push_opt_u32(&mut out, OPT_REBIND_T2, (lease as u64 * 7 / 8) as u32);
        }
        push_opt_ip(&mut out, OPT_SUBNET_MASK, cfg.netmask);
        push_opt_ip(&mut out, OPT_ROUTER, cfg.server_ip);
        push_opt_ip(&mut out, OPT_DNS, cfg.server_ip);
        push_opt_ip(&mut out, OPT_BROADCAST, cfg.broadcast);
        if !cfg.domain.is_empty() && cfg.domain.len() <= 253 {
            let dom = cfg.domain.as_bytes();
            out.push(OPT_DOMAIN_NAME);
            out.push(dom.len() as u8);
            out.extend_from_slice(dom);
        }
    }

    out.push(OPT_END);
    if out.len() < 300 {
        out.resize(300, 0);
    }
    out
}

#[derive(Debug)]
pub struct DhcpCore {
    pub cfg: DhcpPoolConfig,
    pub leases: Vec<LeaseEntry>,
    offers: HashMap<[u8; 6], PendingOffer>,
    declined: HashMap<Ipv4Addr, u64>,
    pub offers_sent: u64,
    pub acks_sent: u64,
    pub naks_sent: u64,
}

impl DhcpCore {
    pub fn new(cfg: DhcpPoolConfig, leases: Vec<LeaseEntry>) -> Self {
        Self {
            cfg,
            leases,
            offers: HashMap::new(),
            declined: HashMap::new(),
            offers_sent: 0,
            acks_sent: 0,
            naks_sent: 0,
        }
    }

    pub fn prune_expired(&mut self, now: u64) -> bool {
        let before = self.leases.len();
        self.leases.retain(|l| l.expiry == 0 || l.expiry > now);
        self.offers.retain(|_, o| o.expires_at > now);
        self.declined.retain(|_, exp| *exp > now);
        self.leases.len() != before
    }

    fn in_same_subnet(&self, ip: Ipv4Addr) -> bool {
        let mask = u32::from(self.cfg.netmask);
        (u32::from(ip) & mask) == (u32::from(self.cfg.server_ip) & mask)
    }

    fn in_pool(&self, ip: Ipv4Addr) -> bool {
        let u = u32::from(ip);
        u >= u32::from(self.cfg.pool_start) && u <= u32::from(self.cfg.pool_end)
    }

    fn static_ip_for_mac(&self, mac: &[u8; 6]) -> Option<&StaticHost> {
        self.cfg.static_hosts.iter().find(|h| &h.mac == mac)
    }

    fn is_ip_reserved_for_other(&self, ip: Ipv4Addr, mac: &[u8; 6], now: u64) -> bool {
        if ip == self.cfg.server_ip {
            return true;
        }
        if self
            .cfg
            .static_hosts
            .iter()
            .any(|h| h.ip == ip && &h.mac != mac)
        {
            return true;
        }
        if self
            .leases
            .iter()
            .any(|l| l.ip == ip && &l.mac != mac && (l.expiry == 0 || l.expiry > now))
        {
            return true;
        }
        if self.declined.get(&ip).is_some_and(|&exp| exp > now) {
            return true;
        }
        false
    }

    fn choose_offer_ip(&self, mac: &[u8; 6], requested: Option<Ipv4Addr>, now: u64) -> Option<Ipv4Addr> {
        if let Some(sh) = self.static_ip_for_mac(mac) {
            return Some(sh.ip);
        }
        if let Some(existing) = self
            .leases
            .iter()
            .find(|l| &l.mac == mac && (l.expiry == 0 || l.expiry > now))
        {
            if self.in_pool(existing.ip) && !self.is_ip_reserved_for_other(existing.ip, mac, now) {
                return Some(existing.ip);
            }
        }
        if let Some(req_ip) = requested {
            if self.in_pool(req_ip) && !self.is_ip_reserved_for_other(req_ip, mac, now) {
                return Some(req_ip);
            }
        }
        let start = u32::from(self.cfg.pool_start);
        let end = u32::from(self.cfg.pool_end);
        for candidate in start..=end {
            let ip = Ipv4Addr::from(candidate);
            if !self.is_ip_reserved_for_other(ip, mac, now)
                && !self
                    .offers
                    .iter()
                    .any(|(m, o)| m != mac && o.ip == ip && o.expires_at > now)
            {
                return Some(ip);
            }
        }
        None
    }

    fn reply_dest(req: &DhcpPacket, msg_type: u8) -> SocketAddrV4 {
        let bcast_flag = (u16::from_be_bytes(req.flags) & 0x8000) != 0;
        if msg_type == DHCP_NAK || req.ciaddr == Ipv4Addr::UNSPECIFIED || bcast_flag {
            SocketAddrV4::new(Ipv4Addr::BROADCAST, DHCP_CLIENT_PORT)
        } else {
            SocketAddrV4::new(req.ciaddr, DHCP_CLIENT_PORT)
        }
    }

    fn upsert_lease(&mut self, entry: LeaseEntry) {
        self.leases
            .retain(|l| l.mac != entry.mac && l.ip != entry.ip);
        self.leases.push(entry);
    }

    pub fn handle_packet(
        &mut self,
        buf: &[u8],
        now: u64,
    ) -> Option<(Vec<u8>, SocketAddrV4, bool)> {
        let req = parse_packet(buf)?;
        self.prune_expired(now);

        match req.msg_type {
            DHCP_DISCOVER => {
                let ip = self.choose_offer_ip(&req.mac, req.requested_ip, now)?;
                self.offers.insert(
                    req.mac,
                    PendingOffer {
                        ip,
                        expires_at: now + OFFER_HOLD_SECS,
                        hostname: req.hostname.clone(),
                    },
                );
                self.offers_sent += 1;
                let reply = build_reply(&req, DHCP_OFFER, ip, &self.cfg);
                let dest = Self::reply_dest(&req, DHCP_OFFER);
                Some((reply, dest, false))
            }
            DHCP_REQUEST => {
                if let Some(sid) = req.server_id {
                    if sid != self.cfg.server_ip {
                        return None;
                    }
                }
                let target_ip = req
                    .requested_ip
                    .or_else(|| {
                        if req.ciaddr != Ipv4Addr::UNSPECIFIED {
                            Some(req.ciaddr)
                        } else {
                            None
                        }
                    })
                    .or_else(|| self.static_ip_for_mac(&req.mac).map(|h| h.ip))
                    .or_else(|| self.offers.get(&req.mac).map(|o| o.ip))
                    .or_else(|| {
                        self.leases
                            .iter()
                            .find(|l| l.mac == req.mac)
                            .map(|l| l.ip)
                    });

                let valid = target_ip.is_some_and(|ip| {
                    if !self.in_same_subnet(ip) || self.is_ip_reserved_for_other(ip, &req.mac, now)
                    {
                        return false;
                    }
                    if let Some(sh) = self.static_ip_for_mac(&req.mac) {
                        return ip == sh.ip;
                    }
                    self.in_pool(ip)
                        || self
                            .leases
                            .iter()
                            .any(|l| l.mac == req.mac && l.ip == ip)
                });

                if !valid {
                    self.naks_sent += 1;
                    let reply = build_reply(&req, DHCP_NAK, Ipv4Addr::UNSPECIFIED, &self.cfg);
                    return Some((
                        reply,
                        SocketAddrV4::new(Ipv4Addr::BROADCAST, DHCP_CLIENT_PORT),
                        false,
                    ));
                }

                let assigned = target_ip.unwrap();
                let offer_host = self
                    .offers
                    .remove(&req.mac)
                    .map(|o| o.hostname)
                    .unwrap_or_default();
                let hostname = if !req.hostname.is_empty() {
                    req.hostname.clone()
                } else if !offer_host.is_empty() {
                    offer_host
                } else if let Some(sh_name) = self.static_ip_for_mac(&req.mac).map(|h| h.name.clone()) {
                    sh_name
                } else {
                    self.leases
                        .iter()
                        .find(|l| l.mac == req.mac)
                        .map(|l| l.hostname.clone())
                        .unwrap_or_default()
                };
                self.upsert_lease(LeaseEntry {
                    expiry: now + u64::from(self.cfg.lease_secs),
                    mac: req.mac,
                    ip: assigned,
                    hostname,
                    client_id: req.client_id.clone(),
                });
                self.acks_sent += 1;
                let reply = build_reply(&req, DHCP_ACK, assigned, &self.cfg);
                let dest = Self::reply_dest(&req, DHCP_ACK);
                Some((reply, dest, true))
            }
            DHCP_RELEASE => {
                let target = if req.ciaddr != Ipv4Addr::UNSPECIFIED {
                    Some(req.ciaddr)
                } else {
                    req.requested_ip
                };
                let before = self.leases.len();
                self.leases.retain(|l| {
                    !(l.mac == req.mac && target.is_none_or(|ip| ip == l.ip))
                });
                self.offers.remove(&req.mac);
                let dirty = self.leases.len() != before;
                if dirty {
                    // Caller persists updated lease file even though no reply packet is sent.
                    return Some((Vec::new(), SocketAddrV4::new(Ipv4Addr::BROADCAST, DHCP_CLIENT_PORT), true));
                }
                None
            }
            DHCP_DECLINE => {
                if let Some(ip) = req.requested_ip {
                    self.declined.insert(ip, now + DECLINE_QUARANTINE_SECS);
                    self.leases.retain(|l| !(l.mac == req.mac && l.ip == ip));
                    self.offers.remove(&req.mac);
                    return Some((Vec::new(), SocketAddrV4::new(Ipv4Addr::BROADCAST, DHCP_CLIENT_PORT), true));
                }
                None
            }
            DHCP_INFORM => {
                if req.ciaddr == Ipv4Addr::UNSPECIFIED {
                    return None;
                }
                self.acks_sent += 1;
                let reply = build_reply(&req, DHCP_ACK, Ipv4Addr::UNSPECIFIED, &self.cfg);
                let dest = Self::reply_dest(&req, DHCP_ACK);
                Some((reply, dest, false))
            }
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct DhcpStatus {
    pub configured_engine: DhcpEngine,
    pub active_engine: DhcpEngine,
    pub dnsmasq_available: bool,
    pub fallback_active: bool,
    pub running: bool,
    pub disabled: bool,
    pub ap_mode: bool,
    pub interface: String,
    pub server_ip: String,
    pub pool_start: String,
    pub pool_end: String,
    pub lease_secs: u32,
    pub active_leases: usize,
    pub static_leases: usize,
    pub offers_sent: u64,
    pub acks_sent: u64,
    pub naks_sent: u64,
    pub last_error: Option<String>,
}

impl DhcpStatus {
    fn from_cfg(
        configured: DhcpEngine,
        active: DhcpEngine,
        fallback_active: bool,
        running: bool,
        cfg: &DhcpPoolConfig,
        active_leases: usize,
        last_error: Option<String>,
    ) -> Self {
        Self {
            configured_engine: configured,
            active_engine: active,
            dnsmasq_available: dnsmasq_installed(),
            fallback_active,
            running,
            disabled: cfg.user_disabled,
            ap_mode: cfg.ap_mode,
            interface: cfg.interface.clone(),
            server_ip: cfg.server_ip.to_string(),
            pool_start: cfg.pool_start.to_string(),
            pool_end: cfg.pool_end.to_string(),
            lease_secs: cfg.lease_secs,
            active_leases,
            static_leases: cfg.static_hosts.len(),
            offers_sent: 0,
            acks_sent: 0,
            naks_sent: 0,
            last_error,
        }
    }
}

struct RuntimeHandle {
    stop_tx: watch::Sender<bool>,
    reload_tx: watch::Sender<u64>,
    task: JoinHandle<()>,
    interface: String,
}

struct InnerState {
    status: DhcpStatus,
    runtime: Option<RuntimeHandle>,
    reload_gen: u64,
}

pub struct DhcpManager {
    sim: bool,
    leases_path: String,
    op_lock: Mutex<()>,
    inner: Arc<RwLock<InnerState>>,
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn set_dnsmasq_dhcp_ignore(ignore: bool) -> Result<()> {
    if !dnsmasq_installed() {
        return Ok(());
    }
    uci::set_opt("dhcp", "lan", "ignore", if ignore { "1" } else { "0" })?;
    let _ = util::run("/etc/init.d/dnsmasq", &["reload"]);
    Ok(())
}

fn bind_dhcp_socket(iface: &str) -> Result<UdpSocket> {
    let fd: RawFd = unsafe {
        libc::socket(
            libc::AF_INET,
            libc::SOCK_DGRAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            0,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error()).context("socket(AF_INET, SOCK_DGRAM)");
    }
    let std_sock = unsafe { std::net::UdpSocket::from_raw_fd(fd) };

    let yes: libc::c_int = 1;
    unsafe {
        if libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_REUSEADDR,
            (&yes as *const libc::c_int).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        ) != 0
        {
            return Err(std::io::Error::last_os_error()).context("SO_REUSEADDR");
        }
        if libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_BROADCAST,
            (&yes as *const libc::c_int).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        ) != 0
        {
            return Err(std::io::Error::last_os_error()).context("SO_BROADCAST");
        }
        if !iface.is_empty() {
            if let Ok(c_if) = std::ffi::CString::new(iface) {
                let rc = libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_BINDTODEVICE,
                    c_if.as_ptr().cast(),
                    (iface.len() + 1) as libc::socklen_t,
                );
                if rc != 0 {
                    tracing::warn!(
                        "SO_BINDTODEVICE({iface}) failed: {}",
                        std::io::Error::last_os_error()
                    );
                }
            }
        }
    }

    let addr = libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: DHCP_SERVER_PORT.to_be(),
        sin_addr: libc::in_addr { s_addr: 0 },
        sin_zero: [0; 8],
    };
    let bind_rc = unsafe {
        libc::bind(
            fd,
            (&addr as *const libc::sockaddr_in).cast(),
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        )
    };
    if bind_rc != 0 {
        return Err(std::io::Error::last_os_error()).context("bind 0.0.0.0:67");
    }

    UdpSocket::from_std(std_sock).context("tokio UdpSocket::from_std")
}

impl DhcpManager {
    pub fn new(sim: bool) -> Self {
        let cfg = load_pool_config();
        let configured = read_configured_engine();
        let leases_count = load_leases_file(DEFAULT_LEASES_PATH, unix_now()).len();
        let status = DhcpStatus::from_cfg(
            configured,
            DhcpEngine::Dnsmasq,
            false,
            false,
            &cfg,
            leases_count,
            None,
        );
        Self {
            sim,
            leases_path: DEFAULT_LEASES_PATH.to_string(),
            op_lock: Mutex::new(()),
            inner: Arc::new(RwLock::new(InnerState {
                status,
                runtime: None,
                reload_gen: 0,
            })),
        }
    }

    pub fn status(&self) -> DhcpStatus {
        self.inner.read().unwrap_or_else(|e| e.into_inner()).status.clone()
    }

    pub async fn bootstrap(&self) {
        let _guard = self.op_lock.lock().await;
        let configured = read_configured_engine();
        let cfg = tokio::task::spawn_blocking(load_pool_config)
            .await
            .unwrap_or_default();

        if self.sim {
            let mut st = self.inner.write().unwrap_or_else(|e| e.into_inner());
            st.status = DhcpStatus::from_cfg(
                configured,
                configured,
                false,
                configured == DhcpEngine::Routerd && !cfg.ap_mode && !cfg.user_disabled,
                &cfg,
                st.status.active_leases,
                None,
            );
            return;
        }

        if configured == DhcpEngine::Routerd && !cfg.ap_mode && !cfg.user_disabled {
            self.start_routerd_with_fallback(&cfg, configured).await;
        } else {
            self.refresh_stopped_status(configured, &cfg, None);
        }
    }

    pub async fn set_engine(&self, engine: DhcpEngine) -> Result<DhcpStatus> {
        let _guard = self.op_lock.lock().await;
        if engine == DhcpEngine::Dnsmasq && !self.sim && !dnsmasq_installed() {
            bail!("系统未安装 dnsmasq，无法切换至 dnsmasq DHCP 引擎");
        }
        tokio::task::spawn_blocking(move || write_configured_engine(engine))
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))??;

        let cfg = tokio::task::spawn_blocking(load_pool_config)
            .await
            .unwrap_or_default();

        if self.sim {
            let mut st = self.inner.write().unwrap_or_else(|e| e.into_inner());
            st.status = DhcpStatus::from_cfg(
                engine,
                engine,
                false,
                engine == DhcpEngine::Routerd && !cfg.ap_mode && !cfg.user_disabled,
                &cfg,
                st.status.active_leases,
                None,
            );
            return Ok(st.status.clone());
        }

        match engine {
            DhcpEngine::Dnsmasq => {
                self.stop_runtime_task().await;
                if !cfg.ap_mode && !cfg.user_disabled {
                    tokio::task::spawn_blocking(|| set_dnsmasq_dhcp_ignore(false))
                        .await
                        .map_err(|e| anyhow::anyhow!("{e}"))??;
                }
                self.refresh_stopped_status(DhcpEngine::Dnsmasq, &cfg, None);
                Ok(self.status())
            }
            DhcpEngine::Routerd => {
                if cfg.ap_mode || cfg.user_disabled {
                    self.stop_runtime_task().await;
                    self.refresh_stopped_status(DhcpEngine::Routerd, &cfg, None);
                    return Ok(self.status());
                }
                self.start_routerd_with_fallback(&cfg, DhcpEngine::Routerd)
                    .await;
                let st = self.status();
                if st.fallback_active {
                    bail!(
                        "Rust DHCP 启动失败，已自动兜底回 dnsmasq: {}",
                        st.last_error.as_deref().unwrap_or("unknown")
                    );
                }
                Ok(st)
            }
        }
    }

    pub async fn reload(&self) -> Result<DhcpStatus> {
        let _guard = self.op_lock.lock().await;
        let configured = read_configured_engine();
        let cfg = tokio::task::spawn_blocking(load_pool_config)
            .await
            .unwrap_or_default();

        if self.sim {
            let mut st = self.inner.write().unwrap_or_else(|e| e.into_inner());
            st.status = DhcpStatus::from_cfg(
                configured,
                configured,
                false,
                configured == DhcpEngine::Routerd && !cfg.ap_mode && !cfg.user_disabled,
                &cfg,
                st.status.active_leases,
                None,
            );
            return Ok(st.status.clone());
        }

        if cfg.ap_mode || cfg.user_disabled {
            self.stop_runtime_task().await;
            let _ = tokio::task::spawn_blocking(|| set_dnsmasq_dhcp_ignore(true)).await;
            self.refresh_stopped_status(configured, &cfg, None);
            return Ok(self.status());
        }

        match configured {
            DhcpEngine::Dnsmasq => {
                self.stop_runtime_task().await;
                let _ = tokio::task::spawn_blocking(|| set_dnsmasq_dhcp_ignore(false)).await;
                self.refresh_stopped_status(DhcpEngine::Dnsmasq, &cfg, None);
            }
            DhcpEngine::Routerd => {
                let same_iface = {
                    let mut st = self.inner.write().unwrap_or_else(|e| e.into_inner());
                    let next_gen = st.reload_gen.wrapping_add(1);
                    let sent = if let Some(rt) = &st.runtime {
                        if rt.interface == cfg.interface && !rt.task.is_finished() {
                            let _ = rt.reload_tx.send(next_gen);
                            true
                        } else {
                            false
                        }
                    } else {
                        false
                    };
                    if sent {
                        st.reload_gen = next_gen;
                    }
                    sent
                };
                if !same_iface {
                    self.start_routerd_with_fallback(&cfg, DhcpEngine::Routerd)
                        .await;
                }
            }
        }
        Ok(self.status())
    }

    pub async fn shutdown(&self) {
        let _guard = self.op_lock.lock().await;
        let was_running = {
            let st = self.inner.read().unwrap_or_else(|e| e.into_inner());
            st.runtime.is_some()
        };
        self.stop_runtime_task().await;
        if was_running && !self.sim {
            let cfg = load_pool_config();
            if !cfg.ap_mode && !cfg.user_disabled {
                let _ = set_dnsmasq_dhcp_ignore(false);
                tracing::info!("routerd DHCP stopped; restored dnsmasq DHCP fallback");
            }
        }
    }

    fn refresh_stopped_status(
        &self,
        configured: DhcpEngine,
        cfg: &DhcpPoolConfig,
        err: Option<String>,
    ) {
        let leases_count = load_leases_file(&self.leases_path, unix_now()).len();
        let mut st = self.inner.write().unwrap_or_else(|e| e.into_inner());
        let running = configured == DhcpEngine::Dnsmasq && !cfg.ap_mode && !cfg.user_disabled;
        st.status = DhcpStatus::from_cfg(
            configured,
            DhcpEngine::Dnsmasq,
            err.is_some(),
            running,
            cfg,
            leases_count,
            err,
        );
    }

    async fn stop_runtime_task(&self) {
        let handle = {
            let mut st = self.inner.write().unwrap_or_else(|e| e.into_inner());
            st.runtime.take()
        };
        if let Some(rt) = handle {
            let _ = rt.stop_tx.send(true);
            let _ = tokio::time::timeout(Duration::from_secs(2), rt.task).await;
        }
    }

    async fn start_routerd_with_fallback(&self, cfg: &DhcpPoolConfig, configured: DhcpEngine) {
        self.stop_runtime_task().await;

        if let Err(e) = tokio::task::spawn_blocking(|| set_dnsmasq_dhcp_ignore(true))
            .await
            .unwrap_or_else(|e| Err(anyhow::anyhow!("{e}")))
        {
            let msg = format!("dnsmasq 让出端口失败: {e:#}");
            tracing::error!("{msg}");
            self.refresh_stopped_status(configured, cfg, Some(msg));
            return;
        }

        let iface = cfg.interface.clone();
        let mut bound = None;
        let mut last_err = String::new();
        for _ in 0..10 {
            match bind_dhcp_socket(&iface) {
                Ok(sock) => {
                    bound = Some(sock);
                    break;
                }
                Err(e) => {
                    last_err = format!("{e:#}");
                    tokio::time::sleep(Duration::from_millis(150)).await;
                }
            }
        }

        let Some(sock) = bound else {
            let msg = format!("绑定 UDP :67 失败 ({last_err})");
            tracing::error!("{msg}; restoring dnsmasq fallback");
            let _ = tokio::task::spawn_blocking(|| set_dnsmasq_dhcp_ignore(false)).await;
            self.refresh_stopped_status(configured, cfg, Some(msg));
            return;
        };

        let leases = load_leases_file(&self.leases_path, unix_now());
        let leases_count = leases.len();
        let (stop_tx, stop_rx) = watch::channel(false);
        let (reload_tx, reload_rx) = watch::channel(0u64);

        {
            let mut st = self.inner.write().unwrap_or_else(|e| e.into_inner());
            st.status = DhcpStatus::from_cfg(
                configured,
                DhcpEngine::Routerd,
                false,
                true,
                cfg,
                leases_count,
                None,
            );
        }

        let inner = self.inner.clone();
        let leases_path = self.leases_path.clone();
        let cfg_clone = cfg.clone();
        let task = tokio::spawn(async move {
            run_dhcp_loop(sock, cfg_clone, leases, leases_path, inner, stop_rx, reload_rx).await;
        });

        let mut st = self.inner.write().unwrap_or_else(|e| e.into_inner());
        st.runtime = Some(RuntimeHandle {
            stop_tx,
            reload_tx,
            task,
            interface: cfg.interface.clone(),
        });
        tracing::info!(
            "routerd DHCPv4 server active on {} ({}..{}, lease {}s)",
            cfg.interface,
            cfg.pool_start,
            cfg.pool_end,
            cfg.lease_secs
        );
    }
}

async fn run_dhcp_loop(
    sock: UdpSocket,
    cfg: DhcpPoolConfig,
    leases: Vec<LeaseEntry>,
    leases_path: String,
    inner: Arc<RwLock<InnerState>>,
    mut stop_rx: watch::Receiver<bool>,
    mut reload_rx: watch::Receiver<u64>,
) {
    let mut core = DhcpCore::new(cfg, leases);
    let mut buf = [0u8; 1500];
    let mut tick = tokio::time::interval(Duration::from_secs(60));
    tick.tick().await;

    let mut fatal_err: Option<String> = None;

    loop {
        tokio::select! {
            _ = stop_rx.changed() => {
                if *stop_rx.borrow() {
                    break;
                }
            }
            _ = reload_rx.changed() => {
                let new_cfg = tokio::task::spawn_blocking(load_pool_config)
                    .await
                    .unwrap_or_else(|_| core.cfg.clone());
                core.cfg = new_cfg;
                let mut st = inner.write().unwrap_or_else(|e| e.into_inner());
                st.status.server_ip = core.cfg.server_ip.to_string();
                st.status.pool_start = core.cfg.pool_start.to_string();
                st.status.pool_end = core.cfg.pool_end.to_string();
                st.status.lease_secs = core.cfg.lease_secs;
                st.status.static_leases = core.cfg.static_hosts.len();
            }
            _ = tick.tick() => {
                let now = unix_now();
                if core.prune_expired(now) {
                    let _ = save_leases_file(&leases_path, &core.leases);
                }
                let mut st = inner.write().unwrap_or_else(|e| e.into_inner());
                st.status.active_leases = core.leases.len();
            }
            recv = sock.recv_from(&mut buf) => {
                match recv {
                    Ok((n, _src)) => {
                        let now = unix_now();
                        if let Some((reply, dest, dirty)) = core.handle_packet(&buf[..n], now) {
                            if dirty {
                                if let Err(e) = save_leases_file(&leases_path, &core.leases) {
                                    tracing::warn!("save dhcp leases failed: {e:#}");
                                }
                            }
                            if !reply.is_empty() {
                                if let Err(e) = sock.send_to(&reply, SocketAddr::V4(dest)).await {
                                    tracing::debug!("dhcp send_to {dest} failed: {e}");
                                }
                            }
                            let mut st = inner.write().unwrap_or_else(|e| e.into_inner());
                            st.status.active_leases = core.leases.len();
                            st.status.offers_sent = core.offers_sent;
                            st.status.acks_sent = core.acks_sent;
                            st.status.naks_sent = core.naks_sent;
                        }
                    }
                    Err(e) => {
                        fatal_err = Some(format!("DHCP recv_from error: {e}"));
                        break;
                    }
                }
            }
        }
    }

    drop(sock);
    if let Some(err) = fatal_err {
        tracing::error!("{err}; activating dnsmasq fallback");
        let _ = tokio::task::spawn_blocking(|| set_dnsmasq_dhcp_ignore(false)).await;
        let mut st = inner.write().unwrap_or_else(|e| e.into_inner());
        st.status.active_engine = DhcpEngine::Dnsmasq;
        st.status.fallback_active = true;
        st.status.running = true;
        st.status.last_error = Some(err);
        st.runtime = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_discover(mac: [u8; 6], xid: [u8; 4], hostname: &str) -> Vec<u8> {
        let mut p = vec![0u8; BOOTP_HEADER_LEN];
        p[0] = BOOTREQUEST;
        p[1] = 1;
        p[2] = 6;
        p[4..8].copy_from_slice(&xid);
        p[28..34].copy_from_slice(&mac);
        p.extend_from_slice(&DHCP_MAGIC_COOKIE);
        p.extend_from_slice(&[OPT_MSG_TYPE, 1, DHCP_DISCOVER]);
        if !hostname.is_empty() {
            p.push(OPT_HOSTNAME);
            p.push(hostname.len() as u8);
            p.extend_from_slice(hostname.as_bytes());
        }
        p.push(OPT_END);
        p
    }

    fn make_request(
        mac: [u8; 6],
        xid: [u8; 4],
        ciaddr: Ipv4Addr,
        req_ip: Option<Ipv4Addr>,
        server_id: Option<Ipv4Addr>,
    ) -> Vec<u8> {
        let mut p = vec![0u8; BOOTP_HEADER_LEN];
        p[0] = BOOTREQUEST;
        p[1] = 1;
        p[2] = 6;
        p[4..8].copy_from_slice(&xid);
        p[12..16].copy_from_slice(&ciaddr.octets());
        p[28..34].copy_from_slice(&mac);
        p.extend_from_slice(&DHCP_MAGIC_COOKIE);
        p.extend_from_slice(&[OPT_MSG_TYPE, 1, DHCP_REQUEST]);
        if let Some(ip) = req_ip {
            push_opt_ip(&mut p, OPT_REQUESTED_IP, ip);
        }
        if let Some(sid) = server_id {
            push_opt_ip(&mut p, OPT_SERVER_ID, sid);
        }
        p.push(OPT_END);
        p
    }

    fn make_simple_pkt(mac: [u8; 6], msg_type: u8, ciaddr: Ipv4Addr, req_ip: Option<Ipv4Addr>) -> Vec<u8> {
        let mut p = vec![0u8; BOOTP_HEADER_LEN];
        p[0] = BOOTREQUEST;
        p[1] = 1;
        p[2] = 6;
        p[4..8].copy_from_slice(&[1, 2, 3, 4]);
        p[12..16].copy_from_slice(&ciaddr.octets());
        p[28..34].copy_from_slice(&mac);
        p.extend_from_slice(&DHCP_MAGIC_COOKIE);
        p.extend_from_slice(&[OPT_MSG_TYPE, 1, msg_type]);
        if let Some(ip) = req_ip {
            push_opt_ip(&mut p, OPT_REQUESTED_IP, ip);
        }
        p.push(OPT_END);
        p
    }

    fn reply_msg_type(reply: &[u8]) -> Option<u8> {
        let mut i = BOOTP_HEADER_LEN + 4;
        while i < reply.len() {
            let code = reply[i];
            i += 1;
            if code == 0 {
                continue;
            }
            if code == OPT_END {
                break;
            }
            let len = *reply.get(i)? as usize;
            i += 1;
            let val = reply.get(i..i + len)?;
            i += len;
            if code == OPT_MSG_TYPE && len == 1 {
                return Some(val[0]);
            }
        }
        None
    }

    #[test]
    fn leasetime_parsing() {
        assert_eq!(parse_leasetime("12h"), 43200);
        assert_eq!(parse_leasetime("30m"), 1800);
        assert_eq!(parse_leasetime("1d"), 86400);
        assert_eq!(parse_leasetime("600"), 600);
        assert_eq!(parse_leasetime("10"), 120);
        assert_eq!(parse_leasetime("bad"), 43200);
    }

    #[test]
    fn dora_roundtrip_and_unicast_renew() {
        let cfg = DhcpPoolConfig::default();
        let mut core = DhcpCore::new(cfg, Vec::new());
        let mac = [0xaa, 0xbb, 0xcc, 0x11, 0x22, 0x33];

        let disc = make_discover(mac, [0x11, 0x22, 0x33, 0x44], "laptop");
        let (offer, dest, dirty) = core.handle_packet(&disc, 1000).unwrap();
        assert!(!dirty);
        assert_eq!(reply_msg_type(&offer), Some(DHCP_OFFER));
        assert_eq!(dest, SocketAddrV4::new(Ipv4Addr::BROADCAST, 68));
        let offered_ip = Ipv4Addr::new(offer[16], offer[17], offer[18], offer[19]);
        assert_eq!(offered_ip, Ipv4Addr::new(192, 168, 1, 100));

        let req = make_request(
            mac,
            [0x11, 0x22, 0x33, 0x44],
            Ipv4Addr::UNSPECIFIED,
            Some(offered_ip),
            Some(Ipv4Addr::new(192, 168, 1, 1)),
        );
        let (ack, dest2, dirty2) = core.handle_packet(&req, 1001).unwrap();
        assert!(dirty2);
        assert_eq!(reply_msg_type(&ack), Some(DHCP_ACK));
        assert_eq!(dest2, SocketAddrV4::new(Ipv4Addr::BROADCAST, 68));
        assert_eq!(core.leases.len(), 1);
        assert_eq!(core.leases[0].hostname, "laptop");

        // Renewing with ciaddr set should unicast to ciaddr:68.
        let renew = make_request(mac, [0x55, 0x66, 0x77, 0x88], offered_ip, None, None);
        let (ack2, dest3, dirty3) = core.handle_packet(&renew, 2000).unwrap();
        assert!(dirty3);
        assert_eq!(reply_msg_type(&ack2), Some(DHCP_ACK));
        assert_eq!(dest3, SocketAddrV4::new(offered_ip, 68));
    }

    #[test]
    fn static_lease_nak_release_decline_inform() {
        let mut cfg = DhcpPoolConfig::default();
        let static_mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        cfg.static_hosts.push(StaticHost {
            mac: static_mac,
            ip: Ipv4Addr::new(192, 168, 1, 50),
            name: "nas".into(),
        });
        let mut core = DhcpCore::new(cfg, Vec::new());

        // Static binding wins.
        let (offer, _, _) = core
            .handle_packet(&make_discover(static_mac, [1, 2, 3, 4], ""), 100)
            .unwrap();
        assert_eq!(
            Ipv4Addr::new(offer[16], offer[17], offer[18], offer[19]),
            Ipv4Addr::new(192, 168, 1, 50)
        );

        // Wrong subnet REQUEST -> NAK broadcast.
        let bad_req = make_request(
            [0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb],
            [9, 9, 9, 9],
            Ipv4Addr::UNSPECIFIED,
            Some(Ipv4Addr::new(10, 0, 0, 5)),
            None,
        );
        let (nak, dest, dirty) = core.handle_packet(&bad_req, 100).unwrap();
        assert!(!dirty);
        assert_eq!(reply_msg_type(&nak), Some(DHCP_NAK));
        assert_eq!(dest, SocketAddrV4::new(Ipv4Addr::BROADCAST, 68));

        // Dynamic client gets .100, then DECLINEs it -> next DISCOVER skips .100 to .101.
        let m2 = [0xde, 0xad, 0xbe, 0xef, 0x00, 0x01];
        let req2 = make_request(
            m2,
            [2, 2, 2, 2],
            Ipv4Addr::UNSPECIFIED,
            Some(Ipv4Addr::new(192, 168, 1, 100)),
            None,
        );
        let (_, _, d) = core.handle_packet(&req2, 100).unwrap();
        assert!(d);
        let decline = make_simple_pkt(
            m2,
            DHCP_DECLINE,
            Ipv4Addr::UNSPECIFIED,
            Some(Ipv4Addr::new(192, 168, 1, 100)),
        );
        let (rep, _, d_dec) = core.handle_packet(&decline, 105).unwrap();
        assert!(rep.is_empty());
        assert!(d_dec);
        let (offer_next, _, _) = core
            .handle_packet(&make_discover(m2, [3, 3, 3, 3], ""), 106)
            .unwrap();
        assert_eq!(
            Ipv4Addr::new(offer_next[16], offer_next[17], offer_next[18], offer_next[19]),
            Ipv4Addr::new(192, 168, 1, 101)
        );

        // RELEASE removes active lease.
        let req_101 = make_request(
            m2,
            [3, 3, 3, 3],
            Ipv4Addr::UNSPECIFIED,
            Some(Ipv4Addr::new(192, 168, 1, 101)),
            None,
        );
        core.handle_packet(&req_101, 107).unwrap();
        assert_eq!(core.leases.len(), 1);
        let rel = make_simple_pkt(m2, DHCP_RELEASE, Ipv4Addr::new(192, 168, 1, 101), None);
        let (rel_rep, _, d_rel) = core.handle_packet(&rel, 110).unwrap();
        assert!(rel_rep.is_empty());
        assert!(d_rel);
        assert!(core.leases.is_empty());

        // INFORM returns ACK without writing lease.
        let inf = make_simple_pkt(m2, DHCP_INFORM, Ipv4Addr::new(192, 168, 1, 200), None);
        let (inf_ack, inf_dest, inf_dirty) = core.handle_packet(&inf, 120).unwrap();
        assert!(!inf_dirty);
        assert_eq!(reply_msg_type(&inf_ack), Some(DHCP_ACK));
        assert_eq!(inf_dest, SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 200), 68));
    }

    #[test]
    fn leases_file_roundtrip_and_expiry() {
        let path = format!("/tmp/routerd-test-leases-{}.tmp", std::process::id());
        let entries = vec![
            LeaseEntry {
                expiry: 500,
                mac: [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01],
                ip: Ipv4Addr::new(192, 168, 1, 100),
                hostname: "expired-dev".into(),
                client_id: String::new(),
            },
            LeaseEntry {
                expiry: 2000,
                mac: [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x02],
                ip: Ipv4Addr::new(192, 168, 1, 101),
                hostname: "active-dev".into(),
                client_id: "01:aa:bb".into(),
            },
        ];
        save_leases_file(&path, &entries).unwrap();
        let loaded = load_leases_file(&path, 1000);
        let _ = std::fs::remove_file(&path);
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].ip, Ipv4Addr::new(192, 168, 1, 101));
        assert_eq!(loaded[0].hostname, "active-dev");
        assert_eq!(loaded[0].client_id, "01:aa:bb");
    }

    #[tokio::test]
    async fn udp_loopback_roundtrip() {
        let srv = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let srv_addr = srv.local_addr().unwrap();
        let cli = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let cli_addr = cli.local_addr().unwrap();

        let mac = [0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc];
        let disc = make_discover(mac, [0xde, 0xad, 0x00, 0x01], "looptest");
        cli.send_to(&disc, srv_addr).await.unwrap();

        let mut buf = [0u8; 1500];
        let (n, _) = srv.recv_from(&mut buf).await.unwrap();
        let mut core = DhcpCore::new(DhcpPoolConfig::default(), Vec::new());
        let (reply, _, _) = core.handle_packet(&buf[..n], 1000).unwrap();
        srv.send_to(&reply, cli_addr).await.unwrap();

        let (rn, _) = cli.recv_from(&mut buf).await.unwrap();
        assert_eq!(reply_msg_type(&buf[..rn]), Some(DHCP_OFFER));
    }
}
