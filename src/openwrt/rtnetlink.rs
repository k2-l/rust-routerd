use std::ffi::{CStr, CString};
use std::io;
use std::net::Ipv4Addr;

use anyhow::{Context, Result};

use crate::openwrt::netlink::{
    nla_u32, put_attr, put_u32, NlSocket, NlaIter, NETLINK_ROUTE, NLM_F_ACK, NLM_F_CREATE,
    NLM_F_DUMP, NLM_F_EXCL, NLM_F_REPLACE, NLM_F_REQUEST,
};

const RTM_NEWROUTE: u16 = 24;
const RTM_DELROUTE: u16 = 25;
const RTM_GETROUTE: u16 = 26;
const RTM_DELNEIGH: u16 = 29;
const RTM_NEWRULE: u16 = 32;
const RTM_DELRULE: u16 = 33;

const RT_TABLE_UNSPEC: u8 = 0;
const RT_TABLE_MAIN: u32 = 254;

const RTN_LOCAL: u8 = 2;
const RTPROT_BOOT: u8 = 3;
const RT_SCOPE_HOST: u8 = 254;
const RTM_F_CLONED: u32 = 0x200;

const RTA_DST: u16 = 1;
const RTA_OIF: u16 = 4;
const RTA_GATEWAY: u16 = 5;
const RTA_PRIORITY: u16 = 6;
const RTA_PREFSRC: u16 = 7;
const RTA_TABLE: u16 = 15;

const NDA_DST: u16 = 1;

const FR_ACT_TO_TBL: u8 = 1;
const FRA_FWMARK: u16 = 10;
const FRA_TABLE: u16 = 15;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv4Route {
    pub target: String,
    pub gateway: String,
    pub device: String,
    pub metric: u32,
    pub proto: String,
    pub source: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RawRouteKey {
    header: [u8; 12],
    dst: Option<[u8; 4]>,
    gateway: Option<[u8; 4]>,
    oif: Option<u32>,
    priority: Option<u32>,
    table: u32,
}

fn is_errno(err: &anyhow::Error, code: libc::c_int) -> bool {
    err.downcast_ref::<io::Error>()
        .and_then(|e| e.raw_os_error())
        == Some(code)
}

pub fn if_nametoindex(name: &str) -> Result<u32> {
    let c = CString::new(name).context("invalid interface name")?;
    let idx = unsafe { libc::if_nametoindex(c.as_ptr()) };
    if idx == 0 {
        return Err(io::Error::last_os_error())
            .with_context(|| format!("interface not found: {name}"));
    }
    Ok(idx)
}

pub fn if_indextoname(idx: u32) -> String {
    if idx == 0 {
        return String::new();
    }
    let mut buf = [0 as libc::c_char; libc::IF_NAMESIZE];
    let ptr = unsafe { libc::if_indextoname(idx, buf.as_mut_ptr()) };
    if ptr.is_null() {
        return String::new();
    }
    unsafe { CStr::from_ptr(buf.as_ptr()) }
        .to_string_lossy()
        .into_owned()
}

pub(crate) fn rtproto_name(proto: u8) -> String {
    match proto {
        0 => String::new(),
        1 => "redirect".into(),
        2 => "kernel".into(),
        3 => "boot".into(),
        4 => "static".into(),
        8 => "gated".into(),
        9 => "ra".into(),
        10 => "mrt".into(),
        11 => "zebra".into(),
        12 => "bird".into(),
        13 => "dnrouted".into(),
        14 => "xorp".into(),
        15 => "ntk".into(),
        16 => "dhcp".into(),
        17 => "mrouted".into(),
        18 => "keepalived".into(),
        42 => "babel".into(),
        186 => "bgp".into(),
        187 => "isis".into(),
        188 => "ospf".into(),
        189 => "rip".into(),
        192 => "eigrp".into(),
        n => n.to_string(),
    }
}

pub(crate) fn parse_ipv4_route(
    payload: &[u8],
    resolve_ifname: impl Fn(u32) -> String,
) -> Option<(u32, Ipv4Route, RawRouteKey)> {
    if payload.len() < 12 {
        return None;
    }
    let family = payload[0];
    let dst_len = payload[1];
    let rtm_table = payload[4];
    let protocol = payload[5];
    let flags = u32::from_ne_bytes(payload[8..12].try_into().ok()?);

    if family != libc::AF_INET as u8 || (flags & RTM_F_CLONED) != 0 {
        return None;
    }

    let mut dst: Option<[u8; 4]> = None;
    let mut gateway: Option<[u8; 4]> = None;
    let mut oif: Option<u32> = None;
    let mut priority: Option<u32> = None;
    let mut prefsrc: Option<[u8; 4]> = None;
    let mut attr_table: Option<u32> = None;

    for (attr, val) in NlaIter::new(&payload[12..]) {
        match attr {
            RTA_DST => {
                if let Ok(octets) = <[u8; 4]>::try_from(val) {
                    dst = Some(octets);
                }
            }
            RTA_GATEWAY => {
                if let Ok(octets) = <[u8; 4]>::try_from(val) {
                    gateway = Some(octets);
                }
            }
            RTA_OIF => oif = nla_u32(val),
            RTA_PRIORITY => priority = nla_u32(val),
            RTA_PREFSRC => {
                if let Ok(octets) = <[u8; 4]>::try_from(val) {
                    prefsrc = Some(octets);
                }
            }
            RTA_TABLE => attr_table = nla_u32(val),
            _ => {}
        }
    }

    let effective_table = attr_table.unwrap_or(u32::from(rtm_table));
    let target = if dst_len == 0 && dst.is_none() {
        "default".to_string()
    } else {
        let ip = Ipv4Addr::from(dst.unwrap_or([0, 0, 0, 0]));
        if dst_len == 32 {
            ip.to_string()
        } else {
            format!("{ip}/{dst_len}")
        }
    };

    let route = Ipv4Route {
        target,
        gateway: gateway
            .map(|o| Ipv4Addr::from(o).to_string())
            .unwrap_or_default(),
        device: oif.map(resolve_ifname).unwrap_or_default(),
        metric: priority.unwrap_or(0),
        proto: rtproto_name(protocol),
        source: prefsrc
            .map(|o| Ipv4Addr::from(o).to_string())
            .unwrap_or_default(),
    };

    let mut header = [0u8; 12];
    header[..8].copy_from_slice(&payload[..8]);
    let key = RawRouteKey {
        header,
        dst,
        gateway,
        oif,
        priority,
        table: effective_table,
    };

    Some((effective_table, route, key))
}

fn build_delete_route_payload(key: &RawRouteKey) -> Vec<u8> {
    let mut buf = Vec::with_capacity(64);
    buf.extend_from_slice(&key.header);
    if let Some(dst) = key.dst {
        put_attr(&mut buf, RTA_DST, &dst);
    }
    if let Some(gw) = key.gateway {
        put_attr(&mut buf, RTA_GATEWAY, &gw);
    }
    if let Some(oif) = key.oif {
        put_u32(&mut buf, RTA_OIF, oif);
    }
    if let Some(prio) = key.priority {
        put_u32(&mut buf, RTA_PRIORITY, prio);
    }
    put_u32(&mut buf, RTA_TABLE, key.table);
    buf
}

fn build_fwmark_rule_payload(fwmark: u32, table: u32) -> Vec<u8> {
    let t8 = if table < 256 {
        table as u8
    } else {
        RT_TABLE_UNSPEC
    };
    let mut buf = vec![
        libc::AF_INET as u8,
        0,
        0,
        0,
        t8,
        0,
        0,
        FR_ACT_TO_TBL,
        0,
        0,
        0,
        0,
    ];
    put_u32(&mut buf, FRA_FWMARK, fwmark);
    put_u32(&mut buf, FRA_TABLE, table);
    buf
}

pub fn list_ipv4_routes() -> Result<Vec<Ipv4Route>> {
    let mut sock = NlSocket::open(NETLINK_ROUTE)?;
    let req = [
        libc::AF_INET as u8,
        0,
        0,
        0,
        RT_TABLE_MAIN as u8,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    ];
    let mut out = Vec::new();
    sock.exchange(
        RTM_GETROUTE,
        NLM_F_REQUEST | NLM_F_DUMP,
        &req,
        |_msg_type, payload| {
            if let Some((table, route, _key)) = parse_ipv4_route(payload, if_indextoname) {
                if table == RT_TABLE_MAIN {
                    out.push(route);
                }
            }
            Ok(())
        },
    )?;
    Ok(out)
}

pub fn delete_ipv4_neigh(ip: Ipv4Addr, dev: &str) -> Result<()> {
    let ifindex = if_nametoindex(dev)?;
    let mut sock = NlSocket::open(NETLINK_ROUTE)?;
    let mut payload = Vec::with_capacity(24);
    payload.extend_from_slice(&[libc::AF_INET as u8, 0, 0, 0]);
    payload.extend_from_slice(&(ifindex as i32).to_ne_bytes());
    payload.extend_from_slice(&[0u8; 4]);
    put_attr(&mut payload, NDA_DST, &ip.octets());

    match sock.exchange(
        RTM_DELNEIGH,
        NLM_F_REQUEST | NLM_F_ACK,
        &payload,
        |_, _| Ok(()),
    ) {
        Ok(()) => Ok(()),
        Err(e) if is_errno(&e, libc::ENOENT) || is_errno(&e, libc::ENXIO) => Ok(()),
        Err(e) => Err(e),
    }
}

pub fn del_fwmark_rule(fwmark: u32, table: u32) -> Result<()> {
    let mut sock = NlSocket::open(NETLINK_ROUTE)?;
    let payload = build_fwmark_rule_payload(fwmark, table);
    for _ in 0..16 {
        match sock.exchange(
            RTM_DELRULE,
            NLM_F_REQUEST | NLM_F_ACK,
            &payload,
            |_, _| Ok(()),
        ) {
            Ok(()) => continue,
            Err(e) if is_errno(&e, libc::ENOENT) => return Ok(()),
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

pub fn add_fwmark_rule(fwmark: u32, table: u32) -> Result<()> {
    let mut sock = NlSocket::open(NETLINK_ROUTE)?;
    let payload = build_fwmark_rule_payload(fwmark, table);
    sock.exchange(
        RTM_NEWRULE,
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
        &payload,
        |_, _| Ok(()),
    )
}

pub fn replace_local_default_route(dev: &str, table: u32) -> Result<()> {
    let ifindex = if_nametoindex(dev)?;
    let mut sock = NlSocket::open(NETLINK_ROUTE)?;
    let t8 = if table < 256 {
        table as u8
    } else {
        RT_TABLE_UNSPEC
    };
    let mut payload = vec![
        libc::AF_INET as u8,
        0,
        0,
        0,
        t8,
        RTPROT_BOOT,
        RT_SCOPE_HOST,
        RTN_LOCAL,
        0,
        0,
        0,
        0,
    ];
    put_u32(&mut payload, RTA_TABLE, table);
    put_u32(&mut payload, RTA_OIF, ifindex);

    sock.exchange(
        RTM_NEWROUTE,
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE,
        &payload,
        |_, _| Ok(()),
    )
}

pub fn flush_ipv4_route_table(table: u32) -> Result<usize> {
    let mut sock = NlSocket::open(NETLINK_ROUTE)?;
    let t8 = if table < 256 {
        table as u8
    } else {
        RT_TABLE_UNSPEC
    };
    let req = [libc::AF_INET as u8, 0, 0, 0, t8, 0, 0, 0, 0, 0, 0, 0];
    let mut keys = Vec::new();
    sock.exchange(
        RTM_GETROUTE,
        NLM_F_REQUEST | NLM_F_DUMP,
        &req,
        |_msg_type, payload| {
            if let Some((entry_table, _route, key)) = parse_ipv4_route(payload, |_| String::new())
            {
                if entry_table == table {
                    keys.push(key);
                }
            }
            Ok(())
        },
    )?;

    let mut deleted = 0usize;
    for key in keys {
        let del_payload = build_delete_route_payload(&key);
        match sock.exchange(
            RTM_DELROUTE,
            NLM_F_REQUEST | NLM_F_ACK,
            &del_payload,
            |_, _| Ok(()),
        ) {
            Ok(()) => deleted += 1,
            Err(e) if is_errno(&e, libc::ESRCH) || is_errno(&e, libc::ENOENT) => {}
            Err(e) => return Err(e),
        }
    }
    Ok(deleted)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_rtmsg(
        dst_len: u8,
        table: u8,
        protocol: u8,
        flags: u32,
        attrs: impl FnOnce(&mut Vec<u8>),
    ) -> Vec<u8> {
        let mut buf = vec![
            libc::AF_INET as u8,
            dst_len,
            0,
            0,
            table,
            protocol,
            0,
            1, // RTN_UNICAST
        ];
        buf.extend_from_slice(&flags.to_ne_bytes());
        attrs(&mut buf);
        buf
    }

    #[test]
    fn parse_ipv4_route_decodes_prefixes_attrs_and_skips_cloned() {
        // Default route via gateway with metric, proto=dhcp, src, RTA_TABLE=254
        let raw_default = make_rtmsg(0, 254, 16, 0, |b| {
            put_attr(b, RTA_GATEWAY, &[192, 168, 1, 1]);
            put_u32(b, RTA_OIF, 2);
            put_u32(b, RTA_PRIORITY, 100);
            put_attr(b, RTA_PREFSRC, &[192, 168, 1, 88]);
            put_u32(b, RTA_TABLE, 254);
        });
        let (tbl, r, _) = parse_ipv4_route(&raw_default, |i| format!("eth{i}")).unwrap();
        assert_eq!(tbl, 254);
        assert_eq!(r.target, "default");
        assert_eq!(r.gateway, "192.168.1.1");
        assert_eq!(r.device, "eth2");
        assert_eq!(r.metric, 100);
        assert_eq!(r.proto, "dhcp");
        assert_eq!(r.source, "192.168.1.88");

        // /24 route with proto=kernel
        let raw_lan = make_rtmsg(24, 254, 2, 0, |b| {
            put_attr(b, RTA_DST, &[10, 2, 2, 0]);
            put_u32(b, RTA_OIF, 5);
            put_attr(b, RTA_PREFSRC, &[10, 2, 2, 1]);
        });
        let (_, r2, _) = parse_ipv4_route(&raw_lan, |_| "br-lan".into()).unwrap();
        assert_eq!(r2.target, "10.2.2.0/24");
        assert_eq!(r2.proto, "kernel");
        assert_eq!(r2.device, "br-lan");

        // /32 host route (omits /32 suffix like ip route show)
        let raw_host = make_rtmsg(32, 0, 3, 0, |b| {
            put_attr(b, RTA_DST, &[8, 8, 8, 8]);
            put_u32(b, RTA_TABLE, 300);
        });
        let (tbl3, r3, _) = parse_ipv4_route(&raw_host, |_| String::new()).unwrap();
        assert_eq!(tbl3, 300);
        assert_eq!(r3.target, "8.8.8.8");
        assert_eq!(r3.proto, "boot");

        // Cloned route must be ignored
        let raw_cloned = make_rtmsg(32, 254, 2, RTM_F_CLONED, |b| {
            put_attr(b, RTA_DST, &[1, 1, 1, 1]);
        });
        assert!(parse_ipv4_route(&raw_cloned, |_| String::new()).is_none());
    }

    #[test]
    fn live_rtnetlink_routes_neigh_and_policy_table_lifecycle() {
        let routes = list_ipv4_routes().expect("list_ipv4_routes");
        assert!(!routes.is_empty(), "container should have at least one IPv4 route");

        const TEST_TABLE: u32 = 199;
        del_fwmark_rule(1, TEST_TABLE).expect("cleanup pre-existing rule");
        let _ = flush_ipv4_route_table(TEST_TABLE);

        add_fwmark_rule(1, TEST_TABLE).expect("add fwmark rule");
        replace_local_default_route("lo", TEST_TABLE).expect("replace local default route");

        let deleted = flush_ipv4_route_table(TEST_TABLE).expect("flush route table");
        assert!(deleted >= 1, "expected >= 1 flushed route, got {deleted}");

        del_fwmark_rule(1, TEST_TABLE).expect("delete fwmark rule");
        delete_ipv4_neigh(Ipv4Addr::new(192, 0, 2, 1), "lo").expect("delete neigh");
    }
}
