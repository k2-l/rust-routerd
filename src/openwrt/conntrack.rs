use std::collections::HashSet;
use std::io;
use std::net::Ipv4Addr;

use anyhow::Result;

use crate::openwrt::netlink::{
    put_attr, NlSocket, NlaIter, NETLINK_NETFILTER, NLA_F_NESTED, NLM_F_ACK, NLM_F_DUMP,
    NLM_F_REQUEST,
};

const NFNL_SUBSYS_CTNETLINK: u16 = 1;
#[allow(dead_code)]
const IPCTNL_MSG_CT_NEW: u16 = 0;
const IPCTNL_MSG_CT_GET: u16 = 1;
const IPCTNL_MSG_CT_DELETE: u16 = 2;

const MSG_CT_GET: u16 = (NFNL_SUBSYS_CTNETLINK << 8) | IPCTNL_MSG_CT_GET;
const MSG_CT_DELETE: u16 = (NFNL_SUBSYS_CTNETLINK << 8) | IPCTNL_MSG_CT_DELETE;

const CTA_TUPLE_ORIG: u16 = 1;
const CTA_TUPLE_REPLY: u16 = 2;
const CTA_ID: u16 = 12;
const CTA_ZONE: u16 = 18;

const CTA_TUPLE_IP: u16 = 1;
const CTA_IP_V4_SRC: u16 = 1;
const CTA_IP_V4_DST: u16 = 2;

fn nfgenmsg_v4() -> [u8; 4] {
    [libc::AF_INET as u8, 0, 0, 0]
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CtEntry {
    pub orig_src: Option<Ipv4Addr>,
    pub orig_dst: Option<Ipv4Addr>,
    pub reply_src: Option<Ipv4Addr>,
    pub reply_dst: Option<Ipv4Addr>,
    pub tuple_orig: Vec<u8>,
    pub id: Option<[u8; 4]>,
    pub zone: Option<[u8; 2]>,
}

impl CtEntry {
    fn matches_any(&self, targets: &HashSet<Ipv4Addr>) -> bool {
        [self.orig_src, self.orig_dst, self.reply_src, self.reply_dst]
            .into_iter()
            .flatten()
            .any(|ip| targets.contains(&ip))
    }
}

fn extract_tuple_v4_ips(tuple_payload: &[u8]) -> (Option<Ipv4Addr>, Option<Ipv4Addr>) {
    let mut src = None;
    let mut dst = None;
    for (attr, val) in NlaIter::new(tuple_payload) {
        if attr == CTA_TUPLE_IP {
            for (ip_attr, ip_val) in NlaIter::new(val) {
                if let Ok(octets) = <[u8; 4]>::try_from(ip_val) {
                    let addr = Ipv4Addr::from(octets);
                    match ip_attr {
                        CTA_IP_V4_SRC => src = Some(addr),
                        CTA_IP_V4_DST => dst = Some(addr),
                        _ => {}
                    }
                }
            }
        }
    }
    (src, dst)
}

pub(crate) fn parse_ct_entry(payload: &[u8]) -> Option<CtEntry> {
    if payload.len() < 4 || payload[0] != libc::AF_INET as u8 {
        return None;
    }

    let mut orig_src = None;
    let mut orig_dst = None;
    let mut reply_src = None;
    let mut reply_dst = None;
    let mut tuple_orig = Vec::new();
    let mut id = None;
    let mut zone = None;

    for (attr, val) in NlaIter::new(&payload[4..]) {
        match attr {
            CTA_TUPLE_ORIG => {
                tuple_orig = val.to_vec();
                (orig_src, orig_dst) = extract_tuple_v4_ips(val);
            }
            CTA_TUPLE_REPLY => {
                (reply_src, reply_dst) = extract_tuple_v4_ips(val);
            }
            CTA_ID => {
                if let Ok(bytes) = <[u8; 4]>::try_from(val) {
                    id = Some(bytes);
                }
            }
            CTA_ZONE => {
                if let Ok(bytes) = <[u8; 2]>::try_from(val) {
                    zone = Some(bytes);
                }
            }
            _ => {}
        }
    }

    if tuple_orig.is_empty() {
        return None;
    }

    Some(CtEntry {
        orig_src,
        orig_dst,
        reply_src,
        reply_dst,
        tuple_orig,
        id,
        zone,
    })
}

pub(crate) fn build_delete_payload(entry: &CtEntry) -> Vec<u8> {
    let mut buf = Vec::with_capacity(16 + entry.tuple_orig.len());
    buf.extend_from_slice(&nfgenmsg_v4());
    put_attr(&mut buf, CTA_TUPLE_ORIG | NLA_F_NESTED, &entry.tuple_orig);
    if let Some(zone) = entry.zone {
        put_attr(&mut buf, CTA_ZONE, &zone);
    }
    if let Some(id) = entry.id {
        put_attr(&mut buf, CTA_ID, &id);
    }
    buf
}

pub fn flush_ips(targets: &HashSet<Ipv4Addr>) -> Result<usize> {
    if targets.is_empty() {
        return Ok(0);
    }

    let mut sock = NlSocket::open(NETLINK_NETFILTER)?;
    let mut matched = Vec::new();
    sock.exchange(
        MSG_CT_GET,
        NLM_F_REQUEST | NLM_F_DUMP,
        &nfgenmsg_v4(),
        |_msg_type, payload| {
            if let Some(entry) = parse_ct_entry(payload) {
                if entry.matches_any(targets) {
                    matched.push(entry);
                }
            }
            Ok(())
        },
    )?;

    let mut deleted = 0usize;
    for entry in matched {
        let del_payload = build_delete_payload(&entry);
        match sock.exchange(
            MSG_CT_DELETE,
            NLM_F_REQUEST | NLM_F_ACK,
            &del_payload,
            |_, _| Ok(()),
        ) {
            Ok(()) => deleted += 1,
            Err(e) => {
                if e.downcast_ref::<io::Error>()
                    .and_then(|ioe| ioe.raw_os_error())
                    == Some(libc::ENOENT)
                {
                    continue;
                }
                tracing::debug!("ctnetlink delete failed: {e:#}");
            }
        }
    }
    Ok(deleted)
}

pub fn flush_ip(ip: Ipv4Addr) -> Result<usize> {
    let mut targets = HashSet::with_capacity(1);
    targets.insert(ip);
    flush_ips(&targets)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::openwrt::netlink::{nest_end, nest_start};

    fn make_tuple(src: Ipv4Addr, dst: Ipv4Addr, proto: u8, sport: u16, dport: u16) -> Vec<u8> {
        let mut tuple = Vec::new();
        let ip = nest_start(&mut tuple, CTA_TUPLE_IP);
        put_attr(&mut tuple, CTA_IP_V4_SRC, &src.octets());
        put_attr(&mut tuple, CTA_IP_V4_DST, &dst.octets());
        nest_end(&mut tuple, ip);

        let l4 = nest_start(&mut tuple, 2 /* CTA_TUPLE_PROTO */);
        put_attr(&mut tuple, 1 /* CTA_PROTO_NUM */, &[proto]);
        put_attr(&mut tuple, 2 /* CTA_PROTO_SRC_PORT */, &sport.to_be_bytes());
        put_attr(&mut tuple, 3 /* CTA_PROTO_DST_PORT */, &dport.to_be_bytes());
        nest_end(&mut tuple, l4);
        tuple
    }

    fn make_ct_dump(
        orig: (Ipv4Addr, Ipv4Addr),
        reply: (Ipv4Addr, Ipv4Addr),
        id: Option<[u8; 4]>,
        zone: Option<[u8; 2]>,
    ) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(&nfgenmsg_v4());
        let orig_bytes = make_tuple(orig.0, orig.1, 6, 51234, 443);
        let reply_bytes = make_tuple(reply.0, reply.1, 6, 443, 51234);
        put_attr(&mut payload, CTA_TUPLE_ORIG | NLA_F_NESTED, &orig_bytes);
        put_attr(&mut payload, CTA_TUPLE_REPLY | NLA_F_NESTED, &reply_bytes);
        if let Some(z) = zone {
            put_attr(&mut payload, CTA_ZONE, &z);
        }
        if let Some(i) = id {
            put_attr(&mut payload, CTA_ID, &i);
        }
        payload
    }

    #[test]
    fn parse_match_and_build_delete_roundtrip() {
        let client = Ipv4Addr::new(10, 2, 2, 50);
        let wan = Ipv4Addr::new(192, 168, 1, 88);
        let remote = Ipv4Addr::new(1, 1, 1, 1);
        let other = Ipv4Addr::new(10, 2, 2, 99);

        // 1. Orig src matches client
        let raw1 = make_ct_dump(
            (client, remote),
            (remote, wan),
            Some([0x12, 0x34, 0x56, 0x78]),
            Some([0x00, 0x01]),
        );
        let e1 = parse_ct_entry(&raw1).expect("entry1 parsed");
        assert_eq!(e1.orig_src, Some(client));
        assert_eq!(e1.orig_dst, Some(remote));
        assert_eq!(e1.reply_src, Some(remote));
        assert_eq!(e1.reply_dst, Some(wan));
        assert_eq!(e1.id, Some([0x12, 0x34, 0x56, 0x78]));
        assert_eq!(e1.zone, Some([0x00, 0x01]));

        let mut targets = HashSet::new();
        targets.insert(client);
        assert!(e1.matches_any(&targets));

        // Verify delete payload preserves CTA_TUPLE_ORIG, CTA_ZONE, CTA_ID verbatim
        let del = build_delete_payload(&e1);
        assert_eq!(&del[..4], &nfgenmsg_v4());
        let attrs: Vec<(u16, &[u8])> = NlaIter::new(&del[4..]).collect();
        assert_eq!(attrs.len(), 3);
        assert_eq!(attrs[0].0, CTA_TUPLE_ORIG);
        assert_eq!(attrs[0].1, e1.tuple_orig.as_slice());
        assert_eq!(attrs[1].0, CTA_ZONE);
        assert_eq!(attrs[1].1, &[0x00, 0x01]);
        assert_eq!(attrs[2].0, CTA_ID);
        assert_eq!(attrs[2].1, &[0x12, 0x34, 0x56, 0x78]);

        // 2. Orig dst matches client (e.g. inbound LAN/DNAT)
        let raw2 = make_ct_dump((remote, client), (client, remote), None, None);
        let e2 = parse_ct_entry(&raw2).expect("entry2 parsed");
        assert!(e2.matches_any(&targets));

        // 3. Reply src matches client (port-forward / NAT reply tuple)
        let raw3 = make_ct_dump((remote, wan), (client, remote), Some([0, 0, 0, 9]), None);
        let e3 = parse_ct_entry(&raw3).expect("entry3 parsed");
        assert!(e3.matches_any(&targets));

        // 4. Non-matching IP
        let raw4 = make_ct_dump((other, remote), (remote, wan), None, None);
        let e4 = parse_ct_entry(&raw4).expect("entry4 parsed");
        assert!(!e4.matches_any(&targets));
    }

    #[test]
    fn container_smoke_flush_ip_does_not_panic() {
        let _ = flush_ip(Ipv4Addr::new(192, 0, 2, 1));
    }
}
