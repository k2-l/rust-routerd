use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use tokio::net::UdpSocket;
use tokio::sync::watch;

use crate::openwrt::uci;
use crate::singbox::config::DnsConfig;
use crate::singbox::router::{RouteContext, RouteNetwork, TargetAddr};
use crate::singbox::runtime::RuntimeCore;
use crate::singbox::tproxy;
use crate::util;

const DNS_TYPE_A: u16 = 1;
const DNS_TYPE_AAAA: u16 = 28;
const DNS_UPSTREAM_TIMEOUT: Duration = Duration::from_secs(4);

/// Bi-directional FakeIP pool (e.g. `198.18.0.0/15`) mapping proxy domains to synthetic IPv4s.
pub struct FakeIpPool {
    net: u32,
    mask: u32,
    size: u32,
    inner: RwLock<FakeIpState>,
}

struct FakeIpState {
    cursor: u32,
    dom_to_ip: HashMap<String, Ipv4Addr>,
    ip_to_dom: HashMap<Ipv4Addr, String>,
}

impl FakeIpPool {
    pub fn new(cidr: &str) -> Result<Self> {
        let (ip_str, prefix_str) = cidr
            .split_once('/')
            .with_context(|| format!("invalid fakeip cidr '{cidr}'"))?;
        let ip: Ipv4Addr = ip_str.parse().context("fakeip cidr must be IPv4")?;
        let prefix: u32 = prefix_str.parse().context("invalid fakeip prefix")?;
        if prefix > 30 {
            bail!("fakeip prefix /{prefix} too small");
        }
        let mask = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
        let net = u32::from(ip) & mask;
        let total = 1u32 << (32 - prefix);
        Ok(Self {
            net,
            mask,
            size: total.saturating_sub(2).max(1),
            inner: RwLock::new(FakeIpState {
                cursor: 1,
                dom_to_ip: HashMap::new(),
                ip_to_dom: HashMap::new(),
            }),
        })
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => (u32::from(v4) & self.mask) == self.net,
            IpAddr::V6(_) => false,
        }
    }

    pub fn allocate(&self, domain: &str) -> Ipv4Addr {
        let key = domain.trim_end_matches('.').to_ascii_lowercase();
        {
            let guard = self.inner.read().unwrap_or_else(|e| e.into_inner());
            if let Some(&ip) = guard.dom_to_ip.get(&key) {
                return ip;
            }
        }
        let mut guard = self.inner.write().unwrap_or_else(|e| e.into_inner());
        if let Some(&ip) = guard.dom_to_ip.get(&key) {
            return ip;
        }
        let offset = guard.cursor;
        guard.cursor = if offset >= self.size { 1 } else { offset + 1 };
        let ip = Ipv4Addr::from(self.net | offset);
        if let Some(old_dom) = guard.ip_to_dom.insert(ip, key.clone()) {
            if old_dom != key {
                guard.dom_to_ip.remove(&old_dom);
            }
        }
        guard.dom_to_ip.insert(key, ip);
        ip
    }

    pub fn lookup_domain(&self, ip: IpAddr) -> Option<String> {
        let IpAddr::V4(v4) = ip else {
            return None;
        };
        if !self.contains(ip) {
            return None;
        }
        self.inner
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .ip_to_dom
            .get(&v4)
            .cloned()
    }
}

#[derive(Debug, Clone)]
pub struct DnsQuery {
    pub txid: [u8; 2],
    pub qname: String,
    pub qtype: u16,
    pub qclass: u16,
    pub q_end: usize,
}

pub fn parse_dns_query(pkt: &[u8]) -> Option<DnsQuery> {
    if pkt.len() < 17 {
        return None;
    }
    let flags = u16::from_be_bytes([pkt[2], pkt[3]]);
    if (flags & 0x8000) != 0 {
        return None; // Not a query
    }
    let qdcount = u16::from_be_bytes([pkt[4], pkt[5]]);
    if qdcount == 0 {
        return None;
    }
    let mut pos = 12usize;
    let mut labels = Vec::new();
    loop {
        let len = *pkt.get(pos)? as usize;
        pos += 1;
        if len == 0 {
            break;
        }
        if len > 63 || pos + len > pkt.len() {
            return None;
        }
        let label = std::str::from_utf8(&pkt[pos..pos + len]).ok()?;
        labels.push(label.to_ascii_lowercase());
        pos += len;
    }
    if pos + 4 > pkt.len() || labels.is_empty() {
        return None;
    }
    let qtype = u16::from_be_bytes([pkt[pos], pkt[pos + 1]]);
    let qclass = u16::from_be_bytes([pkt[pos + 2], pkt[pos + 3]]);
    Some(DnsQuery {
        txid: [pkt[0], pkt[1]],
        qname: labels.join("."),
        qtype,
        qclass,
        q_end: pos + 4,
    })
}

pub fn build_fakeip_response(query_pkt: &[u8], q: &DnsQuery, ip: Ipv4Addr, ttl: u32) -> Vec<u8> {
    let mut resp = Vec::with_capacity(q.q_end + 16);
    resp.extend_from_slice(&q.txid);
    resp.extend_from_slice(&[0x81, 0x80]); // QR=1, RD=1, RA=1, NOERROR
    resp.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT=1
    resp.extend_from_slice(&1u16.to_be_bytes()); // ANCOUNT=1
    resp.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT=0
    resp.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT=0
    resp.extend_from_slice(&query_pkt[12..q.q_end]);
    // Answer RR: pointer to offset 12 (0xC00C), TYPE A, CLASS IN, TTL, RDLENGTH=4, IPv4
    resp.extend_from_slice(&[0xC0, 0x0C]);
    resp.extend_from_slice(&DNS_TYPE_A.to_be_bytes());
    resp.extend_from_slice(&q.qclass.to_be_bytes());
    resp.extend_from_slice(&ttl.to_be_bytes());
    resp.extend_from_slice(&4u16.to_be_bytes());
    resp.extend_from_slice(&ip.octets());
    resp
}

pub fn build_empty_response(query_pkt: &[u8], q: &DnsQuery, rcode: u8) -> Vec<u8> {
    let mut resp = Vec::with_capacity(q.q_end);
    resp.extend_from_slice(&q.txid);
    resp.extend_from_slice(&[0x81, 0x80 | (rcode & 0x0F)]);
    resp.extend_from_slice(&1u16.to_be_bytes());
    resp.extend_from_slice(&0u16.to_be_bytes());
    resp.extend_from_slice(&0u16.to_be_bytes());
    resp.extend_from_slice(&0u16.to_be_bytes());
    resp.extend_from_slice(&query_pkt[12..q.q_end]);
    resp
}

pub struct DnsContext {
    direct_domains: HashSet<String>,
    direct_upstream: SocketAddr,
    proxy_upstream: SocketAddr,
    proxy_outbound: String,
    fakeip_enabled: bool,
    fakeip_ttl: u32,
}

impl DnsContext {
    pub fn from_config(cfg: &DnsConfig) -> Result<Self> {
        let direct_upstream: SocketAddr = cfg
            .direct_upstream
            .parse()
            .with_context(|| format!("invalid dns direct_upstream '{}'", cfg.direct_upstream))?;
        let proxy_upstream: SocketAddr = cfg
            .proxy_upstream
            .parse()
            .with_context(|| format!("invalid dns proxy_upstream '{}'", cfg.proxy_upstream))?;
        let direct_domains = cfg
            .direct_domains
            .iter()
            .map(|s| s.trim_start_matches('.').trim_end_matches('.').to_ascii_lowercase())
            .filter(|s| !s.is_empty())
            .collect();
        Ok(Self {
            direct_domains,
            direct_upstream,
            proxy_upstream,
            proxy_outbound: cfg.proxy_outbound.clone(),
            fakeip_enabled: cfg.fakeip.enabled,
            fakeip_ttl: cfg.fakeip.ttl,
        })
    }

    fn is_direct_domain(&self, dom: &str) -> bool {
        if self.direct_domains.contains(dom) {
            return true;
        }
        let mut rest = dom;
        while let Some((_, sub)) = rest.split_once('.') {
            if self.direct_domains.contains(sub) {
                return true;
            }
            rest = sub;
        }
        false
    }
}

pub async fn serve_dns(
    listen_addr: SocketAddr,
    dns_ctx: Arc<DnsContext>,
    core: Arc<RuntimeCore>,
    shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let sock = UdpSocket::bind(listen_addr)
        .await
        .with_context(|| format!("bind dns server on {listen_addr}"))?;
    tracing::info!("singbox dns server listening on {listen_addr}");
    serve_dns_socket(Arc::new(sock), dns_ctx, core, shutdown).await
}

pub async fn serve_dns_socket(
    sock: Arc<UdpSocket>,
    dns_ctx: Arc<DnsContext>,
    core: Arc<RuntimeCore>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let mut buf = vec![0u8; 4096];
    loop {
        tokio::select! {
            _ = shutdown.changed() => break,
            res = sock.recv_from(&mut buf) => {
                let Ok((n, peer)) = res else { continue };
                let pkt = buf[..n].to_vec();
                let s = sock.clone();
                let dc = dns_ctx.clone();
                let c = core.clone();
                tokio::spawn(async move {
                    if let Ok(resp) = handle_dns_packet(&pkt, peer, &dc, &c).await {
                        let _ = s.send_to(&resp, peer).await;
                    }
                });
            }
        }
    }
    Ok(())
}

pub async fn handle_dns_packet(
    pkt: &[u8],
    peer: SocketAddr,
    dns_ctx: &DnsContext,
    core: &RuntimeCore,
) -> Result<Vec<u8>> {
    let q = parse_dns_query(pkt).context("invalid DNS query")?;

    let route_ctx = RouteContext {
        network: RouteNetwork::Udp,
        target_addr: TargetAddr::Domain(q.qname.clone()),
        target_port: 53,
        src_ip: Some(peer.ip()),
    };
    let matched_ob = core.match_outbound(&route_ctx);
    let matched_kind = core
        .outbound_kind(matched_ob)
        .unwrap_or_else(|| if matched_ob == "direct" { "direct" } else { "proxy" });

    if matched_kind == "block" {
        return Ok(build_empty_response(pkt, &q, 3)); // NXDOMAIN
    }

    let use_direct = dns_ctx.is_direct_domain(&q.qname) || matched_kind == "direct";
    if use_direct {
        return forward_direct_dns(pkt, dns_ctx.direct_upstream, core.fwmark()).await;
    }

    // Proxy domain: FakeIP if enabled, otherwise forward DNS over proxy outbound to prevent ISP leak.
    if dns_ctx.fakeip_enabled {
        if let Some(pool) = core.fakeip_pool() {
            if q.qtype == DNS_TYPE_A {
                let ip = pool.allocate(&q.qname);
                return Ok(build_fakeip_response(pkt, &q, ip, dns_ctx.fakeip_ttl));
            }
            if q.qtype == DNS_TYPE_AAAA {
                return Ok(build_empty_response(pkt, &q, 0));
            }
        }
    }

    let dns_outbound = if matched_kind != "direct" && matched_kind != "block" && core.outbound_kind(matched_ob).is_some() {
        matched_ob
    } else {
        &dns_ctx.proxy_outbound
    };
    forward_proxy_dns(pkt, dns_outbound, dns_ctx.proxy_upstream, core).await
}

async fn forward_direct_dns(pkt: &[u8], upstream: SocketAddr, fwmark: u32) -> Result<Vec<u8>> {
    let bind_addr: SocketAddr = match upstream {
        SocketAddr::V4(_) => "0.0.0.0:0".parse().unwrap(),
        SocketAddr::V6(_) => "[::]:0".parse().unwrap(),
    };
    let sock = tproxy::bind_udp_marked(bind_addr, fwmark)?;
    sock.send_to(pkt, upstream).await?;
    let mut rbuf = vec![0u8; 4096];
    let (n, _) = tokio::time::timeout(DNS_UPSTREAM_TIMEOUT, sock.recv_from(&mut rbuf))
        .await
        .context("direct dns upstream timeout")??;
    rbuf.truncate(n);
    Ok(rbuf)
}

async fn forward_proxy_dns(
    pkt: &[u8],
    outbound_tag: &str,
    upstream: SocketAddr,
    core: &RuntimeCore,
) -> Result<Vec<u8>> {
    let target = TargetAddr::Ip(upstream.ip());
    let port = upstream.port();
    let ctx = RouteContext {
        network: RouteNetwork::Udp,
        target_addr: target.clone(),
        target_port: port,
        src_ip: None,
    };
    let udp = match core.dial_outbound_udp_tag(outbound_tag, &ctx).await {
        Ok(u) => u,
        Err(_) => return forward_direct_dns(pkt, upstream, core.fwmark()).await,
    };
    udp.send_to(pkt, &target, port).await?;
    let mut rbuf = vec![0u8; 4096];
    let n = tokio::time::timeout(DNS_UPSTREAM_TIMEOUT, udp.recv_from(&mut rbuf))
        .await
        .context("proxy dns upstream timeout")??;
    rbuf.truncate(n);
    Ok(rbuf)
}

/// Link or unlink ImmortalWrt `dnsmasq-full` upstream to our local DNS server (`127.0.0.1#<port>`).
pub fn sync_dnsmasq(cfg: &DnsConfig, singbox_enabled: bool, sim: bool) -> Result<()> {
    if sim {
        return Ok(());
    }
    let bin = uci::bin();
    if singbox_enabled && cfg.enabled && cfg.link_dnsmasq {
        let listen: SocketAddr = cfg.listen.parse().context("invalid dns listen addr")?;
        let upstream = format!("127.0.0.1#{}", listen.port());
        util::run(bin, &["set", "dhcp.@dnsmasq[0].noresolv=1"])?;
        let _ = util::run_ok(bin, &["-q", "delete", "dhcp.@dnsmasq[0].server"]);
        util::run(bin, &["add_list", &format!("dhcp.@dnsmasq[0].server={upstream}")])?;
        util::run(bin, &["commit", "dhcp"])?;
        let _ = util::run_ok("/etc/init.d/dnsmasq", &["reload"]);
    } else {
        let uci_cfg = uci::load("dhcp").unwrap_or_default();
        if let Some(sec) = uci_cfg.sections.iter().find(|s| s.kind == "dnsmasq") {
            if sec.get("noresolv") == Some("1") {
                let _ = util::run_ok(bin, &["set", "dhcp.@dnsmasq[0].noresolv=0"]);
                let _ = util::run_ok(bin, &["-q", "delete", "dhcp.@dnsmasq[0].server"]);
                let _ = util::run_ok(bin, &["commit", "dhcp"]);
                let _ = util::run_ok("/etc/init.d/dnsmasq", &["reload"]);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::singbox::config::{OutboundConfig, RouteConfig, RouteRule, SingboxConfig};

    fn make_query(domain: &str, qtype: u16) -> Vec<u8> {
        let mut pkt = vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        for label in domain.split('.') {
            pkt.push(label.len() as u8);
            pkt.extend_from_slice(label.as_bytes());
        }
        pkt.push(0x00);
        pkt.extend_from_slice(&qtype.to_be_bytes());
        pkt.extend_from_slice(&1u16.to_be_bytes());
        pkt
    }

    #[test]
    fn fakeip_pool_allocates_and_reverse_resolves() {
        let pool = FakeIpPool::new("198.18.0.0/15").unwrap();
        let ip1 = pool.allocate("www.google.com");
        let ip2 = pool.allocate("WWW.GOOGLE.COM.");
        let ip3 = pool.allocate("github.com");
        assert_eq!(ip1, ip2);
        assert_ne!(ip1, ip3);
        assert!(pool.contains(IpAddr::V4(ip1)));
        assert_eq!(pool.lookup_domain(IpAddr::V4(ip1)).as_deref(), Some("www.google.com"));
        assert_eq!(pool.lookup_domain(IpAddr::V4(ip3)).as_deref(), Some("github.com"));
        assert_eq!(pool.lookup_domain("8.8.8.8".parse().unwrap()), None);
    }

    #[tokio::test]
    async fn dns_split_routing_fakeip_and_block() {
        // Local mock direct DNS server
        let direct_srv = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let direct_addr = direct_srv.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            while let Ok((n, peer)) = direct_srv.recv_from(&mut buf).await {
                if let Some(q) = parse_dns_query(&buf[..n]) {
                    let resp = build_fakeip_response(&buf[..n], &q, Ipv4Addr::new(220, 181, 38, 148), 120);
                    let _ = direct_srv.send_to(&resp, peer).await;
                }
            }
        });

        let mut cfg = SingboxConfig {
            enabled: true,
            outbounds: vec![
                OutboundConfig::Direct { tag: "direct".into() },
                OutboundConfig::Block { tag: "block".into() },
            ],
            route: RouteConfig {
                rules: vec![RouteRule {
                    domain_suffix: vec!["ads.test".into()],
                    outbound: "block".into(),
                    ..Default::default()
                }],
                final_outbound: "proxy".into(),
            },
            ..Default::default()
        };
        cfg.dns.enabled = true;
        cfg.dns.direct_upstream = direct_addr.to_string();
        cfg.dns.proxy_upstream = direct_addr.to_string();
        cfg.dns.fakeip.enabled = true;

        let core = RuntimeCore::from_config(&cfg).unwrap();
        let dns_ctx = DnsContext::from_config(&cfg.dns).unwrap();
        let peer: SocketAddr = "192.168.1.10:55555".parse().unwrap();

        // 1. Blocked domain -> NXDOMAIN (RCODE=3)
        let q_blk = make_query("tracker.ads.test", DNS_TYPE_A);
        let r_blk = handle_dns_packet(&q_blk, peer, &dns_ctx, &core).await.unwrap();
        assert_eq!(r_blk[3] & 0x0F, 3);

        // 2. Direct domain (.cn) -> forwarded to mock direct DNS (220.181.38.148)
        let q_cn = make_query("www.baidu.cn", DNS_TYPE_A);
        let r_cn = handle_dns_packet(&q_cn, peer, &dns_ctx, &core).await.unwrap();
        assert_eq!(&r_cn[r_cn.len() - 4..], &[220, 181, 38, 148]);

        // 3. Proxy domain -> FakeIP allocated in 198.18.0.0/15, zero leak!
        let q_px = make_query("www.google.com", DNS_TYPE_A);
        let r_px = handle_dns_packet(&q_px, peer, &dns_ctx, &core).await.unwrap();
        let fake_ip = Ipv4Addr::new(r_px[r_px.len() - 4], r_px[r_px.len() - 3], r_px[r_px.len() - 2], r_px[r_px.len() - 1]);
        assert!(core.fakeip_pool().unwrap().contains(IpAddr::V4(fake_ip)));
        assert_eq!(
            core.lookup_fakeip(IpAddr::V4(fake_ip)).as_deref(),
            Some("www.google.com")
        );

        // 4. Proxy domain AAAA -> empty NOERROR (prevents IPv6 DNS leak)
        let q_aaaa = make_query("www.google.com", DNS_TYPE_AAAA);
        let r_aaaa = handle_dns_packet(&q_aaaa, peer, &dns_ctx, &core).await.unwrap();
        assert_eq!(r_aaaa[3] & 0x0F, 0);
        assert_eq!(u16::from_be_bytes([r_aaaa[6], r_aaaa[7]]), 0);
    }
}
