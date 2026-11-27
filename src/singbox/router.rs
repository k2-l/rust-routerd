use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use anyhow::{bail, Result};

use crate::singbox::config::RouteConfig;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteNetwork {
    Tcp,
    Udp,
}

#[derive(Debug, Clone)]
pub enum TargetAddr {
    Ip(IpAddr),
    Domain(String),
}

#[derive(Debug, Clone)]
pub struct RouteContext {
    pub network: RouteNetwork,
    pub target_addr: TargetAddr,
    pub target_port: u16,
    pub src_ip: Option<IpAddr>,
}

#[derive(Debug, Clone)]
enum Cidr {
    V4 { net: u32, mask: u32 },
    V6 { net: u128, mask: u128 },
}

impl Cidr {
    fn parse(s: &str) -> Result<Self> {
        let Some((ip_str, prefix_str)) = s.split_once('/') else {
            let ip: IpAddr = s.parse()?;
            return Ok(match ip {
                IpAddr::V4(v4) => Self::V4 {
                    net: u32::from(v4),
                    mask: u32::MAX,
                },
                IpAddr::V6(v6) => Self::V6 {
                    net: u128::from(v6),
                    mask: u128::MAX,
                },
            });
        };
        let ip: IpAddr = ip_str.parse()?;
        let prefix: u32 = prefix_str.parse()?;
        match ip {
            IpAddr::V4(v4) => {
                if prefix > 32 {
                    bail!("invalid ipv4 prefix: {s}");
                }
                let mask = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
                Ok(Self::V4 {
                    net: u32::from(v4) & mask,
                    mask,
                })
            }
            IpAddr::V6(v6) => {
                if prefix > 128 {
                    bail!("invalid ipv6 prefix: {s}");
                }
                let mask = if prefix == 0 { 0 } else { u128::MAX << (128 - prefix) };
                Ok(Self::V6 {
                    net: u128::from(v6) & mask,
                    mask,
                })
            }
        }
    }

    fn matches(&self, ip: IpAddr) -> bool {
        match (self, ip) {
            (Self::V4 { net, mask }, IpAddr::V4(v4)) => (u32::from(v4) & *mask) == *net,
            (Self::V6 { net, mask }, IpAddr::V6(v6)) => (u128::from(v6) & *mask) == *net,
            _ => false,
        }
    }
}

#[derive(Debug, Clone)]
struct CompiledRule {
    cidrs: Vec<Cidr>,
    src_cidrs: Vec<Cidr>,
    src_macs: HashSet<String>,
    domain_suffix: HashSet<String>,
    domain_exact: HashSet<String>,
    domain_keyword: Vec<String>,
    ports: HashSet<u16>,
    networks: Vec<RouteNetwork>,
    outbound: String,
}

#[derive(Debug, Clone)]
pub struct Router {
    rules: Vec<CompiledRule>,
    final_outbound: String,
    has_src_mac: bool,
}

impl Router {
    pub fn compile(cfg: &RouteConfig) -> Result<Self> {
        let mut rules = Vec::with_capacity(cfg.rules.len());
        for r in &cfg.rules {
            let mut cidrs = Vec::with_capacity(r.ip_cidr.len());
            for c in &r.ip_cidr {
                cidrs.push(Cidr::parse(c)?);
            }
            let mut src_cidrs = Vec::with_capacity(r.src_ip_cidr.len());
            for c in &r.src_ip_cidr {
                src_cidrs.push(Cidr::parse(c)?);
            }
            let mut networks = Vec::with_capacity(r.network.len());
            for n in &r.network {
                match n.to_ascii_lowercase().as_str() {
                    "tcp" => networks.push(RouteNetwork::Tcp),
                    "udp" => networks.push(RouteNetwork::Udp),
                    other => bail!("unsupported route network '{other}'"),
                }
            }
            let mut src_macs = HashSet::with_capacity(r.src_mac.len());
            for m in &r.src_mac {
                let norm = crate::access::devices::normalize_mac(m)
                    .ok_or_else(|| anyhow::anyhow!("invalid route src_mac '{m}'"))?;
                src_macs.insert(norm);
            }
            rules.push(CompiledRule {
                cidrs,
                src_cidrs,
                src_macs,
                domain_suffix: r
                    .domain_suffix
                    .iter()
                    .map(|s| s.trim_start_matches('.').trim_end_matches('.').to_ascii_lowercase())
                    .filter(|s| !s.is_empty())
                    .collect(),
                domain_exact: r
                    .domain_exact
                    .iter()
                    .map(|s| s.trim_end_matches('.').to_ascii_lowercase())
                    .filter(|s| !s.is_empty())
                    .collect(),
                domain_keyword: r
                    .domain_keyword
                    .iter()
                    .map(|s| s.to_ascii_lowercase())
                    .filter(|s| !s.is_empty())
                    .collect(),
                ports: r.port.iter().copied().collect(),
                networks,
                outbound: r.outbound.clone(),
            });
        }
        let has_src_mac = rules.iter().any(|r| !r.src_macs.is_empty());
        Ok(Self {
            rules,
            final_outbound: cfg.final_outbound.clone(),
            has_src_mac,
        })
    }

    pub fn has_src_mac_rules(&self) -> bool {
        self.has_src_mac
    }

    pub fn match_outbound(&self, ctx: &RouteContext) -> &str {
        self.match_outbound_with_mac(ctx, None)
    }

    pub fn match_outbound_with_mac(&self, ctx: &RouteContext, src_mac: Option<&str>) -> &str {
        for rule in &self.rules {
            if rule_matches(rule, ctx, src_mac) {
                return &rule.outbound;
            }
        }
        &self.final_outbound
    }
}

fn rule_matches(rule: &CompiledRule, ctx: &RouteContext, src_mac: Option<&str>) -> bool {
    if !rule.networks.is_empty() && !rule.networks.contains(&ctx.network) {
        return false;
    }
    if !rule.src_macs.is_empty() {
        let Some(mac) = src_mac else {
            return false;
        };
        if !rule.src_macs.contains(mac) {
            return false;
        }
    }
    if !rule.src_cidrs.is_empty() {
        let Some(src) = ctx.src_ip else {
            return false;
        };
        if !rule.src_cidrs.iter().any(|c| c.matches(src)) {
            return false;
        }
    }
    if !rule.ports.is_empty() && !rule.ports.contains(&ctx.target_port) {
        return false;
    }
    let has_ip_cond = !rule.cidrs.is_empty();
    let has_dom_cond = !rule.domain_exact.is_empty()
        || !rule.domain_suffix.is_empty()
        || !rule.domain_keyword.is_empty();

    if !has_ip_cond && !has_dom_cond {
        return !rule.ports.is_empty()
            || !rule.src_cidrs.is_empty()
            || !rule.src_macs.is_empty()
            || !rule.networks.is_empty();
    }

    match &ctx.target_addr {
        TargetAddr::Ip(ip) => has_ip_cond && rule.cidrs.iter().any(|c| c.matches(*ip)),
        TargetAddr::Domain(dom) => {
            if !has_dom_cond {
                return false;
            }
            let d = dom.trim_end_matches('.').to_ascii_lowercase();
            if rule.domain_exact.contains(&d) {
                return true;
            }
            if !rule.domain_suffix.is_empty() {
                if rule.domain_suffix.contains(&d) {
                    return true;
                }
                let mut rest = d.as_str();
                while let Some((_, sub)) = rest.split_once('.') {
                    if rule.domain_suffix.contains(sub) {
                        return true;
                    }
                    rest = sub;
                }
            }
            rule.domain_keyword.iter().any(|k| d.contains(k))
        }
    }
}

pub fn format_socks_target(addr: &TargetAddr, port: u16) -> Vec<u8> {
    let mut buf = Vec::with_capacity(64);
    match addr {
        TargetAddr::Ip(IpAddr::V4(v4)) => {
            buf.push(0x01);
            buf.extend_from_slice(&v4.octets());
        }
        TargetAddr::Ip(IpAddr::V6(v6)) => {
            buf.push(0x04);
            buf.extend_from_slice(&v6.octets());
        }
        TargetAddr::Domain(dom) => {
            let bytes = dom.as_bytes();
            let len = bytes.len().min(255);
            buf.push(0x03);
            buf.push(len as u8);
            buf.extend_from_slice(&bytes[..len]);
        }
    }
    buf.extend_from_slice(&port.to_be_bytes());
    buf
}

#[allow(dead_code)]
pub fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_private() || v4.is_loopback() || v4.is_link_local() || v4 == Ipv4Addr::UNSPECIFIED
        }
        IpAddr::V6(v6) => {
            v6.is_loopback() || v6.is_unspecified() || v6 == Ipv6Addr::LOCALHOST
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::singbox::config::RouteRule;

    #[test]
    fn route_matches_network_src_cidr_and_domain() {
        let cfg = RouteConfig {
            rules: vec![
                RouteRule {
                    network: vec!["udp".into()],
                    port: vec![53],
                    outbound: "dns-direct".into(),
                    ..Default::default()
                },
                RouteRule {
                    src_ip_cidr: vec!["192.168.1.100/32".into()],
                    outbound: "vip-proxy".into(),
                    ..Default::default()
                },
                RouteRule {
                    domain_suffix: vec!["cn".into()],
                    outbound: "direct".into(),
                    ..Default::default()
                },
            ],
            final_outbound: "proxy".into(),
        };
        let router = Router::compile(&cfg).unwrap();

        let udp_dns = RouteContext {
            network: RouteNetwork::Udp,
            target_addr: TargetAddr::Ip(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
            target_port: 53,
            src_ip: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10))),
        };
        assert_eq!(router.match_outbound(&udp_dns), "dns-direct");

        let vip_ctx = RouteContext {
            network: RouteNetwork::Tcp,
            target_addr: TargetAddr::Domain("example.com".into()),
            target_port: 443,
            src_ip: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))),
        };
        assert_eq!(router.match_outbound(&vip_ctx), "vip-proxy");

        let cn_ctx = RouteContext {
            network: RouteNetwork::Tcp,
            target_addr: TargetAddr::Domain("www.baidu.cn".into()),
            target_port: 443,
            src_ip: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50))),
        };
        assert_eq!(router.match_outbound(&cn_ctx), "direct");

        let default_ctx = RouteContext {
            network: RouteNetwork::Tcp,
            target_addr: TargetAddr::Domain("google.com".into()),
            target_port: 443,
            src_ip: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50))),
        };
        assert_eq!(router.match_outbound(&default_ctx), "proxy");
    }

    #[test]
    fn route_matches_cidr_exact_suffix_keyword_and_port() {
        let cfg = RouteConfig {
            rules: vec![
                RouteRule {
                    ip_cidr: vec!["10.0.0.0/8".into(), "fd00::/8".into()],
                    outbound: "direct".into(),
                    ..Default::default()
                },
                RouteRule {
                    domain_exact: vec!["api.internal.test".into()],
                    outbound: "block".into(),
                    ..Default::default()
                },
                RouteRule {
                    domain_suffix: vec!["example.com".into()],
                    outbound: "direct".into(),
                    ..Default::default()
                },
                RouteRule {
                    domain_keyword: vec!["ads".into()],
                    outbound: "block".into(),
                    ..Default::default()
                },
                RouteRule {
                    port: vec![8443],
                    outbound: "alt-proxy".into(),
                    ..Default::default()
                },
            ],
            final_outbound: "proxy".into(),
        };
        let router = Router::compile(&cfg).unwrap();

        let mk_ip = |ip: IpAddr, port: u16| RouteContext {
            network: RouteNetwork::Tcp,
            target_addr: TargetAddr::Ip(ip),
            target_port: port,
            src_ip: None,
        };
        let mk_dom = |dom: &str, port: u16| RouteContext {
            network: RouteNetwork::Tcp,
            target_addr: TargetAddr::Domain(dom.into()),
            target_port: port,
            src_ip: None,
        };

        assert_eq!(router.match_outbound(&mk_ip("10.1.2.3".parse().unwrap(), 443)), "direct");
        assert_eq!(router.match_outbound(&mk_ip("fd12::1".parse().unwrap(), 443)), "direct");
        assert_eq!(router.match_outbound(&mk_dom("API.INTERNAL.TEST.", 443)), "block");
        assert_eq!(router.match_outbound(&mk_dom("sub.example.com", 443)), "direct");
        // Must not match partial label suffix
        assert_eq!(router.match_outbound(&mk_dom("notexample.com", 443)), "proxy");
        assert_eq!(router.match_outbound(&mk_dom("track-ads.net", 443)), "block");
        assert_eq!(router.match_outbound(&mk_dom("unknown.org", 8443)), "alt-proxy");
        assert_eq!(router.match_outbound(&mk_dom("unknown.org", 443)), "proxy");
    }

    #[test]
    fn default_builtin_rules_compile_and_route() {
        let mut cfg = crate::singbox::config::SingboxConfig::default();
        cfg.route.final_outbound = "proxy".into();
        let router = Router::compile(&cfg.route).unwrap();

        let mk_dom = |dom: &str| RouteContext {
            network: RouteNetwork::Tcp,
            target_addr: TargetAddr::Domain(dom.into()),
            target_port: 443,
            src_ip: None,
        };
        let mk_ip = |ip: IpAddr| RouteContext {
            network: RouteNetwork::Tcp,
            target_addr: TargetAddr::Ip(ip),
            target_port: 443,
            src_ip: None,
        };

        assert_eq!(router.match_outbound(&mk_ip("100.64.0.1".parse().unwrap())), "direct");
        assert_eq!(router.match_outbound(&mk_dom("www.baidu.com")), "direct");
        assert_eq!(router.match_outbound(&mk_dom("api.bilibili.com")), "direct");
        assert_eq!(router.match_outbound(&mk_dom("www.tsinghua.edu.cn")), "direct");
        assert_eq!(router.match_outbound(&mk_dom("pagead2.googlesyndication.com")), "block");
        assert_eq!(router.match_outbound(&mk_dom("www.google.com")), "proxy");
    }
}
