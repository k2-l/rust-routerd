use std::net::SocketAddr;
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::util;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SingboxConfig {
    pub enabled: bool,
    pub log_level: String,
    /// Socket SO_MARK used by all outbound connections to bypass TProxy nftables rules.
    pub fwmark: u32,
    /// Policy routing table ID for TProxy marked packets.
    pub route_table: u32,
    pub inbounds: Vec<InboundConfig>,
    pub outbounds: Vec<OutboundConfig>,
    pub route: RouteConfig,
    pub dns: DnsConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct FakeIpConfig {
    pub enabled: bool,
    pub inet4_range: String,
    pub ttl: u32,
}

impl Default for FakeIpConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            inet4_range: "198.18.0.0/15".to_string(),
            ttl: 60,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct DnsConfig {
    pub enabled: bool,
    pub listen: String,
    pub direct_upstream: String,
    pub proxy_upstream: String,
    pub proxy_outbound: String,
    pub direct_domains: Vec<String>,
    pub fakeip: FakeIpConfig,
    pub link_dnsmasq: bool,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            listen: "127.0.0.1:7853".to_string(),
            direct_upstream: "223.5.5.5:53".to_string(),
            proxy_upstream: "8.8.8.8:53".to_string(),
            proxy_outbound: "proxy".to_string(),
            direct_domains: vec![
                "cn".into(),
                "local".into(),
                "lan".into(),
                "arpa".into(),
                "baidu.com".into(),
                "qq.com".into(),
                "taobao.com".into(),
                "alicdn.com".into(),
                "aliyun.com".into(),
                "bilibili.com".into(),
                "jd.com".into(),
                "163.com".into(),
                "xiaomi.com".into(),
                "apple.com".into(),
                "icloud.com".into(),
            ],
            fakeip: FakeIpConfig::default(),
            link_dnsmasq: false,
        }
    }
}

impl Default for SingboxConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            log_level: "info".to_string(),
            fwmark: 0x100,
            route_table: 100,
            inbounds: vec![
                InboundConfig::Mixed {
                    tag: "mixed-in".to_string(),
                    listen: "0.0.0.0".to_string(),
                    port: 7890,
                    username: None,
                    password: None,
                },
                InboundConfig::TProxy {
                    tag: "tproxy-in".to_string(),
                    listen: "0.0.0.0".to_string(),
                    port: 7893,
                    network: TProxyNetwork::Both,
                },
            ],
            outbounds: vec![
                OutboundConfig::Direct {
                    tag: "direct".to_string(),
                },
                OutboundConfig::Block {
                    tag: "block".to_string(),
                },
            ],
            route: RouteConfig::default(),
            dns: DnsConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TProxyNetwork {
    Tcp,
    Udp,
    Both,
}

impl Default for TProxyNetwork {
    fn default() -> Self {
        Self::Both
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum InboundConfig {
    Mixed {
        tag: String,
        #[serde(default = "default_listen")]
        listen: String,
        port: u16,
        #[serde(default)]
        username: Option<String>,
        #[serde(default)]
        password: Option<String>,
    },
    #[serde(rename = "tproxy")]
    TProxy {
        tag: String,
        #[serde(default = "default_listen")]
        listen: String,
        port: u16,
        #[serde(default)]
        network: TProxyNetwork,
    },
}

fn default_listen() -> String {
    "0.0.0.0".to_string()
}

impl InboundConfig {
    pub fn tag(&self) -> &str {
        match self {
            Self::Mixed { tag, .. } | Self::TProxy { tag, .. } => tag,
        }
    }

    pub fn bind_addr(&self) -> Result<SocketAddr> {
        let (listen, port) = match self {
            Self::Mixed { listen, port, .. } | Self::TProxy { listen, port, .. } => {
                (listen.as_str(), *port)
            }
        };
        format!("{listen}:{port}")
            .parse()
            .with_context(|| format!("invalid inbound address {listen}:{port}"))
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct TlsConfig {
    pub enabled: bool,
    pub server_name: Option<String>,
    pub insecure: bool,
    pub alpn: Vec<String>,
    pub reality: Option<RealityConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RealityConfig {
    pub enabled: bool,
    pub public_key: String,
    #[serde(default)]
    pub short_id: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct TransportConfig {
    #[serde(rename = "type")]
    pub kind: String,
    pub path: Option<String>,
    pub host: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum OutboundConfig {
    Direct {
        tag: String,
    },
    Block {
        tag: String,
    },
    Shadowsocks {
        tag: String,
        server: String,
        server_port: u16,
        method: String,
        password: String,
    },
    Trojan {
        tag: String,
        server: String,
        server_port: u16,
        password: String,
        #[serde(default)]
        tls: TlsConfig,
        #[serde(default)]
        transport: TransportConfig,
    },
    Vless {
        tag: String,
        server: String,
        server_port: u16,
        uuid: String,
        #[serde(default)]
        flow: Option<String>,
        #[serde(default)]
        tls: TlsConfig,
        #[serde(default)]
        transport: TransportConfig,
    },
    Vmess {
        tag: String,
        server: String,
        server_port: u16,
        uuid: String,
        #[serde(default = "default_vmess_security")]
        security: String,
        #[serde(default)]
        tls: TlsConfig,
        #[serde(default)]
        transport: TransportConfig,
    },
    Socks {
        tag: String,
        server: String,
        server_port: u16,
        #[serde(default)]
        username: Option<String>,
        #[serde(default)]
        password: Option<String>,
    },
    Http {
        tag: String,
        server: String,
        server_port: u16,
        #[serde(default)]
        username: Option<String>,
        #[serde(default)]
        password: Option<String>,
        #[serde(default)]
        tls: TlsConfig,
    },
}

fn default_vmess_security() -> String {
    "auto".to_string()
}

impl OutboundConfig {
    pub fn tag(&self) -> &str {
        match self {
            Self::Direct { tag }
            | Self::Block { tag }
            | Self::Shadowsocks { tag, .. }
            | Self::Trojan { tag, .. }
            | Self::Vless { tag, .. }
            | Self::Vmess { tag, .. }
            | Self::Socks { tag, .. }
            | Self::Http { tag, .. } => tag,
        }
    }

    pub fn kind(&self) -> &'static str {
        match self {
            Self::Direct { .. } => "direct",
            Self::Block { .. } => "block",
            Self::Shadowsocks { .. } => "shadowsocks",
            Self::Trojan { .. } => "trojan",
            Self::Vless { .. } => "vless",
            Self::Vmess { .. } => "vmess",
            Self::Socks { .. } => "socks",
            Self::Http { .. } => "http",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RouteConfig {
    pub rules: Vec<RouteRule>,
    #[serde(rename = "final")]
    pub final_outbound: String,
}

impl Default for RouteConfig {
    fn default() -> Self {
        Self {
            rules: default_route_rules(),
            final_outbound: "direct".into(),
        }
    }
}

pub fn default_route_rules() -> Vec<RouteRule> {
    vec![
        RouteRule {
            name: "私网与保留网段直连".into(),
            ip_cidr: vec![
                "10.0.0.0/8".into(),
                "172.16.0.0/12".into(),
                "192.168.0.0/16".into(),
                "127.0.0.0/8".into(),
                "169.254.0.0/16".into(),
                "100.64.0.0/10".into(),
                "224.0.0.0/4".into(),
                "fe80::/10".into(),
                "fc00::/7".into(),
                "::1/128".into(),
            ],
            outbound: "direct".into(),
            ..Default::default()
        },
        RouteRule {
            name: "本地域名直连".into(),
            domain_suffix: vec![
                "local".into(),
                "lan".into(),
                "arpa".into(),
                "home.arpa".into(),
                "localhost".into(),
            ],
            outbound: "direct".into(),
            ..Default::default()
        },
        RouteRule {
            name: "NTP 校时直连".into(),
            network: vec!["udp".into()],
            port: vec![123],
            outbound: "direct".into(),
            ..Default::default()
        },
        RouteRule {
            name: "国内常用域名直连".into(),
            domain_suffix: vec![
                "cn".into(),
                "baidu.com".into(),
                "bdstatic.com".into(),
                "qq.com".into(),
                "wechat.com".into(),
                "taobao.com".into(),
                "tmall.com".into(),
                "alicdn.com".into(),
                "aliyun.com".into(),
                "alipay.com".into(),
                "jd.com".into(),
                "360buyimg.com".into(),
                "bilibili.com".into(),
                "hdslb.com".into(),
                "163.com".into(),
                "126.com".into(),
                "netease.com".into(),
                "zhihu.com".into(),
                "douyin.com".into(),
                "bytedance.com".into(),
                "toutiao.com".into(),
                "weibo.com".into(),
                "xiaomi.com".into(),
                "mi.com".into(),
                "huawei.com".into(),
                "meituan.com".into(),
                "ctrip.com".into(),
                "apple.com".into(),
                "icloud.com".into(),
                "msn.cn".into(),
                "bing.com".into(),
            ],
            outbound: "direct".into(),
            ..Default::default()
        },
        RouteRule {
            name: "常见广告与遥测拦截".into(),
            domain_suffix: vec![
                "doubleclick.net".into(),
                "googlesyndication.com".into(),
                "googleadservices.com".into(),
                "app-measurement.com".into(),
            ],
            outbound: "block".into(),
            ..Default::default()
        },
    ]
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct RouteRule {
    pub name: String,
    pub ip_cidr: Vec<String>,
    pub src_ip_cidr: Vec<String>,
    pub src_mac: Vec<String>,
    pub domain_suffix: Vec<String>,
    pub domain_exact: Vec<String>,
    pub domain_keyword: Vec<String>,
    pub port: Vec<u16>,
    pub network: Vec<String>,
    pub outbound: String,
}

impl SingboxConfig {
    pub fn load(path: &str) -> Self {
        let Ok(raw) = std::fs::read_to_string(path) else {
            return Self::default();
        };
        serde_json::from_str(&raw).unwrap_or_default()
    }

    pub fn save(&self, path: &str) -> Result<()> {
        let bytes = serde_json::to_vec_pretty(self)?;
        util::write_atomic(path, &bytes, 0o600)
    }

    pub fn validate(&self) -> Result<()> {
        if self.fwmark == 0 || self.fwmark == 1 {
            bail!("fwmark must be non-zero and not 1 (reserved for TProxy delivery) to prevent routing loops");
        }
        if self.inbounds.is_empty() && self.enabled {
            bail!("at least one inbound must be configured when sing-box is enabled");
        }
        for ib in &self.inbounds {
            if ib.tag().trim().is_empty() {
                bail!("inbound tag cannot be empty");
            }
            let addr = ib.bind_addr()?;
            if addr.port() == 0 {
                bail!("inbound {} port cannot be 0", ib.tag());
            }
        }

        let mut tags = std::collections::HashSet::new();
        for ob in &self.outbounds {
            if ob.tag().trim().is_empty() {
                bail!("outbound tag cannot be empty");
            }
            if !tags.insert(ob.tag()) {
                bail!("duplicate outbound tag: {}", ob.tag());
            }
            match ob {
                OutboundConfig::Shadowsocks {
                    server,
                    server_port,
                    method,
                    password,
                    ..
                } => {
                    if server.trim().is_empty() || *server_port == 0 {
                        bail!("shadowsocks outbound {} requires valid server and port", ob.tag());
                    }
                    if password.is_empty() {
                        bail!("shadowsocks outbound {} requires password", ob.tag());
                    }
                    let m = method.to_ascii_lowercase();
                    if !matches!(
                        m.as_str(),
                        "aes-128-gcm"
                            | "aes-256-gcm"
                            | "chacha20-ietf-poly1305"
                            | "2022-blake3-aes-128-gcm"
                            | "2022-blake3-aes-256-gcm"
                            | "2022-blake3-chacha20-poly1305"
                    ) {
                        bail!("unsupported shadowsocks method: {method}");
                    }
                }
                OutboundConfig::Trojan {
                    server,
                    server_port,
                    password,
                    ..
                } => {
                    if server.trim().is_empty() || *server_port == 0 || password.is_empty() {
                        bail!("trojan outbound {} requires server, port, and password", ob.tag());
                    }
                }
                OutboundConfig::Vless {
                    server,
                    server_port,
                    uuid,
                    ..
                } => {
                    if server.trim().is_empty() || *server_port == 0 {
                        bail!("vless outbound {} requires server and port", ob.tag());
                    }
                    parse_uuid(uuid).with_context(|| format!("invalid vless uuid in {}", ob.tag()))?;
                }
                OutboundConfig::Vmess {
                    server,
                    server_port,
                    uuid,
                    ..
                } => {
                    if server.trim().is_empty() || *server_port == 0 {
                        bail!("vmess outbound {} requires server and port", ob.tag());
                    }
                    parse_uuid(uuid).with_context(|| format!("invalid vmess uuid in {}", ob.tag()))?;
                }
                OutboundConfig::Socks {
                    server,
                    server_port,
                    ..
                }
                | OutboundConfig::Http {
                    server,
                    server_port,
                    ..
                } => {
                    if server.trim().is_empty() || *server_port == 0 {
                        bail!("outbound {} requires valid server and port", ob.tag());
                    }
                }
                OutboundConfig::Direct { .. } | OutboundConfig::Block { .. } => {}
            }
        }

        if !tags.contains(self.route.final_outbound.as_str()) {
            bail!(
                "route.final outbound '{}' is not defined",
                self.route.final_outbound
            );
        }
        for rule in &self.route.rules {
            if !tags.contains(rule.outbound.as_str()) {
                bail!("route rule references unknown outbound '{}'", rule.outbound);
            }
        }
        Ok(())
    }
}

pub fn parse_uuid(s: &str) -> Result<[u8; 16]> {
    let clean: String = s.chars().filter(|c| *c != '-').collect();
    if clean.len() != 32 {
        bail!("uuid must have 32 hex chars");
    }
    let bytes = hex::decode(&clean).context("uuid contains non-hex characters")?;
    let mut out = [0u8; 16];
    out.copy_from_slice(&bytes);
    Ok(out)
}
