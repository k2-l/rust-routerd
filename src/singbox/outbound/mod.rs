pub mod reality;
pub mod shadowsocks;
pub mod tls;
pub mod trojan;
pub mod vless;

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::lookup_host;

use crate::singbox::config::OutboundConfig;
use crate::singbox::router::{RouteContext, TargetAddr};
use crate::singbox::tproxy;

pub trait ProxyStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> ProxyStream for T {}
pub type BoxStream = Box<dyn ProxyStream>;

pub type DialFuture<'a> = Pin<Box<dyn Future<Output = Result<BoxStream>> + Send + 'a>>;

pub trait ProxyUdpSocket: Send + Sync {
    fn send_to<'a>(
        &'a self,
        payload: &'a [u8],
        target: &'a TargetAddr,
        port: u16,
    ) -> Pin<Box<dyn Future<Output = Result<usize>> + Send + 'a>>;
    fn recv_from<'a>(
        &'a self,
        buf: &'a mut [u8],
    ) -> Pin<Box<dyn Future<Output = Result<usize>> + Send + 'a>>;
}

pub type BoxUdpSocket = Box<dyn ProxyUdpSocket>;
pub type UdpDialFuture<'a> = Pin<Box<dyn Future<Output = Result<BoxUdpSocket>> + Send + 'a>>;

pub trait Outbound: Send + Sync {
    fn tag(&self) -> &str;
    fn dial_tcp<'a>(&'a self, ctx: &'a RouteContext) -> DialFuture<'a>;
    fn dial_udp<'a>(&'a self, _ctx: &'a RouteContext) -> UdpDialFuture<'a> {
        let tag = self.tag().to_string();
        Box::pin(async move { bail!("udp relay not supported for outbound '{tag}'") })
    }
}

struct DirectUdpSocket {
    sock: tokio::net::UdpSocket,
}

impl ProxyUdpSocket for DirectUdpSocket {
    fn send_to<'a>(
        &'a self,
        payload: &'a [u8],
        target: &'a TargetAddr,
        port: u16,
    ) -> Pin<Box<dyn Future<Output = Result<usize>> + Send + 'a>> {
        Box::pin(async move {
            let dst = resolve_target(target, port).await?;
            Ok(self.sock.send_to(payload, dst).await?)
        })
    }

    fn recv_from<'a>(
        &'a self,
        buf: &'a mut [u8],
    ) -> Pin<Box<dyn Future<Output = Result<usize>> + Send + 'a>> {
        Box::pin(async move {
            let (n, _) = self.sock.recv_from(buf).await?;
            Ok(n)
        })
    }
}

pub struct DirectOutbound {
    pub tag: String,
    pub fwmark: u32,
}

impl Outbound for DirectOutbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn dial_tcp<'a>(&'a self, ctx: &'a RouteContext) -> DialFuture<'a> {
        Box::pin(async move {
            let addr = resolve_target(&ctx.target_addr, ctx.target_port).await?;
            let stream = tproxy::connect_tcp_marked(addr, self.fwmark).await?;
            Ok(Box::new(stream) as BoxStream)
        })
    }

    fn dial_udp<'a>(&'a self, ctx: &'a RouteContext) -> UdpDialFuture<'a> {
        Box::pin(async move {
            let dst = resolve_target(&ctx.target_addr, ctx.target_port).await?;
            let bind_addr = match dst {
                SocketAddr::V4(_) => SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0),
                SocketAddr::V6(_) => SocketAddr::new(std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED), 0),
            };
            let sock = tproxy::bind_udp_marked(bind_addr, self.fwmark)?;
            Ok(Box::new(DirectUdpSocket { sock }) as BoxUdpSocket)
        })
    }
}

pub struct BlockOutbound {
    pub tag: String,
}

impl Outbound for BlockOutbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn dial_tcp<'a>(&'a self, _ctx: &'a RouteContext) -> DialFuture<'a> {
        Box::pin(async move { bail!("connection blocked by outbound '{}'", self.tag) })
    }
}

pub async fn resolve_target(target: &TargetAddr, port: u16) -> Result<SocketAddr> {
    match target {
        TargetAddr::Ip(ip) => Ok(SocketAddr::new(*ip, port)),
        TargetAddr::Domain(dom) => resolve_host_port(dom, port).await,
    }
}

pub async fn resolve_host_port(host: &str, port: u16) -> Result<SocketAddr> {
    let mut addrs = lookup_host((host, port))
        .await
        .with_context(|| format!("dns lookup {host}:{port}"))?;
    // Prefer IPv4 first on pure-IPv4 ImmortalWrt 25.12 setups.
    let mut fallback = None;
    for addr in &mut addrs {
        if addr.is_ipv4() {
            return Ok(addr);
        }
        if fallback.is_none() {
            fallback = Some(addr);
        }
    }
    fallback.with_context(|| format!("no addresses resolved for {host}:{port}"))
}

pub fn build_outbound(cfg: &OutboundConfig, fwmark: u32) -> Result<Arc<dyn Outbound>> {
    match cfg {
        OutboundConfig::Direct { tag } => Ok(Arc::new(DirectOutbound {
            tag: tag.clone(),
            fwmark,
        })),
        OutboundConfig::Block { tag } => Ok(Arc::new(BlockOutbound { tag: tag.clone() })),
        OutboundConfig::Shadowsocks {
            tag,
            server,
            server_port,
            method,
            password,
        } => Ok(Arc::new(shadowsocks::ShadowsocksOutbound::new(
            tag.clone(),
            server.clone(),
            *server_port,
            method,
            password.clone(),
            fwmark,
        )?)),
        OutboundConfig::Trojan {
            tag,
            server,
            server_port,
            password,
            tls,
        } => Ok(Arc::new(trojan::TrojanOutbound::new(
            tag.clone(),
            server.clone(),
            *server_port,
            password,
            tls.clone(),
            fwmark,
        )?)),
        OutboundConfig::Vless {
            tag,
            server,
            server_port,
            uuid,
            flow,
            tls,
        } => Ok(Arc::new(vless::VlessOutbound::new(
            tag.clone(),
            server.clone(),
            *server_port,
            uuid,
            flow.clone(),
            tls.clone(),
            fwmark,
        )?)),
    }
}
