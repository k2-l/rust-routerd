use anyhow::{bail, Result};
use base64::Engine;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

use crate::singbox::config::TlsConfig;
use crate::singbox::outbound::tls::OutboundTlsConnector;
use crate::singbox::outbound::{resolve_host_port, BoxStream, DialFuture, Outbound};
use crate::singbox::router::{format_socks_target, RouteContext, TargetAddr};
use crate::singbox::tproxy;

pub struct SocksOutbound {
    tag: String,
    server: String,
    server_port: u16,
    auth: Option<(String, String)>,
    fwmark: u32,
}

impl SocksOutbound {
    pub fn new(
        tag: String,
        server: String,
        server_port: u16,
        username: Option<String>,
        password: Option<String>,
        fwmark: u32,
    ) -> Self {
        let auth = match (username, password) {
            (Some(u), Some(p)) if !u.is_empty() => Some((u, p)),
            _ => None,
        };
        Self {
            tag,
            server,
            server_port,
            auth,
            fwmark,
        }
    }
}

impl Outbound for SocksOutbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn dial_tcp<'a>(&'a self, ctx: &'a RouteContext) -> DialFuture<'a> {
        Box::pin(async move {
            let addr = resolve_host_port(&self.server, self.server_port).await?;
            let mut tcp = tproxy::connect_tcp_marked(addr, self.fwmark).await?;

            if let Some((user, pass)) = &self.auth {
                tcp.write_all(&[0x05, 0x02, 0x00, 0x02]).await?;
                let mut choice = [0u8; 2];
                tcp.read_exact(&mut choice).await?;
                if choice[0] != 0x05 {
                    bail!("socks5 invalid version {}", choice[0]);
                }
                if choice[1] == 0x02 {
                    let ub = user.as_bytes();
                    let pb = pass.as_bytes();
                    let mut auth_pkt = Vec::with_capacity(3 + ub.len() + pb.len());
                    auth_pkt.push(0x01);
                    auth_pkt.push(ub.len().min(255) as u8);
                    auth_pkt.extend_from_slice(&ub[..ub.len().min(255)]);
                    auth_pkt.push(pb.len().min(255) as u8);
                    auth_pkt.extend_from_slice(&pb[..pb.len().min(255)]);
                    tcp.write_all(&auth_pkt).await?;
                    let mut aresp = [0u8; 2];
                    tcp.read_exact(&mut aresp).await?;
                    if aresp[1] != 0x00 {
                        bail!("socks5 upstream auth failed");
                    }
                } else if choice[1] != 0x00 {
                    bail!("socks5 upstream rejected auth methods ({:#x})", choice[1]);
                }
            } else {
                tcp.write_all(&[0x05, 0x01, 0x00]).await?;
                let mut choice = [0u8; 2];
                tcp.read_exact(&mut choice).await?;
                if choice != [0x05, 0x00] {
                    bail!("socks5 upstream auth required or rejected");
                }
            }

            let target = format_socks_target(&ctx.target_addr, ctx.target_port);
            let mut req = Vec::with_capacity(3 + target.len());
            req.extend_from_slice(&[0x05, 0x01, 0x00]);
            req.extend_from_slice(&target);
            tcp.write_all(&req).await?;

            let mut hdr = [0u8; 4];
            tcp.read_exact(&mut hdr).await?;
            if hdr[1] != 0x00 {
                bail!("socks5 upstream connect failed with status {:#x}", hdr[1]);
            }
            match hdr[3] {
                0x01 => {
                    let mut b = [0u8; 6];
                    tcp.read_exact(&mut b).await?;
                }
                0x04 => {
                    let mut b = [0u8; 18];
                    tcp.read_exact(&mut b).await?;
                }
                0x03 => {
                    let mut l = [0u8; 1];
                    tcp.read_exact(&mut l).await?;
                    let mut b = vec![0u8; l[0] as usize + 2];
                    tcp.read_exact(&mut b).await?;
                }
                other => bail!("socks5 invalid reply atyp {other}"),
            }

            Ok(Box::new(tcp) as BoxStream)
        })
    }
}

pub struct HttpOutbound {
    tag: String,
    server: String,
    server_port: u16,
    auth_header: Option<String>,
    tls_connector: OutboundTlsConnector,
    fwmark: u32,
}

impl HttpOutbound {
    pub fn new(
        tag: String,
        server: String,
        server_port: u16,
        username: Option<String>,
        password: Option<String>,
        tls: TlsConfig,
        fwmark: u32,
    ) -> Result<Self> {
        let auth_header = match (username, password) {
            (Some(u), Some(p)) if !u.is_empty() => {
                let raw = format!("{u}:{p}");
                let b64 = base64::engine::general_purpose::STANDARD.encode(raw);
                Some(format!("Proxy-Authorization: Basic {b64}\r\n"))
            }
            _ => None,
        };
        let tls_connector = OutboundTlsConnector::new(&server, &tls)?;
        Ok(Self {
            tag,
            server,
            server_port,
            auth_header,
            tls_connector,
            fwmark,
        })
    }
}

impl Outbound for HttpOutbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn dial_tcp<'a>(&'a self, ctx: &'a RouteContext) -> DialFuture<'a> {
        Box::pin(async move {
            let stream = self
                .tls_connector
                .connect(&self.server, self.server_port, self.fwmark)
                .await?;
            let host = match &ctx.target_addr {
                TargetAddr::Ip(std::net::IpAddr::V6(v6)) => format!("[{v6}]"),
                TargetAddr::Ip(ip) => ip.to_string(),
                TargetAddr::Domain(d) => d.clone(),
            };
            let target = format!("{host}:{}", ctx.target_port);
            let mut req = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n");
            if let Some(auth) = &self.auth_header {
                req.push_str(auth);
            }
            req.push_str("\r\n");

            let mut reader = BufReader::new(stream);
            reader.get_mut().write_all(req.as_bytes()).await?;
            reader.get_mut().flush().await?;

            let mut status = String::new();
            if reader.read_line(&mut status).await? == 0 {
                bail!("http proxy closed before CONNECT response");
            }
            if !status.contains("200") {
                bail!("http proxy CONNECT failed: {}", status.trim());
            }
            loop {
                let mut line = String::new();
                let n = reader.read_line(&mut line).await?;
                if n == 0 || line == "\r\n" || line == "\n" {
                    break;
                }
            }
            Ok(reader.into_inner())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::singbox::inbound::mixed;
    use crate::singbox::router::RouteNetwork;
    use crate::singbox::runtime::RuntimeCore;
    use crate::singbox::config::{OutboundConfig, RouteConfig, SingboxConfig};
    use std::sync::Arc;
    use tokio::net::TcpListener;
    use tokio::sync::watch;

    #[tokio::test]
    async fn socks_and_http_outbounds_chain_through_mixed() {
        let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_port = echo_listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = echo_listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 64];
                    while let Ok(n) = s.read(&mut buf).await {
                        if n == 0 || s.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                });
            }
        });

        let cfg = SingboxConfig {
            enabled: true,
            outbounds: vec![OutboundConfig::Direct { tag: "direct".into() }],
            route: RouteConfig { rules: Vec::new(), final_outbound: "direct".into() },
            ..Default::default()
        };
        let core = Arc::new(RuntimeCore::from_config(&cfg).unwrap());
        let mixed_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mixed_port = mixed_listener.local_addr().unwrap().port();
        let (tx, rx) = watch::channel(false);
        tokio::spawn(async move {
            let _ = mixed::serve_mixed_listener(
                mixed_listener,
                Some(("u".into(), "p".into())),
                core,
                rx,
            )
            .await;
        });

        let ctx = RouteContext {
            network: RouteNetwork::Tcp,
            target_addr: TargetAddr::Ip("127.0.0.1".parse().unwrap()),
            target_port: echo_port,
            src_ip: None,
        };

        // 1. SocksOutbound
        let socks_ob = SocksOutbound::new("s".into(), "127.0.0.1".into(), mixed_port, Some("u".into()), Some("p".into()), 0x100);
        let mut s1 = socks_ob.dial_tcp(&ctx).await.unwrap();
        s1.write_all(b"via-socks").await.unwrap();
        let mut b1 = [0u8; 9];
        s1.read_exact(&mut b1).await.unwrap();
        assert_eq!(&b1, b"via-socks");

        // 2. HttpOutbound
        let http_ob = HttpOutbound::new("h".into(), "127.0.0.1".into(), mixed_port, Some("u".into()), Some("p".into()), TlsConfig::default(), 0x100).unwrap();
        let mut s2 = http_ob.dial_tcp(&ctx).await.unwrap();
        s2.write_all(b"via-http").await.unwrap();
        let mut b2 = [0u8; 8];
        s2.read_exact(&mut b2).await.unwrap();
        assert_eq!(&b2, b"via-http");

        let _ = tx.send(true);
    }
}
