use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use anyhow::{bail, Result};
use base64::Engine;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;

use crate::singbox::router::{RouteContext, RouteNetwork, TargetAddr};
use crate::singbox::runtime::RuntimeCore;
use crate::util;

pub async fn serve_mixed(
    listen_addr: SocketAddr,
    auth: Option<(String, String)>,
    core: Arc<RuntimeCore>,
    shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let listener = TcpListener::bind(listen_addr).await?;
    tracing::info!("singbox mixed inbound listening on {listen_addr}");
    serve_mixed_listener(listener, auth, core, shutdown).await
}

pub async fn serve_mixed_listener(
    listener: TcpListener,
    auth: Option<(String, String)>,
    core: Arc<RuntimeCore>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    loop {
        tokio::select! {
            _ = shutdown.changed() => break,
            accepted = listener.accept() => {
                let Ok((stream, peer)) = accepted else { continue };
                let _ = stream.set_nodelay(true);
                let core = core.clone();
                let auth = auth.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_mixed_conn(stream, peer, auth, core).await {
                        tracing::debug!("mixed conn {peer} closed: {e:#}");
                    }
                });
            }
        }
    }
    Ok(())
}

async fn handle_mixed_conn(
    stream: TcpStream,
    peer: SocketAddr,
    auth: Option<(String, String)>,
    core: Arc<RuntimeCore>,
) -> Result<()> {
    let mut first = [0u8; 1];
    stream.peek(&mut first).await?;
    if first[0] == 0x05 {
        handle_socks5(stream, peer, auth, core).await
    } else {
        handle_http(stream, peer, auth, core).await
    }
}

async fn handle_socks5(
    mut stream: TcpStream,
    peer: SocketAddr,
    auth: Option<(String, String)>,
    core: Arc<RuntimeCore>,
) -> Result<()> {
    let mut hdr = [0u8; 2];
    stream.read_exact(&mut hdr).await?;
    if hdr[0] != 0x05 {
        bail!("unexpected socks version {}", hdr[0]);
    }
    let mut methods = vec![0u8; hdr[1] as usize];
    stream.read_exact(&mut methods).await?;

    if let Some((expected_user, expected_pass)) = &auth {
        if !methods.contains(&0x02) {
            stream.write_all(&[0x05, 0xFF]).await?;
            bail!("socks5 client does not support username/password auth");
        }
        stream.write_all(&[0x05, 0x02]).await?;
        let mut ver = [0u8; 2];
        stream.read_exact(&mut ver).await?;
        let mut u = vec![0u8; ver[1] as usize];
        stream.read_exact(&mut u).await?;
        let mut plen = [0u8; 1];
        stream.read_exact(&mut plen).await?;
        let mut p = vec![0u8; plen[0] as usize];
        stream.read_exact(&mut p).await?;
        if u != expected_user.as_bytes() || p != expected_pass.as_bytes() {
            stream.write_all(&[0x01, 0x01]).await?;
            bail!("socks5 auth failed");
        }
        stream.write_all(&[0x01, 0x00]).await?;
    } else {
        stream.write_all(&[0x05, 0x00]).await?;
    }

    let mut req = [0u8; 4];
    stream.read_exact(&mut req).await?;
    if req[1] != 0x01 {
        stream
            .write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await?;
        bail!("unsupported socks5 cmd {}", req[1]);
    }

    let target_addr = match req[3] {
        0x01 => {
            let mut b = [0u8; 4];
            stream.read_exact(&mut b).await?;
            TargetAddr::Ip(IpAddr::V4(Ipv4Addr::from(b)))
        }
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut dom = vec![0u8; len[0] as usize];
            stream.read_exact(&mut dom).await?;
            TargetAddr::Domain(String::from_utf8_lossy(&dom).to_string())
        }
        0x04 => {
            let mut b = [0u8; 16];
            stream.read_exact(&mut b).await?;
            TargetAddr::Ip(IpAddr::V6(Ipv6Addr::from(b)))
        }
        atyp => bail!("unsupported socks5 atyp {atyp}"),
    };
    let mut port_be = [0u8; 2];
    stream.read_exact(&mut port_be).await?;
    let target_port = u16::from_be_bytes(port_be);

    let ctx = RouteContext {
        network: RouteNetwork::Tcp,
        target_addr,
        target_port,
        src_ip: Some(peer.ip()),
    };

    let mut remote = match core.dial_tcp(&ctx).await {
        Ok(s) => s,
        Err(e) => {
            let _ = stream
                .write_all(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await;
            return Err(e);
        }
    };

    stream
        .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await?;
    core.relay_tcp(&mut stream, &mut remote).await
}

fn parse_host_port(raw: &str, default_port: u16) -> (TargetAddr, u16) {
    let (host, port) = if let Some(rest) = raw.strip_prefix('[') {
        if let Some((h, after)) = rest.split_once(']') {
            let p = after
                .strip_prefix(':')
                .and_then(|s| s.parse::<u16>().ok())
                .unwrap_or(default_port);
            (h, p)
        } else {
            (raw, default_port)
        }
    } else if let Some((h, p_str)) = raw.rsplit_once(':') {
        if let Ok(p) = p_str.parse::<u16>() {
            (h, p)
        } else {
            (raw, default_port)
        }
    } else {
        (raw, default_port)
    };
    let addr = match host.parse::<IpAddr>() {
        Ok(ip) => TargetAddr::Ip(ip),
        Err(_) => TargetAddr::Domain(host.to_string()),
    };
    (addr, port)
}

fn verify_http_proxy_auth(header_val: Option<&str>, expected: &(String, String)) -> bool {
    let Some(val) = header_val else {
        return false;
    };
    let Some(b64) = val.trim().strip_prefix("Basic ") else {
        return false;
    };
    let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(b64.trim()) else {
        return false;
    };
    let expected_raw = format!("{}:{}", expected.0, expected.1);
    util::ct_eq(&decoded, expected_raw.as_bytes())
}

async fn handle_http(
    stream: TcpStream,
    peer: SocketAddr,
    auth: Option<(String, String)>,
    core: Arc<RuntimeCore>,
) -> Result<()> {
    let mut reader = BufReader::new(stream);
    let mut req_line = String::new();
    if reader.read_line(&mut req_line).await? == 0 {
        return Ok(());
    }
    let parts: Vec<&str> = req_line.split_whitespace().collect();
    if parts.len() < 3 {
        bail!("malformed http proxy request");
    }
    let method = parts[0];
    let target = parts[1];
    let version = parts[2];

    let mut proxy_auth: Option<String> = None;
    let mut headers = Vec::new();
    loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line).await?;
        if n == 0 || line == "\r\n" || line == "\n" {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            let kl = k.trim().to_ascii_lowercase();
            if kl == "proxy-authorization" {
                proxy_auth = Some(v.trim().to_string());
                continue;
            }
            if kl == "proxy-connection" {
                continue;
            }
        }
        headers.push(line);
    }

    if let Some(expected) = &auth {
        if !verify_http_proxy_auth(proxy_auth.as_deref(), expected) {
            let mut client = reader.into_inner();
            let _ = client
                .write_all(
                    b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"routerd\"\r\nContent-Length: 0\r\n\r\n",
                )
                .await;
            bail!("http proxy auth failed");
        }
    }

    if method.eq_ignore_ascii_case("CONNECT") {
        let (addr, port) = parse_host_port(target, 443);
        let ctx = RouteContext {
            network: RouteNetwork::Tcp,
            target_addr: addr,
            target_port: port,
            src_ip: Some(peer.ip()),
        };
        let mut remote = match core.dial_tcp(&ctx).await {
            Ok(s) => s,
            Err(e) => {
                let mut client = reader.into_inner();
                let _ = client
                    .write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
                    .await;
                return Err(e);
            }
        };
        let mut client = reader.into_inner();
        client
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;
        core.relay_tcp(&mut client, &mut remote).await
    } else if let Some(rest) = target.strip_prefix("http://") {
        let (host_port, path) = match rest.find('/') {
            Some(idx) => (&rest[..idx], &rest[idx..]),
            None => (rest, "/"),
        };
        let (addr, port) = parse_host_port(host_port, 80);
        let ctx = RouteContext {
            network: RouteNetwork::Tcp,
            target_addr: addr,
            target_port: port,
            src_ip: Some(peer.ip()),
        };
        let mut remote = match core.dial_tcp(&ctx).await {
            Ok(s) => s,
            Err(e) => {
                let mut client = reader.into_inner();
                let _ = client
                    .write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
                    .await;
                return Err(e);
            }
        };
        remote
            .write_all(format!("{method} {path} {version}\r\n").as_bytes())
            .await?;
        for h in headers {
            remote.write_all(h.as_bytes()).await?;
        }
        remote.write_all(b"\r\n").await?;

        let buf_rem = reader.buffer().to_vec();
        if !buf_rem.is_empty() {
            remote.write_all(&buf_rem).await?;
        }
        let mut client = reader.into_inner();
        core.relay_tcp(&mut client, &mut remote).await
    } else {
        let mut client = reader.into_inner();
        let _ = client
            .write_all(b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n")
            .await;
        bail!("unsupported http proxy request target '{target}'");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::singbox::config::{OutboundConfig, RouteConfig, RouteRule, SingboxConfig};

    async fn spawn_echo_server() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    while let Ok(n) = s.read(&mut buf).await {
                        if n == 0 {
                            break;
                        }
                        if s.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                });
            }
        });
        addr
    }

    async fn spawn_mixed_test(
        auth: Option<(String, String)>,
        block_port: Option<u16>,
    ) -> (SocketAddr, Arc<RuntimeCore>, watch::Sender<bool>) {
        let mut rules = Vec::new();
        if let Some(p) = block_port {
            rules.push(RouteRule {
                port: vec![p],
                outbound: "block".into(),
                ..Default::default()
            });
        }
        let cfg = SingboxConfig {
            enabled: true,
            outbounds: vec![
                OutboundConfig::Direct {
                    tag: "direct".into(),
                },
                OutboundConfig::Block {
                    tag: "block".into(),
                },
            ],
            route: RouteConfig {
                rules,
                final_outbound: "direct".into(),
            },
            ..Default::default()
        };
        let core = Arc::new(RuntimeCore::from_config(&cfg).unwrap());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = watch::channel(false);
        let c = core.clone();
        tokio::spawn(async move {
            let _ = serve_mixed_listener(listener, auth, c, rx).await;
        });
        (addr, core, tx)
    }

    #[tokio::test]
    async fn mixed_socks5_direct_and_block() {
        let echo_addr = spawn_echo_server().await;
        let blocked_port = echo_addr.port().wrapping_add(1).max(1025);
        let (proxy_addr, core, shutdown) = spawn_mixed_test(None, Some(blocked_port)).await;

        // 1. Direct echo via SOCKS5
        let mut s = TcpStream::connect(proxy_addr).await.unwrap();
        s.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut choice = [0u8; 2];
        s.read_exact(&mut choice).await.unwrap();
        assert_eq!(choice, [0x05, 0x00]);

        let ip = match echo_addr.ip() {
            IpAddr::V4(v4) => v4.octets(),
            _ => unreachable!(),
        };
        let port_be = echo_addr.port().to_be_bytes();
        s.write_all(&[0x05, 0x01, 0x00, 0x01, ip[0], ip[1], ip[2], ip[3], port_be[0], port_be[1]])
            .await
            .unwrap();
        let mut reply = [0u8; 10];
        s.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[1], 0x00);

        s.write_all(b"hello-socks5").await.unwrap();
        let mut recv = [0u8; 12];
        s.read_exact(&mut recv).await.unwrap();
        assert_eq!(&recv, b"hello-socks5");
        drop(s);

        // 2. Blocked port via SOCKS5
        let mut sb = TcpStream::connect(proxy_addr).await.unwrap();
        sb.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        sb.read_exact(&mut choice).await.unwrap();
        let bport_be = blocked_port.to_be_bytes();
        sb.write_all(&[0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, bport_be[0], bport_be[1]])
            .await
            .unwrap();
        sb.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[1], 0x05);

        assert!(core.metrics.total_connections.load(std::sync::atomic::Ordering::Relaxed) >= 1);
        let _ = shutdown.send(true);
    }

    #[tokio::test]
    async fn mixed_http_connect_direct_and_block() {
        let echo_addr = spawn_echo_server().await;
        let blocked_port = echo_addr.port().wrapping_add(1).max(1025);
        let (proxy_addr, _core, shutdown) = spawn_mixed_test(None, Some(blocked_port)).await;

        // 1. Direct echo via HTTP CONNECT
        let mut s = TcpStream::connect(proxy_addr).await.unwrap();
        let req = format!("CONNECT 127.0.0.1:{} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n", echo_addr.port(), echo_addr.port());
        s.write_all(req.as_bytes()).await.unwrap();
        let mut reader = BufReader::new(s);
        let mut status = String::new();
        reader.read_line(&mut status).await.unwrap();
        assert!(status.contains("200 Connection Established"), "got: {status}");
        let mut blank = String::new();
        reader.read_line(&mut blank).await.unwrap();

        let mut s = reader.into_inner();
        s.write_all(b"hello-http").await.unwrap();
        let mut recv = [0u8; 10];
        s.read_exact(&mut recv).await.unwrap();
        assert_eq!(&recv, b"hello-http");

        // 2. Blocked port via HTTP CONNECT -> 502 Bad Gateway
        let mut sb = TcpStream::connect(proxy_addr).await.unwrap();
        let breq = format!("CONNECT 127.0.0.1:{blocked_port} HTTP/1.1\r\n\r\n");
        sb.write_all(breq.as_bytes()).await.unwrap();
        let mut breader = BufReader::new(sb);
        let mut bstatus = String::new();
        breader.read_line(&mut bstatus).await.unwrap();
        assert!(bstatus.contains("502"), "got: {bstatus}");

        let _ = shutdown.send(true);
    }

    #[tokio::test]
    async fn mixed_auth_enforced_for_both_protocols() {
        let echo_addr = spawn_echo_server().await;
        let (proxy_addr, _core, shutdown) =
            spawn_mixed_test(Some(("alice".into(), "s3cr3t".into())), None).await;

        // HTTP without auth -> 407
        let mut s = TcpStream::connect(proxy_addr).await.unwrap();
        let req = format!("CONNECT 127.0.0.1:{} HTTP/1.1\r\n\r\n", echo_addr.port());
        s.write_all(req.as_bytes()).await.unwrap();
        let mut line = String::new();
        BufReader::new(s).read_line(&mut line).await.unwrap();
        assert!(line.contains("407"), "expected 407, got: {line}");

        // HTTP with valid Basic auth -> 200
        let mut s2 = TcpStream::connect(proxy_addr).await.unwrap();
        let tok = base64::engine::general_purpose::STANDARD.encode("alice:s3cr3t");
        let req2 = format!(
            "CONNECT 127.0.0.1:{} HTTP/1.1\r\nProxy-Authorization: Basic {tok}\r\n\r\n",
            echo_addr.port()
        );
        s2.write_all(req2.as_bytes()).await.unwrap();
        let mut line2 = String::new();
        BufReader::new(s2).read_line(&mut line2).await.unwrap();
        assert!(line2.contains("200"), "expected 200, got: {line2}");

        let _ = shutdown.send(true);
    }
}
