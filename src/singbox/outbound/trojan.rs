use std::future::Future;
use std::pin::Pin;

use anyhow::{bail, Result};
use tokio::io::{split, AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::sync::Mutex;

use crate::singbox::config::{TlsConfig, TransportConfig};
use crate::singbox::crypto;
use crate::singbox::outbound::tls::OutboundTlsConnector;
use crate::singbox::outbound::{ws, BoxStream, BoxUdpSocket, DialFuture, Outbound, ProxyUdpSocket, UdpDialFuture};
use crate::singbox::router::{format_socks_target, RouteContext, TargetAddr};

pub struct TrojanOutbound {
    tag: String,
    server: String,
    server_port: u16,
    password_hash: String,
    tls_connector: OutboundTlsConnector,
    transport: TransportConfig,
    fwmark: u32,
}

impl TrojanOutbound {
    pub fn new(
        tag: String,
        server: String,
        server_port: u16,
        password: &str,
        mut tls: TlsConfig,
        transport: TransportConfig,
        fwmark: u32,
    ) -> Result<Self> {
        if !tls.enabled {
            tls.enabled = true;
        }
        let password_hash = crypto::trojan_password_hash(password)?;
        let tls_connector = OutboundTlsConnector::new(&server, &tls)?;
        Ok(Self {
            tag,
            server,
            server_port,
            password_hash,
            tls_connector,
            transport,
            fwmark,
        })
    }

    fn build_request(&self, cmd: u8, target: &TargetAddr, port: u16) -> Vec<u8> {
        let target_bytes = format_socks_target(target, port);
        let mut req = Vec::with_capacity(self.password_hash.len() + 5 + target_bytes.len());
        req.extend_from_slice(self.password_hash.as_bytes());
        req.extend_from_slice(b"\r\n");
        req.push(cmd);
        req.extend_from_slice(&target_bytes);
        req.extend_from_slice(b"\r\n");
        req
    }
}

impl Outbound for TrojanOutbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn dial_tcp<'a>(&'a self, ctx: &'a RouteContext) -> DialFuture<'a> {
        Box::pin(async move {
            let base: BoxStream = self
                .tls_connector
                .connect(&self.server, self.server_port, self.fwmark)
                .await?;
            let mut stream = ws::maybe_wrap_ws(base, &self.server, &self.transport).await?;

            // Trojan TCP request: hex(sha224(password)) + CRLF + CMD(0x01) + ATYP + ADDR + PORT + CRLF
            let req = self.build_request(0x01, &ctx.target_addr, ctx.target_port);
            stream.write_all(&req).await?;
            stream.flush().await?;
            Ok(stream)
        })
    }

    fn dial_udp<'a>(&'a self, ctx: &'a RouteContext) -> UdpDialFuture<'a> {
        Box::pin(async move {
            let mut stream: BoxStream = self
                .tls_connector
                .connect(&self.server, self.server_port, self.fwmark)
                .await?;

            // Trojan UDP-over-TCP request: CMD(0x03)
            let req = self.build_request(0x03, &ctx.target_addr, ctx.target_port);
            stream.write_all(&req).await?;
            stream.flush().await?;

            let (rd, wr) = split(stream);
            Ok(Box::new(TrojanUdpSocket {
                reader: Mutex::new(rd),
                writer: Mutex::new(wr),
            }) as BoxUdpSocket)
        })
    }
}

pub struct TrojanUdpSocket {
    reader: Mutex<ReadHalf<BoxStream>>,
    writer: Mutex<WriteHalf<BoxStream>>,
}

impl ProxyUdpSocket for TrojanUdpSocket {
    fn send_to<'a>(
        &'a self,
        payload: &'a [u8],
        target: &'a TargetAddr,
        port: u16,
    ) -> Pin<Box<dyn Future<Output = Result<usize>> + Send + 'a>> {
        Box::pin(async move {
            if payload.len() > u16::MAX as usize {
                bail!("trojan udp payload too large: {}", payload.len());
            }
            let target_bytes = format_socks_target(target, port);
            let mut frame = Vec::with_capacity(target_bytes.len() + 4 + payload.len());
            frame.extend_from_slice(&target_bytes);
            frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
            frame.extend_from_slice(b"\r\n");
            frame.extend_from_slice(payload);

            let mut wr = self.writer.lock().await;
            wr.write_all(&frame).await?;
            wr.flush().await?;
            Ok(payload.len())
        })
    }

    fn recv_from<'a>(
        &'a self,
        buf: &'a mut [u8],
    ) -> Pin<Box<dyn Future<Output = Result<usize>> + Send + 'a>> {
        Box::pin(async move {
            let mut rd = self.reader.lock().await;
            let mut atyp = [0u8; 1];
            rd.read_exact(&mut atyp).await?;
            match atyp[0] {
                0x01 => {
                    let mut b = [0u8; 4];
                    rd.read_exact(&mut b).await?;
                }
                0x04 => {
                    let mut b = [0u8; 16];
                    rd.read_exact(&mut b).await?;
                }
                0x03 => {
                    let mut len = [0u8; 1];
                    rd.read_exact(&mut len).await?;
                    let mut dom = vec![0u8; len[0] as usize];
                    rd.read_exact(&mut dom).await?;
                }
                other => bail!("invalid trojan udp atyp {other}"),
            }
            let mut port_and_len = [0u8; 4];
            rd.read_exact(&mut port_and_len).await?;
            let payload_len = u16::from_be_bytes([port_and_len[2], port_and_len[3]]) as usize;

            let mut crlf = [0u8; 2];
            rd.read_exact(&mut crlf).await?;
            if &crlf != b"\r\n" {
                bail!("invalid trojan udp frame CRLF");
            }

            let mut payload = vec![0u8; payload_len];
            rd.read_exact(&mut payload).await?;
            let copy_len = payload.len().min(buf.len());
            buf[..copy_len].copy_from_slice(&payload[..copy_len]);
            Ok(copy_len)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::singbox::router::RouteNetwork;
    use openssl::asn1::Asn1Time;
    use openssl::hash::MessageDigest;
    use openssl::pkey::PKey;
    use openssl::rsa::Rsa;
    use openssl::ssl::{Ssl, SslAcceptor, SslMethod};
    use openssl::x509::{X509NameBuilder, X509};
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;
    use tokio::net::TcpListener;
    use tokio_openssl::SslStream;

    fn make_test_acceptor() -> Arc<SslAcceptor> {
        let rsa = Rsa::generate(2048).unwrap();
        let pkey = PKey::from_rsa(rsa).unwrap();
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", "trojan.test.local").unwrap();
        let name = name.build();

        let mut x509 = X509::builder().unwrap();
        x509.set_version(2).unwrap();
        x509.set_subject_name(&name).unwrap();
        x509.set_issuer_name(&name).unwrap();
        x509.set_pubkey(&pkey).unwrap();
        x509.set_not_before(&Asn1Time::days_from_now(0).unwrap()).unwrap();
        x509.set_not_after(&Asn1Time::days_from_now(1).unwrap()).unwrap();
        x509.sign(&pkey, MessageDigest::sha256()).unwrap();
        let cert = x509.build();

        let mut acc = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls_server()).unwrap();
        acc.set_private_key(&pkey).unwrap();
        acc.set_certificate(&cert).unwrap();
        Arc::new(acc.build())
    }

    #[tokio::test]
    async fn trojan_tcp_and_udp_over_tcp_roundtrip() {
        let acceptor = make_test_acceptor();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let expected_hash = crypto::trojan_password_hash("trojan-secret").unwrap();
        assert_eq!(expected_hash.len(), 56);

        let eh = expected_hash.clone();
        let srv = tokio::spawn(async move {
            for _ in 0..2 {
                let (tcp, _) = listener.accept().await.unwrap();
                let acc = acceptor.clone();
                let eh = eh.clone();
                tokio::spawn(async move {
                    let ssl = Ssl::new(acc.context()).unwrap();
                    let mut tls = SslStream::new(ssl, tcp).unwrap();
                    Pin::new(&mut tls).accept().await.unwrap();

                    let mut hash_buf = [0u8; 58];
                    tls.read_exact(&mut hash_buf).await.unwrap();
                    assert_eq!(&hash_buf[..56], eh.as_bytes());
                    assert_eq!(&hash_buf[56..58], b"\r\n");

                    let mut cmd = [0u8; 1];
                    tls.read_exact(&mut cmd).await.unwrap();
                    let mut atyp = [0u8; 1];
                    tls.read_exact(&mut atyp).await.unwrap();
                    assert_eq!(atyp[0], 0x01); // IPv4
                    let mut ip_port_crlf = [0u8; 8];
                    tls.read_exact(&mut ip_port_crlf).await.unwrap();
                    assert_eq!(&ip_port_crlf[6..8], b"\r\n");

                    if cmd[0] == 0x01 {
                        let mut data = [0u8; 10];
                        tls.read_exact(&mut data).await.unwrap();
                        tls.write_all(&data).await.unwrap();
                        tls.flush().await.unwrap();
                    } else if cmd[0] == 0x03 {
                        // Read one Trojan UDP frame and echo it back
                        let mut f_atyp = [0u8; 1];
                        tls.read_exact(&mut f_atyp).await.unwrap();
                        let mut f_ip = [0u8; 4];
                        tls.read_exact(&mut f_ip).await.unwrap();
                        let mut f_pl = [0u8; 4];
                        tls.read_exact(&mut f_pl).await.unwrap();
                        let len = u16::from_be_bytes([f_pl[2], f_pl[3]]) as usize;
                        let mut crlf = [0u8; 2];
                        tls.read_exact(&mut crlf).await.unwrap();
                        let mut payload = vec![0u8; len];
                        tls.read_exact(&mut payload).await.unwrap();

                        let mut resp = Vec::new();
                        resp.push(0x01);
                        resp.extend_from_slice(&f_ip);
                        resp.extend_from_slice(&f_pl);
                        resp.extend_from_slice(b"\r\n");
                        resp.extend_from_slice(&payload);
                        tls.write_all(&resp).await.unwrap();
                        tls.flush().await.unwrap();
                    } else {
                        panic!("unexpected trojan cmd {}", cmd[0]);
                    }
                });
            }
        });

        let tls_cfg = TlsConfig {
            enabled: true,
            server_name: Some("trojan.test.local".into()),
            insecure: true,
            alpn: Vec::new(),
            reality: None,
        };
        let ob = TrojanOutbound::new(
            "trojan".into(),
            "127.0.0.1".into(),
            port,
            "trojan-secret",
            tls_cfg,
            TransportConfig::default(),
            0x100,
        )
        .unwrap();

        // 1. TCP
        let tcp_ctx = RouteContext {
            network: RouteNetwork::Tcp,
            target_addr: TargetAddr::Ip(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))),
            target_port: 443,
            src_ip: None,
        };
        let mut s = ob.dial_tcp(&tcp_ctx).await.unwrap();
        s.write_all(b"trojan-tcp").await.unwrap();
        s.flush().await.unwrap();
        let mut got = [0u8; 10];
        s.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"trojan-tcp");

        // 2. UDP-over-TCP
        let udp_ctx = RouteContext {
            network: RouteNetwork::Udp,
            target_addr: TargetAddr::Ip(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
            target_port: 53,
            src_ip: None,
        };
        let udp = ob.dial_udp(&udp_ctx).await.unwrap();
        udp.send_to(b"trojan-udp", &udp_ctx.target_addr, 53).await.unwrap();
        let mut ubuf = [0u8; 64];
        let un = udp.recv_from(&mut ubuf).await.unwrap();
        assert_eq!(&ubuf[..un], b"trojan-udp");

        srv.await.unwrap();
    }
}
