use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context as TaskContext, Poll};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use base64::Engine;
use rand::RngCore;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpStream, UdpSocket};

use crate::singbox::crypto::{self, AeadKind};
use crate::singbox::outbound::{
    resolve_host_port, BoxStream, BoxUdpSocket, DialFuture, Outbound, ProxyUdpSocket,
    UdpDialFuture,
};
use crate::singbox::router::{format_socks_target, RouteContext, TargetAddr};
use crate::singbox::tproxy;

const MAX_CHUNK_LEN: usize = 0x3FFF;

pub struct ShadowsocksOutbound {
    tag: String,
    server: String,
    server_port: u16,
    kind: AeadKind,
    is_2022: bool,
    master_key: Vec<u8>,
    fwmark: u32,
}

impl ShadowsocksOutbound {
    pub fn new(
        tag: String,
        server: String,
        server_port: u16,
        method: &str,
        password: String,
        fwmark: u32,
    ) -> Result<Self> {
        let (kind, is_2022) = AeadKind::from_ss_method(method)?;
        let master_key = if is_2022 {
            let psk_part = password.split(':').last().unwrap_or(&password);
            let raw = base64::engine::general_purpose::STANDARD
                .decode(psk_part.trim())
                .context("ss2022 password must be valid base64 PSK")?;
            if raw.len() != kind.key_len() {
                bail!(
                    "ss2022 PSK length {} != expected {}",
                    raw.len(),
                    kind.key_len()
                );
            }
            raw
        } else {
            crypto::evp_bytes_to_key(password.as_bytes(), kind.key_len())
        };

        Ok(Self {
            tag,
            server,
            server_port,
            kind,
            is_2022,
            master_key,
            fwmark,
        })
    }
}

impl Outbound for ShadowsocksOutbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn dial_tcp<'a>(&'a self, ctx: &'a RouteContext) -> DialFuture<'a> {
        Box::pin(async move {
            let addr = resolve_host_port(&self.server, self.server_port).await?;
            let mut tcp = tproxy::connect_tcp_marked(addr, self.fwmark).await?;

            let mut tx_salt = vec![0u8; self.kind.salt_len()];
            rand::thread_rng().fill_bytes(&mut tx_salt);

            let tx_key = derive_subkey(self.is_2022, &self.master_key, &tx_salt, self.kind.key_len())?;
            tcp.write_all(&tx_salt).await?;

            let target = format_socks_target(&ctx.target_addr, ctx.target_port);
            let mut stream = ShadowsocksStream {
                inner: tcp,
                kind: self.kind,
                is_2022: self.is_2022,
                master_key: self.master_key.clone(),
                tx_key,
                tx_nonce: [0u8; 12],
                rx_key: None,
                rx_nonce: [0u8; 12],
                rx_buf: Vec::new(),
                rx_plain: Vec::new(),
                rx_plain_pos: 0,
                rx_expected_len: None,
            };
            stream.write_all(&target).await?;
            stream.flush().await?;
            Ok(Box::new(stream) as BoxStream)
        })
    }

    fn dial_udp<'a>(&'a self, _ctx: &'a RouteContext) -> UdpDialFuture<'a> {
        Box::pin(async move {
            let server_addr = resolve_host_port(&self.server, self.server_port).await?;
            let bind_addr = match server_addr {
                SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
                SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
            };
            let sock = tproxy::bind_udp_marked(bind_addr, self.fwmark)?;
            sock.connect(server_addr).await?;
            let session_id = rand::random::<u64>();
            Ok(Box::new(ShadowsocksUdpSocket {
                sock,
                kind: self.kind,
                is_2022: self.is_2022,
                master_key: self.master_key.clone(),
                session_id,
                packet_id: AtomicU64::new(0),
            }) as BoxUdpSocket)
        })
    }
}

fn derive_subkey(is_2022: bool, master: &[u8], salt: &[u8], key_len: usize) -> Result<Vec<u8>> {
    if is_2022 {
        // SIP022 session subkey: blake3::derive_key("shadowsocks 2022 session subkey", psk || salt)
        let mut input = Vec::with_capacity(master.len() + salt.len());
        input.extend_from_slice(master);
        input.extend_from_slice(salt);
        let derived = blake3::derive_key("shadowsocks 2022 session subkey", &input);
        Ok(derived[..key_len].to_vec())
    } else {
        crypto::hkdf_sha1(master, salt, b"ss-subkey", key_len)
    }
}

pub struct ShadowsocksStream {
    inner: TcpStream,
    kind: AeadKind,
    is_2022: bool,
    master_key: Vec<u8>,
    tx_key: Vec<u8>,
    tx_nonce: [u8; 12],
    rx_key: Option<Vec<u8>>,
    rx_nonce: [u8; 12],
    rx_buf: Vec<u8>,
    rx_plain: Vec<u8>,
    rx_plain_pos: usize,
    rx_expected_len: Option<usize>,
}

impl ShadowsocksStream {
    fn try_decode(&mut self) -> io::Result<bool> {
        if self.rx_key.is_none() {
            let salt_len = self.kind.salt_len();
            if self.rx_buf.len() < salt_len {
                return Ok(false);
            }
            let salt: Vec<u8> = self.rx_buf.drain(..salt_len).collect();
            let key = derive_subkey(self.is_2022, &self.master_key, &salt, self.kind.key_len())
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            self.rx_key = Some(key);
        }

        let key = self.rx_key.as_ref().unwrap();
        let tag_len = self.kind.tag_len();

        loop {
            if self.rx_expected_len.is_none() {
                if self.rx_buf.len() < 2 + tag_len {
                    break;
                }
                let hdr: Vec<u8> = self.rx_buf.drain(..2 + tag_len).collect();
                let len_bytes = crypto::aead_open(self.kind, key, &self.rx_nonce, &[], &hdr)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                crypto::increment_nonce_le(&mut self.rx_nonce);
                let payload_len = u16::from_be_bytes([len_bytes[0], len_bytes[1]]) as usize & MAX_CHUNK_LEN;
                self.rx_expected_len = Some(payload_len);
            }

            if let Some(payload_len) = self.rx_expected_len {
                if self.rx_buf.len() < payload_len + tag_len {
                    break;
                }
                let ct: Vec<u8> = self.rx_buf.drain(..payload_len + tag_len).collect();
                let pt = crypto::aead_open(self.kind, key, &self.rx_nonce, &[], &ct)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                crypto::increment_nonce_le(&mut self.rx_nonce);
                self.rx_expected_len = None;
                self.rx_plain.extend_from_slice(&pt);
                return Ok(true);
            }
        }
        Ok(false)
    }
}

impl AsyncRead for ShadowsocksStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            if self.rx_plain_pos < self.rx_plain.len() {
                let avail = &self.rx_plain[self.rx_plain_pos..];
                let n = avail.len().min(buf.remaining());
                buf.put_slice(&avail[..n]);
                self.rx_plain_pos += n;
                if self.rx_plain_pos == self.rx_plain.len() {
                    self.rx_plain.clear();
                    self.rx_plain_pos = 0;
                }
                return Poll::Ready(Ok(()));
            }

            if self.try_decode()? {
                continue;
            }

            let mut tmp = [0u8; 8192];
            let mut tmp_buf = ReadBuf::new(&mut tmp);
            match Pin::new(&mut self.inner).poll_read(cx, &mut tmp_buf) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(())) => {
                    let n = tmp_buf.filled().len();
                    if n == 0 {
                        return Poll::Ready(Ok(()));
                    }
                    self.rx_buf.extend_from_slice(tmp_buf.filled());
                }
            }
        }
    }
}

impl AsyncWrite for ShadowsocksStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let chunk = &data[..data.len().min(MAX_CHUNK_LEN)];
        let len_be = (chunk.len() as u16).to_be_bytes();

        let enc_len = crypto::aead_seal(self.kind, &self.tx_key, &self.tx_nonce, &[], &len_be)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        crypto::increment_nonce_le(&mut self.tx_nonce);

        let enc_payload = crypto::aead_seal(self.kind, &self.tx_key, &self.tx_nonce, &[], chunk)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        crypto::increment_nonce_le(&mut self.tx_nonce);

        let mut frame = Vec::with_capacity(enc_len.len() + enc_payload.len());
        frame.extend_from_slice(&enc_len);
        frame.extend_from_slice(&enc_payload);

        match Pin::new(&mut self.inner).poll_write(cx, &frame) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Ready(Ok(_)) => Poll::Ready(Ok(chunk.len())),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

pub struct ShadowsocksUdpSocket {
    sock: UdpSocket,
    kind: AeadKind,
    is_2022: bool,
    master_key: Vec<u8>,
    session_id: u64,
    packet_id: AtomicU64,
}

impl ProxyUdpSocket for ShadowsocksUdpSocket {
    fn send_to<'a>(
        &'a self,
        payload: &'a [u8],
        target: &'a TargetAddr,
        port: u16,
    ) -> Pin<Box<dyn Future<Output = Result<usize>> + Send + 'a>> {
        Box::pin(async move {
            let pid = self.packet_id.fetch_add(1, Ordering::Relaxed);
            let pkt = encode_udp_packet(
                self.kind,
                self.is_2022,
                &self.master_key,
                self.session_id,
                pid,
                target,
                port,
                payload,
            )?;
            self.sock.send(&pkt).await?;
            Ok(payload.len())
        })
    }

    fn recv_from<'a>(
        &'a self,
        buf: &'a mut [u8],
    ) -> Pin<Box<dyn Future<Output = Result<usize>> + Send + 'a>> {
        Box::pin(async move {
            let mut raw = vec![0u8; 65535];
            let n = self.sock.recv(&mut raw).await?;
            let payload = decode_udp_packet(self.kind, self.is_2022, &self.master_key, &raw[..n])?;
            let copy_len = payload.len().min(buf.len());
            buf[..copy_len].copy_from_slice(&payload[..copy_len]);
            Ok(copy_len)
        })
    }
}

fn unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[allow(clippy::too_many_arguments)]
pub fn encode_udp_packet(
    kind: AeadKind,
    is_2022: bool,
    master_key: &[u8],
    session_id: u64,
    packet_id: u64,
    target: &TargetAddr,
    port: u16,
    payload: &[u8],
) -> Result<Vec<u8>> {
    let target_bytes = format_socks_target(target, port);
    if !is_2022 {
        let mut salt = vec![0u8; kind.salt_len()];
        rand::thread_rng().fill_bytes(&mut salt);
        let subkey = derive_subkey(false, master_key, &salt, kind.key_len())?;
        let mut pt = Vec::with_capacity(target_bytes.len() + payload.len());
        pt.extend_from_slice(&target_bytes);
        pt.extend_from_slice(payload);
        let ct = crypto::aead_seal(kind, &subkey, &[0u8; 12], &[], &pt)?;
        let mut out = Vec::with_capacity(salt.len() + ct.len());
        out.extend_from_slice(&salt);
        out.extend_from_slice(&ct);
        return Ok(out);
    }

    // SIP022 Shadowsocks 2022 UDP
    let mut body = Vec::with_capacity(11 + target_bytes.len() + payload.len());
    body.push(0x00); // client type
    body.extend_from_slice(&unix_secs().to_be_bytes());
    body.extend_from_slice(&0u16.to_be_bytes()); // padding_len = 0
    body.extend_from_slice(&target_bytes);
    body.extend_from_slice(payload);

    if kind == AeadKind::ChaCha20Poly1305 {
        // 2022-blake3-chacha20-poly1305: 24-byte nonce || XChaCha20-Poly1305(psk, nonce, body)
        let mut nonce24 = [0u8; 24];
        nonce24[..8].copy_from_slice(&session_id.to_be_bytes());
        nonce24[8..16].copy_from_slice(&packet_id.to_be_bytes());
        rand::thread_rng().fill_bytes(&mut nonce24[16..24]);

        let psk: [u8; 32] = master_key
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid 2022-chacha20 psk length"))?;
        let n16: [u8; 16] = nonce24[..16].try_into().unwrap();
        let subkey = crypto::hchacha20(&psk, &n16);
        let mut n12 = [0u8; 12];
        n12[4..12].copy_from_slice(&nonce24[16..24]);
        let ct = crypto::aead_seal(AeadKind::ChaCha20Poly1305, &subkey, &n12, &[], &body)?;
        let mut out = Vec::with_capacity(24 + ct.len());
        out.extend_from_slice(&nonce24);
        out.extend_from_slice(&ct);
        Ok(out)
    } else {
        // 2022-blake3-aes-128/256-gcm: AES-ECB(psk, session_id||packet_id) || AEAD(subkey, header[4..16], body)
        let mut hdr = [0u8; 16];
        hdr[..8].copy_from_slice(&session_id.to_be_bytes());
        hdr[8..16].copy_from_slice(&packet_id.to_be_bytes());
        let enc_hdr = crypto::aes_ecb_block(master_key, &hdr, true)?;
        let subkey = derive_subkey(true, master_key, &hdr[..8], kind.key_len())?;
        let nonce: [u8; 12] = hdr[4..16].try_into().unwrap();
        let ct = crypto::aead_seal(kind, &subkey, &nonce, &[], &body)?;
        let mut out = Vec::with_capacity(16 + ct.len());
        out.extend_from_slice(&enc_hdr);
        out.extend_from_slice(&ct);
        Ok(out)
    }
}

pub fn decode_udp_packet(
    kind: AeadKind,
    is_2022: bool,
    master_key: &[u8],
    pkt: &[u8],
) -> Result<Vec<u8>> {
    if !is_2022 {
        let salt_len = kind.salt_len();
        if pkt.len() < salt_len + kind.tag_len() {
            bail!("ss udp packet too short");
        }
        let (salt, ct) = pkt.split_at(salt_len);
        let subkey = derive_subkey(false, master_key, salt, kind.key_len())?;
        let pt = crypto::aead_open(kind, &subkey, &[0u8; 12], &[], ct)?;
        return skip_socks_target(&pt).map(|s| s.to_vec());
    }

    let body = if kind == AeadKind::ChaCha20Poly1305 {
        if pkt.len() < 24 + kind.tag_len() {
            bail!("ss2022 chacha20 udp packet too short");
        }
        let (nonce24, ct) = pkt.split_at(24);
        let psk: [u8; 32] = master_key
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid 2022-chacha20 psk length"))?;
        let n16: [u8; 16] = nonce24[..16].try_into().unwrap();
        let subkey = crypto::hchacha20(&psk, &n16);
        let mut n12 = [0u8; 12];
        n12[4..12].copy_from_slice(&nonce24[16..24]);
        crypto::aead_open(AeadKind::ChaCha20Poly1305, &subkey, &n12, &[], ct)?
    } else {
        if pkt.len() < 16 + kind.tag_len() {
            bail!("ss2022 aes udp packet too short");
        }
        let enc_hdr: [u8; 16] = pkt[..16].try_into().unwrap();
        let hdr = crypto::aes_ecb_block(master_key, &enc_hdr, false)?;
        let subkey = derive_subkey(true, master_key, &hdr[..8], kind.key_len())?;
        let nonce: [u8; 12] = hdr[4..16].try_into().unwrap();
        crypto::aead_open(kind, &subkey, &nonce, &[], &pkt[16..])?
    };

    // SIP022 body: type(1) + timestamp(8) + [client_session_id(8) if server->client] + padding_len(2) + padding + target + payload
    if body.len() < 11 {
        bail!("ss2022 udp body too short");
    }
    let header_base = if body[0] == 0x01 {
        if body.len() < 19 {
            bail!("ss2022 server udp body too short");
        }
        17
    } else {
        9
    };
    let pad_len = u16::from_be_bytes([body[header_base], body[header_base + 1]]) as usize;
    let addr_start = header_base + 2 + pad_len;
    if body.len() < addr_start {
        bail!("ss2022 udp padding exceeds body");
    }
    skip_socks_target(&body[addr_start..]).map(|s| s.to_vec())
}

fn skip_socks_target(buf: &[u8]) -> Result<&[u8]> {
    if buf.is_empty() {
        bail!("empty socks target");
    }
    let offset = match buf[0] {
        0x01 => 1 + 4 + 2,
        0x04 => 1 + 16 + 2,
        0x03 => {
            if buf.len() < 2 {
                bail!("truncated domain target");
            }
            1 + 1 + buf[1] as usize + 2
        }
        other => bail!("invalid socks atyp {other}"),
    };
    if buf.len() < offset {
        bail!("truncated socks target");
    }
    Ok(&buf[offset..])
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpListener;

    #[test]
    fn udp_packet_roundtrip_aead_and_2022() {
        let target = TargetAddr::Domain("dns.google".into());
        let cases = [
            ("aes-128-gcm", "secret-pass".to_string()),
            ("aes-256-gcm", "secret-pass".to_string()),
            ("chacha20-ietf-poly1305", "secret-pass".to_string()),
            ("2022-blake3-aes-128-gcm", base64::engine::general_purpose::STANDARD.encode([0x11u8; 16])),
            ("2022-blake3-aes-256-gcm", base64::engine::general_purpose::STANDARD.encode([0x22u8; 32])),
            ("2022-blake3-chacha20-poly1305", base64::engine::general_purpose::STANDARD.encode([0x33u8; 32])),
        ];

        for (method, pass) in cases {
            let ob = ShadowsocksOutbound::new(
                "ss".into(),
                "127.0.0.1".into(),
                8388,
                method,
                pass,
                0x100,
            )
            .unwrap();
            let pkt = encode_udp_packet(
                ob.kind,
                ob.is_2022,
                &ob.master_key,
                0x1234_5678_9abc_def0,
                7,
                &target,
                53,
                b"dns-query-payload",
            )
            .unwrap();
            let decoded = decode_udp_packet(ob.kind, ob.is_2022, &ob.master_key, &pkt).unwrap();
            assert_eq!(decoded, b"dns-query-payload", "failed for {method}");
        }
    }

    #[tokio::test]
    async fn tcp_stream_aead_roundtrip() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let ob = ShadowsocksOutbound::new(
            "ss".into(),
            "127.0.0.1".into(),
            addr.port(),
            "2022-blake3-aes-256-gcm",
            base64::engine::general_purpose::STANDARD.encode([0x44u8; 32]),
            0x100,
        )
        .unwrap();
        let master = ob.master_key.clone();

        let srv = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut ss = ShadowsocksStream {
                inner: tcp,
                kind: AeadKind::Aes256Gcm,
                is_2022: true,
                master_key: master.clone(),
                tx_key: derive_subkey(true, &master, &[0x55u8; 32], 32).unwrap(),
                tx_nonce: [0u8; 12],
                rx_key: None,
                rx_nonce: [0u8; 12],
                rx_buf: Vec::new(),
                rx_plain: Vec::new(),
                rx_plain_pos: 0,
                rx_expected_len: None,
            };
            // Send server salt first
            ss.inner.write_all(&[0x55u8; 32]).await.unwrap();
            let mut acc = Vec::new();
            let mut buf = [0u8; 64];
            loop {
                let n = ss.read(&mut buf).await.unwrap();
                assert!(n > 0);
                acc.extend_from_slice(&buf[..n]);
                if let Ok(rest) = skip_socks_target(&acc) {
                    if rest.len() >= 7 {
                        ss.write_all(rest).await.unwrap();
                        ss.flush().await.unwrap();
                        break;
                    }
                }
            }
        });

        let ctx = RouteContext {
            network: crate::singbox::router::RouteNetwork::Tcp,
            target_addr: TargetAddr::Domain("example.com".into()),
            target_port: 443,
            src_ip: None,
        };
        let mut client = ob.dial_tcp(&ctx).await.unwrap();
        client.write_all(b"ping-ss").await.unwrap();
        client.flush().await.unwrap();
        let mut got = [0u8; 7];
        client.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"ping-ss");
        srv.await.unwrap();
    }
}
