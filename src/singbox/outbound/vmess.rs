use std::io;
use std::net::IpAddr;
use std::pin::Pin;
use std::task::{Context as TaskContext, Poll};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Result};
use openssl::hash::{Hasher, MessageDigest};
use openssl::pkey::PKey;
use openssl::sign::Signer;
use rand::RngCore;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::singbox::config::{parse_uuid, TlsConfig, TransportConfig};
use crate::singbox::crypto::{self, AeadKind};
use crate::singbox::outbound::tls::OutboundTlsConnector;
use crate::singbox::outbound::{ws, BoxStream, DialFuture, Outbound};
use crate::singbox::router::{RouteContext, TargetAddr};

const VMESS_MAGIC: &[u8] = b"c48619fe-8f02-49e0-b9e9-edf763e17e21";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmessSecurity {
    Aes128Gcm = 3,
    ChaCha20Poly1305 = 4,
    None = 5,
    Zero = 6,
}

impl VmessSecurity {
    pub fn parse(s: &str) -> Result<Self> {
        match s.to_ascii_lowercase().as_str() {
            "" | "auto" | "aes-128-gcm" => Ok(Self::Aes128Gcm),
            "chacha20-poly1305" => Ok(Self::ChaCha20Poly1305),
            "none" => Ok(Self::None),
            "zero" => Ok(Self::Zero),
            other => bail!("unsupported vmess security '{other}'"),
        }
    }

    fn aead_kind(self) -> Option<AeadKind> {
        match self {
            Self::Aes128Gcm => Some(AeadKind::Aes128Gcm),
            Self::ChaCha20Poly1305 => Some(AeadKind::ChaCha20Poly1305),
            Self::None | Self::Zero => None,
        }
    }
}

pub struct VmessOutbound {
    tag: String,
    server: String,
    server_port: u16,
    cmd_key: [u8; 16],
    security: VmessSecurity,
    tls_connector: OutboundTlsConnector,
    transport: TransportConfig,
    fwmark: u32,
}

impl VmessOutbound {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        tag: String,
        server: String,
        server_port: u16,
        uuid_str: &str,
        security: &str,
        tls: TlsConfig,
        transport: TransportConfig,
        fwmark: u32,
    ) -> Result<Self> {
        let uuid = parse_uuid(uuid_str)?;
        let mut h = Hasher::new(MessageDigest::md5())?;
        h.update(&uuid)?;
        h.update(VMESS_MAGIC)?;
        let d = h.finish()?;
        let mut cmd_key = [0u8; 16];
        cmd_key.copy_from_slice(&d[..16]);

        let sec = VmessSecurity::parse(security)?;
        let tls_connector = OutboundTlsConnector::new(&server, &tls)?;
        Ok(Self {
            tag,
            server,
            server_port,
            cmd_key,
            security: sec,
            tls_connector,
            transport,
            fwmark,
        })
    }
}

impl Outbound for VmessOutbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn dial_tcp<'a>(&'a self, ctx: &'a RouteContext) -> DialFuture<'a> {
        Box::pin(async move {
            let base = self
                .tls_connector
                .connect(&self.server, self.server_port, self.fwmark)
                .await?;
            let mut stream = ws::maybe_wrap_ws(base, &self.server, &self.transport).await?;

            let mut body_iv = [0u8; 16];
            let mut body_key = [0u8; 16];
            let mut resp_v = [0u8; 1];
            let mut nonce8 = [0u8; 8];
            rand::thread_rng().fill_bytes(&mut body_iv);
            rand::thread_rng().fill_bytes(&mut body_key);
            rand::thread_rng().fill_bytes(&mut resp_v);
            rand::thread_rng().fill_bytes(&mut nonce8);

            let pkt = encode_aead_request(
                &self.cmd_key,
                &body_iv,
                &body_key,
                resp_v[0],
                &nonce8,
                self.security,
                0x01,
                &ctx.target_addr,
                ctx.target_port,
            )?;
            stream.write_all(&pkt).await?;
            stream.flush().await?;

            let resp_key_full = crypto::sha256_digest(&body_key)?;
            let resp_iv_full = crypto::sha256_digest(&body_iv)?;
            let mut resp_key = [0u8; 16];
            let mut resp_iv = [0u8; 16];
            resp_key.copy_from_slice(&resp_key_full[..16]);
            resp_iv.copy_from_slice(&resp_iv_full[..16]);

            Ok(Box::new(VmessStream {
                inner: stream,
                security: self.security,
                tx_key: derive_chunk_key(self.security, &body_key),
                tx_iv: body_iv,
                tx_seq: 0,
                rx_key: derive_chunk_key(self.security, &resp_key),
                rx_iv: resp_iv,
                rx_seq: 0,
                resp_v: resp_v[0],
                resp_hdr_done: false,
                resp_hdr_len: None,
                rx_raw: Vec::new(),
                rx_plain: Vec::new(),
                rx_plain_pos: 0,
                rx_chunk_len: None,
            }) as BoxStream)
        })
    }
}

fn derive_chunk_key(sec: VmessSecurity, key16: &[u8; 16]) -> Vec<u8> {
    if sec == VmessSecurity::ChaCha20Poly1305 {
        let mut h1 = Hasher::new(MessageDigest::md5()).expect("md5");
        h1.update(key16).expect("md5");
        let k1 = h1.finish().expect("md5");
        let mut h2 = Hasher::new(MessageDigest::md5()).expect("md5");
        h2.update(&k1).expect("md5");
        let k2 = h2.finish().expect("md5");
        let mut out = Vec::with_capacity(32);
        out.extend_from_slice(&k1);
        out.extend_from_slice(&k2);
        out
    } else {
        key16.to_vec()
    }
}

fn crc32_ieee(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

fn fnv1a32(data: &[u8]) -> u32 {
    let mut h = 0x811c_9dc5u32;
    for &b in data {
        h ^= b as u32;
        h = h.wrapping_mul(0x0100_0193);
    }
    h
}

fn vmess_kdf(key: &[u8], path: &[&[u8]]) -> Result<[u8; 32]> {
    let mut cur_key = b"VMess AEAD KDF".to_vec();
    for p in path {
        let pkey = PKey::hmac(&cur_key)?;
        let mut s = Signer::new(MessageDigest::sha256(), &pkey)?;
        s.update(p)?;
        cur_key = s.sign_to_vec()?;
    }
    let pkey = PKey::hmac(&cur_key)?;
    let mut s = Signer::new(MessageDigest::sha256(), &pkey)?;
    s.update(key)?;
    let sig = s.sign_to_vec()?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&sig[..32]);
    Ok(out)
}

#[allow(clippy::too_many_arguments)]
pub fn encode_aead_request(
    cmd_key: &[u8; 16],
    body_iv: &[u8; 16],
    body_key: &[u8; 16],
    resp_v: u8,
    nonce8: &[u8; 8],
    security: VmessSecurity,
    cmd: u8,
    target: &TargetAddr,
    port: u16,
) -> Result<Vec<u8>> {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mut auth_pt = [0u8; 16];
    auth_pt[..8].copy_from_slice(&ts.to_be_bytes());
    rand::thread_rng().fill_bytes(&mut auth_pt[8..12]);
    let crc = crc32_ieee(&auth_pt[..12]);
    auth_pt[12..16].copy_from_slice(&crc.to_be_bytes());

    let auth_key_32 = vmess_kdf(cmd_key, &[b"AES Auth ID Encryption"])?;
    let auth_id = crypto::aes_ecb_block(&auth_key_32[..16], &auth_pt, true)?;

    let mut hdr = Vec::with_capacity(96);
    hdr.push(0x01); // version 1
    hdr.extend_from_slice(body_iv);
    hdr.extend_from_slice(body_key);
    hdr.push(resp_v);
    hdr.push(0x01); // Option S (chunk stream)
    hdr.push(security as u8); // P=0 | Sec
    hdr.push(0x00);
    hdr.push(cmd);
    hdr.extend_from_slice(&port.to_be_bytes());
    match target {
        TargetAddr::Ip(IpAddr::V4(v4)) => {
            hdr.push(0x01);
            hdr.extend_from_slice(&v4.octets());
        }
        TargetAddr::Domain(dom) => {
            let b = dom.as_bytes();
            let len = b.len().min(255);
            hdr.push(0x02);
            hdr.push(len as u8);
            hdr.extend_from_slice(&b[..len]);
        }
        TargetAddr::Ip(IpAddr::V6(v6)) => {
            hdr.push(0x03);
            hdr.extend_from_slice(&v6.octets());
        }
    }
    let fnv = fnv1a32(&hdr);
    hdr.extend_from_slice(&fnv.to_be_bytes());

    let len_be = (hdr.len() as u16).to_be_bytes();
    let len_k = vmess_kdf(cmd_key, &[b"VMess Header AEAD Key_Length", &auth_id, nonce8])?;
    let len_n = vmess_kdf(cmd_key, &[b"VMess Header AEAD Nonce_Length", &auth_id, nonce8])?;
    let mut n12 = [0u8; 12];
    n12.copy_from_slice(&len_n[..12]);
    let enc_len = crypto::aead_seal(AeadKind::Aes128Gcm, &len_k[..16], &n12, &auth_id, &len_be)?;

    let hdr_k = vmess_kdf(cmd_key, &[b"VMess Header AEAD Key", &auth_id, nonce8])?;
    let hdr_n = vmess_kdf(cmd_key, &[b"VMess Header AEAD Nonce", &auth_id, nonce8])?;
    n12.copy_from_slice(&hdr_n[..12]);
    let enc_hdr = crypto::aead_seal(AeadKind::Aes128Gcm, &hdr_k[..16], &n12, &auth_id, &hdr)?;

    let mut out = Vec::with_capacity(16 + enc_len.len() + 8 + enc_hdr.len());
    out.extend_from_slice(&auth_id);
    out.extend_from_slice(&enc_len);
    out.extend_from_slice(nonce8);
    out.extend_from_slice(&enc_hdr);
    Ok(out)
}

fn chunk_nonce(iv: &[u8; 16], seq: u16) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[..2].copy_from_slice(&seq.to_be_bytes());
    n[2..12].copy_from_slice(&iv[2..12]);
    n
}

struct VmessStream {
    inner: BoxStream,
    security: VmessSecurity,
    tx_key: Vec<u8>,
    tx_iv: [u8; 16],
    tx_seq: u16,
    rx_key: Vec<u8>,
    rx_iv: [u8; 16],
    rx_seq: u16,
    resp_v: u8,
    resp_hdr_done: bool,
    resp_hdr_len: Option<usize>,
    rx_raw: Vec<u8>,
    rx_plain: Vec<u8>,
    rx_plain_pos: usize,
    rx_chunk_len: Option<usize>,
}

impl VmessStream {
    fn try_decode(&mut self) -> io::Result<bool> {
        if !self.resp_hdr_done {
            if self.resp_hdr_len.is_none() {
                if self.rx_raw.len() < 18 {
                    return Ok(false);
                }
                let len_k = vmess_kdf(&self.rx_key[..16], &[b"AEAD Resp Header Len Key"])
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                let len_n = vmess_kdf(&self.rx_iv, &[b"AEAD Resp Header Len IV"])
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                let enc: Vec<u8> = self.rx_raw.drain(..18).collect();
                let mut n12 = [0u8; 12];
                n12.copy_from_slice(&len_n[..12]);
                let pt = crypto::aead_open(AeadKind::Aes128Gcm, &len_k[..16], &n12, &[], &enc)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                self.resp_hdr_len = Some(u16::from_be_bytes([pt[0], pt[1]]) as usize);
            }
            if let Some(hlen) = self.resp_hdr_len {
                if self.rx_raw.len() < hlen + 16 {
                    return Ok(false);
                }
                let hdr_k = vmess_kdf(&self.rx_key[..16], &[b"AEAD Resp Header Key"])
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                let hdr_n = vmess_kdf(&self.rx_iv, &[b"AEAD Resp Header IV"])
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                let enc: Vec<u8> = self.rx_raw.drain(..hlen + 16).collect();
                let mut n12 = [0u8; 12];
                n12.copy_from_slice(&hdr_n[..12]);
                let pt = crypto::aead_open(AeadKind::Aes128Gcm, &hdr_k[..16], &n12, &[], &enc)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                if pt.is_empty() || pt[0] != self.resp_v {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "vmess resp_v mismatch"));
                }
                self.resp_hdr_done = true;
            }
        }

        if self.security == VmessSecurity::Zero {
            if !self.rx_raw.is_empty() {
                self.rx_plain.append(&mut self.rx_raw);
                return Ok(true);
            }
            return Ok(false);
        }

        let tag_len = if self.security.aead_kind().is_some() { 16 } else { 0 };
        loop {
            if self.rx_chunk_len.is_none() {
                if self.rx_raw.len() < 2 {
                    return Ok(false);
                }
                let lb: Vec<u8> = self.rx_raw.drain(..2).collect();
                let clen = u16::from_be_bytes([lb[0], lb[1]]) as usize;
                if clen == 0 {
                    return Ok(false);
                }
                self.rx_chunk_len = Some(clen);
            }
            if let Some(clen) = self.rx_chunk_len {
                if self.rx_raw.len() < clen {
                    return Ok(false);
                }
                let ct: Vec<u8> = self.rx_raw.drain(..clen).collect();
                self.rx_chunk_len = None;
                if let Some(kind) = self.security.aead_kind() {
                    if ct.len() < tag_len {
                        return Err(io::Error::new(io::ErrorKind::InvalidData, "short vmess chunk"));
                    }
                    let nonce = chunk_nonce(&self.rx_iv, self.rx_seq);
                    self.rx_seq = self.rx_seq.wrapping_add(1);
                    let pt = crypto::aead_open(kind, &self.rx_key, &nonce, &[], &ct)
                        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                    self.rx_plain.extend_from_slice(&pt);
                } else {
                    self.rx_plain.extend_from_slice(&ct);
                }
                return Ok(true);
            }
        }
    }
}

impl AsyncRead for VmessStream {
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
            let mut rb = ReadBuf::new(&mut tmp);
            match Pin::new(&mut self.inner).poll_read(cx, &mut rb) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(())) => {
                    let n = rb.filled().len();
                    if n == 0 {
                        return Poll::Ready(Ok(()));
                    }
                    self.rx_raw.extend_from_slice(rb.filled());
                }
            }
        }
    }
}

impl AsyncWrite for VmessStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if self.security == VmessSecurity::Zero {
            return Pin::new(&mut self.inner).poll_write(cx, data);
        }
        let chunk = &data[..data.len().min(16384)];
        let payload = if let Some(kind) = self.security.aead_kind() {
            let nonce = chunk_nonce(&self.tx_iv, self.tx_seq);
            self.tx_seq = self.tx_seq.wrapping_add(1);
            crypto::aead_seal(kind, &self.tx_key, &nonce, &[], chunk)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?
        } else {
            chunk.to_vec()
        };

        let mut frame = Vec::with_capacity(2 + payload.len());
        frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        frame.extend_from_slice(&payload);

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

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{duplex, AsyncReadExt};

    #[test]
    fn vmess_aead_request_header_decrypts_with_cmd_key() {
        let ob = VmessOutbound::new(
            "vmess".into(),
            "127.0.0.1".into(),
            10086,
            "11111111-2222-3333-4444-555555555555",
            "aes-128-gcm",
            TlsConfig::default(),
            TransportConfig::default(),
            0x100,
        )
        .unwrap();

        let body_iv = [0x11u8; 16];
        let body_key = [0x22u8; 16];
        let nonce8 = [0x33u8; 8];
        let pkt = encode_aead_request(
            &ob.cmd_key,
            &body_iv,
            &body_key,
            0x77,
            &nonce8,
            VmessSecurity::Aes128Gcm,
            0x01,
            &TargetAddr::Domain("example.com".into()),
            443,
        )
        .unwrap();

        let auth_id = &pkt[..16];
        let enc_len = &pkt[16..34];
        let n8 = &pkt[34..42];
        let enc_hdr = &pkt[42..];

        let len_k = vmess_kdf(&ob.cmd_key, &[b"VMess Header AEAD Key_Length", auth_id, n8]).unwrap();
        let len_n = vmess_kdf(&ob.cmd_key, &[b"VMess Header AEAD Nonce_Length", auth_id, n8]).unwrap();
        let mut n12 = [0u8; 12];
        n12.copy_from_slice(&len_n[..12]);
        let len_pt = crypto::aead_open(AeadKind::Aes128Gcm, &len_k[..16], &n12, auth_id, enc_len).unwrap();
        let hlen = u16::from_be_bytes([len_pt[0], len_pt[1]]) as usize;
        assert_eq!(hlen + 16, enc_hdr.len());

        let hdr_k = vmess_kdf(&ob.cmd_key, &[b"VMess Header AEAD Key", auth_id, n8]).unwrap();
        let hdr_n = vmess_kdf(&ob.cmd_key, &[b"VMess Header AEAD Nonce", auth_id, n8]).unwrap();
        n12.copy_from_slice(&hdr_n[..12]);
        let hdr = crypto::aead_open(AeadKind::Aes128Gcm, &hdr_k[..16], &n12, auth_id, enc_hdr).unwrap();
        assert_eq!(hdr[0], 0x01);
        assert_eq!(&hdr[1..17], &body_iv);
        assert_eq!(&hdr[17..33], &body_key);
        assert_eq!(hdr[33], 0x77);
    }

    #[tokio::test]
    async fn vmess_stream_aead_chunk_roundtrip() {
        let (client_io, server_io) = duplex(65536);
        let body_key = [0x44u8; 16];
        let body_iv = [0x55u8; 16];
        let resp_key_full = crypto::sha256_digest(&body_key).unwrap();
        let resp_iv_full = crypto::sha256_digest(&body_iv).unwrap();
        let mut resp_key = [0u8; 16];
        let mut resp_iv = [0u8; 16];
        resp_key.copy_from_slice(&resp_key_full[..16]);
        resp_iv.copy_from_slice(&resp_iv_full[..16]);

        let mut client = VmessStream {
            inner: Box::new(client_io),
            security: VmessSecurity::Aes128Gcm,
            tx_key: body_key.to_vec(),
            tx_iv: body_iv,
            tx_seq: 0,
            rx_key: resp_key.to_vec(),
            rx_iv: resp_iv,
            rx_seq: 0,
            resp_v: 0x99,
            resp_hdr_done: false,
            resp_hdr_len: None,
            rx_raw: Vec::new(),
            rx_plain: Vec::new(),
            rx_plain_pos: 0,
            rx_chunk_len: None,
        };

        // Server writes AEAD response header [0x99, 0, 0, 0] + echoes one chunk
        let srv = tokio::spawn(async move {
            let mut s = server_io;
            let len_k = vmess_kdf(&resp_key, &[b"AEAD Resp Header Len Key"]).unwrap();
            let len_n = vmess_kdf(&resp_iv, &[b"AEAD Resp Header Len IV"]).unwrap();
            let mut n12 = [0u8; 12];
            n12.copy_from_slice(&len_n[..12]);
            let enc_len = crypto::aead_seal(AeadKind::Aes128Gcm, &len_k[..16], &n12, &[], &4u16.to_be_bytes()).unwrap();

            let hdr_k = vmess_kdf(&resp_key, &[b"AEAD Resp Header Key"]).unwrap();
            let hdr_n = vmess_kdf(&resp_iv, &[b"AEAD Resp Header IV"]).unwrap();
            n12.copy_from_slice(&hdr_n[..12]);
            let enc_hdr = crypto::aead_seal(AeadKind::Aes128Gcm, &hdr_k[..16], &n12, &[], &[0x99, 0, 0, 0]).unwrap();
            s.write_all(&enc_len).await.unwrap();
            s.write_all(&enc_hdr).await.unwrap();

            let mut l = [0u8; 2];
            s.read_exact(&mut l).await.unwrap();
            let clen = u16::from_be_bytes(l) as usize;
            let mut ct = vec![0u8; clen];
            s.read_exact(&mut ct).await.unwrap();
            let pt = crypto::aead_open(AeadKind::Aes128Gcm, &body_key, &chunk_nonce(&body_iv, 0), &[], &ct).unwrap();

            let rct = crypto::aead_seal(AeadKind::Aes128Gcm, &resp_key, &chunk_nonce(&resp_iv, 0), &[], &pt).unwrap();
            s.write_all(&(rct.len() as u16).to_be_bytes()).await.unwrap();
            s.write_all(&rct).await.unwrap();
            s.flush().await.unwrap();
        });

        client.write_all(b"vmess-ok").await.unwrap();
        client.flush().await.unwrap();
        let mut got = [0u8; 8];
        client.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"vmess-ok");
        srv.await.unwrap();
    }
}
