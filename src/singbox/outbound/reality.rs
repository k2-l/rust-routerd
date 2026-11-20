use std::io;
use std::pin::Pin;
use std::task::{Context as TaskContext, Poll};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use base64::Engine;
use openssl::derive::Deriver;
use openssl::pkey::{Id, PKey};
use rand::RngCore;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;

use crate::singbox::config::{RealityConfig, TlsConfig};
use crate::singbox::crypto::{self, AeadKind};
use crate::singbox::outbound::tls::encode_alpn;
use crate::singbox::outbound::{resolve_host_port, BoxStream};
use crate::singbox::tproxy;

const TLS_AES_128_GCM_SHA256: u16 = 0x1301;
const TLS_AES_256_GCM_SHA384: u16 = 0x1302;
const TLS_CHACHA20_POLY1305_SHA256: u16 = 0x1303;

pub fn parse_public_key(s: &str) -> Result<[u8; 32]> {
    let trimmed = s.trim();
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(trimmed)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(trimmed))
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(trimmed))
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(trimmed))
        .context("invalid reality public_key base64")?;
    if decoded.len() != 32 {
        bail!("reality public_key must be 32 bytes, got {}", decoded.len());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&decoded);
    Ok(out)
}

pub fn parse_short_id(s: &str) -> Result<[u8; 8]> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return Ok([0u8; 8]);
    }
    if trimmed.len() > 16 || trimmed.len() % 2 != 0 {
        bail!("reality short_id must be even hex up to 16 chars");
    }
    let raw = hex::decode(trimmed).context("invalid reality short_id hex")?;
    let mut out = [0u8; 8];
    out[..raw.len()].copy_from_slice(&raw);
    Ok(out)
}

fn x25519_ecdh(priv_key: &PKey<openssl::pkey::Private>, peer_pub_raw: &[u8; 32]) -> Result<[u8; 32]> {
    let peer_pub = PKey::public_key_from_raw_bytes(peer_pub_raw, Id::X25519)
        .context("invalid X25519 peer public key")?;
    let mut deriver = Deriver::new(priv_key)?;
    deriver.set_peer(&peer_pub)?;
    let secret = deriver.derive_to_vec()?;
    if secret.len() != 32 {
        bail!("unexpected X25519 shared secret length {}", secret.len());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&secret);
    Ok(out)
}

fn tls13_expand_label(secret: &[u8; 32], label: &[u8], context: &[u8], len: usize) -> Result<Vec<u8>> {
    let mut full_label = Vec::with_capacity(6 + label.len());
    full_label.extend_from_slice(b"tls13 ");
    full_label.extend_from_slice(label);

    let mut info = Vec::with_capacity(2 + 1 + full_label.len() + 1 + context.len());
    info.extend_from_slice(&(len as u16).to_be_bytes());
    info.push(full_label.len() as u8);
    info.extend_from_slice(&full_label);
    info.push(context.len() as u8);
    info.extend_from_slice(context);
    crypto::hkdf_sha256_expand(secret, &info, len)
}

fn derive_traffic_keys(secret: &[u8; 32], kind: AeadKind) -> Result<(Vec<u8>, [u8; 12])> {
    let key = tls13_expand_label(secret, b"key", &[], kind.key_len())?;
    let iv_vec = tls13_expand_label(secret, b"iv", &[], 12)?;
    let mut iv = [0u8; 12];
    iv.copy_from_slice(&iv_vec);
    Ok((key, iv))
}

fn make_tls13_nonce(iv: &[u8; 12], seq: u64) -> [u8; 12] {
    let mut nonce = *iv;
    let seq_bytes = seq.to_be_bytes();
    for i in 0..8 {
        nonce[4 + i] ^= seq_bytes[i];
    }
    nonce
}

/// Build a TLS 1.3 ClientHello handshake message (without the 5-byte TLS record header)
/// with the 32-byte `session_id` encrypted using Reality's `auth_key`.
pub fn build_reality_client_hello(
    sni: &str,
    alpn: &[String],
    client_random: &[u8; 32],
    client_x25519_pub: &[u8; 32],
    server_reality_pub: &[u8; 32],
    client_priv: &PKey<openssl::pkey::Private>,
    short_id: &[u8; 8],
) -> Result<Vec<u8>> {
    let mut exts = Vec::new();
    // 1. SNI extension (0x0000)
    if !sni.is_empty() {
        let sni_bytes = sni.as_bytes();
        let list_len = 1 + 2 + sni_bytes.len();
        let ext_len = 2 + list_len;
        exts.extend_from_slice(&0x0000u16.to_be_bytes());
        exts.extend_from_slice(&(ext_len as u16).to_be_bytes());
        exts.extend_from_slice(&(list_len as u16).to_be_bytes());
        exts.push(0x00); // host_name
        exts.extend_from_slice(&(sni_bytes.len() as u16).to_be_bytes());
        exts.extend_from_slice(sni_bytes);
    }
    // 2. supported_versions (0x002b): TLS 1.3 (0x0304)
    exts.extend_from_slice(&[0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04]);
    // 3. supported_groups (0x000a): x25519 (0x001d)
    exts.extend_from_slice(&[0x00, 0x0a, 0x00, 0x04, 0x00, 0x02, 0x00, 0x1d]);
    // 4. signature_algorithms (0x000d): ecdsa_secp256r1_sha256, rsa_pss_rsae_sha256, ed25519
    exts.extend_from_slice(&[
        0x00, 0x0d, 0x00, 0x08, 0x00, 0x06, 0x04, 0x03, 0x08, 0x04, 0x08, 0x07,
    ]);
    // 5. ALPN (0x0010) if specified
    if let Some(wire) = encode_alpn(alpn)? {
        let ext_len = 2 + wire.len();
        exts.extend_from_slice(&0x0010u16.to_be_bytes());
        exts.extend_from_slice(&(ext_len as u16).to_be_bytes());
        exts.extend_from_slice(&(wire.len() as u16).to_be_bytes());
        exts.extend_from_slice(&wire);
    }
    // 6. key_share (0x0033): X25519 (0x001d, 32 bytes)
    exts.extend_from_slice(&0x0033u16.to_be_bytes());
    exts.extend_from_slice(&(2 + 2 + 2 + 32u16).to_be_bytes());
    exts.extend_from_slice(&(2 + 2 + 32u16).to_be_bytes());
    exts.extend_from_slice(&0x001du16.to_be_bytes());
    exts.extend_from_slice(&32u16.to_be_bytes());
    exts.extend_from_slice(client_x25519_pub);

    // ClientHello body (with 32-byte zeroed session_id placeholder)
    let mut body = Vec::with_capacity(128 + exts.len());
    body.extend_from_slice(&[0x03, 0x03]); // legacy_version TLS 1.2
    body.extend_from_slice(client_random);
    body.push(32); // legacy_session_id len = 32
    let session_id_offset = body.len();
    body.extend_from_slice(&[0u8; 32]);
    // cipher_suites
    body.extend_from_slice(&6u16.to_be_bytes());
    body.extend_from_slice(&TLS_AES_128_GCM_SHA256.to_be_bytes());
    body.extend_from_slice(&TLS_CHACHA20_POLY1305_SHA256.to_be_bytes());
    body.extend_from_slice(&TLS_AES_256_GCM_SHA384.to_be_bytes());
    // compression_methods: null
    body.extend_from_slice(&[0x01, 0x00]);
    // extensions
    body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    body.extend_from_slice(&exts);

    // Handshake message: [0x01][len 3B BE][body]
    let mut hs = Vec::with_capacity(4 + body.len());
    hs.push(0x01);
    let len_bytes = (body.len() as u32).to_be_bytes();
    hs.extend_from_slice(&len_bytes[1..4]);
    hs.extend_from_slice(&body);

    // Derive Reality auth_key = HKDF-SHA256(ikm=ecdh, salt=client_random[..20], info="REALITY", 16)
    let shared = x25519_ecdh(client_priv, server_reality_pub)?;
    let auth_key = crypto::hkdf_sha256(&shared, &client_random[..20], b"REALITY", 16)?;
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&client_random[20..32]);

    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(0);
    let mut auth_payload = [0u8; 16];
    auth_payload[0..4].copy_from_slice(&[1, 8, 1, 0]);
    auth_payload[4..8].copy_from_slice(&now_secs.to_be_bytes());
    auth_payload[8..16].copy_from_slice(short_id);

    // Encrypt auth_payload with AAD = hs (with zeroed session_id)
    let sealed = crypto::aead_seal(AeadKind::Aes128Gcm, &auth_key, &nonce, &hs, &auth_payload)?;
    if sealed.len() != 32 {
        bail!("unexpected reality session_id sealed len {}", sealed.len());
    }
    hs[4 + session_id_offset..4 + session_id_offset + 32].copy_from_slice(&sealed);
    Ok(hs)
}

async fn read_tls_record(stream: &mut TcpStream) -> Result<(u8, Vec<u8>)> {
    let mut hdr = [0u8; 5];
    stream.read_exact(&mut hdr).await?;
    let len = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
    if len > 18432 {
        bail!("tls record too large: {len}");
    }
    let mut payload = vec![0u8; len];
    stream.read_exact(&mut payload).await?;
    Ok((hdr[0], payload))
}

fn parse_server_hello(hs_msg: &[u8]) -> Result<(u16, [u8; 32])> {
    if hs_msg.len() < 4 + 38 || hs_msg[0] != 0x02 {
        bail!("invalid ServerHello");
    }
    let body = &hs_msg[4..];
    let sid_len = body[34] as usize;
    let cs_off = 35 + sid_len;
    if body.len() < cs_off + 5 {
        bail!("truncated ServerHello");
    }
    let cipher_suite = u16::from_be_bytes([body[cs_off], body[cs_off + 1]]);
    let ext_len = u16::from_be_bytes([body[cs_off + 3], body[cs_off + 4]]) as usize;
    let mut pos = cs_off + 5;
    let end = (pos + ext_len).min(body.len());
    let mut server_pub = None;
    while pos + 4 <= end {
        let etype = u16::from_be_bytes([body[pos], body[pos + 1]]);
        let elen = u16::from_be_bytes([body[pos + 2], body[pos + 3]]) as usize;
        pos += 4;
        if pos + elen > end {
            break;
        }
        if etype == 0x0033 && elen >= 36 {
            let group = u16::from_be_bytes([body[pos], body[pos + 1]]);
            let klen = u16::from_be_bytes([body[pos + 2], body[pos + 3]]) as usize;
            if group == 0x001d && klen == 32 && pos + 4 + 32 <= end {
                let mut k = [0u8; 32];
                k.copy_from_slice(&body[pos + 4..pos + 36]);
                server_pub = Some(k);
            }
        }
        pos += elen;
    }
    let pub_key = server_pub.context("ServerHello missing X25519 key_share")?;
    Ok((cipher_suite, pub_key))
}

/// Perform Reality X25519 + TLS 1.3 handshake over marked TCP and return an encrypted `BoxStream`.
pub async fn connect_reality(
    server: &str,
    port: u16,
    tls: &TlsConfig,
    reality: &RealityConfig,
    fwmark: u32,
) -> Result<BoxStream> {
    let server_reality_pub = parse_public_key(&reality.public_key)?;
    let short_id = parse_short_id(&reality.short_id)?;
    let sni = tls
        .server_name
        .as_deref()
        .filter(|s| !s.is_empty())
        .unwrap_or(server);

    let addr = resolve_host_port(server, port).await?;
    let mut tcp = tproxy::connect_tcp_marked(addr, fwmark).await?;

    let client_priv = PKey::generate_x25519()?;
    let client_pub_vec = client_priv.raw_public_key()?;
    let mut client_x25519_pub = [0u8; 32];
    client_x25519_pub.copy_from_slice(&client_pub_vec[..32]);

    let mut client_random = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut client_random);

    let ch = build_reality_client_hello(
        sni,
        &tls.alpn,
        &client_random,
        &client_x25519_pub,
        &server_reality_pub,
        &client_priv,
        &short_id,
    )?;

    let mut transcript = ch.clone();
    let mut ch_rec = Vec::with_capacity(5 + ch.len());
    ch_rec.extend_from_slice(&[0x16, 0x03, 0x01]);
    ch_rec.extend_from_slice(&(ch.len() as u16).to_be_bytes());
    ch_rec.extend_from_slice(&ch);
    tcp.write_all(&ch_rec).await?;
    tcp.flush().await?;

    // Read ServerHello (skip ChangeCipherSpec if any)
    let sh = loop {
        let (rtype, payload) = read_tls_record(&mut tcp).await?;
        if rtype == 0x16 {
            break payload;
        }
        if rtype == 0x14 {
            continue;
        }
        bail!("unexpected TLS record type {rtype:#x} before ServerHello");
    };
    transcript.extend_from_slice(&sh);
    let (cipher_suite, server_x25519_pub) = parse_server_hello(&sh)?;
    let aead_kind = match cipher_suite {
        TLS_AES_128_GCM_SHA256 => AeadKind::Aes128Gcm,
        TLS_CHACHA20_POLY1305_SHA256 => AeadKind::ChaCha20Poly1305,
        TLS_AES_256_GCM_SHA384 => AeadKind::Aes256Gcm,
        other => bail!("unsupported Reality TLS 1.3 cipher suite {other:#x}"),
    };

    // TLS 1.3 key schedule (SHA-256)
    let ecdhe = x25519_ecdh(&client_priv, &server_x25519_pub)?;
    let early_secret = crypto::hkdf_sha256_extract(&[0u8; 32], &[0u8; 32])?;
    let empty_hash = crypto::sha256_digest(&[])?;
    let derived_hs = tls13_expand_label(&early_secret, b"derived", &empty_hash, 32)?;
    let mut derived_hs_arr = [0u8; 32];
    derived_hs_arr.copy_from_slice(&derived_hs);
    let handshake_secret = crypto::hkdf_sha256_extract(&derived_hs_arr, &ecdhe)?;

    let ch_sh_hash = crypto::sha256_digest(&transcript)?;
    let c_hs_vec = tls13_expand_label(&handshake_secret, b"c hs traffic", &ch_sh_hash, 32)?;
    let s_hs_vec = tls13_expand_label(&handshake_secret, b"s hs traffic", &ch_sh_hash, 32)?;
    let mut c_hs = [0u8; 32];
    let mut s_hs = [0u8; 32];
    c_hs.copy_from_slice(&c_hs_vec);
    s_hs.copy_from_slice(&s_hs_vec);

    let (c_hs_key, c_hs_iv) = derive_traffic_keys(&c_hs, aead_kind)?;
    let (s_hs_key, s_hs_iv) = derive_traffic_keys(&s_hs, aead_kind)?;
    let mut s_hs_seq = 0u64;

    // Read encrypted handshake messages until server Finished (0x14)
    let mut hs_buf = Vec::new();
    let mut server_finished_ok = false;
    while !server_finished_ok {
        let (rtype, payload) = read_tls_record(&mut tcp).await?;
        if rtype == 0x14 {
            continue;
        }
        if rtype != 0x17 {
            bail!("expected encrypted TLS 1.3 handshake record, got {rtype:#x}");
        }
        let mut aad = [0u8; 5];
        aad[0] = 0x17;
        aad[1..3].copy_from_slice(&[0x03, 0x03]);
        aad[3..5].copy_from_slice(&(payload.len() as u16).to_be_bytes());
        let nonce = make_tls13_nonce(&s_hs_iv, s_hs_seq);
        s_hs_seq += 1;
        let mut pt = crypto::aead_open(aead_kind, &s_hs_key, &nonce, &aad, &payload)?;
        while pt.last() == Some(&0) {
            pt.pop();
        }
        let inner_type = pt.pop().context("empty TLS 1.3 inner plaintext")?;
        if inner_type == 0x16 {
            hs_buf.extend_from_slice(&pt);
            while hs_buf.len() >= 4 {
                let mtype = hs_buf[0];
                let mlen = u32::from_be_bytes([0, hs_buf[1], hs_buf[2], hs_buf[3]]) as usize;
                if hs_buf.len() < 4 + mlen {
                    break;
                }
                let msg: Vec<u8> = hs_buf.drain(..4 + mlen).collect();
                if mtype == 0x14 {
                    // Verify Server Finished
                    let t_hash = crypto::sha256_digest(&transcript)?;
                    let fin_key_vec = tls13_expand_label(&s_hs, b"finished", &[], 32)?;
                    let mut fin_key = [0u8; 32];
                    fin_key.copy_from_slice(&fin_key_vec);
                    let expected_verify = crypto::hmac_sha256(&fin_key, &t_hash)?;
                    if msg[4..] != expected_verify {
                        bail!("Reality server Finished verification failed");
                    }
                    transcript.extend_from_slice(&msg);
                    server_finished_ok = true;
                    break;
                }
                transcript.extend_from_slice(&msg);
            }
        } else if inner_type == 0x15 {
            bail!("TLS alert received during Reality handshake");
        }
    }

    // Derive application traffic secrets
    let derived_app = tls13_expand_label(&handshake_secret, b"derived", &empty_hash, 32)?;
    let mut derived_app_arr = [0u8; 32];
    derived_app_arr.copy_from_slice(&derived_app);
    let master_secret = crypto::hkdf_sha256_extract(&derived_app_arr, &[0u8; 32])?;
    let fin_hash = crypto::sha256_digest(&transcript)?;

    let c_app_vec = tls13_expand_label(&master_secret, b"c ap traffic", &fin_hash, 32)?;
    let s_app_vec = tls13_expand_label(&master_secret, b"s ap traffic", &fin_hash, 32)?;
    let mut c_app = [0u8; 32];
    let mut s_app = [0u8; 32];
    c_app.copy_from_slice(&c_app_vec);
    s_app.copy_from_slice(&s_app_vec);

    let (c_app_key, c_app_iv) = derive_traffic_keys(&c_app, aead_kind)?;
    let (s_app_key, s_app_iv) = derive_traffic_keys(&s_app, aead_kind)?;

    // Send Client Finished encrypted with c_hs_key
    let c_fin_key_vec = tls13_expand_label(&c_hs, b"finished", &[], 32)?;
    let mut c_fin_key = [0u8; 32];
    c_fin_key.copy_from_slice(&c_fin_key_vec);
    let c_verify = crypto::hmac_sha256(&c_fin_key, &fin_hash)?;
    let mut fin_pt = Vec::with_capacity(4 + 32 + 1);
    fin_pt.extend_from_slice(&[0x14, 0x00, 0x00, 0x20]);
    fin_pt.extend_from_slice(&c_verify);
    fin_pt.push(0x16);

    let rec_len = (fin_pt.len() + aead_kind.tag_len()) as u16;
    let mut aad = [0x17, 0x03, 0x03, 0, 0];
    aad[3..5].copy_from_slice(&rec_len.to_be_bytes());
    let fin_ct = crypto::aead_seal(aead_kind, &c_hs_key, &make_tls13_nonce(&c_hs_iv, 0), &aad, &fin_pt)?;
    let mut fin_rec = Vec::with_capacity(5 + fin_ct.len());
    fin_rec.extend_from_slice(&aad);
    fin_rec.extend_from_slice(&fin_ct);
    tcp.write_all(&fin_rec).await?;
    tcp.flush().await?;

    Ok(Box::new(Tls13Stream {
        inner: tcp,
        kind: aead_kind,
        tx_key: c_app_key,
        tx_iv: c_app_iv,
        tx_seq: 0,
        rx_key: s_app_key,
        rx_iv: s_app_iv,
        rx_seq: 0,
        rx_raw: Vec::new(),
        rx_plain: Vec::new(),
        rx_plain_pos: 0,
    }) as BoxStream)
}

struct Tls13Stream {
    inner: TcpStream,
    kind: AeadKind,
    tx_key: Vec<u8>,
    tx_iv: [u8; 12],
    tx_seq: u64,
    rx_key: Vec<u8>,
    rx_iv: [u8; 12],
    rx_seq: u64,
    rx_raw: Vec<u8>,
    rx_plain: Vec<u8>,
    rx_plain_pos: usize,
}

impl Tls13Stream {
    fn try_decrypt(&mut self) -> io::Result<bool> {
        loop {
            if self.rx_raw.len() < 5 {
                return Ok(false);
            }
            let rtype = self.rx_raw[0];
            let rlen = u16::from_be_bytes([self.rx_raw[3], self.rx_raw[4]]) as usize;
            if self.rx_raw.len() < 5 + rlen {
                return Ok(false);
            }
            let rec: Vec<u8> = self.rx_raw.drain(..5 + rlen).collect();
            if rtype == 0x14 {
                continue;
            }
            if rtype != 0x17 {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "unexpected TLS 1.3 record"));
            }
            let nonce = make_tls13_nonce(&self.rx_iv, self.rx_seq);
            self.rx_seq += 1;
            let mut pt = crypto::aead_open(self.kind, &self.rx_key, &nonce, &rec[..5], &rec[5..])
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            while pt.last() == Some(&0) {
                pt.pop();
            }
            let inner_type = pt.pop().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "empty TLS 1.3 plaintext")
            })?;
            if inner_type == 0x17 {
                self.rx_plain.extend_from_slice(&pt);
                return Ok(true);
            } else if inner_type == 0x15 {
                return Ok(false);
            }
        }
    }
}

impl AsyncRead for Tls13Stream {
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
            if self.try_decrypt()? {
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
                    self.rx_raw.extend_from_slice(tmp_buf.filled());
                }
            }
        }
    }
}

impl AsyncWrite for Tls13Stream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let chunk = &data[..data.len().min(16384)];
        let mut pt = Vec::with_capacity(chunk.len() + 1);
        pt.extend_from_slice(chunk);
        pt.push(0x17);

        let rec_len = (pt.len() + self.kind.tag_len()) as u16;
        let mut aad = [0x17, 0x03, 0x03, 0, 0];
        aad[3..5].copy_from_slice(&rec_len.to_be_bytes());
        let nonce = make_tls13_nonce(&self.tx_iv, self.tx_seq);
        let ct = crypto::aead_seal(self.kind, &self.tx_key, &nonce, &aad, &pt)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        self.tx_seq += 1;

        let mut rec = Vec::with_capacity(5 + ct.len());
        rec.extend_from_slice(&aad);
        rec.extend_from_slice(&ct);
        match Pin::new(&mut self.inner).poll_write(cx, &rec) {
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
    use tokio::net::TcpListener;

    #[test]
    fn reality_client_hello_session_id_decrypts_with_server_key() {
        let srv_priv = PKey::generate_x25519().unwrap();
        let srv_pub_vec = srv_priv.raw_public_key().unwrap();
        let mut srv_pub = [0u8; 32];
        srv_pub.copy_from_slice(&srv_pub_vec);

        let cli_priv = PKey::generate_x25519().unwrap();
        let cli_pub_vec = cli_priv.raw_public_key().unwrap();
        let mut cli_pub = [0u8; 32];
        cli_pub.copy_from_slice(&cli_pub_vec);

        let client_random = [0x42u8; 32];
        let short_id = parse_short_id("0123456789abcdef").unwrap();
        let mut ch = build_reality_client_hello(
            "www.microsoft.com",
            &["h2".into()],
            &client_random,
            &cli_pub,
            &srv_pub,
            &cli_priv,
            &short_id,
        )
        .unwrap();

        // Server extracts session_id (at offset 4 + 2 + 32 + 1 = 39) and zeros it for AAD
        let mut sid = [0u8; 32];
        sid.copy_from_slice(&ch[39..71]);
        ch[39..71].fill(0);

        let shared = x25519_ecdh(&srv_priv, &cli_pub).unwrap();
        let auth_key = crypto::hkdf_sha256(&shared, &client_random[..20], b"REALITY", 16).unwrap();
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&client_random[20..32]);
        let pt = crypto::aead_open(AeadKind::Aes128Gcm, &auth_key, &nonce, &ch, &sid).unwrap();
        assert_eq!(&pt[0..4], &[1, 8, 1, 0]);
        assert_eq!(&pt[8..16], &short_id);
    }

    #[tokio::test]
    async fn reality_tls13_handshake_and_stream_roundtrip() {
        let srv_reality_priv = PKey::generate_x25519().unwrap();
        let srv_reality_pub_b64 =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(srv_reality_priv.raw_public_key().unwrap());

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let srv = tokio::spawn(async move {
            let (mut tcp, _) = listener.accept().await.unwrap();
            let (rtype, ch) = read_tls_record(&mut tcp).await.unwrap();
            assert_eq!(rtype, 0x16);

            // Extract client X25519 key_share (last 32 bytes of ClientHello)
            let mut cli_pub = [0u8; 32];
            cli_pub.copy_from_slice(&ch[ch.len() - 32..]);

            let srv_eph_priv = PKey::generate_x25519().unwrap();
            let srv_eph_pub = srv_eph_priv.raw_public_key().unwrap();

            // Build ServerHello with TLS_AES_128_GCM_SHA256 + X25519 key_share
            let mut sh_body = Vec::new();
            sh_body.extend_from_slice(&[0x03, 0x03]); // legacy_version
            sh_body.extend_from_slice(&[0x77u8; 32]); // server_random
            sh_body.push(32);
            sh_body.extend_from_slice(&ch[39..71]); // echo session_id
            sh_body.extend_from_slice(&TLS_AES_128_GCM_SHA256.to_be_bytes());
            sh_body.push(0x00); // compression
            let mut exts = Vec::new();
            exts.extend_from_slice(&[0x00, 0x2b, 0x00, 0x02, 0x03, 0x04]); // supported_versions 1.3
            exts.extend_from_slice(&[0x00, 0x33, 0x00, 36, 0x00, 0x1d, 0x00, 32]);
            exts.extend_from_slice(&srv_eph_pub);
            sh_body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
            sh_body.extend_from_slice(&exts);

            let mut sh = vec![0x02];
            let l = (sh_body.len() as u32).to_be_bytes();
            sh.extend_from_slice(&l[1..4]);
            sh.extend_from_slice(&sh_body);

            let mut sh_rec = vec![0x16, 0x03, 0x03];
            sh_rec.extend_from_slice(&(sh.len() as u16).to_be_bytes());
            sh_rec.extend_from_slice(&sh);
            tcp.write_all(&sh_rec).await.unwrap();

            let mut transcript = ch;
            transcript.extend_from_slice(&sh);

            let ecdhe = x25519_ecdh(&srv_eph_priv, &cli_pub).unwrap();
            let early = crypto::hkdf_sha256_extract(&[0u8; 32], &[0u8; 32]).unwrap();
            let empty_h = crypto::sha256_digest(&[]).unwrap();
            let mut d_hs = [0u8; 32];
            d_hs.copy_from_slice(&tls13_expand_label(&early, b"derived", &empty_h, 32).unwrap());
            let hs_sec = crypto::hkdf_sha256_extract(&d_hs, &ecdhe).unwrap();
            let ch_sh_h = crypto::sha256_digest(&transcript).unwrap();

            let mut c_hs = [0u8; 32];
            let mut s_hs = [0u8; 32];
            c_hs.copy_from_slice(&tls13_expand_label(&hs_sec, b"c hs traffic", &ch_sh_h, 32).unwrap());
            s_hs.copy_from_slice(&tls13_expand_label(&hs_sec, b"s hs traffic", &ch_sh_h, 32).unwrap());
            let (s_hs_k, s_hs_iv) = derive_traffic_keys(&s_hs, AeadKind::Aes128Gcm).unwrap();

            // Send server Finished
            let s_fin_k_vec = tls13_expand_label(&s_hs, b"finished", &[], 32).unwrap();
            let mut s_fin_k = [0u8; 32];
            s_fin_k.copy_from_slice(&s_fin_k_vec);
            let s_ver = crypto::hmac_sha256(&s_fin_k, &ch_sh_h).unwrap();
            let mut s_fin_msg = vec![0x14, 0x00, 0x00, 0x20];
            s_fin_msg.extend_from_slice(&s_ver);
            transcript.extend_from_slice(&s_fin_msg);
            s_fin_msg.push(0x16);

            let aad = [0x17, 0x03, 0x03, ((s_fin_msg.len() + 16) >> 8) as u8, (s_fin_msg.len() + 16) as u8];
            let ct = crypto::aead_seal(AeadKind::Aes128Gcm, &s_hs_k, &make_tls13_nonce(&s_hs_iv, 0), &aad, &s_fin_msg).unwrap();
            tcp.write_all(&aad).await.unwrap();
            tcp.write_all(&ct).await.unwrap();
            tcp.flush().await.unwrap();

            // Read client Finished
            let (_rt, _cf) = read_tls_record(&mut tcp).await.unwrap();

            let mut d_app = [0u8; 32];
            d_app.copy_from_slice(&tls13_expand_label(&hs_sec, b"derived", &empty_h, 32).unwrap());
            let ms = crypto::hkdf_sha256_extract(&d_app, &[0u8; 32]).unwrap();
            let fin_h = crypto::sha256_digest(&transcript).unwrap();
            let mut c_app = [0u8; 32];
            let mut s_app = [0u8; 32];
            c_app.copy_from_slice(&tls13_expand_label(&ms, b"c ap traffic", &fin_h, 32).unwrap());
            s_app.copy_from_slice(&tls13_expand_label(&ms, b"s ap traffic", &fin_h, 32).unwrap());

            let (c_k, c_iv) = derive_traffic_keys(&c_app, AeadKind::Aes128Gcm).unwrap();
            let (s_k, s_iv) = derive_traffic_keys(&s_app, AeadKind::Aes128Gcm).unwrap();
            let mut s_tls = Tls13Stream {
                inner: tcp,
                kind: AeadKind::Aes128Gcm,
                tx_key: s_k,
                tx_iv: s_iv,
                tx_seq: 0,
                rx_key: c_k,
                rx_iv: c_iv,
                rx_seq: 0,
                rx_raw: Vec::new(),
                rx_plain: Vec::new(),
                rx_plain_pos: 0,
            };
            let mut buf = [0u8; 10];
            s_tls.read_exact(&mut buf).await.unwrap();
            s_tls.write_all(&buf).await.unwrap();
            s_tls.flush().await.unwrap();
        });

        let tls_cfg = TlsConfig {
            enabled: true,
            server_name: Some("www.microsoft.com".into()),
            insecure: false,
            alpn: vec!["h2".into()],
            reality: None,
        };
        let reality_cfg = RealityConfig {
            enabled: true,
            public_key: srv_reality_pub_b64,
            short_id: "01234567".into(),
        };
        let mut stream = connect_reality("127.0.0.1", port, &tls_cfg, &reality_cfg, 0x100)
            .await
            .unwrap();
        stream.write_all(b"reality-ok").await.unwrap();
        stream.flush().await.unwrap();
        let mut got = [0u8; 10];
        stream.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"reality-ok");
        srv.await.unwrap();
    }
}
