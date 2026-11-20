use anyhow::{bail, Context, Result};
use openssl::hash::{Hasher, MessageDigest};
use openssl::pkey::PKey;
use openssl::sign::Signer;
use openssl::symm::{Cipher, Crypter, Mode};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AeadKind {
    Aes128Gcm,
    Aes256Gcm,
    ChaCha20Poly1305,
}

impl AeadKind {
    pub fn from_ss_method(method: &str) -> Result<(Self, bool)> {
        match method.to_ascii_lowercase().as_str() {
            "aes-128-gcm" => Ok((Self::Aes128Gcm, false)),
            "aes-256-gcm" => Ok((Self::Aes256Gcm, false)),
            "chacha20-ietf-poly1305" => Ok((Self::ChaCha20Poly1305, false)),
            "2022-blake3-aes-128-gcm" => Ok((Self::Aes128Gcm, true)),
            "2022-blake3-aes-256-gcm" => Ok((Self::Aes256Gcm, true)),
            "2022-blake3-chacha20-poly1305" => Ok((Self::ChaCha20Poly1305, true)),
            other => bail!("unsupported shadowsocks cipher: {other}"),
        }
    }

    pub fn key_len(self) -> usize {
        match self {
            Self::Aes128Gcm => 16,
            Self::Aes256Gcm | Self::ChaCha20Poly1305 => 32,
        }
    }

    pub fn salt_len(self) -> usize {
        self.key_len()
    }

    pub fn tag_len(self) -> usize {
        16
    }

    fn cipher(self) -> Cipher {
        match self {
            Self::Aes128Gcm => Cipher::aes_128_gcm(),
            Self::Aes256Gcm => Cipher::aes_256_gcm(),
            Self::ChaCha20Poly1305 => Cipher::chacha20_poly1305(),
        }
    }
}

/// EVP_BytesToKey (MD5) key derivation used by legacy Shadowsocks AEAD.
pub fn evp_bytes_to_key(password: &[u8], key_len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(key_len + 16);
    let mut prev: Vec<u8> = Vec::new();
    while out.len() < key_len {
        let mut h = Hasher::new(MessageDigest::md5()).expect("md5");
        if !prev.is_empty() {
            h.update(&prev).expect("md5 update");
        }
        h.update(password).expect("md5 update");
        let digest = h.finish().expect("md5 finish");
        out.extend_from_slice(&digest);
        prev = digest.to_vec();
    }
    out.truncate(key_len);
    out
}

/// HKDF-SHA1 (RFC 5869) using OpenSSL HMAC-SHA1.
pub fn hkdf_sha1(ikm: &[u8], salt: &[u8], info: &[u8], out_len: usize) -> Result<Vec<u8>> {
    let actual_salt = if salt.is_empty() { &[0u8; 20][..] } else { salt };
    let prk = hmac_sha1(actual_salt, ikm)?;
    let mut okm = Vec::with_capacity(out_len);
    let mut t = Vec::new();
    let mut counter: u8 = 1;
    while okm.len() < out_len {
        let mut msg = Vec::with_capacity(t.len() + info.len() + 1);
        msg.extend_from_slice(&t);
        msg.extend_from_slice(info);
        msg.push(counter);
        t = hmac_sha1(&prk, &msg)?;
        okm.extend_from_slice(&t);
        counter = counter.checked_add(1).context("hkdf counter overflow")?;
    }
    okm.truncate(out_len);
    Ok(okm)
}

fn hmac_sha1(key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    let pkey = PKey::hmac(key)?;
    let mut signer = Signer::new(MessageDigest::sha1(), &pkey)?;
    signer.update(data)?;
    Ok(signer.sign_to_vec()?)
}

pub fn hmac_sha256(key: &[u8], data: &[u8]) -> Result<[u8; 32]> {
    let pkey = PKey::hmac(key)?;
    let mut signer = Signer::new(MessageDigest::sha256(), &pkey)?;
    signer.update(data)?;
    let sig = signer.sign_to_vec()?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&sig[..32]);
    Ok(out)
}

/// HKDF-SHA256 Extract + Expand (RFC 5869) using OpenSSL HMAC-SHA256.
pub fn hkdf_sha256_extract(salt: &[u8], ikm: &[u8]) -> Result<[u8; 32]> {
    let actual_salt = if salt.is_empty() { &[0u8; 32][..] } else { salt };
    hmac_sha256(actual_salt, ikm)
}

pub fn hkdf_sha256_expand(prk: &[u8; 32], info: &[u8], out_len: usize) -> Result<Vec<u8>> {
    let mut okm = Vec::with_capacity(out_len);
    let mut t = Vec::new();
    let mut counter: u8 = 1;
    while okm.len() < out_len {
        let mut msg = Vec::with_capacity(t.len() + info.len() + 1);
        msg.extend_from_slice(&t);
        msg.extend_from_slice(info);
        msg.push(counter);
        t = hmac_sha256(prk, &msg)?.to_vec();
        okm.extend_from_slice(&t);
        counter = counter.checked_add(1).context("hkdf-sha256 counter overflow")?;
    }
    okm.truncate(out_len);
    Ok(okm)
}

pub fn hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8], out_len: usize) -> Result<Vec<u8>> {
    let prk = hkdf_sha256_extract(salt, ikm)?;
    hkdf_sha256_expand(&prk, info, out_len)
}

pub fn sha256_digest(data: &[u8]) -> Result<[u8; 32]> {
    let mut h = Hasher::new(MessageDigest::sha256())?;
    h.update(data)?;
    let d = h.finish()?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&d[..32]);
    Ok(out)
}

/// Trojan password hash: hex(SHA-224(password)) (56 lowercase hex chars).
pub fn trojan_password_hash(password: &str) -> Result<String> {
    let mut h = Hasher::new(MessageDigest::sha224())?;
    h.update(password.as_bytes())?;
    let digest = h.finish()?;
    Ok(hex::encode(digest))
}

pub fn aead_seal(kind: AeadKind, key: &[u8], nonce: &[u8; 12], aad: &[u8], pt: &[u8]) -> Result<Vec<u8>> {
    let cipher = kind.cipher();
    let mut c = Crypter::new(cipher, Mode::Encrypt, key, Some(nonce))?;
    if !aad.is_empty() {
        c.aad_update(aad)?;
    }
    let mut out = vec![0u8; pt.len() + cipher.block_size() + kind.tag_len()];
    let mut n = c.update(pt, &mut out)?;
    n += c.finalize(&mut out[n..])?;
    let mut tag = [0u8; 16];
    c.get_tag(&mut tag)?;
    out.truncate(n);
    out.extend_from_slice(&tag);
    Ok(out)
}

pub fn aead_open(kind: AeadKind, key: &[u8], nonce: &[u8; 12], aad: &[u8], ct_with_tag: &[u8]) -> Result<Vec<u8>> {
    if ct_with_tag.len() < kind.tag_len() {
        bail!("ciphertext shorter than AEAD tag");
    }
    let split = ct_with_tag.len() - kind.tag_len();
    let (ct, tag) = ct_with_tag.split_at(split);
    let cipher = kind.cipher();
    let mut c = Crypter::new(cipher, Mode::Decrypt, key, Some(nonce))?;
    if !aad.is_empty() {
        c.aad_update(aad)?;
    }
    c.set_tag(tag)?;
    let mut out = vec![0u8; ct.len() + cipher.block_size()];
    let mut n = c.update(ct, &mut out)?;
    n += c.finalize(&mut out[n..])?;
    out.truncate(n);
    Ok(out)
}

pub fn increment_nonce_le(nonce: &mut [u8; 12]) {
    for b in nonce.iter_mut() {
        *b = b.wrapping_add(1);
        if *b != 0 {
            break;
        }
    }
}

/// Single-block AES-ECB encrypt/decrypt (16 bytes) used by Shadowsocks 2022 UDP separate headers.
pub fn aes_ecb_block(key: &[u8], block: &[u8; 16], encrypt: bool) -> Result<[u8; 16]> {
    let cipher = match key.len() {
        16 => Cipher::aes_128_ecb(),
        32 => Cipher::aes_256_ecb(),
        n => bail!("unsupported AES-ECB key length {n}"),
    };
    let mode = if encrypt { Mode::Encrypt } else { Mode::Decrypt };
    let mut c = Crypter::new(cipher, mode, key, None)?;
    c.pad(false);
    let mut out = [0u8; 32];
    let mut n = c.update(block, &mut out)?;
    n += c.finalize(&mut out[n..])?;
    if n != 16 {
        bail!("unexpected AES-ECB output length {n}");
    }
    let mut res = [0u8; 16];
    res.copy_from_slice(&out[..16]);
    Ok(res)
}

/// HChaCha20 subkey derivation (draft-irtf-cfrg-xchacha) for 2022-blake3-chacha20-poly1305 UDP.
pub fn hchacha20(key: &[u8; 32], nonce16: &[u8; 16]) -> [u8; 32] {
    #[inline]
    fn qr(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
        s[a] = s[a].wrapping_add(s[b]);
        s[d] = (s[d] ^ s[a]).rotate_left(16);
        s[c] = s[c].wrapping_add(s[d]);
        s[b] = (s[b] ^ s[c]).rotate_left(12);
        s[a] = s[a].wrapping_add(s[b]);
        s[d] = (s[d] ^ s[a]).rotate_left(8);
        s[c] = s[c].wrapping_add(s[d]);
        s[b] = (s[b] ^ s[c]).rotate_left(7);
    }
    let u = |b: &[u8]| u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
    let mut s = [
        0x6170_7865,
        0x3320_646e,
        0x7962_2d32,
        0x6b20_6574,
        u(&key[0..4]),
        u(&key[4..8]),
        u(&key[8..12]),
        u(&key[12..16]),
        u(&key[16..20]),
        u(&key[20..24]),
        u(&key[24..28]),
        u(&key[28..32]),
        u(&nonce16[0..4]),
        u(&nonce16[4..8]),
        u(&nonce16[8..12]),
        u(&nonce16[12..16]),
    ];
    for _ in 0..10 {
        qr(&mut s, 0, 4, 8, 12);
        qr(&mut s, 1, 5, 9, 13);
        qr(&mut s, 2, 6, 10, 14);
        qr(&mut s, 3, 7, 11, 15);
        qr(&mut s, 0, 5, 10, 15);
        qr(&mut s, 1, 6, 11, 12);
        qr(&mut s, 2, 7, 8, 13);
        qr(&mut s, 3, 4, 9, 14);
    }
    let mut out = [0u8; 32];
    for (i, idx) in [0, 1, 2, 3, 12, 13, 14, 15].iter().enumerate() {
        out[i * 4..(i + 1) * 4].copy_from_slice(&s[*idx].to_le_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aead_roundtrip_all_ciphers() {
        for kind in [AeadKind::Aes128Gcm, AeadKind::Aes256Gcm, AeadKind::ChaCha20Poly1305] {
            let key = vec![0x42u8; kind.key_len()];
            let nonce = [0x01u8; 12];
            let pt = b"hello shadowsocks aead";
            let ct = aead_seal(kind, &key, &nonce, b"aad", pt).unwrap();
            let dec = aead_open(kind, &key, &nonce, b"aad", &ct).unwrap();
            assert_eq!(dec, pt);
        }
    }

    #[test]
    fn aes_ecb_and_hchacha20_roundtrip() {
        let key = [0x11u8; 16];
        let blk = [0x22u8; 16];
        let enc = aes_ecb_block(&key, &blk, true).unwrap();
        let dec = aes_ecb_block(&key, &enc, false).unwrap();
        assert_eq!(dec, blk);

        // RFC 7539 / draft-irtf-cfrg-xchacha test vector
        let hkey = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let hnonce = [
            0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00, 0x31, 0x41,
            0x59, 0x27,
        ];
        let sub = hchacha20(&hkey, &hnonce);
        assert_eq!(
            hex::encode(sub),
            "82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc"
        );
    }
}
