use std::net::IpAddr;

/// Sniff a domain name from the initial packet of a TCP connection (TLS ClientHello SNI or HTTP Host).
pub fn sniff_domain(buf: &[u8]) -> Option<String> {
    if let Some(sni) = sniff_tls_sni(buf) {
        return Some(sni);
    }
    sniff_http_host(buf)
}

fn is_valid_domain(host: &str) -> bool {
    let h = host.trim().trim_end_matches('.');
    !h.is_empty()
        && h.len() <= 253
        && h.parse::<IpAddr>().is_err()
        && h.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
}

/// Extract SNI hostname from a TLS ClientHello record (`0x16`).
pub fn sniff_tls_sni(buf: &[u8]) -> Option<String> {
    // TLS record header: type(1)=0x16, version(2)=0x0300..0x0303, length(2)
    if buf.len() < 9 || buf[0] != 0x16 || buf[1] != 0x03 {
        return None;
    }
    // Handshake header: msg_type(1)=0x01 (ClientHello), length(3)
    if buf[5] != 0x01 {
        return None;
    }
    let mut pos: usize = 9;
    // client_version(2) + random(32)
    pos = pos.checked_add(34)?;
    if pos >= buf.len() {
        return None;
    }
    // session_id
    let sid_len = *buf.get(pos)? as usize;
    pos = pos.checked_add(1 + sid_len)?;
    // cipher_suites
    let cs_len = u16::from_be_bytes([*buf.get(pos)?, *buf.get(pos + 1)?]) as usize;
    pos = pos.checked_add(2 + cs_len)?;
    // compression_methods
    let cm_len = *buf.get(pos)? as usize;
    pos = pos.checked_add(1 + cm_len)?;
    // extensions_len
    let ext_total = u16::from_be_bytes([*buf.get(pos)?, *buf.get(pos + 1)?]) as usize;
    pos += 2;
    let ext_end = pos.saturating_add(ext_total).min(buf.len());

    while pos + 4 <= ext_end {
        let etype = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
        let elen = u16::from_be_bytes([buf[pos + 2], buf[pos + 3]]) as usize;
        pos += 4;
        if pos + elen > ext_end {
            break;
        }
        if etype == 0x0000 && elen >= 5 {
            let list_len = u16::from_be_bytes([buf[pos], buf[pos + 1]]) as usize;
            let mut p = pos + 2;
            let list_end = (p + list_len).min(pos + elen);
            while p + 3 <= list_end {
                let name_type = buf[p];
                let name_len = u16::from_be_bytes([buf[p + 1], buf[p + 2]]) as usize;
                p += 3;
                if p + name_len > list_end {
                    break;
                }
                if name_type == 0x00 {
                    if let Ok(s) = std::str::from_utf8(&buf[p..p + name_len]) {
                        if is_valid_domain(s) {
                            return Some(s.to_ascii_lowercase());
                        }
                    }
                }
                p += name_len;
            }
        }
        pos += elen;
    }
    None
}

/// Extract `Host` header domain from a plain HTTP/1.x request.
pub fn sniff_http_host(buf: &[u8]) -> Option<String> {
    const METHODS: &[&[u8]] = &[
        b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ", b"OPTIONS ", b"PATCH ", b"CONNECT ",
    ];
    if !METHODS.iter().any(|m| buf.starts_with(m)) {
        return None;
    }
    let text = std::str::from_utf8(buf).ok()?;
    for line in text.lines().skip(1) {
        let trimmed = line.trim_end_matches('\r');
        if trimmed.is_empty() {
            break;
        }
        if let Some((k, v)) = trimmed.split_once(':') {
            if k.trim().eq_ignore_ascii_case("host") {
                let raw = v.trim();
                let host = if let Some(rest) = raw.strip_prefix('[') {
                    rest.split_once(']')?.0
                } else {
                    raw.split_once(':').map(|(h, _)| h).unwrap_or(raw)
                };
                if is_valid_domain(host) {
                    return Some(host.to_ascii_lowercase());
                }
                return None;
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::singbox::outbound::reality;
    use openssl::pkey::PKey;

    #[test]
    fn sniffs_tls_client_hello_sni() {
        let priv_k = PKey::generate_x25519().unwrap();
        let pub_k: [u8; 32] = priv_k.raw_public_key().unwrap().try_into().unwrap();
        let ch = reality::build_reality_client_hello(
            "api.Example.COM",
            &["h2".into()],
            &[0x11u8; 32],
            &pub_k,
            &pub_k,
            &priv_k,
            &[0u8; 8],
        )
        .unwrap();

        let mut rec = vec![0x16, 0x03, 0x01];
        rec.extend_from_slice(&(ch.len() as u16).to_be_bytes());
        rec.extend_from_slice(&ch);

        assert_eq!(sniff_domain(&rec).as_deref(), Some("api.example.com"));
    }

    #[test]
    fn sniffs_http_host_and_ignores_ip_or_garbage() {
        let req = b"GET /index.html HTTP/1.1\r\nHost: News.Example.Org:8080\r\nUser-Agent: curl\r\n\r\n";
        assert_eq!(sniff_domain(req).as_deref(), Some("news.example.org"));

        let ip_req = b"GET / HTTP/1.1\r\nHost: 192.168.1.1:80\r\n\r\n";
        assert_eq!(sniff_domain(ip_req), None);

        assert_eq!(sniff_domain(b"\x00\x01\x02\x03ssh-2.0"), None);
    }
}
