use std::net::IpAddr;
use std::path::Path;
use std::pin::Pin;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use openssl::ssl::{Ssl, SslConnector, SslMethod, SslVerifyMode};
use tokio::net::TcpStream;
use tokio_openssl::SslStream;

use crate::singbox::config::TlsConfig;
use crate::singbox::outbound::{resolve_host_port, BoxStream};
use crate::singbox::tproxy;

const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Reusable OpenSSL 3.5 outbound TLS connector supporting SNI, ALPN and verification toggle.
#[derive(Clone)]
pub struct OutboundTlsConnector {
    connector: Option<SslConnector>,
    sni: String,
    insecure: bool,
}

impl OutboundTlsConnector {
    pub fn new(default_server: &str, tls: &TlsConfig) -> Result<Self> {
        let sni = tls
            .server_name
            .as_deref()
            .filter(|s| !s.is_empty())
            .unwrap_or(default_server)
            .to_string();

        if !tls.enabled {
            return Ok(Self {
                connector: None,
                sni,
                insecure: tls.insecure,
            });
        }

        let mut builder = SslConnector::builder(SslMethod::tls_client())?;
        if tls.insecure {
            builder.set_verify(SslVerifyMode::NONE);
        } else {
            builder.set_default_verify_paths()?;
            let ca_bundle = Path::new("/etc/ssl/certs/ca-certificates.crt");
            if ca_bundle.exists() {
                let _ = builder.set_ca_file(ca_bundle);
            }
            builder.set_verify(SslVerifyMode::PEER);
        }

        if let Some(wire) = encode_alpn(&tls.alpn)? {
            builder.set_alpn_protos(&wire)?;
        }

        Ok(Self {
            connector: Some(builder.build()),
            sni,
            insecure: tls.insecure,
        })
    }

    /// Connect TCP (with `SO_MARK`) and perform OpenSSL TLS handshake if enabled.
    pub async fn connect(&self, server: &str, port: u16, fwmark: u32) -> Result<BoxStream> {
        let addr = resolve_host_port(server, port).await?;
        let tcp = tproxy::connect_tcp_marked(addr, fwmark).await?;
        let Some(connector) = &self.connector else {
            return Ok(Box::new(tcp));
        };

        let mut config = connector.configure()?;
        if !self.insecure {
            if let Ok(ip) = self.sni.parse::<IpAddr>() {
                config.set_use_server_name_indication(false);
                config.param_mut().set_ip(ip)?;
            } else {
                config.set_hostname(&self.sni)?;
            }
        } else if self.sni.parse::<IpAddr>().is_ok() {
            config.set_use_server_name_indication(false);
        }

        let ssl: Ssl = config.into_ssl(&self.sni)?;
        let mut stream: SslStream<TcpStream> = SslStream::new(ssl, tcp)?;
        tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, Pin::new(&mut stream).connect())
            .await
            .with_context(|| format!("tls handshake to {}:{} timed out", self.sni, port))?
            .with_context(|| format!("tls handshake to {}:{}", self.sni, port))?;

        Ok(Box::new(stream))
    }
}

pub fn encode_alpn(protos: &[String]) -> Result<Option<Vec<u8>>> {
    if protos.is_empty() {
        return Ok(None);
    }
    let mut wire = Vec::new();
    for proto in protos {
        let b = proto.as_bytes();
        if b.is_empty() || b.len() > 255 {
            bail!("invalid ALPN protocol '{proto}'");
        }
        wire.push(b.len() as u8);
        wire.extend_from_slice(b);
    }
    Ok(Some(wire))
}

/// Connect TCP (with SO_MARK) and optionally wrap with OpenSSL TLS.
pub async fn connect_tls(
    server: &str,
    port: u16,
    tls: &TlsConfig,
    fwmark: u32,
) -> Result<BoxStream> {
    OutboundTlsConnector::new(server, tls)?
        .connect(server, port, fwmark)
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::asn1::Asn1Time;
    use openssl::hash::MessageDigest;
    use openssl::pkey::PKey;
    use openssl::rsa::Rsa;
    use openssl::ssl::{AlpnError, SslAcceptor};
    use openssl::x509::{X509NameBuilder, X509};
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    fn make_self_signed_acceptor() -> Arc<SslAcceptor> {
        let rsa = Rsa::generate(2048).unwrap();
        let pkey = PKey::from_rsa(rsa).unwrap();
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", "test.routerd.local").unwrap();
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
        acc.set_alpn_select_callback(|_ssl, client| {
            openssl::ssl::select_next_proto(b"\x02h2\x08http/1.1", client).ok_or(AlpnError::NOACK)
        });
        Arc::new(acc.build())
    }

    #[tokio::test]
    async fn tls_connector_verifies_cert_and_negotiates_sni_alpn() {
        let acceptor = make_self_signed_acceptor();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let server_task = tokio::spawn(async move {
            for _ in 0..2 {
                let (tcp, _) = listener.accept().await.unwrap();
                let acc = acceptor.clone();
                tokio::spawn(async move {
                    let ssl = Ssl::new(acc.context()).unwrap();
                    let mut tls = SslStream::new(ssl, tcp).unwrap();
                    if Pin::new(&mut tls).accept().await.is_ok() {
                        assert_eq!(tls.ssl().servername(openssl::ssl::NameType::HOST_NAME), Some("test.routerd.local"));
                        assert_eq!(tls.ssl().selected_alpn_protocol(), Some(b"h2".as_slice()));
                        let mut buf = [0u8; 16];
                        if let Ok(n) = tls.read(&mut buf).await {
                            let _ = tls.write_all(&buf[..n]).await;
                        }
                    }
                });
            }
        });

        // 1. insecure = false must reject untrusted self-signed cert
        let strict_cfg = TlsConfig {
            enabled: true,
            server_name: Some("test.routerd.local".into()),
            insecure: false,
            alpn: vec!["h2".into(), "http/1.1".into()],
            reality: None,
        };
        let strict = OutboundTlsConnector::new("127.0.0.1", &strict_cfg).unwrap();
        assert!(strict.connect("127.0.0.1", port, 0x100).await.is_err());

        // 2. insecure = true succeeds, sends SNI + ALPN, and relays data
        let insecure_cfg = TlsConfig {
            insecure: true,
            ..strict_cfg
        };
        let conn = OutboundTlsConnector::new("127.0.0.1", &insecure_cfg).unwrap();
        let mut stream = conn.connect("127.0.0.1", port, 0x100).await.unwrap();
        stream.write_all(b"tls-ok").await.unwrap();
        let mut buf = [0u8; 6];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"tls-ok");

        server_task.abort();
    }
}
