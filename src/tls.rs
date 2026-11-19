use std::io::BufReader;
use std::sync::Arc;

use anyhow::{Context, Result};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;

fn load_pem(data_dir: &str) -> Option<(Vec<u8>, Vec<u8>)> {
    let cert = std::fs::read(format!("{data_dir}/cert.pem")).ok()?;
    let key = std::fs::read(format!("{data_dir}/key.pem")).ok()?;
    Some((cert, key))
}

fn generate(data_dir: &str, hostname: &str) -> Result<(Vec<u8>, Vec<u8>)> {
    use rcgen::{CertificateParams, DnType, KeyPair};

    let mut params = CertificateParams::new(vec![
        hostname.to_string(),
        "routerd.local".to_string(),
        "localhost".to_string(),
        "192.168.1.1".to_string(),
        "192.168.8.1".to_string(),
        "192.168.10.1".to_string(),
        "10.0.0.1".to_string(),
        "127.0.0.1".to_string(),
        "::1".to_string(),
    ])?;
    params
        .distinguished_name
        .push(DnType::CommonName, hostname.to_string());
    params
        .distinguished_name
        .push(DnType::OrganizationName, "routerd");
    let key_pair = KeyPair::generate()?;
    let cert = params.self_signed(&key_pair)?;
    let cert_pem = cert.pem().into_bytes();
    let key_pem = key_pair.serialize_pem().into_bytes();

    std::fs::create_dir_all(data_dir)?;
    crate::util::write_atomic(&format!("{data_dir}/cert.pem"), &cert_pem, 0o644)?;
    crate::util::write_atomic(&format!("{data_dir}/key.pem"), &key_pem, 0o600)?;
    Ok((cert_pem, key_pem))
}

/// Load the persisted self-signed certificate, generating it on first boot.
pub fn load_or_generate(data_dir: &str, hostname: &str) -> Result<(Vec<u8>, Vec<u8>)> {
    if let Some(pair) = load_pem(data_dir) {
        if !pair.0.is_empty() && !pair.1.is_empty() {
            return Ok(pair);
        }
    }
    generate(data_dir, hostname).with_context(|| "generate self-signed certificate")
}

pub fn server_config(cert_pem: &[u8], key_pem: &[u8]) -> Result<Arc<ServerConfig>> {
    let certs: Vec<CertificateDer<'static>> =
        rustls_pemfile::certs(&mut BufReader::new(cert_pem))
            .collect::<std::result::Result<Vec<_>, _>>()
            .context("parse certificate")?;
    let key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut BufReader::new(key_pem))
        .context("parse private key")?
        .context("no private key in PEM")?;

    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("build rustls config")?;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}
