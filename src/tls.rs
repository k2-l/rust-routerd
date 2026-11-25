use std::net::IpAddr;

use anyhow::{Context, Result};
use openssl::asn1::Asn1Time;
use openssl::bn::{BigNum, MsbOption};
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::ssl::{AlpnError, SslAcceptor, SslMethod, SslOptions};
use openssl::x509::extension::{BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAlternativeName};
use openssl::x509::{X509Builder, X509NameBuilder};

fn load_pem(data_dir: &str) -> Option<(Vec<u8>, Vec<u8>)> {
    let cert = std::fs::read(format!("{data_dir}/cert.pem")).ok()?;
    let key = std::fs::read(format!("{data_dir}/key.pem")).ok()?;
    Some((cert, key))
}

fn generate(data_dir: &str, hostname: &str) -> Result<(Vec<u8>, Vec<u8>)> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).context("EC P-256 group")?;
    let ec_key = EcKey::generate(&group).context("generate EC key")?;
    let pkey = PKey::from_ec_key(ec_key).context("wrap EC PKey")?;

    let mut name_builder = X509NameBuilder::new()?;
    name_builder.append_entry_by_text("O", "Manta OS")?;
    name_builder.append_entry_by_text("CN", hostname)?;
    let name = name_builder.build();

    let mut serial = BigNum::new()?;
    serial.rand(128, MsbOption::MAYBE_ZERO, false)?;
    let serial_asn1 = serial.to_asn1_integer()?;

    let mut builder = X509Builder::new()?;
    builder.set_version(2)?;
    builder.set_serial_number(&serial_asn1)?;
    builder.set_subject_name(&name)?;
    builder.set_issuer_name(&name)?;
    builder.set_pubkey(&pkey)?;

    let not_before = Asn1Time::days_from_now(0)?;
    let not_after = Asn1Time::days_from_now(3650)?;
    builder.set_not_before(&not_before)?;
    builder.set_not_after(&not_after)?;

    builder.append_extension(BasicConstraints::new().build()?)?;
    builder.append_extension(KeyUsage::new().digital_signature().key_encipherment().build()?)?;
    builder.append_extension(ExtendedKeyUsage::new().server_auth().build()?)?;

    let mut san = SubjectAlternativeName::new();
    for dns in [hostname, "mantaos.local", "routerd.local", "localhost"] {
        if !dns.is_empty() {
            san.dns(dns);
        }
    }
    let mut ips = vec![
        "192.168.1.1".to_string(),
        "192.168.8.1".to_string(),
        "192.168.10.1".to_string(),
        "10.0.0.1".to_string(),
        "127.0.0.1".to_string(),
        "::1".to_string(),
    ];
    if let Ok(cfg) = crate::openwrt::uci::load("network") {
        if let Some(lan_ip) = cfg.section("lan").and_then(|s| s.get("ipaddr")) {
            if lan_ip.parse::<IpAddr>().is_ok() && !ips.iter().any(|x| x == lan_ip) {
                ips.push(lan_ip.to_string());
            }
        }
    }
    for ip in &ips {
        san.ip(ip);
    }
    let san_ext = san.build(&builder.x509v3_context(None, None))?;
    builder.append_extension(san_ext)?;

    builder.sign(&pkey, MessageDigest::sha256())?;
    let cert_pem = builder.build().to_pem()?;
    let key_pem = pkey.private_key_to_pem_pkcs8()?;

    std::fs::create_dir_all(data_dir)?;
    crate::util::write_atomic(&format!("{data_dir}/cert.pem"), &cert_pem, 0o644)?;
    crate::util::write_atomic(&format!("{data_dir}/key.pem"), &key_pem, 0o600)?;
    Ok((cert_pem, key_pem))
}

/// Load the persisted self-signed certificate, generating it on first boot via OpenSSL 3.5.
pub fn load_or_generate(data_dir: &str, hostname: &str) -> Result<(Vec<u8>, Vec<u8>)> {
    if let Some(pair) = load_pem(data_dir) {
        if !pair.0.is_empty() && !pair.1.is_empty() {
            return Ok(pair);
        }
    }
    generate(data_dir, hostname).with_context(|| "generate self-signed certificate")
}

pub fn server_config(cert_pem: &[u8], key_pem: &[u8]) -> Result<SslAcceptor> {
    let cert = openssl::x509::X509::from_pem(cert_pem).context("parse certificate PEM")?;
    let pkey = PKey::private_key_from_pem(key_pem).context("parse private key PEM")?;

    let mut acceptor = SslAcceptor::mozilla_modern_v5(SslMethod::tls_server())
        .context("create OpenSSL 3.5 modern acceptor")?;
    acceptor.set_private_key(&pkey).context("set private key")?;
    acceptor.set_certificate(&cert).context("set certificate")?;
    acceptor.check_private_key().context("verify cert/key pair")?;
    acceptor.set_options(SslOptions::NO_COMPRESSION | SslOptions::SINGLE_ECDH_USE);

    acceptor.set_alpn_protos(b"h2http/1.1")?;
    acceptor.set_alpn_select_callback(|_, client| {
        openssl::ssl::select_next_proto(b"h2http/1.1", client).ok_or(AlpnError::NOACK)
    });

    Ok(acceptor.build())
}
