use super::crypto_provider::build_crypto_provider;

use std::sync::Arc;

use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::rustls::ClientConfig;
use tokio_rustls::rustls::pki_types::{CertificateDer};
use tokio_rustls::rustls::server::WebPkiClientVerifier;

// Build server TLS config
// Security policy lives here - CA for certs, cipher suites etc
pub fn build_server_tls_config(
        ca_path: &str,
        cert_path: &str,
        key_path: &str,
) -> Result<ServerConfig, Box<dyn std::error::Error>> {
    let crypto_provider = build_crypto_provider();
    // Load CA certificate used to verify client certs
    let ca_cert_pem = std::fs::read(ca_path)?;
    let ca_certs = rustls_pemfile::certs(&mut ca_cert_pem.as_slice())
        .collect::<Result<Vec<CertificateDer>, _>>()?;

    let mut root_store = tokio_rustls::rustls::RootCertStore::empty();
    for cert in ca_certs {
        root_store.add(cert)?;
    }

    // WebPkiClientVerifier enforces that all connecting clients must present valid certs signed by one of the CAs in root_store
    // This allows for mutual tls - otherwise only the server is verified
    let client_verifier = WebPkiClientVerifier::builder(Arc::new(root_store)).build()?;

    // load server's cert and private key
    let server_cert_pem: Vec<u8> = std::fs::read(cert_path)?;
    let server_certs = rustls_pemfile::certs(&mut server_cert_pem.as_slice())
        .collect::<Result<Vec<CertificateDer>, _>>()?;

    let server_key_pem: Vec<u8> = std::fs::read(key_path)?;
    let server_key = rustls_pemfile::private_key(&mut server_key_pem.as_slice())?
        .ok_or("no private key found in {key_path}")?;

    // Rustls defaults to TLS 1.2 & 1.3 which both mandate forward secrecy - ephemeral key exchange & elliptic curve DHKE
    let config = ServerConfig::builder_with_provider(Arc::new(crypto_provider))
        // ensures we inherit all default cipher suites and only override key encapsulation preference order
        .with_safe_default_protocol_versions()?
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(server_certs, server_key);

    Ok(config?)
}

// build client config
// same as above essentially
pub fn build_client_tls_config(
    ca_path: &str,
    cert_path: &str,
    key_path: &str,
) -> Result<ClientConfig, Box<dyn std::error::Error>> {
    let crypto_provider = build_crypto_provider();

    let ca_pem = std::fs::read(ca_path)?;
    let ca_certs = rustls_pemfile::certs(&mut ca_pem.as_slice())
        .collect::<Result<Vec<CertificateDer>, _>>()?;

    let mut root_store = tokio_rustls::rustls::RootCertStore::empty();
    for cert in ca_certs {
        root_store.add(cert)?;
    }

    let cert_pem = std::fs::read(cert_path)?;
    let client_certs = rustls_pemfile::certs(&mut cert_pem.as_slice())
        .collect::<Result<Vec<CertificateDer>, _>>()?;

    let key_pem = std::fs::read(key_path)?;
    let client_key = rustls_pemfile::private_key(&mut key_pem.as_slice())?
        .ok_or("no private key found in {key_path}")?;

    let config = ClientConfig::builder_with_provider(Arc::new(crypto_provider))
        .with_safe_default_protocol_versions()?
        .with_root_certificates(root_store)
        .with_client_auth_cert(client_certs, client_key)?;

    Ok(config)
}