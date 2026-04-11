use crate::crypto::config_builder::build_client_tls_config;
use crate::crypto::e2e::E2EKeys;
use crate::crypto::peer_auth::sign_e2e_keys;
use crate::processes::app::run_tui;
use crate::protocol::message::Message;

use std::io;
use std::sync::Arc;

use tokio::io::{AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName};

pub async fn run(
    ca_path: &str,
    cert_path: &str,
    key_path: &str,
    server_hostname: &str,
    server_addr: &str,
    client_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::new(ca_path, cert_path, key_path, server_hostname, client_id)?;
    client.connect(server_addr).await?;
    Ok(())
}

pub struct Client {
    connector: TlsConnector,
    server_name: ServerName<'static>,
    client_id: String,
    // DER-encoded CA certificate used to verify peer keys
    ca_cert_der: Vec<u8>,
    // DER-encoded TLS certificate of this client, sent in AnnounceKey
    own_cert_der: Vec<u8>,
    // PEM-encoded private key used to sign E2E keys
    own_key_pem: String,
}

impl Client {
    pub fn new(
        ca_path: &str,
        cert_path: &str,
        key_path: &str,
        server_hostname: &str,
        client_id: &str,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let config = build_client_tls_config(ca_path, cert_path, key_path)?;
        // server_name must match the CN or SAN in the server cert
        let server_name = ServerName::try_from(server_hostname.to_string())?;

        let ca_cert_pem = std::fs::read(ca_path)?;
        let ca_cert_der = rustls_pemfile::certs(&mut ca_cert_pem.as_slice())
            .collect::<Result<Vec<CertificateDer>, _>>()?
            .into_iter()
            .next()
            .ok_or("no certificate found in CA file")?
            .as_ref()
            .to_vec();

        let cert_pem = std::fs::read(cert_path)?;
        let own_cert_der = rustls_pemfile::certs(&mut cert_pem.as_slice())
            .collect::<Result<Vec<CertificateDer>, _>>()?
            .into_iter()
            .next()
            .ok_or("no certificate found in cert file")?
            .as_ref()
            .to_vec();

        let own_key_pem = std::fs::read_to_string(key_path)?;

        Ok(Self {
            connector: TlsConnector::from(Arc::new(config)),
            server_name,
            client_id: client_id.to_string(),
            ca_cert_der,
            own_cert_der,
            own_key_pem,
        })
    }

    pub async fn connect(&self, addr: &str) -> io::Result<()> {
        let tcp_stream = TcpStream::connect(addr).await?;

        // TLS handshake - present client cert, verify server cert, then negotiate crypto suite
        // if Post quantum hybrid encryption is available on both sides itll be used
        let tls_stream = self
            .connector
            .connect(self.server_name.clone(), tcp_stream)
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::ConnectionRefused, e))?;

        println!("TLS connection established with server.");

        let (reader, mut writer) = tokio::io::split(tls_stream);
        let mut reader = BufReader::new(reader);

        // Generate hybrid E2E keypair and register both public keys with server
        // Sign the keys so peers can verify message wasnt substituted in transit
        let e2e = E2EKeys::generate();
        let x25519_bytes = e2e.x25519_public.to_bytes();
        let sig = sign_e2e_keys(&self.own_key_pem, &x25519_bytes, &e2e.mlkem_ek_bytes)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("key signing failed: {e}")))?;
        Message::AnnounceKey {
            x25519_key: x25519_bytes,
            mlkem_ek: e2e.mlkem_ek_bytes.clone(),
            cert: self.own_cert_der.clone(),
            sig,
        }
        .write_framed(&mut writer)
        .await?;

        run_tui(&self.client_id, &mut reader, &mut writer, e2e, self.ca_cert_der.clone()).await?;

        writer.shutdown().await?;
        Ok(())
    }
}