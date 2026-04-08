use crate::crypto::config_builder::build_client_tls_config;
use crate::processes::app::run_tui;

use std::io;
use std::sync::Arc;

use tokio::io::{AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::pki_types::ServerName;

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

        Ok(Client {
            connector: TlsConnector::from(Arc::new(config)),
            server_name,
            client_id: client_id.to_string(),
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

        run_tui(&self.client_id, &mut reader, &mut writer).await?;

        writer.shutdown().await?;
        Ok(())
    }
}