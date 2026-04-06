use crate::protocol::message::Message;
use crate::tls::config_builder::build_client_tls_config;

use std::io;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName};
use tokio_rustls::TlsConnector;

pub async fn run(
        ca_path: &str,
        cert_path: &str,
        key_path: &str,
        server_hostname: &str,
        server_addr: &str,
) -> Result<(), Box<dyn std::error::Error>> {
        let client = Client::new(ca_path, cert_path, key_path, server_hostname)?;
        client.connect(server_addr).await?;
        Ok(())
}

pub struct Client {
    connector: TlsConnector,
    server_name: ServerName<'static>,
}

impl Client {
        pub fn new(
                ca_path: &str,
                cert_path: &str,
                key_path: &str,
                server_hostname: &str,
        ) -> Result<Self, Box<dyn std::error::Error>> {
                let config = build_client_tls_config(ca_path, cert_path, key_path)?;
                // server_name must match the CN or SAN in the server cert
                let server_name = ServerName::try_from(server_hostname.to_string())?;

                Ok(Client {
                        connector: TlsConnector::from(Arc::new(config)),
                        server_name,
                })
        }

        pub async fn connect(&self, addr: &str) -> io::Result<()> {
                let tcp_stream = TcpStream::connect(addr).await?;

                // TLS handshake - present client cert, verify server cert, then negotiate crypto suite
                // if Post quantum hybrid encryption is available on both sides itll be used
                let mut tls_stream = self.connector
                        .connect(self.server_name.clone(), tcp_stream)
                        .await
                        .map_err(|e| io::Error::new(io::ErrorKind::ConnectionRefused, e))?;

                println!("TLS connection established with server");

                // serialise and send messages here
                // example
                /* 
                let msg = Message::new("alice", "bob", "Hello over mTLS!");
                let serialized = msg.serialize();
                tls_stream.write_all(&serialized).await?;

                let mut buf = vec![0u8; 4096];
                let n = tls_stream.read(&mut buf).await?;
                if n > 0 {
                        let response = Message::deserialize(&buf[..n]);
                        println!("Received: {:?}", response);
                }
                */ 

                Ok(())
        }
}