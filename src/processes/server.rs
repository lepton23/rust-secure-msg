use crate::protocol::message::Message;
use crate::tls::config_builder::build_server_tls_config;

use std::collections::HashMap;
use std::io;
use std::sync::{Arc, Mutex};

use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

use tokio_rustls::TlsAcceptor;
use tokio_rustls::server::TlsStream;

pub async fn run(
        ca_path: &str,
        cert_path: &str,
        key_path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let server = Server::new(ca_path, cert_path, key_path)?;
    server.start("127.0.0.1:8080").await?;
    Ok(())
}

pub struct Server {
    clients: Arc<Mutex<HashMap<String, mpsc::Sender<Message>>>>,
    tls_acceptor: TlsAcceptor,
}

impl Server {
    pub fn new(
        ca_path: &str,
        cert_path: &str,
        key_path: &str,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let tls_config = build_server_tls_config(ca_path, cert_path, key_path)?;

        Ok(Server {
            clients: Arc::new(Mutex::new(HashMap::new())),
            tls_acceptor: TlsAcceptor::from(Arc::new(tls_config)),
        })
    }

    pub async fn start(&self, addr: &str) -> io::Result<()> {
        // bind listener, accept connections, spawn handler for each
        let listener = TcpListener::bind(addr).await?;
        println!("Server listening on {}", addr);

        loop {
            let (stream, peer_addr) = listener.accept().await?;
            println!("TCP connection from {}", peer_addr);

            let acceptor = self.tls_acceptor.clone();
            let server_clone = self.clone();

            tokio::spawn(async move {
                // mutual TLS handshake
                // server presents cert, client does same, then both sides verify
                match acceptor.accept(stream).await {
                    Ok(tls_stream) => {
                        let client_id = extract_client_id(&tls_stream);
                        println!("TLS established with {}", client_id);
                        server_clone.handle_client(tls_stream, client_id).await;
                    }
                    Err(e) => {
                        // handshake failure due to lack of cert or untrusted cert
                        eprintln!("TLS handshake failed from {}: {}", peer_addr, e);
                    }
                }
            });
        }
    }

    async fn handle_client(&self, _stream: TlsStream<TcpStream>, client_id: String) {
        // read messages from client, route to other clients
        println!("Secure client connected via mTLS stream: {}", client_id);
    }
}

impl Clone for Server {
    fn clone(&self) -> Self {
        Server {
            clients: Arc::clone(&self.clients),
            tls_acceptor: self.tls_acceptor.clone(),
        }
    }
}

// extract client identifier from peer's TLS cert
// pulls common name from unique cert
fn extract_client_id(stream: &TlsStream<TcpStream>) -> String {
    let (_, server_conn) = stream.get_ref();

    server_conn
        .peer_certificates()
        .and_then(|certs| certs.first())
        .and_then(|cert| {
            // pass DER-encoded cert with x509-parser to read common name of peer
            x509_parser::parse_x509_certificate(cert.as_ref())
                .ok()
                .and_then(|(_, parsed)| {
                    parsed
                        .subject()
                        .iter_common_name()
                        .next()
                        .and_then(|cn| cn.as_str().ok().map(String::from))
                })
        })
        .unwrap_or_else(|| "unknown client".to_string())
}
