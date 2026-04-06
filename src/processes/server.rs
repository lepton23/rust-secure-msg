use crate::protocol::message::Message;
use std::collections::HashMap;
use std::io;
use std::sync::{Arc, Mutex};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::rustls::server::WebPkiClientVerifier;
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsAcceptor;

pub async fn run() {
    let server = Server::new().expect("Failed to initialise TLS server");
    if let Err(e) = server.start("127.0.0.1:8080").await {
        eprintln!("Server error: {}", e);
    }
}

pub struct Server {
    clients: Arc<Mutex<HashMap<String, mpsc::Sender<Message>>>>,
    tls_acceptor: TlsAcceptor,
}

impl Server {
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let tls_config = build_tls_config()?;

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

// Build Rustls TLS config
// Security policy lives here - CA for certs, cipher suites etc
fn build_tls_config() -> Result<ServerConfig, Box<dyn std::error::Error>> {
    // Load CA certificate used to verify client certs
    let ca_cert_pem = std::fs::read("certs/ca.pem")?;
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
    let server_cert_pem: Vec<u8> = std::fs::read("certs/server.pem")?;
    let server_certs = rustls_pemfile::certs(&mut server_cert_pem.as_slice())
        .collect::<Result<Vec<CertificateDer>, _>>()?;

    let server_key_pem: Vec<u8> = std::fs::read("certs/server-key.pem")?;
    let server_key = rustls_pemfile::private_key(&mut server_key_pem.as_slice())?
        .ok_or("no private key found in server-key.pem")?;

    // Rustls defaults to TLS 1.2 & 1.3 which both mandate forward secrecy - ephemeral key exchange & elliptic curve DHKE
    let config = ServerConfig::builder()
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(server_certs, PrivateKeyDer::from(server_key))?;

    Ok(config)
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
