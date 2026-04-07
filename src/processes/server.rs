use crate::protocol::message::Message;
use crate::tls::config_builder::build_server_tls_config;

use std::collections::HashMap;
use std::io;
use std::sync::{Arc, Mutex};

use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

use tokio_rustls::TlsAcceptor;
use tokio_rustls::server::TlsStream;

// number of messages allowed in TLS stream at once
const CHANNEL_BUFFER: usize = 64;

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

    async fn handle_client(&self, stream: TlsStream<TcpStream>, client_id: String) {
        // split into independent read and write halves for mpsc
        let (mut reader, mut writer) = tokio::io::split(stream);

        // create mpsc channel for this client
        // server holds `tx`, write task holds `rx`
        let (tx, mut rx) = mpsc::channel::<Message>(CHANNEL_BUFFER);

        // Register message
        {
            let mut map = self.clients.lock().unwrap();
            if map.contains_key(&client_id) {
                // duplicate identity - security threat!
                eprintln!("Duplicate client_id '{}', rejecting", client_id);
                return;
            }
            map.insert(client_id.clone(), tx);
            println!("Registered '{}'. Online: {}", client_id, map.len());
        }

        // write taks
        let write_task = tokio::spawn(async move {
            while let Some(msg) = rx.recv().await {
                if let Err(e) = msg.write_framed(&mut writer).await {
                    eprintln!("Write error: {}", e);
                    break;
                }
            }
            // graceful shutdown, flush and close write half of channel
            let _ = writer.shutdown().await;
        });

        // read loop
        loop {
            match Message::read_framed(&mut reader).await {
                Ok(msg) => {
                    self.route(msg, &client_id).await;
                }
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                    println!("Client '{}' disconnected", client_id);
                    break;
                }
                Err(e) => {
                    eprintln!("Read error from {}: {}", client_id, e);
                    break;
                }
            }
        }

        // deregister
        {
            let mut map = self.clients.lock().unwrap();
            map.remove(&client_id);
            println!("Deregistered '{}'. Online: {}", client_id, map.len());
        }

        write_task.abort();
    }

    async fn route(&self, msg: Message, from_id: &str) {
        match msg {
            // explicit deregister request from client
            Message::Deregsiter { client_id } => {
                let mut map = self.clients.lock().unwrap();
                map.remove(&client_id);
                println!("'{}' explicitly deregistered", client_id);
            }

            // client wants to send msg to another client
            Message::Send { to, content } => {
                let sender_opt = {
                    let map = self.clients.lock().unwrap();
                    map.get(&to).cloned()
                };

                match sender_opt {
                    Some(tx) => {
                        let delivery = Message::Receive {
                            from: from_id.to_string(),
                            content,
                        };
                        // mpsc is async so send outside of lock
                        if tx.send(delivery).await.is_err() {
                            // receiver dropped
                            eprintln!("Failed to deliver to '{}': channel closed", to);
                            self.send_error(from_id, format!("'{}' is no longer connected", to))
                                .await;
                        }
                    }
                    None => {
                        self.send_error(from_id, format!("Unknown recipient '{}'", to))
                            .await;
                    }
                }
            }

            // clients don't send recieve - protocol violation
            Message::Receive { .. } => {
                eprintln!("Protocol violation: '{}' sent a Receive message", from_id);
            }

            // client requests list of connected clients
            Message::List => {
                let list = {
                    let map = self.clients.lock().unwrap();
                    map.keys().cloned().collect::<Vec<_>>()
                };
                self.send_to(from_id, Message::ClientsList(list)).await;
            }

            // clients dont send ClientsList - protocol violation
            Message::ClientsList(_) => {
                eprintln!(
                    "Protocol violation: '{}' send a ClientsList message",
                    from_id
                );
            }

            Message::Error(_) => {
                eprintln!("'{}' sent an Error message (ignored)", from_id);
            }
        }
    }

    // helper to send messages through mpsc writer
    async fn send_to(&self, client_id: &str, msg: Message) {
        let tx_opt = {
            let map = self.clients.lock().unwrap();
            map.get(client_id).cloned()
        };
        if let Some(tx) = tx_opt {
            let _ = tx.send(msg).await;
        }
    }

    // helper to send errors back to client
    async fn send_error(&self, client_id: &str, err: String) {
        self.send_to(client_id, Message::Error(err)).await;
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
