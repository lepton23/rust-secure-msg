use crate::crypto::config_builder::build_client_tls_config;
use crate::protocol::message::Message;

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

        // spawn task to read messages from server
        let read_task = tokio::spawn(async move {
            loop {
                match Message::read_framed(&mut reader).await {
                    Ok(msg) => handle_incoming(msg),
                    Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                        println!("Server closed connection.");
                        break;
                    }
                    Err(e) => {
                        eprintln!("Read error: {}", e);
                        break;
                    }
                }
            }
        });

        self.interactive_loop(&mut writer).await?;

        // graceful shutdown
        let _ = Message::Deregsiter {
            client_id: self.client_id.clone(),
        }
        .write_framed(&mut writer)
        .await;

        writer.shutdown().await?;
        read_task.abort();

        Ok(())
    }

    // placeholder ui interactive loop
    // could use ratatui? or crossterm? - make it real nice
    //
    // also need to implement forward secrecy with e2e encryption
    async fn interactive_loop<W>(&self, writer: &mut W) -> io::Result<()>
    where
        W: tokio::io::AsyncWrite + Unpin,
    {
        use tokio::io::AsyncBufReadExt;
        let stdin = tokio::io::stdin();
        let mut lines = tokio::io::BufReader::new(stdin).lines();

        println!("Commands: list | send <to> <message> | quit");

        while let Some(line) = lines.next_line().await? {
            let trimmed = line.trim();
            if trimmed == "quit" {
                break;
            } else if trimmed == "list" {
                Message::List.write_framed(writer).await?;
            } else if let Some(rest) = trimmed.strip_prefix("send ") {
                if let Some((to, content)) = rest.split_once(' ') {
                    Message::Send {
                        to: to.to_string(),
                        content: content.to_string(),
                    }
                    .write_framed(writer)
                    .await?;
                } else {
                    eprintln!("Usage: send <recipient_id> <message>");
                }
            } else {
                eprintln!("Unknown command: {}", trimmed);
            }
        }
        Ok(())
    }
}

// handle message from server
fn handle_incoming(msg: Message) {
    match msg {
        Message::Receive { from, content } => {
            println!("[{}]: {}", from, content);
        }
        Message::ClientsList(clients) => {
            println!("Online clients: {}", clients.join(", "));
        }
        Message::Error(err) => {
            eprintln!("Server error: {}", err);
        }
        other => {
            eprintln!("Unexpected message from server: {:?}", other);
        }
    }
}
