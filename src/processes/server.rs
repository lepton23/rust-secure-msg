use crate::protocol::message::Message;
use std::collections::HashMap;
use std::io;
use std::sync::{Arc, Mutex};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

pub async fn run() {
    let server = Server::new();
    if let Err(e) = server.start("127.0.0.1:8080").await {
        eprintln!("Server error: {}", e);
    }
}

pub struct Server {
    clients: Arc<Mutex<HashMap<String, mpsc::Sender<Message>>>>,
}

impl Server {
    pub fn new() -> Self {
        Server {
            clients: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub async fn start(&self, addr: &str) -> io::Result<()> {
        // bind listener, accept connections, spawn handler for each
        let listener = TcpListener::bind(addr).await?;
        println!("Server listening on {}", addr);

        loop {
            let (stream, _) = listener.accept().await?;

            // placeholder client id for now
            // later clients will send a registration message
            let client_id = format!("client_{}", self.clients.lock().unwrap().len());

            let server_clone = self.clone();
            tokio::spawn(async move {
                server_clone.handle_client(stream, client_id).await;
            });
        }
    }

    async fn handle_client(&self, stream: TcpStream, client_id: String) {
        // read messages from client, route to other clients
        println!("New client connected: {}", client_id);
    }
}

impl Clone for Server {
    fn clone(&self) -> Self {
        Server {
            clients: Arc::clone(&self.clients),
        }
    }
}
