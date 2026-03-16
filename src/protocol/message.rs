use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Message {
    Register { client_id: String },
    Send { to: String, content: String },
    Receive { from: String, content: String },
    List,
    ClientsList(Vec<String>),
    Error(String),
}
