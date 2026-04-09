use serde::{Deserialize, Serialize};
use std::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Message {
    Deregister { client_id: String },
    // Encrypted content: `nonce (12 bytes) || ciphertext`
    Send { to: String, content: Vec<u8> },
    // Encrypted content: `nonce (12 bytes) || ciphertext`
    Receive { from: String, content: Vec<u8> },
    List,
    ClientsList(Vec<String>),
    Error(String),
    /// Sent by a client immediately after connecting to register both halves of
    /// its hybrid E2E public key.
    AnnounceKey {
        x25519_key: [u8; 32],
        /// ML-KEM-768 encapsulation key (1184 bytes).
        mlkem_ek: Vec<u8>,
    },
    /// Ask the server for another client's hybrid E2E public key.
    RequestKey { client_id: String },
    /// Server reply carrying the requested client's hybrid E2E public key.
    KeyResponse {
        client_id: String,
        x25519_key: [u8; 32],
        /// ML-KEM-768 encapsulation key (1184 bytes).
        mlkem_ek: Vec<u8>,
    },
}

impl Message {
    // serialise to bytes with 4 byte big endian length header
    // [u32 length][binary payload]
    pub fn serialise(&self) -> Vec<u8> {
        let payload = bincode::serialize(self).expect("cannot serialise this type");
        let len = payload.len() as u32;
        let mut buf = Vec::with_capacity(4 + payload.len());
        buf.extend_from_slice(&len.to_be_bytes());
        buf.extend_from_slice(&payload);
        buf
    }

    // read framed message from async reader
    pub async fn read_framed<R>(reader: &mut R) -> io::Result<Self>
    where
        R: AsyncReadExt + Unpin,
    {
        // Read size header
        let mut len_buf = [0u8; 4];
        reader.read_exact(&mut len_buf).await?;
        let len = u32::from_be_bytes(len_buf) as usize;

        // filter out corrupted frames
        if len > 8 * 1024 * 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "frame too large",
            ));
        }

        // read payload bytes
        let mut payload = vec![0u8; len];
        reader.read_exact(&mut payload).await?;

        bincode::deserialize(&payload).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    // write framed message to async writer
    pub async fn write_framed<W>(&self, writer: &mut W) -> io::Result<()>
    where
        W: AsyncWriteExt + Unpin,
    {
        let framed = self.serialise();
        writer.write_all(&framed).await?;
        writer.flush().await
    }
}
