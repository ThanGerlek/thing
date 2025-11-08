use serde::{Deserialize, Serialize};

// These structs provide formats for a Hello message, Encrypted message, and
// Server response.

// The #derive allows these structs to be serialized and deserialized

// DO NOT MODIFY THIS FILE!

#[derive(Serialize, Deserialize)]
pub struct HelloMessage {
    pub signed_message: Vec<u8>,
    pub pub_key: String,
    pub nonce: [u8; 32],
}

impl HelloMessage {
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    pub fn from_json(message: String) -> Result<HelloMessage, serde_json::Error> {
        serde_json::from_str(&message)
    }
}

#[derive(Serialize, Deserialize)]
pub struct EncryptedMessage {
    pub encrypted_key: Vec<u8>,
    pub nonce_bytes: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

impl EncryptedMessage {
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    pub fn from_json(message: String) -> Result<EncryptedMessage, serde_json::Error> {
        serde_json::from_str(&message)
    }
}

#[derive(Serialize, Deserialize)]
pub struct ServerResponse {
    pub encrypted_message: Vec<u8>,
    pub nonce_bytes: Vec<u8>,
}

impl ServerResponse {
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    pub fn from_json(message: String) -> Result<ServerResponse, serde_json::Error> {
        serde_json::from_str(&message)
    }
}
