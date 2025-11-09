use std::net::TcpStream;
use std::io;
use std::io::Read;
use std::io::Write;
use std::string::FromUtf8Error;

use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm,
    Key,
    Nonce,
};

mod messages;
use messages::{EncryptedMessage, HelloMessage, ServerResponse};

use rand::thread_rng;
use rand::RngCore;

use rsa::{Pkcs1v15Encrypt, RsaPublicKey};
use rsa::pkcs8::DecodePublicKey;
use rsa::pss::{Signature, VerifyingKey};
use rsa::sha2::Sha256;
use rsa::signature::Verifier;


fn main() {
    let mut stream = match TcpStream::connect("127.0.0.1:2222") {
        Ok(stream) => stream,
        Err(_e) => {
            println!("Could not connect to server. Check that it is running");
            return ();
        }
    };
    println!("Connected to server");

    // sends a Hello Message
    let hello_response = send_hello(&mut stream).unwrap();

    // parses the server response
    let pub_key: RsaPublicKey = parse_hello_response(hello_response).unwrap();

    // loops:
    loop {
        let mut input = String::new();
        // reads some text from the terminal
        print!("Enter message: ");
        io::stdin().read_line(&mut input).expect("Failed to read input");
        // if the text is “exit”, break from the loop
        if input == "exit" {
            break;
        };
        // otherwise...
        let output = handle_input(input, &mut stream, &pub_key).unwrap();
        println!("{}", output);
    }
}


//
// Hello Messages
//

fn send_hello(stream: &mut TcpStream) -> Result<HelloMessage, MyError> {
    let msg = HelloMessage {
        signed_message: vec![],
        pub_key: "".to_string(),
        nonce: generate_nonce(),
    };

    let msg = msg.to_json();
    stream.write_all(msg?.as_bytes())?;

    let mut buffer = [0; 4096];
    let bytes_read = stream.read(&mut buffer)?;
    let response_json = str::from_utf8(&buffer[..bytes_read]).expect("Server response not in UTF8").to_string();

    return Ok(HelloMessage::from_json(response_json)?);
}

fn parse_hello_response(hello_response: HelloMessage) -> Result<RsaPublicKey, MyError> {
    let server_public_key_pem: String = hello_response.pub_key;
    let signed_nonce: Vec<u8> = hello_response.signed_message;
    let nonce: [u8; 32] = hello_response.nonce;

    // Convert from PEM format
    let pub_key: RsaPublicKey = RsaPublicKey::from_public_key_pem(&server_public_key_pem)?;
    
    // Derive the verifying key from the public key   
    let verifying_key: VerifyingKey<Sha256> = VerifyingKey::from(pub_key.clone());
    
    // Verify the PKCS#1 v1.5 signature on the nonce
    let signature = Signature::try_from(&nonce[..])?;
    verifying_key.verify(&signed_nonce, &signature)?;  // FIXME Verification error

    return Ok(pub_key);
}


//
//  Encrypted Messages
//

fn handle_input(message: String, stream: &mut TcpStream, pub_key: &RsaPublicKey) -> Result<String, MyError> {

    //        Send an Encrypted Message

    // Create a new symmetric key K
    let symmetric_key = Aes256Gcm::generate_key(OsRng);
    
    // Create a new nonce
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    
    // Encrypt the message with K
    let symmetric_cipher = Aes256Gcm::new(&symmetric_key);
    let ciphertext: Vec<u8> = symmetric_cipher.encrypt(&nonce, message.as_ref())?;

    // Encrypt that key K with the server’s public key
    let mut rng = rand::thread_rng();
    let encrypted_symmetric_key = pub_key.encrypt(&mut rng, Pkcs1v15Encrypt, symmetric_key.as_ref())?;

    // Actually build and send the message
    let msg = EncryptedMessage {
        encrypted_key: encrypted_symmetric_key,
        nonce_bytes: nonce.to_vec(),
        ciphertext: ciphertext,
    };

    let msg = msg.to_json();
    stream.write_all(msg?.as_bytes())?;

    // Read the response
    let mut buffer = [0; 4096];
    let bytes_read = stream.read(&mut buffer)?;
    let message_json = str::from_utf8(&buffer[..bytes_read]).expect("Server response not in UTF8").to_string();
    let message = ServerResponse::from_json(message_json)?;


    //        Parse the Server Response

    let outer_nonce: Vec<u8> = message.nonce_bytes;
    let outer_nonce = Nonce::from_slice(&outer_nonce[..]);
    let message: Vec<u8> = message.encrypted_message;

    // Extract underlying EncryptedMessage data
    let message: String = String::from_utf8(message)?;
    let message: EncryptedMessage = EncryptedMessage::from_json(message)?;

    let inner_nonce: Vec<u8> = message.nonce_bytes;
    let inner_nonce = Nonce::from_slice(&inner_nonce[..]);
    let inner_key: Vec<u8> = message.encrypted_key;
    let message: Vec<u8> = message.ciphertext;

    // Decrypt key using symmetric key and nonce
    let cipher = Aes256Gcm::new(&symmetric_key);
    let inner_key: Vec<u8> = cipher.decrypt(&outer_nonce, inner_key.as_ref())?;
    let inner_key = Key::<Aes256Gcm>::from_slice(&inner_key);
    
    // Decrypt message
    let cipher = Aes256Gcm::new(&inner_key);
    let message: Vec<u8> = cipher.decrypt(&inner_nonce, message.as_ref())?;

    let message = String::from_utf8(message)?;

    return Ok(message);
}


//
//    Misc
//

fn generate_nonce() -> [u8; 32] {
    let mut nonce = [0u8; 32];
    thread_rng().fill_bytes(&mut nonce);
    return nonce;
}


#[allow(dead_code)]
#[derive(Debug)]
enum MyError {
    Io(io::Error),
    Json(serde_json::Error),
    AesGcm(aes_gcm::Error),
    RsaPkcs8Spki(rsa::pkcs8::spki::Error),
    RsaSignature(rsa::signature::Error),
    Rsa(rsa::Error),
    FromUtf8(FromUtf8Error),
}

impl From<io::Error> for MyError {
    fn from(e: io::Error) -> Self {
        MyError::Io(e)
    }
}

impl From<serde_json::Error> for MyError {
    fn from(e: serde_json::Error) -> Self {
        MyError::Json(e)
    }
}

impl From<aes_gcm::Error> for MyError {
    fn from(e: aes_gcm::Error) -> Self {
        MyError::AesGcm(e)
    }
}

impl From<rsa::pkcs8::spki::Error> for MyError {
    fn from(e: rsa::pkcs8::spki::Error) -> Self {
        MyError::RsaPkcs8Spki(e)
    }
}

impl From<rsa::signature::Error> for MyError {
    fn from(e: rsa::signature::Error) -> Self {
        MyError::RsaSignature(e)
    }
}

impl From<rsa::Error> for MyError {
    fn from(e: rsa::Error) -> Self {
        MyError::Rsa(e)
    }
}

impl From<FromUtf8Error> for MyError {
    fn from(e: FromUtf8Error) -> Self {
        MyError::FromUtf8(e)
    }
}
