use std::io;
use std::io::Read;
use std::io::Write;
use std::net::TcpStream;

use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};

mod messages;
use messages::{EncryptedMessage, HelloMessage, ServerResponse};

use rand::thread_rng;
use rand::RngCore;

use rsa::pkcs1v15::{Signature, VerifyingKey};
use rsa::pkcs8::DecodePublicKey;
// use rsa::pss::{Signature, VerifyingKey};
use rsa::sha2::Sha256;
use rsa::signature::Verifier;
use rsa::{Pkcs1v15Encrypt, RsaPublicKey};

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
    let (hello_response, nonce) = send_hello(&mut stream);

    // parses the server response
    let pub_key: RsaPublicKey = parse_hello_response(hello_response, nonce);

    // loops:
    loop {
        let mut input = String::new();
        // reads some text from the terminal
        println!("Enter message:");
        io::stdin()
            .read_line(&mut input)
            .expect("Failed to read input");
        // if the text is “exit”, break from the loop
        if input.contains("exit") {
            break;
        };
        // otherwise...
        let output = handle_input(input, &mut stream, &pub_key);
        println!("Client received: {}", output);
    }
}

//
// Hello Messages
//

fn send_hello(stream: &mut TcpStream) -> (HelloMessage, [u8; 32]) {
    // let nonce = generate_nonce();
    let nonce: [u8; 32] = [
        154, 13, 198, 96, 91, 118, 75, 241, 229, 58, 170, 15, 164, 137, 49, 222, 108, 79, 232, 121,
        226, 165, 25, 251, 138, 222, 179, 25, 169, 234, 82, 38,
    ];
    let message = HelloMessage {
        signed_message: vec![],
        pub_key: "".to_string(),
        nonce,
    };

    let message = message.to_json().unwrap();
    stream.write_all(message.as_bytes()).unwrap();

    let mut buffer = [0; 4096];
    let bytes_read = stream.read(&mut buffer).unwrap();
    let response_json = str::from_utf8(&buffer[..bytes_read])
        .expect("Server response not in UTF8")
        .to_string();
    let response = HelloMessage::from_json(response_json.clone()).unwrap();
    
    return (response, nonce);
}

fn parse_hello_response(hello_response: HelloMessage, nonce: [u8; 32]) -> RsaPublicKey {
    let server_public_key_pem: String = hello_response.pub_key;
    let signed_nonce: Vec<u8> = hello_response.signed_message;
    let server_nonce: [u8; 32] = hello_response.nonce;

    if server_nonce != nonce {
        panic!("Nonces don't match!");
    }

    // Convert from PEM format
    let pub_key: RsaPublicKey = RsaPublicKey::from_public_key_pem(&server_public_key_pem).unwrap();

    // Derive the verifying key from the public key
    let verifying_key: VerifyingKey<Sha256> = VerifyingKey::from(pub_key.clone());

    // Verify the PKCS#1 v1.5 signature on the nonce
    let signature = Signature::try_from(&signed_nonce[..]).unwrap();
    match verifying_key.verify(&nonce, &signature) { // FIXME Verification error
        Ok(_) => (),
        Err(e) => println!("Signature failed to verify: {}", e)
    };

    return pub_key;
}

//
//  Encrypted Messages
//

fn handle_input(message: String, stream: &mut TcpStream, pub_key: &RsaPublicKey) -> String {
    //        Send an Encrypted Message

    // Create a new symmetric key K
    let symmetric_key = Aes256Gcm::generate_key(OsRng);

    // Create a new nonce
    let sending_nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    // Encrypt the message with K
    let symmetric_cipher = Aes256Gcm::new(&symmetric_key);
    let sending_ciphertext: Vec<u8> = symmetric_cipher.encrypt(&sending_nonce, message.as_ref()).unwrap();

    // Encrypt that key K with the server’s public key
    let mut rng = rand::thread_rng();
    let encrypted_symmetric_key = pub_key
        .encrypt(&mut rng, Pkcs1v15Encrypt, symmetric_key.as_ref())
        .unwrap();

    // Actually build and send the message
    let sending_encrypted_message = EncryptedMessage {
        encrypted_key: encrypted_symmetric_key,
        nonce_bytes: sending_nonce.to_vec(),
        ciphertext: sending_ciphertext,
    };

    let sending_encrypted_message_json = sending_encrypted_message.to_json().unwrap();
    stream.write_all(sending_encrypted_message_json.as_bytes()).unwrap();

    // Read the response
    let mut buffer = [0; 4096];
    let bytes_read = stream.read(&mut buffer).unwrap();
    let received_message_json = str::from_utf8(&buffer[..bytes_read]).unwrap().to_string();
    let server_response = ServerResponse::from_json(received_message_json.clone()).unwrap();

    //        Parse the Server Response

    // Extract
    let ciphertext: Vec<u8> = server_response.encrypted_message;
    let receiving_nonce: Vec<u8> = server_response.nonce_bytes;
    #[allow(deprecated)]
    let receiving_nonce = Nonce::from_slice(&receiving_nonce[..]);

    // Decrypt
    let cipher = Aes256Gcm::new(&symmetric_key);
    let plaintext: Vec<u8> = cipher.decrypt(&receiving_nonce, ciphertext.as_ref()).unwrap();
    let plaintext: String = String::from_utf8(plaintext).unwrap();

    return plaintext;
}

//
//    Misc
//

#[allow(dead_code)]
fn generate_nonce() -> [u8; 32] {
    let mut nonce = [0u8; 32];
    thread_rng().fill_bytes(&mut nonce);
    return nonce;
}

// #[allow(dead_code)]
// #[derive(Debug)]
// enum MyError {
//     Io(io::Error),
//     Json(serde_json::Error),
//     AesGcm(aes_gcm::Error),
//     RsaPkcs8Spki(rsa::pkcs8::spki::Error),
//     RsaSignature(rsa::signature::Error),
//     Rsa(rsa::Error),
//     FromUtf8(FromUtf8Error),
// }

// impl From<io::Error> for MyError {
//     fn from(e: io::Error) -> Self {
//         MyError::Io(e)
//     }
// }

// impl From<serde_json::Error> for MyError {
//     fn from(e: serde_json::Error) -> Self {
//         MyError::Json(e)
//     }
// }

// impl From<aes_gcm::Error> for MyError {
//     fn from(e: aes_gcm::Error) -> Self {
//         MyError::AesGcm(e)
//     }
// }

// impl From<rsa::pkcs8::spki::Error> for MyError {
//     fn from(e: rsa::pkcs8::spki::Error) -> Self {
//         MyError::RsaPkcs8Spki(e)
//     }
// }

// impl From<rsa::signature::Error> for MyError {
//     fn from(e: rsa::signature::Error) -> Self {
//         MyError::RsaSignature(e)
//     }
// }

// impl From<rsa::Error> for MyError {
//     fn from(e: rsa::Error) -> Self {
//         MyError::Rsa(e)
//     }
// }

// impl From<FromUtf8Error> for MyError {
//     fn from(e: FromUtf8Error) -> Self {
//         MyError::FromUtf8(e)
//     }
// }
