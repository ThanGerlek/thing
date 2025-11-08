use std::net::TcpStream;

mod messages;
use messages::{EncryptedMessage, HelloMessage, ServerResponse};

fn main() {
    let mut stream = match TcpStream::connect("127.0.0.1:2222") {
        Ok(stream) => stream,
        Err(_e) => {
            println!("Could not connect to server. Check that it is running");
            return ();
        }
    };
    println!("Connected to server");
}
