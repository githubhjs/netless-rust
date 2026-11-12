use std::net::{TcpListener, UdpSocket};

fn main() {
    match TcpListener::bind("127.0.0.1:0") {
        Ok(listener) => {
            println!(
                "loopback TCP bind allowed: {}",
                listener.local_addr().unwrap()
            );
        }
        Err(error) => println!("loopback TCP bind blocked: {error}"),
    }
    match UdpSocket::bind("127.0.0.1:0") {
        Ok(socket) => {
            let result = socket.send_to(b"netless probe", "127.0.0.1:9");
            println!("loopback UDP send result: {result:?}");
        }
        Err(error) => println!("loopback UDP socket blocked: {error}"),
    }
}
