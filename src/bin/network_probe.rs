use std::net::{TcpListener, UdpSocket};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().is_some_and(|arg| arg == "--exit-code") {
        let code = args
            .get(1)
            .and_then(|value| value.parse::<i32>().ok())
            .unwrap_or(2);
        std::process::exit(code);
    }
    if args.first().is_some_and(|arg| arg == "--spawn-child") {
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exit-code", "0"])
            .status()
            .unwrap();
        std::process::exit(if status.success() { 0 } else { 1 });
    }
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
