//! Tiny TCP-connect probe for the AppContainer **net** kernel proofs.
//!
//! `ab-netprobe [tcp|udp] <host> <port>` exits `0` if the network operation to
//! `host:port` succeeds within a short timeout, and `1` otherwise. Run as the
//! confined child of `agent-bridle-aclaunch`, it turns "can this AppContainer
//! reach the socket?" into a clean exit code.

use std::net::{SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::time::Duration;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let (mode, host, port) = if args.len() == 3 {
        ("tcp", args[1].as_str(), args[2].as_str())
    } else if args.len() == 4 && matches!(args[1].as_str(), "tcp" | "udp") {
        (args[1].as_str(), args[2].as_str(), args[3].as_str())
    } else {
        eprintln!("usage: ab-netprobe [tcp|udp] <host> <port>");
        std::process::exit(2);
    };
    let addr = format!("{host}:{port}");
    let addrs: Vec<SocketAddr> = match addr.to_socket_addrs() {
        Ok(addrs) => addrs.collect(),
        Err(e) => {
            eprintln!("ab-netprobe: resolve {mode} {addr} failed: {e}");
            std::process::exit(1);
        }
    };
    if addrs.is_empty() {
        eprintln!("ab-netprobe: resolve {mode} {addr} failed: no addresses");
        std::process::exit(2);
    }

    let mut last = String::from("no address resolved");
    for sa in addrs {
        match mode {
            "tcp" => match TcpStream::connect_timeout(&sa, Duration::from_secs(3)) {
                Ok(_) => std::process::exit(0),
                Err(e) => last = e.to_string(),
            },
            "udp" => {
                let bind = if sa.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
                match UdpSocket::bind(bind).and_then(|sock| sock.send_to(b"ping", sa)) {
                    Ok(_) => std::process::exit(0),
                    Err(e) => last = e.to_string(),
                }
            }
            _ => unreachable!("mode parser only accepts tcp or udp"),
        };
    }
    eprintln!("ab-netprobe: {mode} to {addr} failed: {last}");
    std::process::exit(1);
}
