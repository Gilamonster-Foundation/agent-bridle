//! Tiny TCP-connect probe for the AppContainer **net** kernel proofs.
//!
//! `ab-netprobe <host> <port>` exits `0` if a TCP connection to `host:port`
//! succeeds within a short timeout, and `1` otherwise. Run as the confined child of
//! `agent-bridle-aclaunch`, it turns "can this AppContainer reach the socket?" into
//! a clean exit code — so a proof can assert the kernel *blocks* loopback egress by
//! default and *permits* it under `--loopback-exemption`. Std-only, cross-platform.

use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("usage: ab-netprobe <host> <port>");
        std::process::exit(2);
    }
    let addr = format!("{}:{}", args[1], args[2]);
    let mut last = String::from("no address resolved");
    match addr.to_socket_addrs() {
        Ok(addrs) => {
            for sa in addrs {
                match TcpStream::connect_timeout(&sa, Duration::from_secs(3)) {
                    Ok(_) => std::process::exit(0),
                    Err(e) => last = e.to_string(),
                }
            }
        }
        Err(e) => last = e.to_string(),
    }
    eprintln!("ab-netprobe: connect to {addr} failed: {last}");
    std::process::exit(1);
}
