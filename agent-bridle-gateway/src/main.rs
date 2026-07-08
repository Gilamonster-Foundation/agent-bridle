//! Binary entry point for `agent-bridle-gateway`.
//!
//! Binds an HTTP/WS server on `127.0.0.1:<port>` (loopback only — this is a
//! single-operator local service) and serves the two-tab presence + traffic
//! console. See the crate docs for the trust model.
//!
//! Usage: `agent-bridle-gateway [--port <PORT>] [--rp-id <HOST>]`
//! Defaults: port 8787, rp-id `localhost` (a WebAuthn secure context by
//! exemption; off-`localhost` set `--rp-id` to the served TLS origin).

use std::sync::Arc;

use agent_bridle_gateway::{app, AppState};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut port: u16 = 8787;
    let mut rp_id = String::from("localhost");

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--port" => {
                port = args
                    .next()
                    .ok_or("--port needs a value")?
                    .parse()
                    .map_err(|_| "--port must be a number")?;
            }
            "--rp-id" => {
                rp_id = args.next().ok_or("--rp-id needs a value")?;
            }
            "-h" | "--help" => {
                println!("agent-bridle-gateway [--port <PORT>] [--rp-id <HOST>]");
                return Ok(());
            }
            other => return Err(format!("unknown argument: {other}").into()),
        }
    }

    let state = Arc::new(AppState::new(rp_id));
    let router = app(state);

    let addr = format!("127.0.0.1:{port}");
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    println!("agent-bridle-gateway listening on http://{addr}  (mesh leg: mocked)");
    axum::serve(listener, router).await?;
    Ok(())
}
