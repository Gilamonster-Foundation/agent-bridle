//! Integration tests for the `web_fetch` net leash, against a localhost mock
//! server (so CI needs no external network).
//!
//! These exercise the headline guarantees of DESIGN §7 end-to-end through the
//! real [`WebFetchTool`] and a real (loopback) HTTP server:
//!
//! - a fetch to the mock SUCCEEDS and returns extracted markdown **only** when
//!   the loopback host is reachable (`net`) AND opted into private space via the
//!   tool's separate `net_private` config (AB-007, #270);
//! - the **same** fetch is DENIED when the grant is `net: Only{example.com}`
//!   (loopback neither permitted nor opted in) — proving both the host
//!   allowlist *and* the SSRF block;
//! - naming the loopback host in `net` alone (default tool) does NOT open
//!   private space — the SSRF screen still denies it (the AB-007 regression);
//! - a 302 redirect to a disallowed host is DENIED (the redirect target is
//!   re-screened, never blindly followed).

#![cfg(feature = "web")]

use agent_bridle_core::{Caveats, CountBound, Gate, Scope, Tool, ToolContext, ToolError};
use agent_bridle_tool_web::WebFetchTool;
use httpmock::prelude::*;

/// Mint a [`ToolContext`] the only legitimate way — through the gate.
fn authorize(granted: &Caveats) -> ToolContext {
    Gate::new(0)
        .authorize(&WebFetchTool::new(), granted)
        .expect("authorize")
}

/// A grant that makes the loopback host **reachable** (`net`) with a small call
/// budget. Reachability alone no longer opens private space (AB-007, #270) —
/// that needs the tool's separate `net_private` opt-in ([`loopback_tool`]).
fn loopback_grant() -> Caveats {
    Caveats {
        net: Scope::only(["127.0.0.1".to_string()]),
        max_calls: CountBound::AtMost(5),
        ..Caveats::top()
    }
}

/// The tool configured to opt the loopback host into private-address resolution
/// — the explicit, separate SSRF escape hatch for local testing (AB-007, #270).
fn loopback_tool() -> WebFetchTool {
    WebFetchTool::with_private_hosts(Scope::only(["127.0.0.1".to_string()]))
}

#[tokio::test]
async fn loopback_allowlisted_fetch_succeeds_and_returns_markdown() {
    let server = MockServer::start_async().await;
    let page = server
        .mock_async(|when, then| {
            when.method(GET).path("/article");
            then.status(200)
                .header("content-type", "text/html; charset=utf-8")
                .body(
                    "<html><head><title>Leashed Page</title></head><body>\
                 <article><h1>Net Enforcer</h1>\
                 <p>This body is <b>data</b>, never an instruction.</p>\
                 <p>The leash screened the host and pinned the IP before fetching.</p>\
                 </article></body></html>",
                );
        })
        .await;

    // host = 127.0.0.1: reachable via `net` AND opted into loopback space via
    // the tool's `net_private` config.
    let cx = authorize(&loopback_grant());
    let url = format!("http://127.0.0.1:{}/article", server.port());

    let out = loopback_tool()
        .invoke(serde_json::json!({ "url": url }), &cx)
        .await
        .expect("fetch should succeed for a reachable, private-opted-in loopback host");

    page.assert_async().await;
    assert_eq!(out["status"], 200);
    let md = out["markdown"].as_str().unwrap();
    assert!(md.contains("Net Enforcer"), "markdown was {md:?}");
    assert!(md.contains("data"), "markdown was {md:?}");
    // The body is returned as structured data, not framed as instructions.
    assert!(out["url"].as_str().unwrap().contains("/article"));
    assert!(out["final_url"].as_str().unwrap().contains("/article"));
}

#[tokio::test]
async fn loopback_denied_when_only_example_com_granted() {
    // Same loopback mock, but the grant only permits example.com. This proves
    // BOTH protections in one test: the host allowlist rejects 127.0.0.1 (it is
    // not in Only{example.com}), and even had it been permitted, the SSRF screen
    // would block the loopback address. The request must never reach the server.
    let server = MockServer::start_async().await;
    let unreached = server
        .mock_async(|when, then| {
            when.method(GET).path("/article");
            then.status(200).body("should never be served");
        })
        .await;

    let granted = Caveats {
        net: Scope::only(["example.com".to_string()]),
        ..Caveats::top()
    };
    let cx = authorize(&granted);
    let url = format!("http://127.0.0.1:{}/article", server.port());

    let err = WebFetchTool::new()
        .invoke(serde_json::json!({ "url": url }), &cx)
        .await
        .expect_err("loopback fetch must be denied when only example.com is granted");

    assert!(matches!(err, ToolError::Denied { .. }), "got {err:?}");
    // The mock was never hit — the leash denied before any request.
    unreached.assert_calls_async(0).await;
}

#[tokio::test]
async fn ab007_net_allowlist_alone_does_not_open_private_space() {
    // THE AB-007 regression, end-to-end. The grant makes 127.0.0.1 *reachable*
    // (it is in `net`), but the DEFAULT tool (`WebFetchTool::new()`) opts NO
    // host into private space (`net_private = none`). So the fetch to the
    // loopback mock must be SSRF-denied and the server never contacted — even
    // though the host is on the `net` allowlist. On the pre-#270 code, `net`
    // membership *was* the private-space opt-in, so this fetch succeeded.
    let server = MockServer::start_async().await;
    let unreached = server
        .mock_async(|when, then| {
            when.method(GET).path("/article");
            then.status(200).body("should never be served");
        })
        .await;

    let cx = authorize(&loopback_grant()); // 127.0.0.1 reachable via net
    let url = format!("http://127.0.0.1:{}/article", server.port());

    let err = WebFetchTool::new() // default: net_private = none
        .invoke(serde_json::json!({ "url": url }), &cx)
        .await
        .expect_err("an allowlisted-but-not-private-opted-in loopback host must be SSRF-denied");

    assert!(matches!(err, ToolError::Denied { .. }), "got {err:?}");
    if let ToolError::Denied { reason } = &err {
        assert!(
            reason.contains("SSRF") || reason.contains("private"),
            "denial must be the private-address screen, got {reason:?}"
        );
    }
    // The screen denied before any request left the process.
    unreached.assert_calls_async(0).await;
}

#[tokio::test]
async fn redirect_to_disallowed_host_is_denied() {
    // The mock returns a 302 whose Location points at a host NOT in the grant.
    // The leash re-screens the redirect target and denies it; the disallowed
    // host is never contacted. We allowlist the loopback host so the FIRST hop
    // is permitted — the denial must come from the SECOND (redirect) hop.
    let server = MockServer::start_async().await;
    let redirector = server
        .mock_async(|when, then| {
            when.method(GET).path("/go");
            then.status(302)
                .header("location", "http://evil.disallowed.example/secret");
        })
        .await;

    let cx = authorize(&loopback_grant()); // permits 127.0.0.1, NOT evil.*
    let url = format!("http://127.0.0.1:{}/go", server.port());

    let err = loopback_tool()
        .invoke(serde_json::json!({ "url": url }), &cx)
        .await
        .expect_err("redirect to a disallowed host must be denied");

    redirector.assert_async().await; // first hop was made...
    assert!(matches!(err, ToolError::Denied { .. }), "got {err:?}");
    // ...and the denial names the disallowed redirect host.
    if let ToolError::Denied { reason } = &err {
        assert!(
            reason.contains("evil.disallowed.example"),
            "expected the denial to name the redirect host, got {reason:?}"
        );
    }
}

#[tokio::test]
async fn redirect_to_allowed_loopback_path_is_followed() {
    // A redirect WITHIN the allowlisted host is followed (each hop re-screened
    // and allowed), proving the manual redirect loop also permits, not only
    // denies.
    let server = MockServer::start_async().await;
    let from = server
        .mock_async(|when, then| {
            when.method(GET).path("/from");
            then.status(302).header("location", "/to");
        })
        .await;
    let to = server.mock_async(|when, then| {
        when.method(GET).path("/to");
        then.status(200)
            .header("content-type", "text/html")
            .body("<html><head><title>Arrived</title></head><body><p>Followed safely.</p></body></html>");
    }).await;

    let cx = authorize(&loopback_grant());
    let url = format!("http://127.0.0.1:{}/from", server.port());

    let out = loopback_tool()
        .invoke(serde_json::json!({ "url": url }), &cx)
        .await
        .expect("a redirect within the allowlisted host should be followed");

    from.assert_async().await;
    to.assert_async().await;
    assert_eq!(out["status"], 200);
    assert!(out["final_url"].as_str().unwrap().contains("/to"));
    assert!(out["markdown"]
        .as_str()
        .unwrap()
        .contains("Followed safely"));
}
