//! Integration tests for the `web_fetch` net leash, against a localhost mock
//! server (so CI needs no external network).
//!
//! These exercise the headline guarantees of DESIGN §7 end-to-end through the
//! real [`WebFetchTool`] and a real (loopback) HTTP server:
//!
//! - a fetch to the mock SUCCEEDS and returns extracted markdown **only** when
//!   the loopback host is explicitly opted into the `net` allowlist;
//! - the **same** fetch is DENIED when the grant is `net: Only{example.com}`
//!   (loopback neither permitted nor opted in) — proving both the host
//!   allowlist *and* the SSRF block;
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

/// A grant that explicitly allowlists the loopback host (opting it into
/// loopback-IP space) with a small call budget.
fn loopback_grant() -> Caveats {
    Caveats {
        net: Scope::only(["127.0.0.1".to_string()]),
        max_calls: CountBound::AtMost(5),
        ..Caveats::top()
    }
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

    // host = 127.0.0.1, explicitly allowlisted -> opted into loopback space.
    let cx = authorize(&loopback_grant());
    let url = format!("http://127.0.0.1:{}/article", server.port());

    let out = WebFetchTool::new()
        .invoke(serde_json::json!({ "url": url }), &cx)
        .await
        .expect("fetch should succeed for an explicitly-allowlisted loopback host");

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

    let err = WebFetchTool::new()
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

    let out = WebFetchTool::new()
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
