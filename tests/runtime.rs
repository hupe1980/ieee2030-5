#![cfg(feature = "runtime")]
// 005-runtime/SR-001
mod support;
use bytes::Bytes;
use hyper::{Request, Response, StatusCode};
use ieee2030_5::runtime::{Limits, exchange, serve};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use tokio::net::{TcpListener, TcpStream};
#[tokio::test(flavor = "current_thread")]
async fn reject_oversized_body_before_handler_and_serve_past_idle_peer() {
    let fixtures = support::Setup::new();
    let client = fixtures.context(&fixtures.client);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let limits = Limits {
        max_body_bytes: 16,
        ..Limits::default()
    };
    let calls = Arc::new(AtomicUsize::new(0));
    let seen = calls.clone();
    let server = tokio::spawn(serve(
        listener,
        fixtures.context(&fixtures.server),
        limits,
        move |_, req| {
            seen.fetch_add(1, Ordering::SeqCst);
            Response::new(req.into_body())
        },
    ));
    let _slow_peer = TcpStream::connect(addr).await.unwrap();
    for (body, status, media) in [
        (
            "12345678901234567",
            StatusCode::PAYLOAD_TOO_LARGE,
            "application/sep+xml",
        ),
        (
            "exi",
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "application/sep-exi",
        ),
        ("ok", StatusCode::OK, "application/sep+xml"),
    ] {
        let req = Request::post("/unit")
            .header("Content-Type", media)
            .body(Bytes::from_static(body.as_bytes()))
            .unwrap();
        let response = exchange(addr, "server.local", &client, Limits::default(), req)
            .await
            .unwrap();
        assert_eq!(response.status(), status);
        if status == StatusCode::OK {
            assert_eq!(response.body(), "ok");
        }
    }
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    server.abort();
}
