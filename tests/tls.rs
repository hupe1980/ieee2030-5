#![cfg(feature = "runtime")]
// 002-identity-and-tls/SR-001 and 002-identity-and-tls/SR-002
mod support;
use bytes::Bytes;
use hyper::{Request, Response};
use ieee2030_5::{
    runtime::{Limits, exchange, serve, tls_context},
    security::Lfdi,
};
use support::{Setup, mint};
use tokio::net::TcpListener;
#[tokio::test(flavor = "current_thread")]
async fn private_roots_authenticate_both_peers_and_require_the_expected_hostname() {
    let fixtures = Setup::new();
    let expected = Lfdi::from_certificate_der(&fixtures.client.cert.to_der().unwrap());
    let limits = Limits::default();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(serve(
        listener,
        fixtures.context(&fixtures.server),
        limits,
        move |peer, _| {
            assert_eq!(peer, expected);
            Response::new(Bytes::from_static(b"ok"))
        },
    ));
    let request = || Request::get("/dcap").body(Bytes::new()).unwrap();
    let client = fixtures.context(&fixtures.client);
    assert_eq!(
        exchange(addr, "server.local", &client, limits, request())
            .await
            .unwrap()
            .body(),
        "ok"
    );
    assert!(
        exchange(addr, "wrong.local", &client, limits, request())
            .await
            .is_err()
    );
    let rogue = mint("rogue", 7, None);
    let rogue_leaf = mint("client.local", 8, Some(&rogue));
    let untrusted = tls_context(
        &rogue_leaf.cert,
        &[],
        &rogue_leaf.key,
        std::slice::from_ref(&fixtures.ca.cert),
    )
    .unwrap();
    assert!(
        exchange(addr, "server.local", &untrusted, limits, request())
            .await
            .is_err()
    );
    let weak = support::mint_signed(
        "client.local",
        9,
        Some(&fixtures.ca),
        openssl::hash::MessageDigest::sha1(),
    );
    assert!(
        exchange(
            addr,
            "server.local",
            &fixtures.context(&weak),
            limits,
            request()
        )
        .await
        .is_err()
    );
    server.abort();
}
