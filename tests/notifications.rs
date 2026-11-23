#![cfg(feature = "runtime")]
// 005-runtime/SR-002
mod support;

use bytes::Bytes;
use hyper::{Method, Response, StatusCode};
use ieee2030_5::{
    client::{Client, ControlFeed, subscriptions::ControlSubscription},
    codec::SEP,
    resource::{Contents, Link, Representation, ResourceTree},
    runtime,
    security::Lfdi,
};
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::net::TcpListener;

fn response(status: StatusCode) -> Response<Bytes> {
    Response::builder()
        .status(status)
        .body(Bytes::new())
        .unwrap()
}

#[tokio::test(flavor = "current_thread")]
async fn authenticated_list_change_reaches_only_the_provisioned_callback() {
    let pki = support::Setup::new();
    let subscriber = Lfdi::from_certificate_der(&pki.client.cert.to_der().unwrap());
    let publisher = Lfdi::from_certificate_der(&pki.server.cert.to_der().unwrap());
    let service = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let inbox = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let service_addr = service.local_addr().unwrap();
    let inbox_addr = inbox.local_addr().unwrap();
    let origin = format!("https://server.local:{}", service_addr.port());
    let callback = format!("https://client.local:{}/inbox", inbox_addr.port());
    let feed = ControlFeed {
        program_id: vec![1],
        primacy: 0,
        url: format!("{origin}/controls"),
        subscription_list: Some(format!("{origin}/subscriptions")),
        poll_interval: Duration::from_secs(1),
    };
    let authorized =
        ControlSubscription::new(&feed.url, "/subscriptions/1", &callback, subscriber, 1024)
            .unwrap();
    let tree = Arc::new(Mutex::new(ResourceTree::<String>::new(Default::default())));
    tree.lock()
        .unwrap()
        .publish(
            "/controls",
            "DERControlList",
            Contents::List { members: vec![] },
        )
        .unwrap();
    let state = tree.clone();
    let allowed = authorized.clone();
    let host = tokio::spawn(runtime::serve(
        service,
        pki.context(&pki.server),
        Default::default(),
        move |peer, request| match (request.method(), request.uri().path()) {
            (&Method::POST, "/subscriptions") => {
                let body = std::str::from_utf8(request.body()).unwrap();
                if allowed
                    .validate_request(peer, body, Default::default())
                    .is_err()
                {
                    return response(StatusCode::FORBIDDEN);
                }
                state.lock().unwrap().subscribe(1, "/controls").unwrap();
                Response::builder()
                    .status(201)
                    .header("Location", allowed.location())
                    .body(Bytes::new())
                    .unwrap()
            }
            (&Method::DELETE, "/subscriptions/1") if peer == subscriber => {
                assert!(state.lock().unwrap().unsubscribe(1));
                response(StatusCode::NO_CONTENT)
            }
            (&Method::GET, "/controls") if peer == subscriber => {
                let tree = state.lock().unwrap();
                let Representation::Page { all, members } = tree
                    .read(
                        "/controls",
                        ieee2030_5::resource::Method::Get,
                        Default::default(),
                    )
                    .unwrap()
                else {
                    panic!("expected a list")
                };
                let mut items = String::new();
                for member in members {
                    let Representation::Item { value, .. } = tree
                        .read(
                            &member.path,
                            ieee2030_5::resource::Method::Get,
                            Default::default(),
                        )
                        .unwrap()
                    else {
                        panic!("expected an item")
                    };
                    items.push_str(value);
                }
                Response::new(Bytes::from(format!(
                    r#"<DERControlList xmlns="{SEP}" all="{all}" results="{}">{items}</DERControlList>"#,
                    members.len()
                )))
            }
            _ => response(StatusCode::NOT_FOUND),
        },
    ));
    let client = Client::new(
        service_addr,
        "server.local",
        pki.context(&pki.client),
        Default::default(),
    )
    .unwrap();
    assert!(
        client
            .subscribe_controls(&feed, "https://unprovisioned.invalid/inbox", publisher)
            .await
            .is_err()
    );
    assert!(
        client
            .subscribe_controls(&feed, &callback.replace("/inbox", "/other"), publisher)
            .await
            .is_err()
    );
    let sub = client
        .subscribe_controls(&feed, &callback, publisher)
        .await
        .unwrap();
    let receiver_sub = sub.clone();
    let (updates, mut received) = tokio::sync::mpsc::channel(1);
    let endpoint = tokio::spawn(runtime::serve(
        inbox,
        pki.context(&pki.client),
        Default::default(),
        move |peer, request| {
            if request.method() != Method::POST || request.uri().path() != "/inbox" {
                return response(StatusCode::NOT_FOUND);
            }
            if receiver_sub
                .validate_notification(
                    peer,
                    std::str::from_utf8(request.body()).unwrap(),
                    Default::default(),
                )
                .is_err()
            {
                return response(StatusCode::FORBIDDEN);
            }
            updates.try_send(()).unwrap();
            Response::builder()
                .status(201)
                .header("Location", "/inbox/1")
                .body(Bytes::new())
                .unwrap()
        },
    ));
    let mut before = Vec::new();
    client
        .controls(&feed, |c| {
            before.push(c.as_base().as_base().as_base().mrid().unwrap().bytes())
        })
        .await
        .unwrap();
    assert!(before.is_empty());
    let changes = {
        let mut tree = tree.lock().unwrap();
        tree.publish("/controls/1","DERControl",Contents::Item {value:"<DERControl><mRID>01</mRID><creationTime>0</creationTime><EventStatus><currentStatus>0</currentStatus><dateTime>0</dateTime><potentiallySuperseded>false</potentiallySuperseded></EventStatus><interval><duration>10</duration><start>1</start></interval><DERControlBase><opModConnect>true</opModConnect></DERControlBase></DERControl>".into(),links:vec![]}).unwrap();
        tree.replace(
            "/controls",
            Contents::List {
                members: vec![Link {
                    path: "/controls/1".into(),
                    time_key: None,
                }],
            },
        )
        .unwrap()
    };
    assert_eq!(changes.len(), 1);
    assert_eq!(changes[0].subscription, 1);
    let wrong = Client::new(
        inbox_addr,
        "client.local",
        pki.context(&pki.client),
        Default::default(),
    )
    .unwrap();
    assert!(
        authorized
            .notify(&wrong, 1)
            .await
            .unwrap_err()
            .to_string()
            .contains("403")
    );
    assert!(received.try_recv().is_err());
    let target = Client::new(
        inbox_addr,
        "client.local",
        pki.context(&pki.server),
        Default::default(),
    )
    .unwrap();
    assert!(
        authorized
            .notify(&client, 1)
            .await
            .unwrap_err()
            .to_string()
            .contains("cross-origin")
    );
    authorized.notify(&target, 1).await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), received.recv())
        .await
        .unwrap()
        .unwrap();
    let mut after = Vec::new();
    client
        .controls(&feed, |c| {
            after.push(c.as_base().as_base().as_base().mrid().unwrap().bytes())
        })
        .await
        .unwrap();
    assert_eq!(after, [[1]]);
    client.unsubscribe_controls(&sub).await.unwrap();
    assert!(
        tree.lock()
            .unwrap()
            .replace("/controls", Contents::List { members: vec![] })
            .unwrap()
            .is_empty()
    );
    endpoint.abort();
    let _ = endpoint.await;
    assert!(authorized.notify(&target, 1).await.is_err());
    host.abort();
}
