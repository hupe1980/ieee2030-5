#![cfg(feature = "runtime")]
mod support;

use bytes::Bytes;
use hyper::{Response, StatusCode};
use ieee2030_5::{
    client::{Client, Limits},
    codec::SEP,
    model::View,
    runtime,
    security::Lfdi,
};
use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;

#[tokio::test(flavor = "current_thread")]
async fn walk_registered_device_to_paged_controls_over_mtls() {
    let pki = support::Setup::new();
    let client_identity = Lfdi::from_certificate_der(&pki.client.cert.to_der().unwrap());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let requests = Arc::new(Mutex::new(Vec::new()));
    let log = requests.clone();
    let updated = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let state = updated.clone();
    let server = tokio::spawn(runtime::serve(
        listener,
        pki.context(&pki.server),
        Default::default(),
        move |peer, req| {
            assert_eq!(peer, client_identity);
            log.lock().unwrap().push(req.uri().to_string());
            if req.uri().path() == "/site/devices" && req.method() == hyper::Method::POST {
                let doc = ieee2030_5::codec::Document::parse(
                    std::str::from_utf8(req.body()).unwrap(),
                    Default::default(),
                )
                .unwrap();
                let device = doc.as_type::<ieee2030_5::model::EndDevice>().unwrap();
                assert_eq!(device.as_base().lfdi().unwrap().bytes(), peer.0);
                assert_eq!(
                    device.as_base().sfdi().unwrap().value(),
                    peer.sfdi().as_u64()
                );
                assert_eq!(device.changed_time().unwrap().value(), 100);
                return Response::builder()
                    .status(StatusCode::CREATED)
                    .header("Location", "/site/device/1")
                    .body(Bytes::new())
                    .unwrap();
            }
            let changed = state.load(std::sync::atomic::Ordering::SeqCst);
            let (tag, attrs, content) = match req.uri().path() {
            "/site/cap" => ("DeviceCapability","","<EndDeviceListLink href=\"devices\"/>".into()),
            "/site/devices" => ("EndDeviceList","all=\"1\" results=\"1\"",format!("<EndDevice><lFDI>{peer}</lFDI><sFDI>{}</sFDI><changedTime>0</changedTime><FunctionSetAssignmentsListLink href=\"/assign\"/><RegistrationLink href=\"/reg\"/><SubscriptionListLink href=\"/subscriptions\"/></EndDevice>",peer.sfdi().as_u64())),
            "/reg" => ("Registration","","<dateTimeRegistered>1</dateTimeRegistered><pIN>111115</pIN>".into()),
            "/assign" => ("FunctionSetAssignmentsList","all=\"1\" results=\"1\"","<FunctionSetAssignments><DERProgramListLink href=\"/programs\"/><mRID>AA</mRID></FunctionSetAssignments>".into()),
            "/programs" => ("DERProgramList",if changed { "all=\"1\" results=\"1\" pollRate=\"2\"" } else { "all=\"1\" results=\"1\" pollRate=\"1\"" },"<DERProgram><mRID>BB</mRID><DERControlListLink href=\"/controls\"/><primacy>3</primacy></DERProgram>".into()),
            "/controls" => {
                let id = if req.uri().query().unwrap().starts_with("s=0&") {if changed {"03"} else {"01"}} else {"02"};
                ("DERControlList","all=\"2\" results=\"1\"",format!("<DERControl><mRID>{id}</mRID><creationTime>0</creationTime><EventStatus><currentStatus>0</currentStatus><dateTime>0</dateTime><potentiallySuperseded>false</potentiallySuperseded></EventStatus><interval><duration>10</duration><start>1</start></interval><DERControlBase><opModConnect>true</opModConnect></DERControlBase></DERControl>"))
            }
            _ => return Response::builder().status(StatusCode::NOT_FOUND).body(Bytes::new()).unwrap(),
        };
            Response::new(Bytes::from(format!(
                "<{tag} xmlns=\"{SEP}\" {attrs}>{content}</{tag}>"
            )))
        },
    ));
    let client = Client::new(
        addr,
        "server.local",
        pki.context(&pki.client),
        Limits {
            page_size: 1,
            ..Default::default()
        },
    )
    .unwrap();
    assert!(
        client
            .register("/site/cap", 100)
            .await
            .unwrap()
            .ends_with("/site/device/1")
    );
    assert!(
        client
            .discover("/site/cap", 7)
            .await
            .unwrap_err()
            .to_string()
            .contains("PIN")
    );
    assert!(
        requests
            .lock()
            .unwrap()
            .iter()
            .all(|s| !s.starts_with("/assign"))
    );
    let mut feeds = client.discover("/site/cap", 111115).await.unwrap();
    assert_eq!(feeds.len(), 1);
    assert_eq!(feeds[0].program_id, [0xbb]);
    assert_eq!(feeds[0].primacy, 3);
    assert_eq!(feeds[0].poll_interval.as_secs(), 1);
    let mut controls = Vec::new();
    client
        .controls(&feeds[0], |c| controls.push(c.encode()))
        .await
        .unwrap();
    assert_eq!(controls.len(), 2);
    for xml in controls {
        ieee2030_5::codec::Document::parse(&xml, Default::default()).unwrap();
    }
    assert!(
        requests
            .lock()
            .unwrap()
            .ends_with(&["/controls?s=0&l=1".into(), "/controls?s=1&l=1".into()])
    );
    assert!(
        feeds[0]
            .subscription_list
            .as_deref()
            .unwrap()
            .ends_with("/subscriptions")
    );
    updated.store(true, std::sync::atomic::Ordering::SeqCst);
    for expected_delay in [1, 2] {
        let start = std::time::Instant::now();
        let mut ids = Vec::new();
        client
            .poll_controls("/site/cap", 111115, &mut feeds[0], |control| {
                ids.push(
                    control
                        .as_base()
                        .as_base()
                        .as_base()
                        .mrid()
                        .unwrap()
                        .bytes(),
                );
            })
            .await
            .unwrap();
        assert!(start.elapsed() >= std::time::Duration::from_secs(expected_delay));
        assert_eq!(feeds[0].poll_interval.as_secs(), 2);
        assert_eq!(ids, [[3], [2]]);
    }
    server.abort();
}
