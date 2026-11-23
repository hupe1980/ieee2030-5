use crate::support;

use bytes::Bytes;
use hyper::{Request, Response};
use ieee2030_5::{
    codec::Document,
    discovery::{Endpoint, Service},
    runtime::{self, Limits},
    xmdns::{Advertisement, Interface, Reply, Responder, browse},
};
use std::{
    net::Ipv4Addr,
    sync::{Arc, Mutex},
    time::Duration,
};

pub fn run() {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(scenario());
}

async fn scenario() {
    // 006-discovery/SR-001. All discovery and HTTPS traffic stays on loopback.
    let setup = support::Setup::new();
    let server_id = support::mint("utility.site", 4, Some(&setup.ca));
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let address = listener.local_addr().unwrap();
    let paths = Arc::new(Mutex::new(Vec::new()));
    let observed = paths.clone();
    let web = tokio::spawn(runtime::serve(
        listener,
        setup.context(&server_id),
        Limits::default(),
        move |_, req| {
            assert_eq!(req.method(), hyper::Method::GET);
            let path = req.uri().path();
            observed.lock().unwrap().push(path.to_owned());
            let resource = match path {
                "/demo/programs" => {
                    r#"<DERProgramList xmlns="urn:ieee:std:2030.5:ns" href="/demo/programs" all="0" results="0"/>"#
                }
                "/demo/time" => {
                    r#"<Time xmlns="urn:ieee:std:2030.5:ns" href="/demo/time"><currentTime>100</currentTime><dstEndTime>0</dstEndTime><dstOffset>0</dstOffset><dstStartTime>0</dstStartTime><quality>7</quality><tzOffset>0</tzOffset></Time>"#
                }
                "/demo/cap" => {
                    r#"<DeviceCapability xmlns="urn:ieee:std:2030.5:ns" href="/demo/cap"><DERProgramListLink all="0" href="/demo/programs"/><TimeLink href="/demo/time"/></DeviceCapability>"#
                }
                _ => return Response::builder().status(404).body(Bytes::new()).unwrap(),
            };
            Response::new(Bytes::from_static(resource.as_bytes()))
        },
    ));
    let interface = Interface::V4(Ipv4Addr::LOCALHOST);
    let port = address.port().to_string();
    let endpoint = Endpoint::from_txt(Some(&port), "/demo/cap").unwrap();
    let offers = [
        ("device", None),
        ("derp", Some((Service::DerPrograms, "/demo/programs"))),
        ("time", Some((Service::Time, "/demo/time"))),
    ]
    .into_iter()
    .map(|(kind, service)| {
        Advertisement::new(
            &format!("{kind}-demo"),
            "utility.site.",
            address.ip(),
            endpoint,
            service,
        )
        .unwrap()
    })
    .collect();
    let responder = Responder::bind(interface, offers).unwrap();
    let dns = tokio::spawn(async move { responder.run().await });
    let context = setup.context(&setup.client);
    for (service, reply, path, kind) in [
        (
            Service::DerPrograms,
            Reply::Multicast,
            "/demo/programs",
            "DERProgramList",
        ),
        (
            Service::DerPrograms,
            Reply::Unicast,
            "/demo/programs",
            "DERProgramList",
        ),
        (Service::Time, Reply::Multicast, "/demo/time", "Time"),
        (
            Service::Capabilities,
            Reply::Multicast,
            "/demo/cap",
            "DeviceCapability",
        ),
    ] {
        let record = browse(interface, service, reply, Duration::from_secs(3))
            .await
            .unwrap_or_else(|e| panic!("{service:?} {reply:?}: {e}"));
        assert_eq!(record.resource_path, path);
        assert_eq!(record.capability_path, "/demo/cap");
        assert_eq!(record.host, "utility.site");
        assert_eq!(record.address, address);
        let response = runtime::exchange(
            record.address,
            &record.host,
            &context,
            Limits::default(),
            Request::get(record.resource_path)
                .body(Bytes::new())
                .unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(response.status(), 200);
        let doc = Document::parse(
            std::str::from_utf8(response.body()).unwrap(),
            Default::default(),
        )
        .unwrap();
        assert_eq!(doc.root().tag_name().name(), kind);
        println!("COMM-001 {service:?} {reply:?}: HTTPS GET {path} -> 200 {kind}");
    }
    assert_eq!(
        paths.lock().unwrap().as_slice(),
        [
            "/demo/programs",
            "/demo/programs",
            "/demo/time",
            "/demo/cap"
        ]
    );
    dns.abort();
    web.abort();
}
