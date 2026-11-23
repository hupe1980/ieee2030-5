#![cfg(feature = "runtime")]
mod support;
use bytes::Bytes;
use hyper::{Request, Response};
use ieee2030_5::{
    codec::Document,
    discovery::{Endpoint, Service},
    model::DeviceCapability,
    runtime,
};
use mdns_sd::{IfKind, ServiceDaemon, ServiceEvent};
use std::{
    net::{Ipv4Addr, SocketAddr, UdpSocket},
    time::Duration,
};
use tokio::net::TcpListener;

#[tokio::test(flavor = "current_thread")]
async fn browse_der_subtype_and_read_authenticated_capability() {
    let pki = support::Setup::new();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(runtime::serve(
        listener,
        pki.context(&pki.server),
        Default::default(),
        |_, req| {
            assert_eq!(req.uri().path(), "/scope/cap");
            Response::new(Bytes::from_static(br#"<DeviceCapability xmlns="urn:ieee:std:2030.5:ns"><DERProgramListLink href="/programs"/></DeviceCapability>"#))
        },
    ));
    // Isolate the real multicast packets from LAN services and parallel test runs.
    let port = UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let daemon = || {
        let d = ServiceDaemon::new_with_port(port).unwrap();
        d.disable_interface(IfKind::All).unwrap();
        d.enable_interface(IfKind::LoopbackV4).unwrap();
        d
    };
    let publisher = daemon();
    let browser = daemon();
    let event = runtime::browse_service(&browser, Service::DerPrograms).unwrap();
    let info = runtime::advertise_service(
        "der-unit",
        "server.local.",
        address.ip(),
        Endpoint::from_txt(Some(&address.port().to_string()), "/scope/cap").unwrap(),
        Some((Service::DerPrograms, "/programs")),
    )
    .unwrap();
    let name = info.get_fullname().to_owned();
    publisher.register(info).unwrap();
    let resolved = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let ServiceEvent::ServiceResolved(s) = event.recv_async().await.unwrap()
                && s.get_fullname() == name
            {
                break s;
            }
        }
    })
    .await
    .expect("loopback subtype discovery");
    let endpoint = runtime::resolved_endpoint(&resolved, Service::DerPrograms).unwrap();
    let ip = resolved
        .get_addresses_v4()
        .into_iter()
        .find(|ip| *ip == Ipv4Addr::LOCALHOST)
        .unwrap();
    let discovered = SocketAddr::new(ip.into(), endpoint.https_port.get());
    let response = runtime::exchange(
        discovered,
        "server.local",
        &pki.context(&pki.client),
        Default::default(),
        Request::get(endpoint.capability_path)
            .body(Bytes::new())
            .unwrap(),
    )
    .await
    .unwrap();
    Document::parse(
        std::str::from_utf8(response.body()).unwrap(),
        Default::default(),
    )
    .unwrap()
    .as_type::<DeviceCapability>()
    .unwrap();
    publisher.unregister(&name).unwrap();
    publisher.shutdown().unwrap();
    browser.shutdown().unwrap();
    server.abort();
}
