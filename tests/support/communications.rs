//! conformance-as-data/SR-002
//! CSIP-TP v1.3 COMM-002 and COMM-003, server role. The external client receives only the
//! initial endpoint, the identity bundle and the test CA.
use bytes::Bytes;
use hyper::{Method, Response, StatusCode};
use ieee2030_5::runtime::{Limits, serve};
use std::io::Write;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};

const ENTRY: &str = "/utility/dcap";
const DEVICES: &str = "/assets/site/devices";

pub fn run(procedure: &'static str, paths: &[&str]) {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(scenario(procedure, paths));
}

async fn scenario(procedure: &'static str, paths: &[&str]) {
    let setup = crate::support::Setup::new();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let requests = Arc::new(Mutex::new(Vec::new()));
    let observed = requests.clone();
    let server = tokio::spawn(serve(
        listener,
        setup.context(&setup.server),
        Limits::default(),
        move |_, request| {
            let path = request.uri().path();
            observed
                .lock()
                .unwrap()
                .push((request.method().clone(), path.to_owned()));
            let body = match (request.method(), path) {
                (&Method::GET, ENTRY) => format!(
                    r#"<DeviceCapability xmlns="urn:ieee:std:2030.5:ns" href="{ENTRY}"><EndDeviceListLink all="0" href="{DEVICES}"/></DeviceCapability>"#
                ),
                (&Method::GET, DEVICES) => format!(
                    r#"<EndDeviceList xmlns="urn:ieee:std:2030.5:ns" href="{DEVICES}" all="0" results="0"/>"#
                ),
                _ => {
                    return Response::builder()
                        .status(StatusCode::NOT_FOUND)
                        .body(Bytes::new())
                        .unwrap();
                }
            };
            Response::new(Bytes::from(body))
        },
    ));
    let mut pem = setup.ca.cert.to_pem().unwrap();
    pem.push(0);
    pem.extend(setup.client.cert.to_pem().unwrap());
    pem.extend(setup.client.key.private_key_to_pem_pkcs8().unwrap());
    let output = tokio::task::spawn_blocking(move || {
        let mut child = Command::new("python3")
            .args([
                "-I",
                concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/tests/support/communications.py"
                ),
            ])
            .args([
                procedure.to_owned(),
                addr.ip().to_string(),
                addr.port().to_string(),
                ENTRY.to_owned(),
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("CSIP procedure driver requires Python 3");
        child.stdin.take().unwrap().write_all(&pem).unwrap();
        child.wait_with_output().unwrap()
    })
    .await
    .unwrap();
    server.abort();
    println!(
        "{procedure} server transcript\n{}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(
        output.status.success(),
        "{procedure} peer failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        *requests.lock().unwrap(),
        paths
            .iter()
            .map(|p| (Method::GET, (*p).to_owned()))
            .collect::<Vec<_>>()
    );
}
