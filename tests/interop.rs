#![cfg(feature = "runtime")]
use bytes::Bytes;
use hyper::{Request, Response, StatusCode};
use ieee2030_5::{
    codec::Document,
    model::{DERControl, DERProgramList},
    runtime::{self, RuntimeError},
    security::{Lfdi, profile::validate_device_leaf},
};
use openssl::{pkey::PKey, ssl::SslContext, x509::X509};
use std::{
    env, fs,
    net::SocketAddr,
    path::PathBuf,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::net::TcpListener;

fn context(server: bool) -> Result<SslContext, RuntimeError> {
    let dir = PathBuf::from(env::var("SEP_INTEROP_DIR")?);
    let role = if server { "server" } else { "device" };
    let cert = X509::from_pem(&fs::read(dir.join(format!("{role}.crt")))?)?;
    let key = PKey::private_key_from_pem(&fs::read(dir.join(format!("{role}.key")))?)?;
    let ca = X509::from_pem(&fs::read(dir.join("ca.crt"))?)?;
    if server {
        Ok(runtime::manufacturing_server_context(
            &cert,
            &[],
            &key,
            &[ca],
        )?)
    } else {
        Ok(runtime::tls_context(&cert, &[], &key, &[ca])?)
    }
}
async fn get(addr: SocketAddr, ctx: &SslContext, path: &str) -> Result<String, RuntimeError> {
    let response = runtime::exchange(
        addr,
        "localhost",
        ctx,
        Default::default(),
        Request::get(path).body(Bytes::new())?,
    )
    .await?;
    if response.status() != StatusCode::OK {
        return Err(format!("GET {path} returned {}", response.status()).into());
    }
    Ok(String::from_utf8(response.into_body().to_vec())?)
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "run python3 tests/interop/run.py against the pinned peers"]
async fn independent_server_publishes_control() -> Result<(), RuntimeError> {
    let ctx = context(false)?;
    let addr = env::var("SEP_INTEROP_ADDR")?.parse()?;
    let xml = get(addr, &ctx, "/edev/0/fsa/0/derp").await?;
    let doc = Document::parse(&xml, Default::default())?;
    let program = doc
        .as_type::<DERProgramList>()?
        .der_program()
        .next()
        .ok_or("missing program")?;
    let path = program
        .der_control_list_link()
        .and_then(|l| l.as_base().as_base().href())
        .ok_or("missing control list href")?;
    let xml = get(addr, &ctx, path).await?;
    // This pinned peer attaches pollRate to DERControlList; the 2018 schema
    // permits it on DERProgramList only. Preserve strict list validation.
    assert!(
        matches!(Document::parse(&xml, Default::default()), Err(ieee2030_5::codec::Error::UnexpectedMember(ref name)) if name == "pollRate")
    );
    let location = env::var("SEP_INTEROP_CONTROL")?;
    assert!(location.starts_with(&format!("{path}/")));
    let payload = get(addr, &ctx, &location).await?;
    let resource = Document::parse(&payload, Default::default())?;
    let control = resource.as_type::<DERControl>()?;
    assert_eq!(
        control
            .der_control_base()
            .and_then(|b| b.op_mod_max_lim_w())
            .unwrap()
            .value(),
        4321
    );

    Ok(())
}
#[tokio::test(flavor = "current_thread")]
#[ignore = "run python3 tests/interop/run.py against the pinned peers"]
async fn independent_client_reads_control() -> Result<(), RuntimeError> {
    let dir = PathBuf::from(env::var("SEP_INTEROP_DIR")?);
    let device = X509::from_pem(&fs::read(dir.join("device.crt"))?)?.to_der()?;
    let expected = Lfdi::from_certificate_der(&device);
    assert_eq!(
        validate_device_leaf(
            &device,
            SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64
        )?,
        expected
    );
    let socket = TcpListener::bind("127.0.0.1:0").await?;
    let addr = socket.local_addr()?;
    let programs = r#"<DERProgramList xmlns="urn:ieee:std:2030.5:ns" all="1" results="1"><DERProgram><mRID>01</mRID><DERControlListLink href="/feed/pending"/><primacy>0</primacy></DERProgram></DERProgramList>"#;
    let controls = r#"<DERControlList xmlns="urn:ieee:std:2030.5:ns" all="1" results="1"><DERControl><mRID>02</mRID><creationTime>1</creationTime><EventStatus><currentStatus>0</currentStatus><dateTime>1</dateTime><potentiallySuperseded>false</potentiallySuperseded></EventStatus><interval><duration>30</duration><start>10</start></interval><DERControlBase><opModMaxLimW>4321</opModMaxLimW></DERControlBase></DERControl></DERControlList>"#;
    let dcap = r#"<DeviceCapability xmlns="urn:ieee:std:2030.5:ns"><EndDeviceListLink href="/devices"/></DeviceCapability>"#;
    let end_device = format!(
        r#"<EndDevice xmlns="urn:ieee:std:2030.5:ns"><lFDI>{expected}</lFDI><sFDI>{}</sFDI><changedTime>1</changedTime><FunctionSetAssignmentsListLink href="/assignments"/><RegistrationLink href="/enrolled/pin"/></EndDevice>"#,
        expected.sfdi().as_u64()
    );
    let registration = r#"<Registration xmlns="urn:ieee:std:2030.5:ns"><dateTimeRegistered>1</dateTimeRegistered><pIN>111115</pIN></Registration>"#;
    let assignments = r#"<FunctionSetAssignmentsList xmlns="urn:ieee:std:2030.5:ns" all="1" results="1"><FunctionSetAssignments><DERProgramListLink href="/assigned"/><mRID>03</mRID></FunctionSetAssignments></FunctionSetAssignmentsList>"#;
    for xml in [
        programs,
        controls,
        dcap,
        &end_device,
        registration,
        assignments,
    ] {
        Document::parse(xml, Default::default())?;
    }
    let enrolled = std::sync::atomic::AtomicBool::new(false);
    let server = tokio::spawn(runtime::serve(
        socket,
        context(true)?,
        Default::default(),
        move |peer, req| {
            if peer != expected {
                return Response::builder().status(403).body(Bytes::new()).unwrap();
            }
            match req.uri().path() {
                "/dcap" => Response::new(Bytes::from_static(dcap.as_bytes())),
                "/devices" if req.method() == hyper::Method::POST => {
                    let input = std::str::from_utf8(req.body()).unwrap();
                    let doc = Document::parse(input, Default::default()).unwrap();
                    let submitted = doc
                        .as_type::<ieee2030_5::model::EndDevice>()
                        .unwrap()
                        .as_base();
                    assert_eq!(submitted.lfdi().unwrap().bytes(), expected.0);
                    assert_eq!(submitted.sfdi().unwrap().value(), expected.sfdi().as_u64());
                    enrolled.store(true, std::sync::atomic::Ordering::Release);
                    Response::builder()
                        .status(201)
                        .header("Location", "/enrolled")
                        .body(Bytes::new())
                        .unwrap()
                }
                _ if !enrolled.load(std::sync::atomic::Ordering::Acquire) => {
                    Response::builder().status(403).body(Bytes::new()).unwrap()
                }
                "/enrolled" => Response::new(Bytes::copy_from_slice(end_device.as_bytes())),
                "/enrolled/pin" => Response::new(Bytes::from_static(registration.as_bytes())),
                "/assignments" => Response::new(Bytes::from_static(assignments.as_bytes())),
                "/assigned" => Response::new(Bytes::from_static(programs.as_bytes())),
                "/feed/pending" => Response::new(Bytes::from_static(controls.as_bytes())),
                _ => Response::builder().status(404).body(Bytes::new()).unwrap(),
            }
        },
    ));
    let result = tokio::task::spawn_blocking(move || {
        Command::new(env::var("SEP_INTEROP_CLIENT_TEST")?)
            .arg("-test.run=^TestRustPeerDERControl$")
            .arg("-test.v")
            .env("SEP_INTEROP_URL", format!("https://{addr}"))
            .env("SEP_INTEROP_CERT", dir.join("device.crt"))
            .env("SEP_INTEROP_KEY", dir.join("device.key"))
            .env("SEP_INTEROP_CA", dir.join("ca.crt"))
            .status()
            .map_err(RuntimeError::from)
    })
    .await??;
    server.abort();
    assert!(result.success());
    Ok(())
}
