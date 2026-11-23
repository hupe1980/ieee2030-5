//! HTTP/1.1 carried by mutually authenticated TLS 1.2.
//!
//! The application supplies a private trust store, endpoint certificate chain and key.
//! The request handler receives the authenticated peer identity for authorization.
use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::{Request, Response, StatusCode, body::Incoming, header, service::service_fn};
use hyper_util::rt::TokioIo;
use openssl::{
    error::ErrorStack,
    pkey::{PKeyRef, Private},
    ssl::{Ssl, SslContext, SslContextBuilder, SslMethod, SslVerifyMode, SslVersion},
    x509::{X509, X509Ref, store::X509StoreBuilder},
};
use std::{
    convert::Infallible,
    error::Error,
    io,
    net::{IpAddr, SocketAddr},
    num::NonZeroUsize,
    pin::Pin,
    sync::Arc,
    time::Duration,
};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::Semaphore,
    time::timeout,
};
use tokio_openssl::SslStream;

use crate::security::Lfdi;

/// The XML media type carried by this adapter.
pub const MEDIA_TYPE: &str = "application/sep+xml";
pub type RuntimeError = Box<dyn Error + Send + Sync>;

/// Build a private endpoint context that presents a leaf and optional intermediates.
/// No operating-system trust roots are loaded. Both sides must present a certificate.
pub fn tls_context(
    leaf: &X509Ref,
    intermediates: &[X509],
    key: &PKeyRef<Private>,
    roots: &[X509],
) -> Result<SslContext, ErrorStack> {
    build_context(leaf, intermediates, key, roots, false)
}

/// Server context that additionally requires the manufacturing device leaf profile
/// after validating the client's chain against the configured private trust roots.
pub fn manufacturing_server_context(
    leaf: &X509Ref,
    intermediates: &[X509],
    key: &PKeyRef<Private>,
    roots: &[X509],
) -> Result<SslContext, ErrorStack> {
    build_context(leaf, intermediates, key, roots, true)
}

fn build_context(
    leaf: &X509Ref,
    intermediates: &[X509],
    key: &PKeyRef<Private>,
    roots: &[X509],
    manufacturing: bool,
) -> Result<SslContext, ErrorStack> {
    let mut context = SslContextBuilder::new(SslMethod::tls())?;
    context.set_min_proto_version(Some(SslVersion::TLS1_2))?;
    context.set_max_proto_version(Some(SslVersion::TLS1_2))?;
    // OpenSSL security levels reject a 64-bit authentication tag. Limit the
    // exception to this isolated protocol context and explicitly select every
    // permitted handshake primitive. OpenSSL copies the TLS security level into
    // its path builder, so explicitly check every verified certificate below.
    context.set_security_level(0);
    context.set_options(
        openssl::ssl::SslOptions::NO_RENEGOTIATION
            | openssl::ssl::SslOptions::NO_COMPRESSION
            | openssl::ssl::SslOptions::NO_TICKET,
    );
    context.set_sigalgs_list("ECDSA+SHA256")?;
    context.set_cipher_list("ECDHE-ECDSA-AES128-CCM8")?;
    context.set_groups_list("P-256")?;
    context.set_verify_callback(
        SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT,
        move |trusted, path| {
            if !trusted {
                return false;
            }
            let Some(cert) = path.current_cert() else {
                return false;
            };
            if !crate::security::profile::credential_algorithms(cert) {
                return false;
            }
            if !manufacturing || path.error_depth() != 0 {
                return true;
            }
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .ok()
                .and_then(|v| i64::try_from(v.as_secs()).ok());
            cert.to_der().ok().zip(now).is_some_and(|(der, now)| {
                crate::security::profile::validate_device_leaf(&der, now).is_ok()
                    && path.chain().is_some_and(|chain| {
                        crate::security::profile::validate_issuers(chain).is_ok()
                    })
            })
        },
    );
    context.set_verify_depth(8);
    let mut store = X509StoreBuilder::new()?;
    for root in roots {
        store.add_cert(root.clone())?;
    }
    context.set_cert_store(store.build());
    context.set_certificate(leaf)?;
    for cert in intermediates {
        context.add_extra_chain_cert(cert.clone())?;
    }
    context.set_private_key(key)?;
    context.check_private_key()?;
    Ok(context.build())
}

/// Hard limits applied before delivering any peer-controlled body to the application.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub max_body_bytes: usize,
    pub max_connections: NonZeroUsize,
    pub connection_timeout: Duration,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            max_body_bytes: 1024 * 1024,
            max_connections: NonZeroUsize::new(32).unwrap(),
            connection_timeout: Duration::from_secs(15),
        }
    }
}

fn status(code: StatusCode) -> Response<Full<Bytes>> {
    let mut response = Response::new(Full::new(Bytes::new()));
    *response.status_mut() = code;
    response
}

fn accepts_xml(headers: &hyper::HeaderMap) -> bool {
    if !headers.contains_key(header::ACCEPT) {
        return true;
    }
    // More specific media ranges take precedence, including a specific q=0 (RFC 9110 §12.5.1).
    let mut preference = None;
    for item in headers
        .get_all(header::ACCEPT)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
    {
        let mut parts = item.split(';');
        let media = parts.next().unwrap_or("").trim();
        let specificity = if media.eq_ignore_ascii_case(MEDIA_TYPE) {
            2
        } else if media.eq_ignore_ascii_case("application/*") {
            1
        } else if media == "*/*" {
            0
        } else {
            continue;
        };
        let mut quality = 1000;
        for param in parts {
            if let Some((key, value)) = param.trim().split_once('=')
                && key.trim().eq_ignore_ascii_case("q")
            {
                let value = value.trim();
                quality = match value.split_once('.').unwrap_or((value, "")) {
                    ("1", fraction)
                        if fraction.len() <= 3 && fraction.bytes().all(|b| b == b'0') =>
                    {
                        1000
                    }
                    ("0", fraction)
                        if fraction.len() <= 3 && fraction.bytes().all(|b| b.is_ascii_digit()) =>
                    {
                        fraction.parse::<u16>().unwrap_or(0) * 10u16.pow(3 - fraction.len() as u32)
                    }
                    _ => 0,
                };
            }
        }
        preference = preference.max(Some((specificity, quality)));
    }
    preference.is_some_and(|(_, quality)| quality > 0)
}
async fn dispatch<F>(
    request: Request<Incoming>,
    peer: Lfdi,
    limit: usize,
    handler: &F,
) -> Result<Response<Full<Bytes>>, Infallible>
where
    F: Fn(Lfdi, Request<Bytes>) -> Response<Bytes>,
{
    let (parts, body) = request.into_parts();
    if !accepts_xml(&parts.headers) {
        return Ok(status(StatusCode::NOT_ACCEPTABLE));
    }
    if let Some(content) = parts.headers.get(header::CONTENT_TYPE)
        && !content
            .to_str()
            .ok()
            .and_then(|v| v.split(';').next())
            .is_some_and(|v| v.trim().eq_ignore_ascii_case(MEDIA_TYPE))
    {
        return Ok(status(StatusCode::UNSUPPORTED_MEDIA_TYPE));
    }
    let data = match Limited::new(body, limit).collect().await {
        Ok(data) => data.to_bytes(),
        Err(err) if err.is::<http_body_util::LengthLimitError>() => {
            return Ok(status(StatusCode::PAYLOAD_TOO_LARGE));
        }
        Err(_) => return Ok(status(StatusCode::BAD_REQUEST)),
    };
    if !data.is_empty() && !parts.headers.contains_key(header::CONTENT_TYPE) {
        return Ok(status(StatusCode::UNSUPPORTED_MEDIA_TYPE));
    }
    let response = handler(peer, Request::from_parts(parts, data));
    let (mut parts, body) = response.into_parts();
    if body.len() > limit {
        return Ok(status(StatusCode::INTERNAL_SERVER_ERROR));
    }
    if !body.is_empty() {
        parts.headers.insert(
            header::CONTENT_TYPE,
            header::HeaderValue::from_static(MEDIA_TYPE),
        );
    }
    Ok(Response::from_parts(parts, Full::new(body)))
}

/// Serve until cancelled. Limits bound simultaneous handshakes as well as HTTP connections.
/// The synchronous handler should perform bounded, in-memory work.
pub async fn serve<F>(
    listener: TcpListener,
    context: SslContext,
    limits: Limits,
    handler: F,
) -> Result<(), RuntimeError>
where
    F: Fn(Lfdi, Request<Bytes>) -> Response<Bytes> + Send + Sync + 'static,
{
    if limits.max_connections.get() > Semaphore::MAX_PERMITS {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "connection limit exceeds semaphore capacity",
        )
        .into());
    }
    let slots = Arc::new(Semaphore::new(limits.max_connections.get()));
    let handler = Arc::new(handler);
    let mut workers = tokio::task::JoinSet::new();
    loop {
        while workers.try_join_next().is_some() {}
        let permit = slots.clone().acquire_owned().await?;
        let (tcp, _) = listener.accept().await?;
        let mut stream = SslStream::new(Ssl::new(&context)?, tcp)?;
        let handler = handler.clone();
        workers.spawn(async move {
            let _permit = permit;
            let _ = timeout(limits.connection_timeout, async {
                Pin::new(&mut stream).accept().await?;
                let cert = stream
                    .ssl()
                    .peer_certificate()
                    .ok_or_else(|| io::Error::other("missing authenticated peer"))?;
                let peer = Lfdi::from_certificate_der(&cert.to_der()?);
                let service = service_fn(move |req| {
                    let handler = handler.clone();
                    async move { dispatch(req, peer, limits.max_body_bytes, handler.as_ref()).await }
                });
                hyper::server::conn::http1::Builder::new()
                    .keep_alive(false)
                    .serve_connection(TokioIo::new(stream), service)
                    .await?;
                Ok::<(), RuntimeError>(())
            })
            .await;
        });
    }
}

/// Send one origin-form HTTP request to a verified server. The identity name is
/// checked independently of the socket address supplied by service discovery.
pub async fn exchange(
    address: SocketAddr,
    name: &str,
    context: &SslContext,
    limits: Limits,
    mut request: Request<Bytes>,
) -> Result<Response<Bytes>, RuntimeError> {
    if request.body().len() > limits.max_body_bytes
        || request.uri().scheme().is_some()
        || request.uri().authority().is_some()
        || !request.uri().path().starts_with('/')
        || request.uri().path().starts_with("//")
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "expected a bounded request with an origin-relative target",
        )
        .into());
    }
    timeout(limits.connection_timeout,async{
        let mut ssl=Ssl::new(context)?;
        let http_host=match name.parse::<IpAddr>(){
            Ok(ip)=>{ssl.param_mut().set_ip(ip)?;if ip.is_ipv6(){format!("[{ip}]")}else{ip.to_string()}},
            Err(_)=>{ssl.set_hostname(name)?;ssl.param_mut().set_host(name)?;name.to_owned()}
        };
        request.headers_mut().insert(header::HOST,format!("{http_host}:{}",address.port()).parse()?);
        request.headers_mut().insert(header::ACCEPT,header::HeaderValue::from_static(MEDIA_TYPE));
        if !request.body().is_empty(){request.headers_mut().entry(header::CONTENT_TYPE).or_insert(header::HeaderValue::from_static(MEDIA_TYPE));}
        let mut stream=SslStream::new(ssl,TcpStream::connect(address).await?)?;
        Pin::new(&mut stream).connect().await?;
        let (mut sender,connection)=hyper::client::conn::http1::handshake(TokioIo::new(stream)).await?;
        // Drive the connection within the same future so cancellation also closes the socket.
        let command=async {
            let response=sender.send_request(request.map(Full::new)).await?;
            let (parts,body)=response.into_parts();
            let body=Limited::new(body,limits.max_body_bytes).collect().await?.to_bytes();
            Ok::<_,RuntimeError>(Response::from_parts(parts,body))
        };
        tokio::pin!(command,connection);
        tokio::select!{ biased; result=&mut command=>result, result=&mut connection=>{result?;command.await} }
    }).await?
}

/// Construct the link-local mDNS advertisement for an HTTPS DeviceCapability resource.
/// The caller owns the daemon and may unregister the returned service at shutdown.
pub fn advertisement(
    instance: &str,
    host: &str,
    ip: IpAddr,
    endpoint: crate::discovery::Endpoint<'_>,
) -> Result<mdns_sd::ServiceInfo, mdns_sd::Error> {
    advertise_service(instance, host, ip, endpoint, None)
}

/// Register a function-set instance with its own TXT path (IEEE 2030.5-2018 §7.5).
/// The SRV port describes HTTP; secure clients use the HTTPS port in TXT.
pub fn advertise_service(
    instance: &str,
    host: &str,
    ip: IpAddr,
    endpoint: crate::discovery::Endpoint<'_>,
    function: Option<(crate::discovery::Service, &str)>,
) -> Result<mdns_sd::ServiceInfo, mdns_sd::Error> {
    use crate::discovery::{Service, from_record};
    let port = endpoint.https_port.to_string();
    let (service, path) = function.map_or((Service::Capabilities, None), |(s, p)| (s, Some(p)));
    if service == Service::Capabilities && path.is_some() {
        return Err(mdns_sd::Error::Msg(
            "capability advertisement must omit function path".into(),
        ));
    }
    from_record(
        Some("1"),
        Some("-S1"),
        Some(&port),
        Some(endpoint.capability_path),
        path,
        service,
    )
    .map_err(|e| mdns_sd::Error::Msg(format!("invalid discovery record: {e:?}")))?;
    let mut txt = vec![
        ("txtvers", "1"),
        ("dcap", endpoint.capability_path),
        ("https", &port),
        ("level", "-S1"),
    ];
    if let Some(path) = path {
        txt.push(("path", path));
    }
    mdns_sd::ServiceInfo::new(&service.local_name(), instance, host, ip, 80, &txt[..])
}
/// Extract validated HTTPS metadata from a resolved multicast service.
pub fn resolved_endpoint(
    record: &mdns_sd::ResolvedService,
    service: crate::discovery::Service,
) -> Result<crate::discovery::Endpoint<'_>, crate::discovery::DiscoveryError> {
    use crate::discovery::{DiscoveryError, from_record};
    let txt = |key| {
        record
            .get_property_val(key)
            .map(|s| {
                std::str::from_utf8(s.unwrap_or_default()).map_err(|_| DiscoveryError::InvalidPath)
            })
            .transpose()
    };
    from_record(
        txt("txtvers")?,
        txt("level")?,
        txt("https")?,
        txt("dcap")?,
        txt("path")?,
        service,
    )
}
pub fn browse_service(
    daemon: &mdns_sd::ServiceDaemon,
    service: crate::discovery::Service,
) -> Result<mdns_sd::Receiver<mdns_sd::ServiceEvent>, mdns_sd::Error> {
    daemon.browse(&service.local_name())
}
/// Browse link-local IEEE 2030.5 announcements. Use the resolved address and
/// validated TXT metadata as routing hints, then authenticate the server during exchange.
pub fn browse(
    daemon: &mdns_sd::ServiceDaemon,
) -> Result<mdns_sd::Receiver<mdns_sd::ServiceEvent>, mdns_sd::Error> {
    daemon.browse(crate::discovery::SERVICE_TYPE)
}
