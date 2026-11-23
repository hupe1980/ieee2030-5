//! Walk a registered device's advertised DER resources over authenticated HTTP.
//! Every link stays on the configured origin. Each discovery pass has a request budget.
use crate::codec::{self, Document};
use crate::model::{self, View};
use crate::resource::resolve_href;
use crate::runtime::{self, RuntimeError};
use crate::security::Lfdi;
use bytes::Bytes;
use hyper::{Request, Uri};
use openssl::ssl::SslContext;
use std::{collections::BTreeSet, net::SocketAddr, time::Duration};

#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub transport: runtime::Limits,
    pub xml: codec::Limits,
    pub requests: usize,
    pub page_size: u16,
    pub href_bytes: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            transport: Default::default(),
            xml: Default::default(),
            requests: 128,
            page_size: 32,
            href_bytes: 2048,
        }
    }
}

pub mod subscriptions;

pub struct Client {
    address: SocketAddr,
    name: String,
    origin: String,
    context: SslContext,
    identity: Lfdi,
    limits: Limits,
    #[cfg(feature = "csip-aus")]
    australian_profile: bool,
}

/// A control list advertised by a DER program assigned to this device.
#[derive(Debug, Clone)]
pub struct ControlFeed {
    pub program_id: Vec<u8>,
    pub primacy: u8,
    pub url: String,
    pub poll_interval: Duration,
    /// Advertised subscription collection for the registered device, if supported.
    pub subscription_list: Option<String>,
}
impl ControlFeed {
    /// Wait one advertised polling interval. Refresh the assignment to observe poll-rate changes.
    pub async fn wait(&self) {
        tokio::time::sleep(self.poll_interval).await;
    }
}

fn link(base: &str, value: &str, max: usize) -> Result<String, RuntimeError> {
    resolve_href(base, value, max)
        .map_err(|_| "invalid, oversized or cross-origin resource link".into())
}
fn child_link(n: roxmltree::Node<'_, '_>, name: &str) -> Result<String, RuntimeError> {
    Ok(n.children()
        .find(|c| c.has_tag_name((codec::SEP, name)))
        .and_then(|c| c.attribute("href"))
        .ok_or_else(|| format!("missing {name} href"))?
        .into())
}
fn number(value: Option<&str>) -> Result<u32, RuntimeError> {
    Ok(u32::try_from(
        value
            .ok_or("missing integer attribute")?
            .trim()
            .parse::<i128>()?,
    )?)
}
impl Client {
    pub fn new(
        address: SocketAddr,
        name: &str,
        context: SslContext,
        limits: Limits,
    ) -> Result<Self, RuntimeError> {
        if limits.page_size == 0 || limits.requests == 0 {
            return Err("empty traversal budget".into());
        }
        let host = if name.parse::<std::net::Ipv6Addr>().is_ok() {
            format!("[{name}]")
        } else {
            name.into()
        };
        let origin = format!("https://{host}:{}/", address.port());
        let authority = origin.parse::<Uri>()?;
        if authority.host().is_none() || name.contains(['/', '@', '?', '#']) {
            return Err("invalid endpoint name".into());
        }
        let identity = Lfdi::from_certificate_der(
            &context
                .certificate()
                .ok_or("missing client certificate")?
                .to_der()?,
        );
        Ok(Self {
            address,
            name: name.into(),
            origin,
            context,
            identity,
            limits,
            #[cfg(feature = "csip-aus")]
            australian_profile: false,
        })
    }
    /// Validate responses using CSIP-AUS 1.2 for this enrolled endpoint.
    #[cfg(feature = "csip-aus")]
    pub fn with_csip_aus(mut self) -> Self {
        self.australian_profile = true;
        self
    }
    fn parse<'a>(&self, bytes: &'a [u8]) -> Result<Document<'a>, RuntimeError> {
        let xml = std::str::from_utf8(bytes)?;
        #[cfg(feature = "csip-aus")]
        if self.australian_profile {
            return Ok(Document::parse_aus(xml, self.limits.xml)?);
        }
        Ok(Document::parse(xml, self.limits.xml)?)
    }
    async fn request(
        &self,
        method: hyper::Method,
        url: &str,
        body: Bytes,
    ) -> Result<hyper::Response<Bytes>, RuntimeError> {
        let url = link(&self.origin, url, self.limits.href_bytes)?.parse::<Uri>()?;
        let request = Request::builder()
            .method(method)
            .uri(url.path_and_query().ok_or("missing path")?.as_str())
            .body(body)?;
        runtime::exchange(
            self.address,
            &self.name,
            &self.context,
            self.limits.transport,
            request,
        )
        .await
    }
    async fn read(&self, url: &str, budget: &mut usize) -> Result<Bytes, RuntimeError> {
        *budget = budget
            .checked_sub(1)
            .ok_or("traversal request budget exhausted")?;
        let res = self.request(hyper::Method::GET, url, Bytes::new()).await?;
        if res.status() != hyper::StatusCode::OK {
            return Err(format!("resource GET returned {}", res.status()).into());
        }
        if !res
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(';').next())
            .is_some_and(|v| v.trim().eq_ignore_ascii_case(runtime::MEDIA_TYPE))
        {
            return Err("expected SEP XML response".into());
        }
        Ok(res.into_body())
    }
    /// Iterate successive list pages with validated counts. Callbacks borrow one page at a time.
    async fn pages(
        &self,
        url: &str,
        list: &str,
        item: &str,
        budget: &mut usize,
        mut visit: impl FnMut(&Document<'_>, roxmltree::Node<'_, '_>) -> Result<(), RuntimeError>,
    ) -> Result<(), RuntimeError> {
        let mut start = 0u32;
        loop {
            let (path, query) = url.split_once('?').unwrap_or((url, ""));
            let mut params: Vec<_> = query
                .split('&')
                .filter(|s| !s.is_empty() && !matches!(s.split('=').next(), Some("s" | "l")))
                .collect();
            let page = format!("s={start}&l={}", self.limits.page_size);
            params.push(&page);
            let bytes = self
                .read(&format!("{path}?{}", params.join("&")), budget)
                .await?;
            let doc = self.parse(&bytes)?;
            let root = doc.root();
            if !root.has_tag_name((codec::SEP, list)) {
                return Err("unexpected list resource".into());
            }
            let total = number(root.attribute("all"))?;
            let results = number(root.attribute("results"))?;
            let items = root
                .children()
                .filter(|n| n.has_tag_name((codec::SEP, item)));
            if items.clone().count() != results as usize
                || results > u32::from(self.limits.page_size)
            {
                return Err("inconsistent page count".into());
            }
            let end = start.checked_add(results).ok_or("page offset overflow")?;
            if end > total || (end < total && results == 0) {
                return Err("inconsistent page bounds".into());
            }
            for n in items {
                visit(&doc, n)?;
            }
            if end == total {
                return Ok(());
            }
            start = end;
        }
    }
    async fn device_collection(
        &self,
        capability: &str,
        budget: &mut usize,
    ) -> Result<String, RuntimeError> {
        let dcap = link(&self.origin, capability, self.limits.href_bytes)?;
        let bytes = self.read(&dcap, budget).await?;
        let doc = self.parse(&bytes)?;
        let capability = doc.as_type::<model::DeviceCapability>()?;
        link(
            &dcap,
            &child_link(capability.node(), "EndDeviceListLink")?,
            self.limits.href_bytes,
        )
    }

    /// Submit this certificate's device identifiers to the advertised EndDeviceList.
    /// Use this for client-initiated registration. Pre-provisioned devices can call discover directly.
    pub async fn register(
        &self,
        capability: &str,
        changed_time: i64,
    ) -> Result<String, RuntimeError> {
        let mut budget = self.limits.requests;
        let collection = self.device_collection(capability, &mut budget).await?;
        if budget == 0 {
            return Err("registration request budget exhausted".into());
        }
        let e = crate::encode::Element::sep;
        let xml = e("EndDevice")
            .child(e("lFDI").text(self.identity))
            .child(e("sFDI").text(self.identity.sfdi().as_u64()))
            .child(e("changedTime").text(changed_time))
            .encode(self.limits.xml)?;
        let res = self
            .request(hyper::Method::POST, &collection, Bytes::from(xml))
            .await?;
        post_location(&res, &collection, self.limits.href_bytes)
    }

    /// Match both device identifiers, verify its registration PIN, and follow assignments to programs.
    pub async fn discover(
        &self,
        capability: &str,
        pin: u32,
    ) -> Result<Vec<ControlFeed>, RuntimeError> {
        let mut budget = self.limits.requests;
        let devices = self.device_collection(capability, &mut budget).await?;
        let mut mine = None;
        self.pages(
            &devices,
            "EndDeviceList",
            "EndDevice",
            &mut budget,
            |_, n| {
                let field = |name| n.children().find(|c| c.has_tag_name((codec::SEP, name)));
                let sfdi = field("sFDI").ok_or("missing sFDI")?;
                if codec::element_text(sfdi).trim().parse::<u64>()? != self.identity.sfdi().as_u64()
                {
                    return Ok(());
                }
                let lfdi = field("lFDI").ok_or("missing lFDI")?;
                if !codec::element_text(lfdi)
                    .trim()
                    .eq_ignore_ascii_case(&self.identity.to_string())
                {
                    return Err("device identity mismatch".into());
                }
                let registration = child_link(n, "RegistrationLink")?;
                let assignments = child_link(n, "FunctionSetAssignmentsListLink")?;
                let subscriptions = n
                    .children()
                    .find(|c| c.has_tag_name((codec::SEP, "SubscriptionListLink")))
                    .and_then(|child| child.attribute("href"))
                    .map(|href| link(&devices, href, self.limits.href_bytes))
                    .transpose()?;
                if mine
                    .replace((registration, assignments, subscriptions))
                    .is_some()
                {
                    return Err("duplicate device identity".into());
                }
                Ok(())
            },
        )
        .await?;
        let (registration, assignments, subscriptions) = mine.ok_or("registered device absent")?;
        let bytes = self
            .read(
                &link(&devices, &registration, self.limits.href_bytes)?,
                &mut budget,
            )
            .await?;
        let reg = self.parse(&bytes)?;
        if reg
            .as_type::<model::Registration>()?
            .pin()
            .ok_or("missing registration PIN")?
            .value()
            != pin
        {
            return Err("registration PIN mismatch".into());
        }
        let assignments = link(&devices, &assignments, self.limits.href_bytes)?;
        let mut lists = BTreeSet::new();
        self.pages(
            &assignments,
            "FunctionSetAssignmentsList",
            "FunctionSetAssignments",
            &mut budget,
            |_, n| {
                if let Ok(href) = child_link(n, "DERProgramListLink") {
                    lists.insert(link(&assignments, &href, self.limits.href_bytes)?);
                    if lists.len() > self.limits.requests {
                        return Err("program list budget exhausted".into());
                    }
                }
                Ok(())
            },
        )
        .await?;
        let mut feeds = Vec::new();
        let mut ids = BTreeSet::new();
        for list in lists {
            self.pages(
                &list,
                "DERProgramList",
                "DERProgram",
                &mut budget,
                |doc, n| {
                    let interval = number(doc.as_type::<model::DERProgramList>()?.poll_rate())?;
                    if interval == 0 {
                        return Err("zero program poll interval".into());
                    }
                    let Some(link_node) = n
                        .children()
                        .find(|c| c.has_tag_name((codec::SEP, "DERControlListLink")))
                    else {
                        return Ok(());
                    };
                    let program = model::DERProgram::from_validated(n, codec::Validated::new());
                    let id = program
                        .as_base()
                        .mrid()
                        .ok_or("missing program mRID")?
                        .bytes();
                    if ids.insert(id.clone()) {
                        if feeds.len() >= self.limits.requests {
                            return Err("control feed budget exhausted".into());
                        }
                        feeds.push(ControlFeed {
                            program_id: id,
                            subscription_list: subscriptions.clone(),
                            primacy: program.primacy().ok_or("missing primacy")?.value(),
                            url: link(
                                &list,
                                link_node.attribute("href").ok_or("missing list href")?,
                                self.limits.href_bytes,
                            )?,
                            poll_interval: Duration::from_secs(interval.into()),
                        });
                    }
                    Ok(())
                },
            )
            .await?;
        }
        Ok(feeds)
    }
    /// Wait the advertised interval, refresh the device assignment, and visit the current
    /// controls. The next call uses the updated poll rate and resource links.
    pub async fn poll_controls(
        &self,
        capability: &str,
        pin: u32,
        feed: &mut ControlFeed,
        visit: impl FnMut(model::DERControl<'_>),
    ) -> Result<(), RuntimeError> {
        feed.wait().await;
        let refreshed = self
            .discover(capability, pin)
            .await?
            .into_iter()
            .find(|item| item.program_id == feed.program_id)
            .ok_or("program no longer assigned")?;
        *feed = refreshed;
        self.controls(feed, visit).await
    }
    /// Read and validate the controls in a feed, streaming each item to the application.
    pub async fn controls(
        &self,
        feed: &ControlFeed,
        mut visit: impl FnMut(model::DERControl<'_>),
    ) -> Result<(), RuntimeError> {
        let mut budget = self.limits.requests;
        self.pages(
            &feed.url,
            "DERControlList",
            "DERControl",
            &mut budget,
            |_, n| {
                visit(model::DERControl::from_validated(
                    n,
                    codec::Validated::new(),
                ));
                Ok(())
            },
        )
        .await
    }
}

fn post_location(
    response: &hyper::Response<Bytes>,
    collection: &str,
    max_bytes: usize,
) -> Result<String, RuntimeError> {
    if !matches!(
        response.status(),
        hyper::StatusCode::OK | hyper::StatusCode::CREATED
    ) {
        return Err(format!("POST to {collection} returned {}", response.status()).into());
    }
    let location = response
        .headers()
        .get(hyper::header::LOCATION)
        .ok_or("missing POST response Location")?
        .to_str()?;
    link(collection, location, max_bytes)
}
