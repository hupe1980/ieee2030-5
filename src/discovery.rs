//! Secure endpoints described by DNS-SD (IEEE 2030.5-2018 §7, Table 16).
use core::num::NonZeroU16;

/// Link-local mDNS service type. Site-scoped xmDNS uses a different multicast group.
pub const SERVICE_TYPE: &str = "_smartenergy._tcp.local.";

/// A borrowed endpoint from a validated pair of DNS-SD TXT fields.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Endpoint<'a> {
    pub https_port: NonZeroU16,
    pub capability_path: &'a str,
}

/// A record cannot identify a secure, origin-relative resource.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DiscoveryError {
    InvalidVersion,
    InvalidLevel,
    MissingHttps,
    InvalidPort,
    InvalidPath,
}

impl<'a> Endpoint<'a> {
    /// Read the `https` and `dcap` TXT fields. An empty HTTPS field advertises port 443.
    pub fn from_txt(https: Option<&str>, dcap: &'a str) -> Result<Self, DiscoveryError> {
        let value = https.ok_or(DiscoveryError::MissingHttps)?;
        let port = if value.is_empty() {
            443
        } else {
            if !value.bytes().all(|b| b.is_ascii_digit()) {
                return Err(DiscoveryError::InvalidPort);
            }
            value
                .parse::<u16>()
                .map_err(|_| DiscoveryError::InvalidPort)?
        };
        let https_port = NonZeroU16::new(port).ok_or(DiscoveryError::InvalidPort)?;
        // A single DNS TXT string including "dcap=" is limited to 255 bytes (RFC 6763 §6.1).
        if !dcap.starts_with('/')
            || dcap.starts_with("//")
            || dcap.len() > 250
            || fluent_uri::UriRef::parse(dcap).is_err()
            || dcap
                .bytes()
                .any(|b| !b.is_ascii_graphic() || matches!(b, b'#' | b'\\'))
        {
            return Err(DiscoveryError::InvalidPath);
        }
        Ok(Self {
            https_port,
            capability_path: dcap,
        })
    }
}

/// Function-set filters in IEEE 2030.5-2018 §7.5, Table 17.
/// The `edev-SFDI` form identifies a specific EndDevice.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Service {
    Capabilities,
    Billing,
    DerPrograms,
    DemandResponse,
    EndDevices,
    Device(crate::security::Sfdi),
    Files,
    Messaging,
    MirrorUsagePoints,
    Prepayment,
    Responses,
    SelfDevice,
    Time,
    Tariffs,
    UsagePoints,
}
impl Service {
    pub fn local_name(self) -> alloc::string::String {
        let subtype = match self {
            Self::Capabilities => return SERVICE_TYPE.into(),
            Self::Billing => "bill",
            Self::DerPrograms => "derp",
            Self::DemandResponse => "dr",
            Self::EndDevices => "edev",
            Self::Device(id) => return alloc::format!("edev-{id}._sub.{SERVICE_TYPE}"),
            Self::Files => "file",
            Self::Messaging => "msg",
            Self::MirrorUsagePoints => "mup",
            Self::Prepayment => "ppy",
            Self::Responses => "rsps",
            Self::SelfDevice => "sdev",
            Self::Time => "tm",
            Self::Tariffs => "tp",
            Self::UsagePoints => "upt",
        };
        alloc::format!("{subtype}._sub.{SERVICE_TYPE}")
    }
}

/// Validate the mandatory TXT fields for link-local discovery (2018 §7.4).
/// The version must be 1. Unknown keys can be ignored by the record reader.
pub fn from_record<'a>(
    version: Option<&str>,
    level: Option<&str>,
    https: Option<&str>,
    capability: Option<&'a str>,
    function_path: Option<&str>,
    service: Service,
) -> Result<Endpoint<'a>, DiscoveryError> {
    if version != Some("1") {
        return Err(DiscoveryError::InvalidVersion);
    }
    if !level
        .and_then(|s| s.strip_prefix("+S").or_else(|| s.strip_prefix("-S")))
        .is_some_and(|s| !s.is_empty() && s.bytes().all(|c| c.is_ascii_digit()))
    {
        return Err(DiscoveryError::InvalidLevel);
    }
    if service != Service::Capabilities {
        Endpoint::from_txt(https, function_path.ok_or(DiscoveryError::InvalidPath)?)?;
    }
    Endpoint::from_txt(https, capability.ok_or(DiscoveryError::InvalidPath)?)
}
