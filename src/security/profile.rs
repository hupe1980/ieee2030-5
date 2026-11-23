//! Manufacturing certificate checks and private-root path validation.
//! Use [`validate_device_leaf`] to inspect a leaf or [`verify_device_chain`] to authenticate it.
use super::Lfdi;
use x509_parser::{
    asn1_rs::{Any, Class, Tag},
    der_parser::der::parse_der_sequence,
    extensions::{GeneralName, ParsedExtension},
    prelude::*,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProfileError {
    InvalidDer,
    Expired,
    Lifetime,
    ForbiddenExtension,
    IssuerKey,
    Authority,
    NotYetValid,
    WrongCurve,
    WrongSignature,
    KeyUsage,
    Policy,
    HardwareIdentity,
    IsCa,
}

impl core::fmt::Display for ProfileError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "device certificate: {self:?}")
    }
}
impl core::error::Error for ProfileError {}

fn hardware_name(value: &[u8]) -> bool {
    let Ok(([], tag)) = Any::from_der(value) else {
        return false;
    };
    if tag.header.class() != Class::ContextSpecific
        || tag.tag() != Tag(0)
        || !tag.header.constructed()
    {
        return false;
    }
    let Ok(([], seq)) = parse_der_sequence(tag.data) else {
        return false;
    };
    let Ok(items) = seq.as_sequence() else {
        return false;
    };
    let [oid, serial] = items.as_slice() else {
        return false;
    };
    oid.as_oid().is_ok()
        && serial.header.tag() == Tag::OctetString
        && serial.as_slice().is_ok_and(|v| !v.is_empty())
}

/// IEEE 2030.5-2018 §6.11.6 specifies GeneralizedTime 99991231235959Z.
const INDEFINITE: i64 = 253402300799;
const ANY_POLICY: u8 = 8;

fn device_policies(cert: &X509Certificate<'_>) -> u8 {
    let mut bits = 0;
    for extension in cert.extensions() {
        if let ParsedExtension::CertificatePolicies(policies) = extension.parsed_extension() {
            if !extension.critical {
                return 0;
            }
            for policy in policies {
                bits |= match policy.policy_id.to_id_string().as_str() {
                    "1.3.6.1.4.1.40732.1.1" => 1,
                    "1.3.6.1.4.1.40732.1.2" => 2,
                    "1.3.6.1.4.1.40732.1.3" => 4,
                    "2.5.29.32.0" => ANY_POLICY,
                    _ => 0,
                };
            }
        }
    }
    bits
}

fn common_profile(cert: &X509Certificate<'_>) -> Result<(), ProfileError> {
    if cert.version() != X509Version::V3 || cert.extensions_map().is_err() {
        return Err(ProfileError::InvalidDer);
    }
    if cert.validity().not_after.timestamp() != INDEFINITE {
        return Err(ProfileError::Lifetime);
    }
    if cert
        .extensions()
        .iter()
        .any(|e| matches!(e.oid.to_id_string().as_str(), "2.5.29.30" | "2.5.29.33"))
    {
        return Err(ProfileError::ForbiddenExtension);
    }
    let point = &cert.public_key().subject_public_key;
    if point.unused_bits != 0 || point.data.len() != 65 || point.data.first() != Some(&4) {
        return Err(ProfileError::WrongCurve);
    }
    Ok(())
}
/// Inspect one DER certificate at the caller's Unix time. Verifies the leaf's
/// P-256 key, ECDSA/SHA-256 signature algorithm, validity, critical key usage,
/// device-class policy and RFC 4108 hardware identity. The caller must verify
/// its signature chain separately before trusting the returned identifier.
pub fn validate_device_leaf(der: &[u8], unix_seconds: i64) -> Result<Lfdi, ProfileError> {
    if der.len() > 64 * 1024 {
        return Err(ProfileError::InvalidDer);
    }
    let (rest, cert) = X509Certificate::from_der(der).map_err(|_| ProfileError::InvalidDer)?;
    if !rest.is_empty() {
        return Err(ProfileError::InvalidDer);
    }
    if unix_seconds < cert.validity().not_before.timestamp() {
        return Err(ProfileError::NotYetValid);
    }
    if unix_seconds > cert.validity().not_after.timestamp() {
        return Err(ProfileError::Expired);
    }
    common_profile(&cert)?;
    let key = &cert.public_key().algorithm;
    if key.algorithm.to_id_string() != "1.2.840.10045.2.1"
        || !key
            .parameters
            .as_ref()
            .and_then(|v| v.as_oid().ok())
            .is_some_and(|v| v.to_id_string() == "1.2.840.10045.3.1.7")
    {
        return Err(ProfileError::WrongCurve);
    }
    if cert.signature_algorithm != cert.tbs_certificate.signature
        || cert.signature_algorithm.algorithm.to_id_string() != "1.2.840.10045.4.3.2"
    {
        return Err(ProfileError::WrongSignature);
    }
    if cert.is_ca() {
        return Err(ProfileError::IsCa);
    }
    let usage = cert
        .key_usage()
        .map_err(|_| ProfileError::KeyUsage)?
        .ok_or(ProfileError::KeyUsage)?;
    if !usage.critical
        || !(usage.value.digital_signature() || usage.value.key_agreement())
        || usage.value.flags & !0b1_0001 != 0
    {
        return Err(ProfileError::KeyUsage);
    }
    let device_types = device_policies(&cert);
    if device_types == 0 || device_types & ANY_POLICY != 0 {
        return Err(ProfileError::Policy);
    }
    let san = cert
        .subject_alternative_name()
        .map_err(|_| ProfileError::HardwareIdentity)?
        .ok_or(ProfileError::HardwareIdentity)?;
    let [GeneralName::OtherName(oid, value)] = san.value.general_names.as_slice() else {
        return Err(ProfileError::HardwareIdentity);
    };
    if !san.critical
        || cert.subject().iter().next().is_some()
        || oid.to_id_string() != "1.3.6.1.5.5.7.8.4"
        || !hardware_name(value)
    {
        return Err(ProfileError::HardwareIdentity);
    }
    let has_authority_key = cert.extensions().iter().any(|ext| {
        matches!(
            ext.parsed_extension(), ParsedExtension::AuthorityKeyIdentifier(id)
            if !ext.critical
                && id.key_identifier.is_some()
                && id.authority_cert_issuer.is_none()
                && id.authority_cert_serial.is_none()
        )
    });
    if !has_authority_key {
        return Err(ProfileError::IssuerKey);
    }
    Ok(Lfdi::from_certificate_der(der))
}

/// The failure that prevented certificate-based authentication at a supplied instant.
#[derive(Debug)]
pub enum ChainError {
    Profile(ProfileError),
    ChainTooLong,
    UnsupportedPathAlgorithm,
    CertificateTooLarge,
    TimeOutOfRange,
    Provider(openssl::error::ErrorStack),
    Path {
        depth: u32,
        reason: openssl::x509::X509VerifyResult,
    },
}
impl core::fmt::Display for ChainError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Profile(err) => err.fmt(f),
            Self::UnsupportedPathAlgorithm => f.write_str("path requires P-256 and ECDSA/SHA-256"),
            Self::ChainTooLong => f.write_str("too many intermediates"),
            Self::CertificateTooLarge => f.write_str("certificate exceeds 64 KiB"),
            Self::TimeOutOfRange => f.write_str("certificate verification time out of range"),
            Self::Provider(e) => e.fmt(f),
            Self::Path { depth, reason } => {
                write!(f, "certificate path at depth {depth}: {reason}")
            }
        }
    }
}
impl core::error::Error for ChainError {}
impl From<openssl::error::ErrorStack> for ChainError {
    fn from(e: openssl::error::ErrorStack) -> Self {
        Self::Provider(e)
    }
}

/// Verify the leaf profile and an RFC 5280 certificate path using libcrypto.
/// All certificates are DER. The caller chooses trust anchors and the verification
/// instant. Peer-supplied intermediates are untrusted and limited to eight entries.
pub fn verify_device_chain(
    leaf: &[u8],
    intermediates: &[&[u8]],
    roots: &[&[u8]],
    unix_seconds: i64,
) -> Result<Lfdi, ChainError> {
    use openssl::{
        stack::Stack,
        x509::{
            X509, X509PurposeId, X509StoreContext, store::X509StoreBuilder, verify::X509VerifyParam,
        },
    };
    let id = validate_device_leaf(leaf, unix_seconds).map_err(ChainError::Profile)?;
    if intermediates.len() > 8 {
        return Err(ChainError::ChainTooLong);
    }
    let parse = |der: &[u8]| -> Result<X509, ChainError> {
        if der.len() > 64 * 1024 {
            return Err(ChainError::CertificateTooLarge);
        }
        Ok(X509::from_der(der)?)
    };
    let leaf = parse(leaf)?;
    let mut chain = Stack::new()?;
    for cert in intermediates {
        chain.push(parse(cert)?)?;
    }
    let mut store = X509StoreBuilder::new()?;
    for root in roots {
        store.add_cert(parse(root)?)?;
    }
    let mut params = X509VerifyParam::new()?;
    params.set_auth_level(2);
    params.set_depth(8);
    params.set_purpose(X509PurposeId::SSL_CLIENT)?;
    #[allow(clippy::useless_conversion)] // time_t width depends on target.
    params.set_time(
        unix_seconds
            .try_into()
            .map_err(|_| ChainError::TimeOutOfRange)?,
    );
    store.set_param(&params)?;
    let mut ctx = X509StoreContext::new()?;
    let verdict = ctx.init(&store.build(), &leaf, &chain, |c| {
        if c.verify_cert()? {
            if !c
                .chain()
                .is_some_and(|chain| chain.iter().all(credential_algorithms))
            {
                return Ok(Err(ChainError::UnsupportedPathAlgorithm));
            }
            Ok(c.chain()
                .ok_or(ChainError::UnsupportedPathAlgorithm)
                .and_then(|path| validate_issuers(path).map_err(ChainError::Profile)))
        } else {
            Ok(Err(ChainError::Path {
                depth: c.error_depth(),
                reason: c.error(),
            }))
        }
    })?;
    verdict?;
    Ok(id)
}

/// Inspect the actual RFC 5280 path, in leaf-to-anchor order. Never treat the
/// unverified certificates supplied by a peer as a path.
pub(crate) fn validate_issuers(
    chain: &openssl::stack::StackRef<openssl::x509::X509>,
) -> Result<(), ProfileError> {
    if !(2..=4).contains(&chain.len()) {
        return Err(ProfileError::Authority);
    }
    let mut child_policy = 0u8;
    let mut child_issuer = None;
    for (index, cert) in chain.iter().enumerate() {
        let der = cert.to_der().map_err(|_| ProfileError::InvalidDer)?;
        let (_, parsed) = X509Certificate::from_der(&der).map_err(|_| ProfileError::InvalidDer)?;
        common_profile(&parsed)?;
        let policies = device_policies(&parsed);
        if index > 0 {
            let root = index + 1 == chain.len();
            let constraints = parsed
                .basic_constraints()
                .map_err(|_| ProfileError::Authority)?
                .ok_or(ProfileError::Authority)?;
            let path_len = if root { None } else { Some((index - 1) as u32) };
            if !constraints.critical
                || !constraints.value.ca
                || constraints.value.path_len_constraint != path_len
            {
                return Err(ProfileError::Authority);
            }
            let key = parsed
                .key_usage()
                .map_err(|_| ProfileError::KeyUsage)?
                .ok_or(ProfileError::KeyUsage)?;
            if !key.critical || !key.value.key_cert_sign() || (root && !key.value.crl_sign()) {
                return Err(ProfileError::KeyUsage);
            }
            if root && policies != ANY_POLICY
                || !root
                    && (policies == 0
                        || policies & ANY_POLICY != 0
                        || child_policy & !policies != 0)
            {
                return Err(ProfileError::Policy);
            }
            let subject = cert
                .subject_key_id()
                .map(|v| v.as_slice())
                .ok_or(ProfileError::IssuerKey)?;
            if child_issuer.as_deref() != Some(subject) {
                return Err(ProfileError::IssuerKey);
            }
        }
        child_policy = policies;
        child_issuer = cert.authority_key_id().map(|v| v.as_slice().to_vec());
    }
    Ok(())
}

pub(crate) fn credential_algorithms(cert: &openssl::x509::X509Ref) -> bool {
    use openssl::nid::Nid;
    cert.signature_algorithm().object().nid() == Nid::ECDSA_WITH_SHA256
        && cert
            .public_key()
            .ok()
            .and_then(|key| key.ec_key().ok())
            .is_some_and(|key| key.group().curve_name() == Some(Nid::X9_62_PRIME256V1))
}
