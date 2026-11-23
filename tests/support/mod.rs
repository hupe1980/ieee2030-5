#![allow(dead_code)]
use ieee2030_5::runtime::tls_context;
use openssl::{
    asn1::{Asn1Integer, Asn1Time},
    bn::BigNum,
    ec::{EcGroup, EcKey},
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, Private},
    x509::{
        X509, X509NameBuilder,
        extension::{
            AuthorityKeyIdentifier, BasicConstraints, KeyUsage, SubjectAlternativeName,
            SubjectKeyIdentifier,
        },
    },
};

pub struct Identity {
    pub cert: X509,
    pub key: PKey<Private>,
}
pub fn mint(label: &str, serial: u32, issuer: Option<&Identity>) -> Identity {
    mint_signed(label, serial, issuer, MessageDigest::sha256())
}
pub fn mint_signed(
    label: &str,
    serial: u32,
    issuer: Option<&Identity>,
    digest: MessageDigest,
) -> Identity {
    let curve = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let key = PKey::from_ec_key(EcKey::generate(&curve).unwrap()).unwrap();
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", label).unwrap();
    let name = name.build();
    let mut cert = X509::builder().unwrap();
    cert.set_version(2).unwrap();
    cert.set_serial_number(&Asn1Integer::from_bn(&BigNum::from_u32(serial).unwrap()).unwrap())
        .unwrap();
    cert.set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    cert.set_not_after(&Asn1Time::days_from_now(1).unwrap())
        .unwrap();
    cert.set_pubkey(&key).unwrap();
    cert.set_subject_name(&name).unwrap();
    cert.set_issuer_name(issuer.map(|i| i.cert.subject_name()).unwrap_or(&name))
        .unwrap();
    let key_id = SubjectKeyIdentifier::new()
        .build(&cert.x509v3_context(issuer.map(|identity| identity.cert.as_ref()), None))
        .unwrap();
    cert.append_extension(key_id).unwrap();
    match issuer {
        None => {
            cert.append_extension(BasicConstraints::new().critical().ca().build().unwrap())
                .unwrap();
            cert.append_extension(KeyUsage::new().critical().key_cert_sign().build().unwrap())
                .unwrap();
        }
        Some(i) => {
            cert.append_extension(BasicConstraints::new().critical().build().unwrap())
                .unwrap();
            cert.append_extension(
                KeyUsage::new()
                    .critical()
                    .digital_signature()
                    .key_agreement()
                    .build()
                    .unwrap(),
            )
            .unwrap();
            let authority = AuthorityKeyIdentifier::new()
                .keyid(true)
                .build(&cert.x509v3_context(Some(&i.cert), None))
                .unwrap();
            cert.append_extension(authority).unwrap();
            let san = SubjectAlternativeName::new()
                .dns(label)
                .build(&cert.x509v3_context(Some(&i.cert), None))
                .unwrap();
            cert.append_extension(san).unwrap();
        }
    }
    cert.sign(issuer.map(|i| &i.key).unwrap_or(&key), digest)
        .unwrap();
    Identity {
        cert: cert.build(),
        key,
    }
}
pub struct Setup {
    pub ca: Identity,
    pub client: Identity,
    pub server: Identity,
}
impl Setup {
    pub fn new() -> Self {
        let ca = mint("Test Root", 1, None);
        let client = mint("client.local", 2, Some(&ca));
        let server = mint("server.local", 3, Some(&ca));
        Self { ca, client, server }
    }
    pub fn context(&self, identity: &Identity) -> openssl::ssl::SslContext {
        tls_context(
            &identity.cert,
            &[],
            &identity.key,
            std::slice::from_ref(&self.ca.cert),
        )
        .unwrap()
    }
}
