// 006-discovery/SR-001
use ieee2030_5::discovery::{DiscoveryError, Endpoint};
#[test]
fn require_secure_origin_relative_capabilities() {
    assert_eq!(
        Endpoint::from_txt(None, "/dcap"),
        Err(DiscoveryError::MissingHttps)
    );
    for path in [
        "//peer/path",
        "/bad\r\nheader",
        "/bad#fragment",
        "/\\example",
        "https://peer",
        "",
    ] {
        assert_eq!(
            Endpoint::from_txt(Some("443"), path),
            Err(DiscoveryError::InvalidPath)
        );
    }
    for port in ["0", "65536", "+443", "4 43"] {
        assert_eq!(
            Endpoint::from_txt(Some(port), "/dcap"),
            Err(DiscoveryError::InvalidPort)
        );
    }
    assert_eq!(
        Endpoint::from_txt(Some(""), "/SEP/dcap")
            .unwrap()
            .https_port
            .get(),
        443
    );
}

#[test]
fn check_version_level_and_subtype_path_before_following_records() {
    use ieee2030_5::discovery::{Service, from_record};
    let parse = |version, level, path| {
        from_record(
            version,
            level,
            Some(""),
            Some("/cap"),
            path,
            Service::DerPrograms,
        )
    };
    assert!(parse(None, Some("-S1"), Some("/programs")).is_err());
    assert!(parse(Some("1"), Some(""), Some("/programs")).is_err());
    assert!(parse(Some("1"), Some("-S1"), None).is_err());
    assert!(parse(Some("1"), Some("-S1"), Some("//another")).is_err());
    assert_eq!(
        parse(Some("1"), Some("-S1"), Some("/programs"))
            .unwrap()
            .https_port
            .get(),
        443
    );
    assert_eq!(
        Service::DerPrograms.local_name(),
        "derp._sub._smartenergy._tcp.local."
    );
}
