#![cfg(feature = "csip-aus")]
use ieee2030_5::{
    codec::{Document, Limits},
    csip_aus::*,
    model::DERControlBase,
    schedule::*,
};

#[test]
fn exact_site_limits() {
    // 009-csip-aus/SR-001
    for (value, multiplier, expected) in [
        (10, -1, Ok(1)),
        (-250, -1, Ok(-25)),
        (1, -1, Err(PowerError::Fractional)),
        (1, 127, Err(PowerError::Overflow)),
        (0, -128, Ok(0)),
        (1, -128, Err(PowerError::Fractional)),
    ] {
        assert_eq!(ActivePower { value, multiplier }.whole_watts(), expected);
    }
}

#[test]
fn dynamic_export_limit_across_roles() {
    // 009-csip-aus/SR-002
    let xml = r#"<DERControlBase xmlns="urn:ieee:std:2030.5:ns" xmlns:aus="https://csipaus.org/ns"><aus:opModExpLimW><multiplier>1</multiplier><value>450</value></aus:opModExpLimW></DERControlBase>"#;
    let published = Document::parse_aus(xml, Limits::default())
        .unwrap()
        .encode();
    let received = Document::parse_aus(&published, Limits::default()).unwrap();
    let base = received.as_type::<DERControlBase>().unwrap();
    let limit = ActivePower::from_control(base, Mode::Export)
        .unwrap()
        .unwrap();
    assert_eq!(ActivePower::from_control(base, Mode::Import).unwrap(), None);
    let site = SiteMode {
        connection_point: "site-123",
        mode: Mode::Export,
    };
    let other = SiteMode {
        connection_point: "site-456",
        ..site
    };
    let event = Event {
        id: 5,
        mode: site,
        value: limit,
        primacy: 1,
        created: 1,
        received: 1,
        window: Window::new(10, 30, Offset::default(), Offset::default()).unwrap(),
        termination: None,
    };
    let events = [event];
    let Selection::Event { value, .. } = effective_limit(&events, site, 11, None, 8).unwrap()
    else {
        panic!()
    };
    assert_eq!(value.whole_watts(), Ok(4500));
    assert_eq!(
        effective_limit(&events, other, 11, Some((site, &limit)), 8),
        Ok(Selection::Idle)
    );
    assert_eq!(
        effective_limit(&events, site, 40, None, 8),
        Ok(Selection::Idle)
    );
}

#[test]
fn extension_elements_round_trip_and_keep_their_namespace() {
    let sep = "urn:ieee:std:2030.5:ns";
    let power = "<multiplier>0</multiplier><value>500</value>";
    for (name, contents, attrs) in [
        ("opModImpLimW", power, ""),
        ("opModExpLimW", power, ""),
        ("opModGenLimW", power, ""),
        ("opModLoadLimW", power, ""),
        ("doeModesSupported", "0F", ""),
        ("doeModesEnabled", "03", ""),
        ("ConnectionPointLink", "", " href=\"/nmi\""),
        (
            "ConnectionPoint",
            "<aus:connectionPointId>SITE123</aus:connectionPointId>",
            "",
        ),
    ] {
        let xml = format!(
            "<aus:{name} xmlns=\"{sep}\" xmlns:aus=\"{NAMESPACE}\"{attrs}>{contents}</aus:{name}>"
        );
        let doc = Document::parse_aus(&xml, Limits::default()).unwrap();
        let encoded = doc.encode();
        let decoded = Document::parse_aus(&encoded, Limits::default()).unwrap();
        assert_eq!(decoded.encode(), encoded);
        assert_eq!(decoded.root().tag_name().namespace(), Some(NAMESPACE));
        assert!(Document::parse(&encoded, Limits::default()).is_err());
    }
}
