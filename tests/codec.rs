use ieee2030_5::{
    codec::{Document, Error, Limits, element_text},
    model::{Reading, Registration},
};
fn parse(s: &str) -> Result<Document<'_>, Error> {
    Document::parse(s, Limits::default())
}
const REGISTRATION: &str = r#"<Registration xmlns="urn:ieee:std:2030.5:ns" href="/reg?a=1&amp;b=2"><dateTimeRegistered>10</dateTimeRegistered><pIN>123455</pIN></Registration>"#;

#[test]
fn typed_registration_and_round_trip() {
    let doc = parse(REGISTRATION).unwrap();
    let reg = doc.as_type::<Registration>().unwrap();
    assert_eq!(reg.as_base().href(), Some("/reg?a=1&b=2"));
    use ieee2030_5::model::View;
    assert_eq!(
        element_text(reg.date_time_registered().unwrap().node()),
        "10"
    );
    assert!(doc.as_type::<Reading>().is_err());
    let encoded = doc.encode();
    assert_eq!(parse(&encoded).unwrap().encode(), encoded);
}

// 001-schema-codegen/SR-001
#[test]
fn enforces_all_budgets_and_rejects_entity_declarations() {
    for limits in [
        Limits {
            bytes: 5,
            ..Limits::default()
        },
        Limits {
            nodes: 2,
            ..Limits::default()
        },
        Limits {
            depth: 1,
            ..Limits::default()
        },
    ] {
        assert!(matches!(
            Document::parse(REGISTRATION, limits),
            Err(Error::Limit(_))
        ));
    }
    assert!(
        parse(&format!(
            "<!DOCTYPE Registration [<!ENTITY a 'value'>]>{REGISTRATION}"
        ))
        .is_err()
    );
}

// 001-schema-codegen/SR-002
#[test]
fn enforces_namespace_derivation_order_and_facets() {
    for xml in [
        REGISTRATION.replace("urn:ieee:std:2030.5:ns", "urn:other"),
        REGISTRATION.replace("<pIN>", "<pIN xmlns=\"urn:other\">"),
        REGISTRATION.replace("123455", "4294967296"),
        REGISTRATION.replace("</pIN>", "</pIN><pIN>2</pIN>"),
        REGISTRATION.replace("<dateTimeRegistered>10</dateTimeRegistered>", ""),
        REGISTRATION.replace(
            "href=",
            "xmlns:i=\"http://www.w3.org/2001/XMLSchema-instance\" i:type=\"Reading\" href=",
        ),
    ] {
        assert!(parse(&xml).is_err(), "{xml}");
    }
}

#[test]
fn scalar_views_respect_facets_and_text_segments() {
    use ieee2030_5::model::Registration;
    let split = REGISTRATION.replace("123455", "12<!-- split -->3455");
    let doc = parse(&split).unwrap();
    assert_eq!(
        doc.as_type::<Registration>()
            .unwrap()
            .pin()
            .unwrap()
            .value(),
        123455
    );
    for value in ["-1", "4294967296", "123.0"] {
        assert!(parse(&REGISTRATION.replace("123455", value)).is_err());
    }
    let mut xml =
        r#"<Reading xmlns="urn:ieee:std:2030.5:ns"><localID>ABCD</localID></Reading>"#.to_owned();
    assert!(parse(&xml).is_ok());
    for invalid in ["ABCD00", "ABC", "XX"] {
        let bad = xml.replace("ABCD", invalid);
        assert!(parse(&bad).is_err());
    }
    xml = xml.replace("ABCD", "aB<!-- join -->CD");
    assert_eq!(
        parse(&xml)
            .unwrap()
            .as_type::<Reading>()
            .unwrap()
            .local_id()
            .unwrap()
            .bytes(),
        [0xab, 0xcd]
    );
}

#[test]
fn writer_escapes_values_and_validates_required_fields() {
    use ieee2030_5::encode::Element;
    let registration = Element::sep("Registration")
        .attribute("href", "/reg?a=b&c=d")
        .child(Element::sep("dateTimeRegistered").text(0))
        .child(Element::sep("pIN").text(123455));
    let xml = registration.encode(Limits::default()).unwrap();
    assert!(xml.contains("b&amp;c"));
    assert!(
        Element::sep("Registration")
            .encode(Limits::default())
            .is_err()
    );
    assert!(
        Element::sep("Registration")
            .attribute("xmlns", "other")
            .encode(Limits::default())
            .is_err()
    );
}
