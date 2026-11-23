use ieee2030_5::schedule::*;
fn event(id: u128, primacy: u8, start: i64, duration: u32) -> Event<u8, i32> {
    Event {
        id,
        mode: 0,
        value: id as i32,
        primacy,
        created: start,
        received: start,
        window: Window::new(start, duration, Offset::default(), Offset::default()).unwrap(),
        termination: None,
    }
}

#[test]
fn randomizable_event_validates_all_boundaries() {
    // 004-der-scheduling/SR-001
    let pos = Offset { bound: 3, draw: 2 };
    let neg = Offset {
        bound: -4,
        draw: -4,
    };
    let w = Window::new(100, 10, pos, neg).unwrap();
    assert_eq!((w.start(), w.end()), (102, 108));
    assert_eq!(
        Window::new(i64::MAX, 1, pos, neg),
        Err(Error::InvalidInterval)
    );
    assert_eq!(
        Window::new(i64::MIN, 10, neg, pos),
        Err(Error::InvalidInterval)
    );
    assert_eq!(Window::new(12, 4, pos, neg), Err(Error::InvalidInterval));
    for bad in [
        Offset { bound: 3, draw: -1 },
        Offset { bound: -4, draw: 1 },
        Offset {
            bound: 3601,
            draw: 0,
        },
    ] {
        assert_eq!(Window::new(0, 1, bad, pos), Err(Error::InvalidOffset));
    }
}

#[test]
fn csip_aus_explainer_7_primacy_and_displacement() {
    // 004-der-scheduling/SR-002
    let mut other = event(32, 0, 50, 200);
    other.mode = 1;
    let events = [event(2, 1, 100, 50), event(1, 2, 0, 200), other];
    let selected = |now| select(&events, &0, now, Some(&9), 6).unwrap();
    assert_eq!(selected(-1), Selection::Default(&9));
    assert_eq!(selected(0), Selection::Event { id: 1, value: &1 });
    assert_eq!(selected(99), Selection::Event { id: 1, value: &1 });
    assert_eq!(selected(100), Selection::Event { id: 2, value: &2 });
    assert_eq!(selected(149), Selection::Event { id: 2, value: &2 });
    assert_eq!(selected(150), Selection::Default(&9));
    assert_eq!(
        select(&events, &1, 175, None, 3),
        Ok(Selection::Event { id: 32, value: &32 })
    );
    assert_eq!(select(&events, &0, 0, None, 2), Err(Error::Capacity));
}

#[test]
fn event_status_cancellation_supersession_and_responses() {
    for termination in [Termination::Cancelled(3), Termination::Superseded(3)] {
        let mut e = event(18, 0, 1, 8);
        e.termination = Some(termination);
        assert_eq!(select(&[e], &0, 3, None, 1), Ok(Selection::Idle));
    }
    let mut replies = Responses::default();
    use ResponseStatus::*;
    for status in [Received, Started, Completed] {
        assert_eq!(replies.observe(status, 3), Ok(Some(status)));
        assert_eq!(replies.observe(status, 3), Ok(None));
    }
    assert_eq!(replies.observe(Started, 3), Err(Error::InvalidTransition));
    let mut replies = Responses::default();
    assert_eq!(replies.observe(Received, 2), Ok(None));
    assert_eq!(replies.observe(Cancelled, 2), Ok(Some(Cancelled)));
}

#[test]
fn wire_program_control_and_acknowledgement() {
    use ieee2030_5::resource::{Contents, Link, Method, PageQuery, Representation, ResourceTree};
    use ieee2030_5::{
        codec::{Document, Limits},
        model,
        security::Lfdi,
    };
    let program_xml = r#"<DERProgram xmlns="urn:ieee:std:2030.5:ns"><mRID>AA</mRID><DERControlListLink href="/program/events"/><primacy>1</primacy></DERProgram>"#;
    let control_xml = r#"<DERControl xmlns="urn:ieee:std:2030.5:ns" responseRequired="03" replyTo="/responses"><mRID>BB</mRID><creationTime>2</creationTime><EventStatus><currentStatus>0</currentStatus><dateTime>2</dateTime><potentiallySuperseded>false</potentiallySuperseded></EventStatus><interval><duration>5</duration><start>10</start></interval><DERControlBase><opModConnect>true</opModConnect><opModTargetW><multiplier>1</multiplier><value>5</value></opModTargetW></DERControlBase><deviceCategory>01</deviceCategory></DERControl>"#;
    let mut server = ResourceTree::new(Default::default());
    server
        .publish(
            "/event",
            "DERControl",
            Contents::Item {
                value: control_xml,
                links: vec![],
            },
        )
        .unwrap();
    server
        .publish(
            "/program/events",
            "DERControlList",
            Contents::List {
                members: vec![Link {
                    path: "/event".into(),
                    time_key: None,
                }],
            },
        )
        .unwrap();
    server
        .publish(
            "/program",
            "DERProgram",
            Contents::Item {
                value: program_xml,
                links: vec!["/program/events".into()],
            },
        )
        .unwrap();
    let read = |path: &str| {
        server
            .read(path, Method::Get, PageQuery::default())
            .unwrap()
    };
    let Representation::Item { value, .. } = read("/program") else {
        panic!()
    };
    let program_doc = Document::parse(value, Limits::default()).unwrap();
    let program = program_doc.as_type::<model::DERProgram>().unwrap();
    let resource = program
        .der_control_list_link()
        .unwrap()
        .as_base()
        .as_base()
        .href()
        .unwrap();
    let Representation::Page { members, .. } = read(resource) else {
        panic!()
    };
    let Representation::Item { value, .. } = read(&members[0].path) else {
        panic!()
    };
    let control_doc = Document::parse(value, Limits::default()).unwrap();
    let control = control_doc.as_type::<model::DERControl>().unwrap();
    assert!(
        from_control(program, control, Draws::default(), 2, 3)
            .unwrap()
            .is_empty()
    );
    let projected = from_control(program, control, Draws::default(), 1, 3).unwrap();
    assert_eq!(projected.len(), 2);
    let key = projected[1].mode;
    let Selection::Event { id, value } = select(&projected, &key, 11, None, 10).unwrap() else {
        panic!()
    };
    assert_eq!(id, 187);
    assert_eq!(value.tag_name().name(), "opModTargetW");
    let default_xml = r#"<DefaultDERControl xmlns="urn:ieee:std:2030.5:ns"><mRID>DC</mRID><DERControlBase><opModConnect>false</opModConnect></DERControlBase></DefaultDERControl>"#;
    let default_doc = Document::parse(default_xml, Limits::default()).unwrap();
    let controls = [ReceivedControl {
        resource: control,
        received: 3,
        draws: Draws::default(),
    }];
    let programs = [Program {
        resource: program,
        default: Some(default_doc.as_type::<model::DefaultDERControl>().unwrap()),
        controls: &controls,
    }];
    let query = ("urn:ieee:std:2030.5:ns", "opModConnect");
    let ActiveControl::Default(v) = effective_control(&programs, query, 9, 1, 4).unwrap() else {
        panic!()
    };
    assert_eq!(v.text(), Some("false"));
    assert!(matches!(
        effective_control(&programs, query, 10, 1, 4),
        Ok(ActiveControl::Event { id: 187, .. })
    ));
    let mut replies = Responses::default();
    assert!(
        replies
            .acknowledge(control, Lfdi([0x42; 20]), 2, 3, ResponseStatus::Received)
            .unwrap()
            .is_none()
    );
    for (status, now) in [
        (ResponseStatus::Received, 3),
        (ResponseStatus::Started, 10),
        (ResponseStatus::Completed, 15),
    ] {
        let write = replies
            .acknowledge(control, Lfdi([0x42; 20]), 1, now, status)
            .unwrap()
            .unwrap();
        assert_eq!(write.href, "/responses");
        let doc = Document::parse(&write.xml, Limits::default()).unwrap();
        doc.as_type::<model::DERControlResponse>().unwrap();
        assert!(write.xml.contains("<subject>BB</subject>"));
    }
}

#[test]
fn der_reports_follow_advertised_links() {
    use ieee2030_5::{
        codec::{Document, Limits},
        model,
    };
    let common = "urn:ieee:std:2030.5:ns";
    let der=Document::parse(r#"<DER xmlns="urn:ieee:std:2030.5:ns"><DERAvailabilityLink href="/av"/><DERCapabilityLink href="/cap"/><DERSettingsLink href="/set"/><DERStatusLink href="/st"/></DER>"#,Limits::default()).unwrap();
    let device = der.as_type::<model::DER>().unwrap();
    let power = "<multiplier>1</multiplier><value>25</value>";
    for (kind, href, fields) in [
        (
            "DERAvailability",
            "/av",
            "<readingTime>1</readingTime>".into(),
        ),
        ("DERStatus", "/st", "<readingTime>2</readingTime>".into()),
        (
            "DERCapability",
            "/cap",
            format!("<modesSupported>01</modesSupported><rtgMaxW>{power}</rtgMaxW><type>00</type>"),
        ),
        (
            "DERSettings",
            "/set",
            format!(
                "<setGradW>100</setGradW><setMaxW>{power}</setMaxW><updatedTime>1</updatedTime>"
            ),
        ),
    ] {
        let xml = format!("<{kind} xmlns=\"{common}\">{fields}</{kind}>");
        let doc = Document::parse(&xml, Limits::default()).unwrap();
        let put = report(device, &doc).unwrap();
        assert_eq!(put.href, href);
        assert_eq!(put.method, ieee2030_5::resource::Method::Put);
        assert!(Document::parse(&put.xml, Limits::default()).is_ok());
    }
}

#[test]
fn csip_7_10_receipt_before_or_after_start() {
    let mut low = event(1, 2, 3, 7);
    low.received = 1;
    let mut high = event(2, 0, 6, 3);
    high.received = 2;
    let early = [low.clone(), high.clone()];
    assert_eq!(
        select(&early, &0, 4, Some(&9), 16),
        Ok(Selection::Default(&9))
    );
    high.received = 4;
    let late = [high, low];
    assert_eq!(
        select(&late, &0, 5, Some(&9), 16),
        Ok(Selection::Event { id: 1, value: &1 })
    );
    assert_eq!(
        select(&late, &0, 6, Some(&9), 16),
        Ok(Selection::Event { id: 2, value: &2 })
    );
    assert_eq!(
        select(&late, &0, 9, Some(&9), 16),
        Ok(Selection::Default(&9))
    );
    let mut responses = Responses::default();
    responses.observe(ResponseStatus::Received, 3).unwrap();
    assert_eq!(
        responses
            .observe(ResponseStatus::SupersededByOtherProgram, 3)
            .unwrap()
            .unwrap() as u8,
        14
    );
}
