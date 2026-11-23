#![cfg(feature = "runtime")]
use hickory_proto::{
    op::{Message, OpCode},
    rr::{
        Name, RData, Record,
        rdata::{A, PTR, SRV, TXT},
    },
};
use ieee2030_5::{discovery::Service, xmdns::*};
use std::net::Ipv4Addr;

fn answer() -> Message {
    let base = Name::from_ascii("_smartenergy._tcp.site.").unwrap();
    let inst = Name::from_ascii("server._smartenergy._tcp.site.").unwrap();
    let host = Name::from_ascii("utility.site.").unwrap();
    let mut msg = Message::response(0, OpCode::Query);
    msg.metadata.authoritative = true;
    msg.answers
        .push(Record::from_rdata(base, 30, RData::PTR(PTR(inst.clone()))));
    msg.additionals = vec![
        Record::from_rdata(
            inst.clone(),
            30,
            RData::SRV(SRV::new(0, 0, 80, host.clone())),
        ),
        Record::from_rdata(
            inst,
            30,
            RData::TXT(TXT::new(vec![
                "txtvers=1".into(),
                "dcap=/cap".into(),
                "level=-S1".into(),
                "https".into(),
            ])),
        ),
        Record::from_rdata(host, 30, RData::A(A(Ipv4Addr::LOCALHOST))),
    ];
    msg
}

#[test]
fn bounds_and_association_before_following_an_answer() {
    // 006-discovery/SR-002
    let good = answer();
    assert_eq!(
        resolve_packet(&good.to_vec().unwrap(), Service::Capabilities)
            .unwrap()
            .address
            .port(),
        443
    );
    let other = Name::from_ascii("ignored.site.").unwrap();
    for i in 0..3 {
        let mut crossed = good.clone();
        crossed.additionals[i].name = other.clone();
        assert!(resolve_packet(&crossed.to_vec().unwrap(), Service::Capabilities).is_none());
        let mut stale = good.clone();
        stale.additionals[i].ttl = 0;
        assert!(resolve_packet(&stale.to_vec().unwrap(), Service::Capabilities).is_none());
    }
    for bytes in [vec![0; 11], vec![255; 12], vec![0; 9001]] {
        assert!(resolve_packet(&bytes, Service::Capabilities).is_none())
    }
    assert!(resolve_packet(&good.to_vec().unwrap(), Service::Time).is_none());
    let mut bad = good.clone();
    bad.metadata.truncation = true;
    assert!(resolve_packet(&bad.to_vec().unwrap(), Service::Capabilities).is_none());
}
