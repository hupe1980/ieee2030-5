#![no_main]
use ieee2030_5::codec::{Document, Limits};
use libfuzzer_sys::fuzz_target;
fuzz_target!(|xml: &str| {
    let limits = Limits {
        bytes: 16 * 1024,
        ..Limits::default()
    };
    if let Ok(doc) = Document::parse(xml, limits) {
        assert!(Document::parse(&doc.encode(), Limits::default()).is_ok());
    }
    if let Ok(doc) = Document::parse_aus(xml, limits) {
        assert!(Document::parse_aus(&doc.encode(), Limits::default()).is_ok());
    }
});
