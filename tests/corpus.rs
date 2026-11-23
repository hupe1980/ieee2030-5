use ieee2030_5::codec::{Document, Limits};

// Compare every expanded element/attribute name, value, text segment and child order.
// The representation permits XML-equivalent choices of namespace prefixes and quoting.
fn assert_equivalent(left: roxmltree::Node<'_, '_>, right: roxmltree::Node<'_, '_>) {
    assert_eq!(left.tag_name(), right.tag_name());
    assert_eq!(left.attributes().len(), right.attributes().len());
    for a in left.attributes() {
        let other = right
            .attributes()
            .find(|b| b.namespace() == a.namespace() && b.name() == a.name())
            .unwrap();
        assert_eq!(a.value(), other.value());
    }
    assert_eq!(
        ieee2030_5::codec::element_text(left),
        ieee2030_5::codec::element_text(right)
    );
    let lc = left.children().filter(roxmltree::Node::is_element);
    let rc = right.children().filter(roxmltree::Node::is_element);
    assert_eq!(lc.clone().count(), rc.clone().count());
    for (a, b) in lc.zip(rc) {
        assert_equivalent(a, b);
    }
}

/// Run explicitly with the Examples directory from the publisher's 2018 download.
#[test]
#[ignore = "requires the IEEE supplementary Examples directory"]
fn published_examples() {
    let dir = std::env::var_os("IEEE2030_5_EXAMPLES").expect("set IEEE2030_5_EXAMPLES");
    let mut valid = 0;
    let mut rejected = Vec::new();
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("xml") {
            continue;
        }
        let xml = std::fs::read_to_string(&path).unwrap();
        let doc = Document::parse(&xml, Limits::default());
        if path.file_name().unwrap() == "16_13_15_MirrorMeterReadingList.xml" {
            assert!(matches!(
                doc,
                Err(ieee2030_5::codec::Error::Missing("all" | "results"))
            ));
            rejected.push(path);
            continue;
        }
        let original = doc.unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        let encoded = original.encode();
        let parsed = Document::parse(&encoded, Limits::default()).unwrap();
        assert_equivalent(original.root(), parsed.root());
        assert_eq!(parsed.encode(), encoded);
        valid += 1;
    }
    assert_eq!(valid, 74);
    assert_eq!(rejected.len(), 1);
    println!("{valid} published XML examples round-tripped; 1 invalid example rejected");
}
