use ieee2030_5::resource::*;

fn item(value: u8, links: &[&str]) -> Contents<u8> {
    Contents::Item {
        value,
        links: links.iter().copied().map(String::from).collect(),
    }
}

#[test]
fn gen_019_through_027_page_limits_and_time_keys() {
    // 003-resource-core/SR-001
    for size in 0..18 {
        let mut tree = ResourceTree::new(Limits {
            page: 5,
            ..Limits::default()
        });
        let mut members = Vec::new();
        for n in 0..size {
            let path = format!("/r/{n}");
            tree.publish(&path, "EndDevice", item(n, &[])).unwrap();
            members.push(Link {
                path,
                time_key: Some(i64::from(n / 2)),
            });
        }
        tree.publish("/list", "EndDeviceList", Contents::List { members })
            .unwrap();
        for start in [0, 1, 5, 17, u32::MAX] {
            for limit in [0, 1, 3, 5, u32::MAX] {
                for after in [None, Some(-1), Some(0), Some(4), Some(100)] {
                    let query = PageQuery {
                        start,
                        limit,
                        after,
                    };
                    let Representation::Page { all, members } =
                        tree.read("/list", Method::Get, query).unwrap()
                    else {
                        panic!()
                    };
                    assert_eq!(all, size as usize);
                    let expected: Vec<_> = (0..size)
                        .filter(|n| after.is_none_or(|a| i64::from(n / 2) > a))
                        .skip(start as usize)
                        .take(limit.min(5) as usize)
                        .map(|n| format!("/r/{n}"))
                        .collect();
                    assert_eq!(
                        members.iter().map(|m| &m.path).collect::<Vec<_>>(),
                        expected.iter().collect::<Vec<_>>()
                    );
                }
            }
        }
    }
    assert_eq!(
        PageQuery::parse("l=4&l=bad&other=fail&a=-3"),
        Ok(PageQuery {
            limit: 4,
            after: Some(-3),
            start: 0
        })
    );
    assert_eq!(PageQuery::parse(""), Ok(PageQuery::default()));
    assert_eq!(PageQuery::parse("s=-1"), Err(Error::BadQuery));
}

#[test]
fn authenticated_client_walk_and_subscription() {
    let mut tree = ResourceTree::new(Limits {
        subscriptions: 1,
        ..Limits::default()
    });
    tree.publish(
        "/fsa",
        "FunctionSetAssignmentsList",
        Contents::List { members: vec![] },
    )
    .unwrap();
    tree.publish("/dev/67", "EndDevice", item(1, &["/fsa"]))
        .unwrap();
    tree.publish(
        "/devices",
        "EndDeviceList",
        Contents::List {
            members: vec![Link {
                path: "/dev/67".into(),
                time_key: None,
            }],
        },
    )
    .unwrap();
    tree.publish("/dcap", "DeviceCapability", item(1, &["/devices"]))
        .unwrap();
    let Representation::Item { links, .. } = tree
        .read("/dcap", Method::Get, PageQuery::default())
        .unwrap()
    else {
        panic!()
    };
    let Representation::Page { members, .. } = tree
        .read(&links[0], Method::Get, PageQuery::default())
        .unwrap()
    else {
        panic!()
    };
    let Representation::Item { links, .. } = tree
        .read(&members[0].path, Method::Get, PageQuery::default())
        .unwrap()
    else {
        panic!()
    };
    assert!(matches!(
        tree.read(&links[0], Method::Get, PageQuery::default()),
        Ok(Representation::Page { all: 0, .. })
    ));
    tree.subscribe(12, "/dev/67").unwrap();
    assert_eq!(tree.subscribe(14, "/dcap"), Err(Error::Capacity));
    assert_eq!(
        tree.put("/dcap", item(3, &[])),
        Err(Error::MethodNotAllowed)
    );
    assert_eq!(
        tree.put("/dev/67", item(2, &["/missing"])),
        Err(Error::NotFound)
    );
    assert_eq!(
        tree.put("/dev/67", item(2, &["/fsa"])),
        Ok(vec![Notification { subscription: 12 }])
    );
    assert!(tree.put("/dev/67", item(2, &["/fsa"])).unwrap().is_empty());
    assert!(tree.unsubscribe(12));
}

#[test]
fn href_origin_is_preserved() {
    // 003-resource-core/SR-002
    let base = "https://utility.example/d/a/";
    assert_eq!(
        resolve_href(base, "../fsa", 128).unwrap(),
        "https://utility.example/d/fsa"
    );
    assert!(resolve_href(base, "https://UTILITY.example:443/path", 128).is_ok());
    for bad in [
        "https://other.example/",
        "//utility.example:444/",
        "http://utility.example/",
        "//user@utility.example/",
        "x#fragment",
    ] {
        assert_eq!(resolve_href(base, bad, 128), Err(Error::InvalidPath));
    }
}

#[test]
fn wadl_collection_writes_are_atomic() {
    let mut tree = ResourceTree::new(Limits::default());
    tree.publish("/list", "EndDeviceList", Contents::List { members: vec![] })
        .unwrap();
    tree.subscribe(8, "/list").unwrap();
    let link = Link {
        path: "/edev/a".into(),
        time_key: None,
    };
    assert_eq!(
        tree.post("/list", 0, link.clone(), "DeviceCapability", item(1, &[])),
        Err(Error::WrongShape)
    );
    assert!(matches!(
        tree.read("/edev/a", Method::Get, PageQuery::default()),
        Err(Error::NotFound)
    ));
    assert_eq!(
        tree.post("/list", 0, link, "EndDevice", item(1, &[]))
            .unwrap(),
        vec![Notification { subscription: 8 }]
    );
    tree.subscribe(9, "/edev/a").unwrap();
    assert_eq!(
        tree.delete("/edev/a").unwrap(),
        vec![
            Notification { subscription: 8 },
            Notification { subscription: 9 }
        ]
    );
    assert!(matches!(
        tree.read("/list", Method::Get, PageQuery::default()),
        Ok(Representation::Page { all: 0, .. })
    ));
}
