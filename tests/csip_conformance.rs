//! Executable accounting against the approved SunSpec CSIP procedures, v1.3.
//! Review the uncovered baseline against section 4 independently of the page index.
use std::collections::BTreeSet;

const CATALOGUE: &str = include_str!("data/csip-1.3.tsv");

// Register complete procedures here. A case earns credit only after its driver returns.
type Driver = (&'static str, fn());
#[cfg(feature = "runtime")]
#[path = "support/communications.rs"]
mod communications;
#[cfg(feature = "runtime")]
#[path = "support/site_discovery.rs"]
mod site_discovery;
#[cfg(feature = "runtime")]
mod support;

#[cfg(feature = "runtime")]
const DRIVERS: &[Driver] = &[
    ("COMM-001", site_discovery::run),
    ("COMM-002", || {
        communications::run("COMM-002", &["/utility/dcap", "/assets/site/devices"])
    }),
    ("COMM-003", || {
        communications::run("COMM-003", &["/utility/dcap"])
    }),
];
#[cfg(not(feature = "runtime"))]
const DRIVERS: &[Driver] = &[];

// Section 4 lists optional cases too. Preserve the gaps in CORE numbering.
const UNCOVERED: &[(&str, &[u8])] = &[
    #[cfg(feature = "runtime")]
    ("COMM", &[4]),
    #[cfg(not(feature = "runtime"))]
    ("COMM", &[1, 2, 3, 4]),
    (
        "CORE",
        &[1, 2, 3, 4, 5, 9, 10, 11, 12, 13, 14, 18, 19, 21, 22],
    ),
    (
        "BASIC",
        &[
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
            25, 26, 27, 28, 29,
        ],
    ),
    ("UTIL", &[1, 2, 3, 4]),
    ("AGG", &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]),
    ("ERR", &[1, 2]),
    ("MAINT", &[1, 2, 3, 4, 5]),
];

fn assess<'a>(
    catalogue: &'a str,
    drivers: &[Driver],
    expected: &BTreeSet<String>,
) -> Result<BTreeSet<&'a str>, String> {
    let mut uncovered = BTreeSet::new();
    for row in catalogue.lines().filter(|row| !row.starts_with('#')) {
        let fields: Vec<_> = row.split('\t').collect();
        let [id, page, subject] = fields.as_slice() else {
            return Err(format!("Invalid catalogue row: {row}"));
        };
        if page.parse::<u16>().unwrap_or_default() == 0 || subject.trim().is_empty() {
            return Err(format!("Missing source page or subject for {id}"));
        }
        if !uncovered.insert(*id) {
            return Err(format!("Duplicate procedure {id}"));
        }
    }
    for (id, run) in drivers {
        if !uncovered.remove(id) {
            return Err(format!("Duplicate or unknown driver {id}"));
        }
        run();
    }
    if !uncovered
        .iter()
        .copied()
        .eq(expected.iter().map(String::as_str))
    {
        let actual: BTreeSet<_> = uncovered.iter().map(|id| (*id).to_string()).collect();
        return Err(format!(
            "Uncovered set changed. Added {:?}, removed {:?}",
            actual.difference(expected),
            expected.difference(&actual)
        ));
    }
    Ok(uncovered)
}

// conformance-as-data/SR-001 and conformance-as-data/SR-002
#[test]
fn procedure_coverage() {
    let expected = UNCOVERED
        .iter()
        .flat_map(|(prefix, numbers)| numbers.iter().map(move |n| format!("{prefix}-{n:03}")))
        .collect();
    let uncovered = assess(CATALOGUE, DRIVERS, &expected).unwrap();
    let covered = DRIVERS.len();
    let claim = format!(
        "CSIP procedure coverage: {covered}/{}.",
        covered + uncovered.len()
    );
    println!(
        "{claim}\nUncovered: {}",
        uncovered.into_iter().collect::<Vec<_>>().join(", ")
    );
    #[cfg(feature = "runtime")]
    assert!(
        include_str!("../README.md")
            .lines()
            .any(|line| line.trim() == claim),
        "Update README with measured result: {claim}"
    );
}

// conformance-as-data/SR-001
#[test]
fn rejects_inventory_drift_and_invalid_drivers() {
    let expected = BTreeSet::from(["CORE-001".to_owned()]);
    let cat = "CORE-001\t30\tHTTP requests";
    assert!(assess("", &[], &expected).is_err());
    assert!(assess(cat, &[("CORE-001", || {})], &expected).is_err());
    assert!(assess(cat, &[("CORE-999", || {})], &expected).is_err());
    assert!(
        assess(
            cat,
            &[("CORE-001", || {}), ("CORE-001", || {})],
            &BTreeSet::new()
        )
        .is_err()
    );
    assert!(assess(&format!("{cat}\n{cat}"), &[], &expected).is_err());
}
