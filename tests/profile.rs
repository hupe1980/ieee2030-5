#![cfg(feature = "pki")]
use ieee2030_5::security::profile::{
    ChainError, ProfileError, validate_device_leaf, verify_device_chain,
};
const ROOT: &[u8] = include_bytes!("data/pki/root.der");
const ISSUER: &[u8] = include_bytes!("data/pki/issuer.der");
const DEVICE: &[u8] = include_bytes!("data/pki/device.der");
// Fixed date inside all fixture validity windows, 2026-12-01 UTC.
const NOW: i64 = 1796083200;

#[test]
fn authenticate_only_the_configured_manufacturing_path() {
    let id = verify_device_chain(DEVICE, &[ISSUER], &[ROOT], NOW).unwrap();
    assert_eq!(id, validate_device_leaf(DEVICE, NOW).unwrap());
    assert!(matches!(
        verify_device_chain(DEVICE, &[], &[ROOT], NOW),
        Err(ChainError::Path { .. })
    ));
    assert!(matches!(
        verify_device_chain(DEVICE, &[ISSUER, ROOT], &[], NOW),
        Err(ChainError::Path { .. })
    ));
}
#[test]
fn identify_the_specific_device_profile_failure() {
    assert_eq!(
        validate_device_leaf(DEVICE, 0),
        Err(ProfileError::NotYetValid)
    );
    assert_eq!(
        validate_device_leaf(DEVICE, 253402300800),
        Err(ProfileError::Expired)
    );
    for (cert, error) in [
        (
            &include_bytes!("data/pki/wrong-curve.der")[..],
            ProfileError::WrongCurve,
        ),
        (
            &include_bytes!("data/pki/wrong-usage.der")[..],
            ProfileError::KeyUsage,
        ),
        (
            &include_bytes!("data/pki/wrong-policy.der")[..],
            ProfileError::Policy,
        ),
    ] {
        assert_eq!(validate_device_leaf(cert, NOW), Err(error));
    }
}

#[test]
fn issuer_cannot_grant_a_device_class_outside_its_policy() {
    let leaf = include_bytes!("data/pki/unauthorized-class.der");
    assert!(validate_device_leaf(leaf, NOW).is_ok());
    assert!(matches!(
        verify_device_chain(leaf, &[ISSUER], &[ROOT], NOW),
        Err(ChainError::Profile(ProfileError::Policy))
    ));
}
