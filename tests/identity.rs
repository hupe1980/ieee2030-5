use ieee2030_5::security::{Lfdi, Sfdi};
#[test]
fn device_credentials_6_3_3_worked_example() {
    let lfdi = Lfdi([
        0x3e, 0x4f, 0x45, 0xab, 0x31, 0xed, 0xfe, 0x5b, 0x67, 0xe3, 0x43, 0xe5, 0xe4, 0x56, 0x2e,
        0x31, 0x98, 0x4e, 0x23, 0xe5,
    ]);
    assert_eq!(lfdi.sfdi().as_u64(), 167261211391);
    assert_eq!(lfdi.to_string(), "3E4F45AB31EDFE5B67E343E5E4562E31984E23E5");
    assert_eq!(Sfdi::from_decimal(167261211391), Some(lfdi.sfdi()));
    assert_eq!(Sfdi::from_decimal(167261211392), None);
    assert_eq!(Sfdi::from_decimal(u64::MAX), None);
    assert_eq!(Lfdi([0; 20]).sfdi().to_string(), "000000000000");
}
#[test]
fn digest_hashes_the_original_bytes() {
    assert_eq!(
        Lfdi::from_certificate_der(b"abc").to_string(),
        "BA7816BF8F01CFEA414140DE5DAE2223B00361A3"
    );
}
