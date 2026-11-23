#![no_main]

use ieee2030_5::security::{Lfdi, profile::validate_device_leaf};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|der: &[u8]| {
    if let Ok(id) = validate_device_leaf(der, 1_796_083_200) {
        assert_eq!(id, Lfdi::from_certificate_der(der));
    }
});
