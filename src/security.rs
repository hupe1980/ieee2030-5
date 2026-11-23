//! Certificate-derived identifiers (IEEE 2030.5-2018 §6.3).
use core::fmt;
use sha2::{Digest, Sha256};

/// Leftmost 160 bits of a device certificate's SHA-256 digest.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Lfdi(pub [u8; 20]);

impl Lfdi {
    /// Hash the exact DER-encoded certificate. Derivation does not authenticate the input.
    pub fn from_certificate_der(der: &[u8]) -> Self {
        let digest = Sha256::digest(der);
        let mut id = [0; 20];
        id.copy_from_slice(&digest[..20]);
        Self(id)
    }

    /// Derive the short identifier, including its decimal checksum (2018 §6.3.3).
    pub fn sfdi(self) -> Sfdi {
        let [a, b, c, d, e, ..] = self.0;
        let prefix = u64::from_be_bytes([0, 0, 0, a, b, c, d, e]) >> 4;
        Sfdi(prefix * 10 + (10 - digit_sum(prefix) % 10) % 10)
    }
}

impl fmt::Display for Lfdi {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02X}")?;
        }
        Ok(())
    }
}

fn digit_sum(mut number: u64) -> u64 {
    let mut result = 0;
    while number > 0 {
        result += number % 10;
        number /= 10;
    }
    result
}

/// A 36-bit certificate prefix expressed in decimal with a trailing check digit.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Sfdi(u64);

impl Sfdi {
    /// Validate an XML integer, including range and check digit.
    pub fn from_decimal(number: u64) -> Option<Self> {
        (number / 10 < (1 << 36) && digit_sum(number).is_multiple_of(10)).then_some(Self(number))
    }
    pub fn as_u64(self) -> u64 {
        self.0
    }
}
impl fmt::Display for Sfdi {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:012}", self.0)
    }
}

#[cfg(feature = "pki")]
pub mod profile;
