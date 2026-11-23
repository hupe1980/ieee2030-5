//! CSIP-AUS v1.2 site limits at the connection point. The application chooses
//! the site and retains independent limits for import, export, generation and load.
use crate::schedule::{self, Event, Selection};

pub const NAMESPACE: &str = "https://csipaus.org/ns";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Export,
    Import,
    Generation,
    Load,
}
impl Mode {
    pub const fn local_name(self) -> &'static str {
        match self {
            Self::Export => "opModExpLimW",
            Self::Import => "opModImpLimW",
            Self::Generation => "opModGenLimW",
            Self::Load => "opModLoadLimW",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActivePower {
    pub value: i16,
    pub multiplier: i8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PowerError {
    Fractional,
    Overflow,
    InvalidElement,
}
impl ActivePower {
    /// Convert the schema's decimal quantity exactly, including negative limits.
    pub fn whole_watts(self) -> Result<i64, PowerError> {
        if self.value == 0 {
            return Ok(0);
        }
        let value = i64::from(self.value);
        if self.multiplier >= 0 {
            let factor = 10i64
                .checked_pow(self.multiplier as u32)
                .ok_or(PowerError::Overflow)?;
            value.checked_mul(factor).ok_or(PowerError::Overflow)
        } else {
            let factor = 10i64
                .checked_pow(u32::from(self.multiplier.unsigned_abs()))
                .ok_or(PowerError::Fractional)?;
            if value % factor == 0 {
                Ok(value / factor)
            } else {
                Err(PowerError::Fractional)
            }
        }
    }

    /// Read a qualified limit from a validated Australian DERControlBase.
    pub fn from_control(
        base: crate::model::DERControlBase<'_>,
        mode: Mode,
    ) -> Result<Option<Self>, PowerError> {
        use crate::model::View;
        let Some(node) = base
            .node()
            .children()
            .find(|n| n.has_tag_name((NAMESPACE, mode.local_name())))
        else {
            return Ok(None);
        };
        let field = |name| {
            node.children()
                .find(|n| n.has_tag_name(("urn:ieee:std:2030.5:ns", name)))
                .map(crate::codec::element_text)
                .ok_or(PowerError::InvalidElement)
        };
        Ok(Some(Self {
            value: field("value")?
                .trim()
                .parse()
                .map_err(|_| PowerError::InvalidElement)?,
            multiplier: field("multiplier")?
                .trim()
                .parse()
                .map_err(|_| PowerError::InvalidElement)?,
        }))
    }
}

/// Site-scoped mode identity. `connection_point` is the network connection
/// identifier carried by the CSIP-AUS ConnectionPoint resource.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SiteMode<'a> {
    pub connection_point: &'a str,
    pub mode: Mode,
}

/// Evaluate one connection point and mode. Scope the default to the same key.
pub fn effective_limit<'a>(
    events: &'a [Event<SiteMode<'_>, ActivePower>],
    key: SiteMode<'a>,
    now: i64,
    default: Option<(SiteMode<'_>, &'a ActivePower)>,
    max_events: usize,
) -> Result<Selection<'a, ActivePower>, schedule::Error> {
    let default = default.filter(|(k, _)| *k == key).map(|(_, v)| v);
    schedule::select(events, &key, now, default, max_events)
}
