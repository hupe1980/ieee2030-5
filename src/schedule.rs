//! Deterministic, per-mode selection of DER controls. Callers supply UTC seconds
//! and device-specific random draws. Completed or displaced events never restart
//! in the 2018 CSIP policy (CSIP-AUS v1.2 Explainer §7).

use alloc::{collections::BTreeSet, vec::Vec};

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Error {
    InvalidOffset,
    InvalidControl,
    MissingLink,
    InvalidInterval,
    Capacity,
    DuplicateEvent,
    AmbiguousPriority,
    InvalidTransition,
}

/// Signed offsets in seconds. A draw is sampled once and retained with the event.
#[derive(Debug, Copy, Clone, Default, PartialEq, Eq)]
pub struct Offset {
    pub bound: i16,
    pub draw: i16,
}
impl Offset {
    fn seconds(self) -> Result<i64, Error> {
        if !(-3600..=3600).contains(&self.bound)
            || !(0.min(self.bound)..=0.max(self.bound)).contains(&self.draw)
        {
            return Err(Error::InvalidOffset);
        }
        Ok(i64::from(self.draw))
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Window {
    start: i64,
    end: i64,
}
impl Window {
    /// IEEE supplemental RandomizableEvent and DateTimeInterval. The effective
    /// duration is applied to the effective start and the end is exclusive.
    pub fn new(
        start: i64,
        duration: u32,
        random_start: Offset,
        random_duration: Offset,
    ) -> Result<Self, Error> {
        let start = start
            .checked_add(random_start.seconds()?)
            .ok_or(Error::InvalidInterval)?;
        let duration = i64::from(duration) + random_duration.seconds()?;
        if duration <= 0 {
            return Err(Error::InvalidInterval);
        }
        let end = start.checked_add(duration).ok_or(Error::InvalidInterval)?;
        Ok(Self { start, end })
    }
    pub fn start(self) -> i64 {
        self.start
    }
    pub fn end(self) -> i64 {
        self.end
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Termination {
    Cancelled(i64),
    Superseded(i64),
}

/// One mode of a DER control in its parent program. Project a multi-mode event
/// once per mode. Use the same mRID for each projection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event<M, V> {
    pub id: u128,
    pub mode: M,
    pub value: V,
    pub primacy: u8,
    pub created: i64,
    /// Local first receipt expressed on the program server clock.
    pub received: i64,
    pub window: Window,
    /// Effective termination, including any previously sampled cancellation delay.
    pub termination: Option<Termination>,
}
impl<M, V> Event<M, V> {
    fn start(&self) -> i64 {
        self.window.start.max(self.received)
    }
    fn end(&self) -> i64 {
        match self.termination {
            Some(Termination::Cancelled(t) | Termination::Superseded(t)) => t.min(self.window.end),
            None => self.window.end,
        }
    }
    fn rank(&self) -> (core::cmp::Reverse<u8>, i64) {
        (core::cmp::Reverse(self.primacy), self.created)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Selection<'a, V> {
    Event { id: u128, value: &'a V },
    Default(&'a V),
    Idle,
}

/// Replay effective starts through `now` so an expired high-priority event
/// cannot accidentally reactivate an older, displaced one. Supply one site's
/// events and its highest-priority applicable default for the requested mode.
pub fn select<'a, M: PartialEq, V>(
    events: &'a [Event<M, V>],
    mode: &M,
    now: i64,
    default: Option<&'a V>,
    max_events: usize,
) -> Result<Selection<'a, V>, Error> {
    if events.len() > max_events {
        return Err(Error::Capacity);
    }
    let mut seen = BTreeSet::new();
    let mut candidates = Vec::new();
    for e in events.iter().filter(|e| &e.mode == mode) {
        if !seen.insert(e.id) {
            return Err(Error::DuplicateEvent);
        }
        if e.received <= now && e.start() < e.end() {
            candidates.push(e);
        }
    }
    // CSIP §7.10 figures 34 and 35 distinguish an overlap announced before
    // the lower-priority event starts from one announced while it is active.
    candidates.sort_unstable_by_key(|e| (e.received, core::cmp::Reverse(e.rank())));
    let mut accepted: Vec<(&Event<M, V>, i64)> = Vec::new();
    for next in candidates {
        let overlaps =
            |current: &Event<M, V>, end: i64| next.start() < end && current.start() < next.end();
        let mut superseded = false;
        for &(current, end) in &accepted {
            if !overlaps(current, end) {
                continue;
            }
            match current.rank().cmp(&next.rank()) {
                core::cmp::Ordering::Greater => {
                    superseded = true;
                    break;
                }
                core::cmp::Ordering::Equal => return Err(Error::AmbiguousPriority),
                core::cmp::Ordering::Less => {}
            }
        }
        if superseded {
            continue;
        }
        accepted.retain_mut(|(current, end)| {
            if !overlaps(current, *end) {
                return true;
            }
            if current.start() >= next.received {
                return false;
            }
            *end = (*end).min(next.start());
            true
        });
        accepted.push((next, next.end()));
    }
    Ok(
        match accepted
            .into_iter()
            .find(|(e, end)| e.start() <= now && now < *end)
        {
            Some((e, _)) => Selection::Event {
                id: e.id,
                value: &e.value,
            },
            None => default.map_or(Selection::Idle, Selection::Default),
        },
    )
}

/// IEEE 2030.5 Table 27 / CSIP-AUS v1.2 Explainer §4.3.3.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(u8)]
pub enum ResponseStatus {
    Received = 1,
    Started = 2,
    Completed = 3,
    Cancelled = 6,
    Superseded = 7,
    SupersededByOtherProgram = 14,
}

/// Track one DER event per device. Pass actual application transitions here;
/// store a returned status for delivery to the event's replyTo resource.
#[derive(Debug, Copy, Clone, Default)]
pub struct Responses {
    last: Option<ResponseStatus>,
}
impl Responses {
    pub fn observe(
        &mut self,
        status: ResponseStatus,
        response_required: u8,
    ) -> Result<Option<ResponseStatus>, Error> {
        use ResponseStatus::*;
        if self.last == Some(status) {
            return Ok(None);
        }
        match (self.last, status) {
            (None, Received)
            | (Some(Received), Started | Cancelled | Superseded | SupersededByOtherProgram)
            | (Some(Started), Completed | Cancelled | Superseded | SupersededByOtherProgram) => {}
            _ => return Err(Error::InvalidTransition),
        }
        self.last = Some(status);
        let mask = if status == Received { 1 } else { 2 };
        Ok((response_required & mask != 0).then_some(status))
    }
}

/// Once-sampled offsets for a single device and event. A randomized
/// cancellation uses a non-negative delay bounded by the largest absolute
/// start/duration bound (sep.xsd EventStatus).
#[derive(Debug, Clone, Copy, Default)]
pub struct Draws {
    pub start: i16,
    pub duration: i16,
    pub cancellation: u16,
}

pub type WireEvent<'a> = Event<roxmltree::ExpandedName<'a, 'a>, roxmltree::Node<'a, 'a>>;

fn targets_device(
    control: crate::model::DERControl<'_>,
    device_category: u32,
) -> Result<bool, Error> {
    use crate::{codec::element_text, model::View};
    let Some(category) = control.device_category() else {
        return Ok(true);
    };
    let bits = u32::from_str_radix(element_text(category.node()).trim(), 16)
        .map_err(|_| Error::InvalidControl)?;
    Ok(bits & device_category != 0)
}

/// Project a schema-validated DER control into one candidate for each mode.
/// Keep the input documents alive while evaluating borrowed control values.
pub fn from_control<'a>(
    program: crate::model::DERProgram<'_>,
    control: crate::model::DERControl<'a>,
    draws: Draws,
    device_category: u32,
    received: i64,
) -> Result<Vec<WireEvent<'a>>, Error> {
    use crate::{codec::element_text, model::View};
    fn number<'a, T: core::str::FromStr>(field: Option<impl View<'a>>) -> Result<T, Error> {
        element_text(field.ok_or(Error::InvalidControl)?.node())
            .trim()
            .parse()
            .map_err(|_| Error::InvalidControl)
    }
    if !targets_device(control, device_category)? {
        return Ok(Vec::new());
    }
    let rand = control.as_base();
    let event = rand.as_base();
    let start_bound = rand
        .randomize_start()
        .map(|v| number(Some(v)))
        .transpose()?
        .unwrap_or(0);
    let duration_bound = rand
        .randomize_duration()
        .map(|v| number(Some(v)))
        .transpose()?
        .unwrap_or(0);
    let interval = event.interval().ok_or(Error::InvalidControl)?;
    let window = Window::new(
        number(interval.start())?,
        number(interval.duration())?,
        Offset {
            bound: start_bound,
            draw: draws.start,
        },
        Offset {
            bound: duration_bound,
            draw: draws.duration,
        },
    )?;
    let status = event.event_status().ok_or(Error::InvalidControl)?;
    let changed: i64 = number(status.date_time())?;
    let termination = match number::<u8>(status.current_status())? {
        0 | 1 => None,
        2 => Some(Termination::Cancelled(changed)),
        3 => {
            if draws.cancellation
                > start_bound
                    .unsigned_abs()
                    .max(duration_bound.unsigned_abs())
            {
                return Err(Error::InvalidOffset);
            }
            Some(Termination::Cancelled(
                changed
                    .checked_add(i64::from(draws.cancellation))
                    .ok_or(Error::InvalidInterval)?,
            ))
        }
        4 => Some(Termination::Superseded(changed)),
        _ => return Err(Error::InvalidControl),
    };
    let mrid = event.as_base().mrid().ok_or(Error::InvalidControl)?;
    let id = u128::from_str_radix(element_text(mrid.node()).trim(), 16)
        .map_err(|_| Error::InvalidControl)?;
    let primacy = number(program.primacy())?;
    let created = number(event.creation_time())?;
    Ok(control
        .der_control_base()
        .ok_or(Error::InvalidControl)?
        .node()
        .children()
        .filter(|n| n.is_element() && n.tag_name().name().starts_with("opMod"))
        .map(|value| Event {
            id,
            primacy,
            created,
            received,
            window,
            termination,
            mode: value.tag_name(),
            value,
        })
        .collect())
}

/// Typed write intent for the caller's authenticated transport.
#[derive(Debug, PartialEq, Eq)]
pub struct Write<'a> {
    pub method: crate::resource::Method,
    pub href: &'a str,
    pub xml: alloc::string::String,
}

/// Route a validated measurement to the endpoint advertised by this DER.
pub fn report<'a>(
    device: crate::model::DER<'a>,
    body: &crate::codec::Document<'_>,
) -> Result<Write<'a>, Error> {
    let link = match body.root().tag_name().name() {
        "DERAvailability" => device
            .der_availability_link()
            .and_then(|v| v.as_base().href()),
        "DERCapability" => device
            .der_capability_link()
            .and_then(|v| v.as_base().href()),
        "DERSettings" => device.der_settings_link().and_then(|v| v.as_base().href()),
        "DERStatus" => device.der_status_link().and_then(|v| v.as_base().href()),
        _ => return Err(Error::InvalidControl),
    }
    .ok_or(Error::MissingLink)?;
    Ok(Write {
        method: crate::resource::Method::Put,
        href: link,
        xml: body.encode(),
    })
}

impl Responses {
    /// Emit a DERControlResponse on an eligible transition. Queue the returned
    /// intent for retry if transport delivery fails.
    pub fn acknowledge<'a>(
        &mut self,
        control: crate::model::DERControl<'a>,
        device: crate::security::Lfdi,
        device_category: u32,
        now: i64,
        status: ResponseStatus,
    ) -> Result<Option<Write<'a>>, Error> {
        use crate::{codec::element_text, model::View};
        if !targets_device(control, device_category)? {
            return Ok(None);
        }
        let identified = control.as_base().as_base().as_base();
        let resource = identified.as_base();
        let mask = u8::from_str_radix(resource.response_required().unwrap_or("00").trim(), 16)
            .map_err(|_| Error::InvalidControl)?;
        let mut next = *self;
        let pending = if next.observe(status, mask)?.is_some() {
            let href = resource.reply_to().ok_or(Error::MissingLink)?;
            let mrid = identified.mrid().ok_or(Error::InvalidControl)?;
            let subject = element_text(mrid.node());
            let xml = alloc::format!(
                "<DERControlResponse xmlns=\"urn:ieee:std:2030.5:ns\"><createdDateTime>{now}</createdDateTime><endDeviceLFDI>{device}</endDeviceLFDI><status>{}</status><subject>{}</subject></DERControlResponse>",
                status as u8,
                subject.trim()
            );
            Some(Write {
                method: crate::resource::Method::Post,
                href,
                xml,
            })
        } else {
            None
        };
        *self = next;
        Ok(pending)
    }
}

/// Controls discovered under a single DERProgram and the receipt data kept by
/// the client. Use the returned expanded names to distinguish profile modes.
pub struct Program<'a, 's> {
    pub resource: crate::model::DERProgram<'a>,
    pub default: Option<crate::model::DefaultDERControl<'a>>,
    pub controls: &'s [ReceivedControl<'a>],
}

#[derive(Clone, Copy, Debug)]
pub struct ReceivedControl<'a> {
    pub resource: crate::model::DERControl<'a>,
    pub received: i64,
    pub draws: Draws,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActiveControl<'a> {
    Event {
        id: u128,
        value: roxmltree::Node<'a, 'a>,
    },
    Default(roxmltree::Node<'a, 'a>),
    Idle,
}

/// Select a mode directly from both roles' program, event and default wire views.
pub fn effective_control<'a>(
    programs: &[Program<'a, '_>],
    mode: (&str, &str),
    now: i64,
    device_category: u32,
    max_resources: usize,
) -> Result<ActiveControl<'a>, Error> {
    use crate::model::View;
    let mut events = Vec::new();
    let mut count = programs.len();
    if count > max_resources {
        return Err(Error::Capacity);
    }
    let mut highest = u16::MAX;
    let mut default = None;
    let mut ambiguous_default = false;
    for program in programs {
        count = count
            .checked_add(program.controls.len())
            .ok_or(Error::Capacity)?;
        if count > max_resources {
            return Err(Error::Capacity);
        }
        let primacy = u16::from(
            program
                .resource
                .primacy()
                .ok_or(Error::InvalidControl)?
                .value(),
        );
        if primacy <= highest {
            let value = program
                .default
                .and_then(|d| d.der_control_base())
                .and_then(|base| base.node().children().find(|n| n.has_tag_name(mode)));
            if primacy < highest {
                default = value;
                ambiguous_default = false
            } else if value.is_some() {
                ambiguous_default |= default.is_some();
                default = value;
            }
            highest = primacy;
        }
        for control in program.controls {
            events.extend(
                from_control(
                    program.resource,
                    control.resource,
                    control.draws,
                    device_category,
                    control.received,
                )?
                .into_iter()
                .filter(|e| e.value.has_tag_name(mode)),
            );
        }
    }
    if let Some(first) = events.first()
        && let Selection::Event { id, value } =
            select(&events, &first.mode, now, None, max_resources)?
    {
        return Ok(ActiveControl::Event { id, value: *value });
    }
    if ambiguous_default {
        return Err(Error::AmbiguousPriority);
    }
    Ok(default.map_or(ActiveControl::Idle, ActiveControl::Default))
}
