//! In-process resource lookup, list paging and subscription matching.
//! Scope each tree to the resources a principal may access.

use alloc::{collections::BTreeMap, string::String, vec::Vec};

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Method {
    Get,
    Head,
    Put,
    Post,
    Delete,
}
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Mode {
    Mandatory,
    Optional,
    Discouraged,
    Error,
}

/// Resource-method policy from the IEEE 2030.5-2018 supplemental WADL.
pub fn method_mode(kind: &str, method: Method) -> Option<Mode> {
    Some(policy(kind)?.1[method as usize])
}

type Policy = (
    &'static str,
    [Mode; 5],
    &'static [&'static str],
    &'static str,
);
fn policy(kind: &str) -> Option<&'static Policy> {
    use Mode::*;
    const ROWS: &[Policy] = include!("wadl_methods.in");
    let i = ROWS.binary_search_by_key(&kind, |row| row.0).ok()?;
    Some(&ROWS[i])
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Error {
    BadQuery,
    InvalidPath,
    UnknownKind,
    NotFound,
    AlreadyExists,
    InUse,
    MethodNotAllowed,
    Capacity,
    InvalidOrder,
    WrongShape,
}

/// IEEE 2030.5 §4.6.2. The first occurrence of a known parameter wins.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct PageQuery {
    pub start: u32,
    pub after: Option<i64>,
    pub limit: u32,
}

impl Default for PageQuery {
    fn default() -> Self {
        Self {
            start: 0,
            after: None,
            limit: 1,
        }
    }
}

impl PageQuery {
    pub fn parse(query: &str) -> Result<Self, Error> {
        let (mut start, mut after, mut limit) = (None, None, None);
        for field in query.trim_start_matches('?').split('&') {
            let (key, value) = field.split_once('=').unwrap_or((field, ""));
            match key {
                "s" if start.is_none() => start = Some(value.parse().map_err(|_| Error::BadQuery)?),
                "a" if after.is_none() => after = Some(value.parse().map_err(|_| Error::BadQuery)?),
                "l" if limit.is_none() => limit = Some(value.parse().map_err(|_| Error::BadQuery)?),
                _ => {}
            }
        }
        Ok(Self {
            start: start.unwrap_or(0),
            after,
            limit: limit.unwrap_or(1),
        })
    }
}

#[derive(Debug, Copy, Clone)]
pub struct Limits {
    pub resources: usize,
    pub links: usize,
    pub subscriptions: usize,
    pub page: u32,
    pub path_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            resources: 1024,
            links: 1024,
            subscriptions: 128,
            page: 64,
            path_bytes: 255,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Link {
    pub path: String,
    pub time_key: Option<i64>,
}

/// Supply list members in the ordering defined by the containing function set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Contents<T> {
    Item { value: T, links: Vec<String> },
    List { members: Vec<Link> },
}

struct Resource<T> {
    kind: &'static str,
    contents: Contents<T>,
}

#[derive(Debug)]
pub enum Representation<'a, T> {
    Head,
    Item { value: &'a T, links: &'a [String] },
    Page { all: usize, members: &'a [Link] },
}

/// Identifies a matching subscription so the publisher can deliver a change notification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Notification {
    pub subscription: u64,
}

pub struct ResourceTree<T> {
    limits: Limits,
    resources: BTreeMap<String, Resource<T>>,
    subscriptions: BTreeMap<u64, String>,
}

impl<T: PartialEq> ResourceTree<T> {
    pub fn new(limits: Limits) -> Self {
        Self {
            limits,
            resources: BTreeMap::new(),
            subscriptions: BTreeMap::new(),
        }
    }

    /// Install a resource after installing each of its targets.
    pub fn publish(
        &mut self,
        path: &str,
        kind: &'static str,
        contents: Contents<T>,
    ) -> Result<(), Error> {
        self.check_path(path)?;
        if method_mode(kind, Method::Get).is_none() {
            return Err(Error::UnknownKind);
        }
        if kind.ends_with("List") != matches!(contents, Contents::List { .. }) {
            return Err(Error::WrongShape);
        }
        if self.resources.contains_key(path) {
            return Err(Error::AlreadyExists);
        }
        if self.resources.len() >= self.limits.resources {
            return Err(Error::Capacity);
        }
        self.validate(kind, &contents)?;
        self.resources
            .insert(path.into(), Resource { kind, contents });
        Ok(())
    }

    fn check_path(&self, path: &str) -> Result<(), Error> {
        if path.len() > self.limits.path_bytes
            || !path.starts_with('/')
            || path.starts_with("//")
            || path.contains(['?', '#', '\\'])
            || path.bytes().any(|c| c.is_ascii_control() || c == b' ')
            || path.split('/').any(|s| matches!(s, "." | ".."))
        {
            return Err(Error::InvalidPath);
        }
        Ok(())
    }

    fn validate(&self, kind: &str, contents: &Contents<T>) -> Result<(), Error> {
        let check = |path: &str| {
            if self.resources.contains_key(path) {
                Ok(())
            } else {
                Err(Error::NotFound)
            }
        };
        match contents {
            Contents::Item { links, .. } => {
                if links.len() > self.limits.links {
                    return Err(Error::Capacity);
                }
                for path in links {
                    check(path)?
                }
            }
            Contents::List { members } => {
                if members.len() > self.limits.links {
                    return Err(Error::Capacity);
                }
                let list_type = policy(kind).ok_or(Error::UnknownKind)?.3;
                let member_type = crate::model::shape(list_type)
                    .and_then(|s| s.members.iter().find(|m| m.max == usize::MAX))
                    .ok_or(Error::WrongShape)?
                    .ty;
                for m in members {
                    let member = self.resources.get(&m.path).ok_or(Error::NotFound)?;
                    let actual = policy(member.kind).ok_or(Error::UnknownKind)?.3;
                    if !crate::codec::derives_from(actual, member_type) {
                        return Err(Error::WrongShape);
                    }
                }
                if members
                    .windows(2)
                    .any(|w| w[0].time_key.is_some() != w[1].time_key.is_some())
                {
                    return Err(Error::InvalidOrder);
                }
                // Time-keyed lists can sort in either direction in the 2018 schema.
                let asc = members.windows(2).all(|w| w[0].time_key <= w[1].time_key);
                let desc = members.windows(2).all(|w| w[0].time_key >= w[1].time_key);
                if !asc && !desc {
                    return Err(Error::InvalidOrder);
                }
            }
        }
        Ok(())
    }

    pub fn read(
        &self,
        path: &str,
        method: Method,
        query: PageQuery,
    ) -> Result<Representation<'_, T>, Error> {
        let entry = self.resources.get(path).ok_or(Error::NotFound)?;
        if !matches!(method, Method::Get | Method::Head)
            || !matches!(
                method_mode(entry.kind, method),
                Some(Mode::Mandatory | Mode::Optional)
            )
        {
            return Err(Error::MethodNotAllowed);
        }
        if method == Method::Head {
            return Ok(Representation::Head);
        }
        match &entry.contents {
            Contents::Item { value, links } => Ok(Representation::Item { value, links }),
            Contents::List { members } => {
                let all = members.len();
                let eligible = match query.after {
                    Some(a) if members.first().is_some_and(|m| m.time_key.is_some()) => {
                        // For descending lists, times greater than a form a prefix.
                        if members.first().and_then(|m| m.time_key)
                            > members.last().and_then(|m| m.time_key)
                        {
                            &members[..members.partition_point(|m| m.time_key > Some(a))]
                        } else {
                            &members[members.partition_point(|m| m.time_key <= Some(a))..]
                        }
                    }
                    _ => &members[..],
                };
                let start = (query.start as usize).min(eligible.len());
                let end = start
                    .saturating_add(query.limit.min(self.limits.page) as usize)
                    .min(eligible.len());
                Ok(Representation::Page {
                    all,
                    members: &eligible[start..end],
                })
            }
        }
    }

    pub fn subscribe(&mut self, id: u64, path: &str) -> Result<(), Error> {
        if !self.resources.contains_key(path) {
            return Err(Error::NotFound);
        }
        if self.subscriptions.contains_key(&id) {
            return Err(Error::AlreadyExists);
        }
        if self.subscriptions.len() >= self.limits.subscriptions {
            return Err(Error::Capacity);
        }
        self.subscriptions.insert(id, path.into());
        Ok(())
    }

    pub fn unsubscribe(&mut self, id: u64) -> bool {
        self.subscriptions.remove(&id).is_some()
    }

    /// Insert into a collection at the publisher's chosen sort position.
    /// The publisher supplies the new resource's Location after validating its XML.
    pub fn post(
        &mut self,
        collection: &str,
        position: usize,
        member: Link,
        kind: &'static str,
        contents: Contents<T>,
    ) -> Result<Vec<Notification>, Error> {
        let list = self.resources.get(collection).ok_or(Error::NotFound)?;
        let row = policy(list.kind).ok_or(Error::UnknownKind)?;
        if !matches!(
            row.1[Method::Post as usize],
            Mode::Mandatory | Mode::Optional
        ) {
            return Err(Error::MethodNotAllowed);
        }
        if !row.2.contains(&kind) {
            return Err(Error::WrongShape);
        }
        let Contents::List { members } = &list.contents else {
            return Err(Error::WrongShape);
        };
        if members.len() >= self.limits.links {
            return Err(Error::Capacity);
        }
        if position > members.len() {
            return Err(Error::InvalidOrder);
        }
        let mut updated = members.clone();
        updated.insert(position, member.clone());
        self.publish(&member.path, kind, contents)?;
        match self.replace(collection, Contents::List { members: updated }) {
            Ok(deliveries) => Ok(deliveries),
            Err(error) => {
                self.resources.remove(&member.path);
                Err(error)
            }
        }
    }

    /// Delete a peer-deletable resource and remove it from its collections.
    /// A live single-resource link prevents removal until the publisher changes it.
    pub fn delete(&mut self, path: &str) -> Result<Vec<Notification>, Error> {
        let entry = self.resources.get(path).ok_or(Error::NotFound)?;
        if !matches!(
            method_mode(entry.kind, Method::Delete),
            Some(Mode::Mandatory | Mode::Optional)
        ) {
            return Err(Error::MethodNotAllowed);
        }
        if self
            .resources
            .values()
            .any(|r| matches!(&r.contents,Contents::Item{links,..} if links.iter().any(|s|s==path)))
        {
            return Err(Error::InUse);
        }
        self.resources.remove(path);
        let mut changed = alloc::collections::BTreeSet::new();
        changed.insert(path);
        for (p, r) in &mut self.resources {
            if let Contents::List { members } = &mut r.contents {
                let len = members.len();
                members.retain(|m| m.path != path);
                if members.len() != len {
                    changed.insert(p.as_str());
                }
            }
        }
        let notifications = self
            .subscriptions
            .iter()
            .filter(|(_, p)| changed.contains(p.as_str()))
            .map(|(&subscription, _)| Notification { subscription })
            .collect();
        self.subscriptions.retain(|_, p| p != path);
        Ok(notifications)
    }

    /// Apply a peer PUT if supported by this resource and emit change notifications.
    pub fn put(&mut self, path: &str, contents: Contents<T>) -> Result<Vec<Notification>, Error> {
        let entry = self.resources.get(path).ok_or(Error::NotFound)?;
        if !matches!(
            method_mode(entry.kind, Method::Put),
            Some(Mode::Mandatory | Mode::Optional)
        ) {
            return Err(Error::MethodNotAllowed);
        }
        self.replace(path, contents)
    }

    /// Apply a local publisher update, including updates to peer-read-only resources.
    pub fn replace(
        &mut self,
        path: &str,
        contents: Contents<T>,
    ) -> Result<Vec<Notification>, Error> {
        let kind = self.resources.get(path).ok_or(Error::NotFound)?.kind;
        self.validate(kind, &contents)?;
        let entry = self.resources.get_mut(path).ok_or(Error::NotFound)?;
        if core::mem::discriminant(&contents) != core::mem::discriminant(&entry.contents) {
            return Err(Error::WrongShape);
        }
        if entry.contents == contents {
            return Ok(Vec::new());
        }
        entry.contents = contents;
        Ok(self
            .subscriptions
            .iter()
            .filter(|(_, p)| p.as_str() == path)
            .map(|(&subscription, _)| Notification { subscription })
            .collect())
    }
}

/// Resolve an advertised href against the authenticated HTTPS resource URL.
/// A different origin requires a separate trust decision by the caller.
pub fn resolve_href(base: &str, href: &str, max_bytes: usize) -> Result<String, Error> {
    use fluent_uri::{Uri, UriRef};
    if base.len() > max_bytes || href.len() > max_bytes {
        return Err(Error::Capacity);
    }
    let base = Uri::parse(base).map_err(|_| Error::InvalidPath)?;
    let reference = UriRef::parse(href).map_err(|_| Error::InvalidPath)?;
    let target = reference
        .resolve_against(&base)
        .map_err(|_| Error::InvalidPath)?;
    let original = base.authority().ok_or(Error::InvalidPath)?;
    let dest = target.authority().ok_or(Error::InvalidPath)?;
    if !base.scheme().as_str().eq_ignore_ascii_case("https")
        || base.scheme() != target.scheme()
        || base.fragment().is_some()
        || target.fragment().is_some()
        || original.userinfo().is_some()
        || dest.userinfo().is_some()
        || original.host().is_empty()
        || !original.host().eq_ignore_ascii_case(dest.host())
        || original
            .port_to_u16()
            .map_err(|_| Error::InvalidPath)?
            .unwrap_or(443)
            != dest
                .port_to_u16()
                .map_err(|_| Error::InvalidPath)?
                .unwrap_or(443)
    {
        return Err(Error::InvalidPath);
    }
    if target.as_str().len() > max_bytes {
        return Err(Error::Capacity);
    }
    Ok(target.into_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_wadl_list_has_a_paged_representation() {
        use Mode::*;
        const ROWS: &[Policy] = include!("wadl_methods.in");
        for row in ROWS.iter().filter(|r| r.0.ends_with("List")) {
            let mut tree = ResourceTree::<()>::new(Limits::default());
            tree.publish(
                "/list",
                row.0,
                Contents::List {
                    members: Vec::new(),
                },
            )
            .unwrap();
            let page = tree.read("/list", Method::Get, PageQuery::default());
            if matches!(row.1[0], Mandatory | Optional) {
                assert!(
                    matches!(
                        page,
                        Ok(Representation::Page {
                            all: 0,
                            members: []
                        })
                    ),
                    "{}",
                    row.0
                );
            } else {
                assert!(matches!(page, Err(super::Error::MethodNotAllowed)));
            }
        }
    }
}
