//! Namespace-aware XML validation against the generated IEEE schema.
use crate::model::{View, root_type, shape};
use alloc::{borrow::Cow, string::String, vec::Vec};
use core::fmt;
use roxmltree::{Node, ParsingOptions};

pub const SEP: &str = "urn:ieee:std:2030.5:ns";
pub const AUS: &str = "https://csipaus.org/ns";
const XSI: &str = "http://www.w3.org/2001/XMLSchema-instance";

#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub bytes: usize,
    pub nodes: u32,
    pub depth: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            bytes: 1024 * 1024,
            nodes: 64 * 1024,
            depth: 64,
        }
    }
}

#[derive(Debug)]
pub enum Error {
    Xml(roxmltree::Error),
    Limit(&'static str),
    UnknownRoot,
    UnexpectedMember(String),
    Missing(&'static str),
    InvalidValue(String),
    WrongType,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Xml(e) => write!(f, "XML syntax error: {e}"),
            Self::Limit(which) => write!(f, "XML {which} limit exceeded"),
            Self::UnknownRoot => f.write_str("unknown root element or namespace"),
            Self::UnexpectedMember(name) => write!(f, "unexpected or misplaced member {name}"),
            Self::Missing(name) => write!(f, "missing required member {name}"),
            Self::InvalidValue(ty) => write!(f, "invalid value for {ty}"),
            Self::WrongType => f.write_str("incompatible schema type"),
        }
    }
}
impl core::error::Error for Error {}

pub(crate) struct Attribute {
    pub name: &'static str,
    pub ty: &'static str,
    pub required: bool,
}
pub(crate) struct Member {
    pub ns: &'static str,
    pub name: &'static str,
    pub ty: &'static str,
    pub min: usize,
    pub max: usize,
}
pub(crate) struct Shape {
    pub ns: &'static str,
    pub base: &'static str,
    pub attrs: &'static [Attribute],
    pub members: &'static [Member],
    pub min: Option<i128>,
    pub max: Option<i128>,
    pub max_len: Option<usize>,
}

#[doc(hidden)]
pub struct Validated(());

#[derive(Debug)]
pub struct Document<'xml> {
    tree: roxmltree::Document<'xml>,
    ty: &'static str,
}
impl<'xml> Document<'xml> {
    /// Validate a base-profile XML resource.
    pub fn parse(xml: &'xml str, limits: Limits) -> Result<Self, Error> {
        Self::parse_profile(xml, limits, false)
    }
    /// Validate a CSIP-AUS 1.2 resource, including its additional required fields.
    #[cfg(feature = "csip-aus")]
    pub fn parse_aus(xml: &'xml str, limits: Limits) -> Result<Self, Error> {
        Self::parse_profile(xml, limits, true)
    }
    fn parse_profile(xml: &'xml str, limits: Limits, aus: bool) -> Result<Self, Error> {
        if xml.len() > limits.bytes {
            return Err(Error::Limit("byte"));
        }
        let options = ParsingOptions {
            nodes_limit: limits.nodes,
            ..Default::default()
        };
        let tree =
            roxmltree::Document::parse_with_options(xml, options).map_err(|err| match err {
                roxmltree::Error::NodesLimitReached => Error::Limit("node"),
                other => Error::Xml(other),
            })?;
        let root = tree.root_element();
        let ns = root.tag_name().namespace().ok_or(Error::UnknownRoot)?;
        if !aus && ns != SEP {
            return Err(Error::UnknownRoot);
        }
        let declared = root_type(ns, root.tag_name().name()).ok_or(Error::UnknownRoot)?;
        let ty = validate(root, declared, limits.depth.min(128), aus)?;
        Ok(Self { tree, ty })
    }
    pub fn root(&self) -> Node<'_, 'xml> {
        self.tree.root_element()
    }
    pub fn as_type<'a, T: View<'a>>(&'a self) -> Result<T, Error> {
        if !derives_from(self.ty, T::NAME) {
            return Err(Error::WrongType);
        }
        Ok(T::from_validated(self.root(), Validated(())))
    }
    /// Serialize the validated element tree, preserving significant text and QName bindings.
    pub fn encode(&self) -> String {
        let mut xml = String::new();
        write_element(self.root(), true, &mut xml);
        xml
    }
}
pub(crate) fn derives_from(mut ty: &str, base: &str) -> bool {
    loop {
        if ty == base {
            return true;
        }
        let Some(desc) = shape(ty) else {
            return false;
        };
        ty = desc.base;
    }
}
fn validate(
    n: Node<'_, '_>,
    declared: &'static str,
    depth: usize,
    aus: bool,
) -> Result<&'static str, Error> {
    if depth == 0 {
        return Err(Error::Limit("depth"));
    }
    let mut ty = declared;
    if let Some(qname) = n.attribute((XSI, "type")) {
        let qname = qname.trim();
        let (prefix, local) = qname
            .split_once(':')
            .map_or((None, qname), |(p, l)| (Some(p), l));
        let ns = n.lookup_namespace_uri(prefix).ok_or(Error::WrongType)?;
        let (canonical, desc) = crate::model::named_shape(local).ok_or(Error::WrongType)?;
        if ns != desc.ns || (!aus && ns == AUS) || !derives_from(canonical, declared) {
            return Err(Error::WrongType);
        }
        ty = canonical;
    }
    let mut lineage = Vec::new();
    let mut primitive = ty;
    while let Some(desc) = shape(primitive) {
        lineage.push(desc);
        primitive = desc.base;
    }
    for a in n.attributes() {
        if a.namespace() == Some(XSI) && a.name() == "type" {
            continue;
        }
        let Some(attr) = lineage
            .iter()
            .flat_map(|s| s.attrs)
            .find(|d| a.namespace().is_none() && d.name == a.name())
        else {
            return Err(Error::UnexpectedMember(a.name().into()));
        };
        validate_attribute(attr.ty, a.value())?;
    }
    for attr in lineage.iter().flat_map(|s| s.attrs) {
        if attr.required && n.attribute(attr.name).is_none() {
            return Err(Error::Missing(attr.name));
        }
    }
    let mut children = n.children().filter(Node::is_element).peekable();
    for m in lineage
        .iter()
        .rev()
        .flat_map(|s| s.members)
        .filter(|m| aus || m.ns != AUS)
    {
        let mut count = 0;
        while let Some(child) = children.next_if(|c| c.has_tag_name((m.ns, m.name))) {
            count += 1;
            if count > m.max {
                return Err(Error::UnexpectedMember(m.name.into()));
            }
            validate(child, m.ty, depth - 1, aus)?;
        }
        if count < m.min {
            return Err(Error::Missing(m.name));
        }
    }
    if let Some(child) = children.next() {
        return Err(Error::UnexpectedMember(child.tag_name().name().into()));
    }
    if primitive.is_empty() {
        if n.children()
            .any(|c| c.is_text() && !c.text().unwrap_or("").trim_matches(xml_space).is_empty())
        {
            return Err(Error::InvalidValue(ty.into()));
        }
    } else {
        let text = element_text(n);
        validate_scalar(ty, primitive, &text, &lineage)?;
    }
    Ok(ty)
}
fn xml_space(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\r' | '\n')
}

/// Gather the complete character value, including text separated by XML comments.
pub fn element_text<'a>(n: Node<'a, '_>) -> Cow<'a, str> {
    let mut chunks = n.children().filter(Node::is_text).filter_map(|c| c.text());
    let first = chunks.next().unwrap_or("");
    let Some(second) = chunks.next() else {
        return Cow::Borrowed(first);
    };
    let mut text = String::from(first);
    text.push_str(second);
    text.extend(chunks);
    Cow::Owned(text)
}
fn validate_attribute(ty: &'static str, s: &str) -> Result<(), Error> {
    let mut lineage = Vec::new();
    let mut base = ty;
    while let Some(desc) = shape(base) {
        lineage.push(desc);
        base = desc.base;
    }
    validate_scalar(ty, base, s, &lineage)
}
fn validate_scalar(ty: &str, base: &str, value: &str, lineage: &[&Shape]) -> Result<(), Error> {
    let s = value.trim_matches(xml_space);
    let bounded = |len| {
        lineage
            .iter()
            .all(|d| d.max_len.is_none_or(|max| len <= max))
    };
    let valid = match base {
        "xs:string" => bounded(value.len()),
        "xs:anyURI" => true,
        "xs:boolean" => matches!(s, "true" | "false" | "0" | "1"),
        "xs:hexBinary" => {
            s.len().is_multiple_of(2)
                && bounded(s.len() / 2)
                && s.bytes().all(|b| b.is_ascii_hexdigit())
        }
        integer => s.parse::<i128>().is_ok_and(|v| {
            let fits = match integer {
                "xs:unsignedByte" => u8::try_from(v).is_ok(),
                "xs:unsignedShort" => u16::try_from(v).is_ok(),
                "xs:unsignedInt" => u32::try_from(v).is_ok(),
                "xs:unsignedLong" => u64::try_from(v).is_ok(),
                "xs:byte" => i8::try_from(v).is_ok(),
                "xs:short" => i16::try_from(v).is_ok(),
                "xs:int" => i32::try_from(v).is_ok(),
                "xs:long" => i64::try_from(v).is_ok(),
                _ => false,
            };
            fits && lineage
                .iter()
                .all(|d| d.min.is_none_or(|min| v >= min) && d.max.is_none_or(|max| v <= max))
        }),
    };
    if valid {
        Ok(())
    } else {
        Err(Error::InvalidValue(ty.into()))
    }
}
pub(crate) fn escape(s: &str, attr: bool, out: &mut String) {
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' if attr => out.push_str("&quot;"),
            '\r' => out.push_str("&#13;"),
            '\n' if attr => out.push_str("&#10;"),
            '\t' if attr => out.push_str("&#9;"),
            c => out.push(c),
        }
    }
}
fn write_name(prefix: Option<&str>, name: &str, out: &mut String) {
    if let Some(prefix) = prefix {
        out.push_str(prefix);
        out.push(':');
    }
    out.push_str(name);
}
pub(crate) fn write_element(n: Node<'_, '_>, standalone: bool, out: &mut String) {
    let tag = n.tag_name();
    let prefix = tag
        .namespace()
        .filter(|ns| Some(*ns) != n.default_namespace())
        .and_then(|ns| n.lookup_prefix(ns));
    out.push('<');
    write_name(prefix, tag.name(), out);
    let parent = n.parent_element().filter(|_| !standalone);
    for ns in n.namespaces() {
        if parent.is_some_and(|p| p.lookup_namespace_uri(ns.name()) == Some(ns.uri())) {
            continue;
        }
        out.push(' ');
        if let Some(p) = ns.name() {
            write_name(Some("xmlns"), p, out);
        } else {
            out.push_str("xmlns");
        }
        out.push_str("=\"");
        escape(ns.uri(), true, out);
        out.push('"');
    }
    for attr in n.attributes() {
        out.push(' ');
        let prefix = attr.namespace().and_then(|uri| {
            n.namespaces()
                .find(|ns| ns.name().is_some() && ns.uri() == uri)
                .and_then(|ns| ns.name())
        });
        write_name(prefix, attr.name(), out);
        out.push_str("=\"");
        escape(attr.value(), true, out);
        out.push('"');
    }
    out.push('>');
    for child in n.children() {
        if child.is_element() {
            write_element(child, false, out);
        } else if child.is_text() {
            escape(child.text().unwrap_or(""), false, out);
        }
    }
    out.push_str("</");
    write_name(prefix, tag.name(), out);
    out.push('>');
}
#[cfg(feature = "runtime")]
impl Validated {
    pub(crate) fn new() -> Self {
        Self(())
    }
}
