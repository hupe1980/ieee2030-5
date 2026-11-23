//! Construct a schema-checked resource from application values.
use crate::codec::{Document, Error, Limits, SEP, escape};
use alloc::{string::String, vec::Vec};
use core::fmt::Display;

/// An element under construction. Encoding validates the complete resource before returning XML.
///
/// ```
/// use ieee2030_5::{codec::{Document, Limits}, encode::Element, model::Registration};
/// let xml = Element::sep("Registration")
///     .attribute("href", "/reg")
///     .child(Element::sep("dateTimeRegistered").text(0))
///     .child(Element::sep("pIN").text(111115))
///     .encode(Limits::default())?;
/// let doc = Document::parse(&xml, Limits::default())?;
/// assert_eq!(doc.as_type::<Registration>()?.pin().unwrap().value(), 111115);
/// # Ok::<(), ieee2030_5::codec::Error>(())
/// ```
#[derive(Debug, Clone)]
pub struct Element {
    namespace: &'static str,
    name: &'static str,
    attributes: Vec<(&'static str, String)>,
    text: Option<String>,
    children: Vec<Element>,
}
impl Element {
    pub fn sep(name: &'static str) -> Self {
        Self {
            namespace: SEP,
            name,
            attributes: Vec::new(),
            text: None,
            children: Vec::new(),
        }
    }
    #[cfg(feature = "csip-aus")]
    pub fn aus(name: &'static str) -> Self {
        Self {
            namespace: crate::codec::AUS,
            ..Self::sep(name)
        }
    }
    pub fn attribute(mut self, name: &'static str, value: impl Display) -> Self {
        use alloc::string::ToString;
        self.attributes.push((name, value.to_string()));
        self
    }
    pub fn text(mut self, value: impl Display) -> Self {
        use alloc::string::ToString;
        self.text = Some(value.to_string());
        self
    }
    pub fn child(mut self, child: Self) -> Self {
        self.children.push(child);
        self
    }
    pub fn encode(&self, limits: Limits) -> Result<String, Error> {
        let xml = self.xml(limits)?;
        Document::parse(&xml, limits)?;
        Ok(xml)
    }
    #[cfg(feature = "csip-aus")]
    pub fn encode_aus(&self, limits: Limits) -> Result<String, Error> {
        let xml = self.xml(limits)?;
        Document::parse_aus(&xml, limits)?;
        Ok(xml)
    }
    fn xml(&self, limits: Limits) -> Result<String, Error> {
        let mut xml = String::new();
        self.write(None, &mut xml, limits, 0)?;
        Ok(xml)
    }
    fn write(
        &self,
        parent_ns: Option<&str>,
        xml: &mut String,
        limits: Limits,
        depth: usize,
    ) -> Result<(), Error> {
        if depth >= limits.depth.min(128) {
            return Err(Error::Limit("depth"));
        }
        valid_name(self.name)?;
        xml.push('<');
        xml.push_str(self.name);
        if Some(self.namespace) != parent_ns {
            xml.push_str(" xmlns=\"");
            xml.push_str(self.namespace);
            xml.push('"');
        }
        for (name, value) in &self.attributes {
            valid_name(name)?;
            if *name == "xmlns" {
                return Err(Error::UnexpectedMember((*name).into()));
            }
            xml.push(' ');
            xml.push_str(name);
            xml.push_str("=\"");
            bounded_escape(value, true, xml, limits.bytes)?;
            xml.push('"');
        }
        xml.push('>');
        if let Some(text) = &self.text {
            bounded_escape(text, false, xml, limits.bytes)?;
        }
        for child in &self.children {
            child.write(Some(self.namespace), xml, limits, depth + 1)?;
        }
        xml.push_str("</");
        xml.push_str(self.name);
        xml.push('>');
        if xml.len() > limits.bytes {
            return Err(Error::Limit("byte"));
        }
        Ok(())
    }
}
fn valid_name(name: &str) -> Result<(), Error> {
    let mut bytes = name.bytes();
    if !bytes
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == b'_')
        || !bytes.all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-' | b'.'))
    {
        return Err(Error::UnexpectedMember(name.into()));
    }
    Ok(())
}
fn bounded_escape(value: &str, attr: bool, xml: &mut String, limit: usize) -> Result<(), Error> {
    if value.len() > limit.saturating_sub(xml.len()) {
        return Err(Error::Limit("byte"));
    }
    escape(value, attr, xml);
    if xml.len() > limit {
        return Err(Error::Limit("byte"));
    }
    Ok(())
}
