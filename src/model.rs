//! Borrowed views on schema-validated IEEE 2030.5 elements.
//! Inherited members are available through the generated `as_base()` methods.
#[cfg(feature = "csip-aus")]
use crate::codec::AUS;
use crate::codec::{Attribute, Member, SEP, Shape};
use roxmltree::Node;

mod private {
    pub trait Sealed {}
}

pub trait View<'a>: private::Sealed + Sized {
    const NAME: &'static str;
    #[doc(hidden)]
    fn from_validated(node: Node<'a, 'a>, _: crate::codec::Validated) -> Self;
    fn node(&self) -> Node<'a, 'a>;
    /// Serialize this element with all namespace bindings needed outside its parent.
    fn encode(&self) -> alloc::string::String {
        let mut xml = alloc::string::String::new();
        crate::codec::write_element(self.node(), true, &mut xml);
        xml
    }
}

macro_rules! view {
    ($name:ident) => {
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        pub struct $name<'a>(Node<'a, 'a>);
        impl private::Sealed for $name<'_> {}
        impl<'a> View<'a> for $name<'a> {
            const NAME: &'static str = stringify!($name);
            fn from_validated(node: Node<'a, 'a>, _: crate::codec::Validated) -> Self {
                Self(node)
            }
            fn node(&self) -> Node<'a, 'a> {
                self.0
            }
        }
    };
}

#[allow(non_camel_case_types)]
#[rustfmt::skip]
mod generated;
pub use generated::*;

// The generated scalar views are constructed only after schema validation.
fn integer<T: TryFrom<i128>>(node: Node<'_, '_>) -> T {
    // Normalize through i128 so the XSD lexical value "-0" is valid for unsigned types.
    let number = crate::codec::element_text(node)
        .trim()
        .parse::<i128>()
        .expect("validated integer");
    T::try_from(number).ok().expect("validated range")
}
fn hex(node: Node<'_, '_>) -> alloc::vec::Vec<u8> {
    let text = crate::codec::element_text(node);
    text.trim()
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let digit = |b: u8| {
                if b.is_ascii_digit() {
                    b - b'0'
                } else {
                    b.to_ascii_lowercase() - b'a' + 10
                }
            };
            digit(pair[0]) * 16 + digit(pair[1])
        })
        .collect()
}
