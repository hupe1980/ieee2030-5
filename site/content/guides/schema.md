+++
title = "XML and the schema"
description = "Read typed views, build a resource and set limits for incoming XML."
weight = 2
+++

`Document::parse` accepts UTF-8 and a `Limits` value. Use `as_type` to obtain
a generated view. Views borrow the document. Required and optional elements
share the same accessor convention, and repeating elements return iterators.
Numeric views expose `value()`, binary views expose `bytes()`, and `as_base()`
exposes inherited members. Attribute accessors include schema defaults.

## Write a resource

To construct a resource, start with `encode::Element::sep("Registration")`, append
attributes and children, then call `encode(limits)`. The writer escapes application
values and checks the finished resource before returning XML. The
`encode::Element` API documentation includes a runnable registration example.

## Validation and limits

The validator checks expanded names, element order, repetition bounds, required
attributes, scalar widths, UTF-8 byte limits on bounded strings, hex syntax and
numeric facets. It resolves `xsi:type` against in-scope namespace bindings and
checks derivation. Unknown members and namespaces return errors. Application
rules in schema annotations (for example reserved enumeration values) require
function-set validation. URI lexical values are accepted as XML Schema anyURI;
use the resource resolver before following a link.

`Document::encode` serializes the validated element tree. Prefix choices,
attribute quoting, comments and processing instructions can change. Character
content and expanded names are preserved. Parsing enforces a byte budget, a
node budget and a nesting budget with a hard ceiling of 128 elements. The
default limits suit ordinary resource exchanges and can be reduced per peer.

## Regenerate or audit the model from a source checkout

Use Python 3.9 or newer and install the Rust toolchain’s rustfmt component.
Obtain the 2018 supplemental archive from [IEEE SA Downloads](https://standards.ieee.org/downloads/).
Extract the XSD and Examples directory. Put the [pinned BSGIP extension and overlay XSDs](https://github.com/bsgip/envoy-schema/tree/885e6c0ba554f4c5295a32c02597d6385e308d93)
beside the base XSD under the names `csipaus-ext-v1.2.xsd` and
`csipaus-core-v1.2.xsd`. The generator verifies all three file digests before
producing Rust. Ordinary builds use the included Rust file and need no schemas.

```sh
cargo xtask codegen --schema /path/to/sep.xsd --check
IEEE2030_5_EXAMPLES=/path/to/Examples cargo test --test corpus -- --ignored --nocapture
cargo doc --all-features --no-deps --open
```

The corpus test covers the publisher's XML examples and checks the malformed
MirrorMeterReadingList as a negative case. Its missing `all` and `results`
attributes also fail independent XSD validation with `xmllint --schema`.
