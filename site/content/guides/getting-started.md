+++
title = "Getting started"
description = "Parse a registration resource and choose the Cargo features your application needs."
weight = 1
+++

IEEE 2030.5 (Smart Energy Profile 2.0) represents devices, programs and controls as linked resources. A client typically begins at DeviceCapability and follows links to the resources assigned to its device. You can work with the XML model before connecting to a server.

## Add the library

From your Rust project directory, run:

```sh
cargo add ieee2030-5
```

## Read a registration

A registration carries the PIN used during device enrollment. Parsing validates the document against the 2018 schema. The typed view borrows the parsed document.

```rust
use ieee2030_5::{codec::{Document, Error, Limits}, model::Registration};

fn main() -> Result<(), Error> {
    let xml = r#"<Registration xmlns="urn:ieee:std:2030.5:ns" href="/reg"><dateTimeRegistered>0</dateTimeRegistered><pIN>123455</pIN></Registration>"#;
    let document = Document::parse(xml, Limits::default())?;
    let registration = document.as_type::<Registration>()?;
    assert_eq!(registration.pin().unwrap().value(), 123455);
    Ok(())
}
```

## Choose features

| Cargo feature | When to enable it |
| --- | --- |
| Default (empty) | Parse and build XML or evaluate controls with `no_std` and an allocator. |
| `pki` | Verify manufacturing certificate chains offline with OpenSSL. |
| `runtime` | Connect, discover and subscribe with Tokio, HTTP/1.1 and mutual TLS. Includes `pki`. |
| `csip-aus` | Read the Australian v1.2 overlay and evaluate connection-point power limits. |

The OpenSSL features require development headers and libraries. For a networked client, start with [device identity and trust](@/guides/security.md), then [polling and subscriptions](@/guides/client-and-notifications.md).
