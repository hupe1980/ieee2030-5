# ieee2030-5

A Rust library for IEEE 2030.5-2018 (Smart Energy Profile 2.0). Read and write schema-checked XML, follow distributed energy resource (DER) programs and evaluate scheduled controls. The default build uses `no_std` with an allocator. Enable `runtime` for discovery, HTTP/1.1 and mutual TLS, `pki` for offline certificate verification, or `csip-aus` for Australian v1.2 site limits.

## Get started

```sh
cargo add ieee2030-5
```

The `pki` and `runtime` features require OpenSSL development libraries.

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

## Documentation

[Getting started](https://hupe1980.github.io/ieee2030-5/guides/getting-started/) · [Protocol guides](https://hupe1980.github.io/ieee2030-5/guides/) · [Rust API reference](https://docs.rs/ieee2030-5)

## Verification

Run `just` to list development commands or `just check` to run the Rust CI checks locally. The bare-metal check requires `rustup target add thumbv7em-none-eabihf`.

CSIP procedure coverage: 3/71.

The [coverage report](https://hupe1980.github.io/ieee2030-5/guides/conformance/) identifies the role exercised for each procedure. The crate supports XML. Server conformance also requires EXI.

## License

Licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option.
