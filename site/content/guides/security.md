+++
title = "Device identity and trust"
description = "Derive device identifiers, verify a manufacturing certificate and configure mutual TLS."
weight = 4
+++

## Identify the device

Use `Lfdi::from_certificate_der` on the exact DER certificate bytes. It returns the first 20 octets of SHA-256. Call `.sfdi()` to derive the short identifier, or `Sfdi::from_decimal` to validate an integer from XML. The short form contains the first 36 digest bits in decimal plus a check digit. For the standard's fingerprint beginning `3E4F45AB31`, it is `167261211391`. Device authorization should use the authenticated LFDI. [IEEE 2030.5-2018, §6.3](https://standards.ieee.org/ieee/2030.5/5897/)

## Verify a certificate chain

Enable `pki` for inspection and offline path validation. It requires the OpenSSL development libraries. Pass a leaf, untrusted intermediates, trusted root certificates and an explicit Unix time to `security::profile::verify_device_chain`. The verifier returns the authenticated LFDI or a typed error. `validate_device_leaf` inspects a single leaf's fields and omits path authentication.

The manufacturing profile checks the P-256 public key, ECDSA/SHA-256 signature algorithm, indefinite end of validity, critical device-class policy, permitted key usages, empty subject and critical hardware-module name. The verifier checks the issuer's device classes, key identifier chain and CA path lengths. Provision the root through a trusted channel. Enrollment and per-resource authorization remain application decisions. [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280) · [RFC 4108, §5](https://www.rfc-editor.org/rfc/rfc4108#section-5)

## Authenticate an HTTPS connection

Enable `runtime` for HTTP/1.1 and mutually authenticated TLS 1.2. Use `manufacturing_server_context` on the server to enforce the device profile on incoming clients. `tls_context` supports privately provisioned P-256 certificates, including service certificates with DNS names. Both builders accept a private root set, a leaf, optional intermediates and the corresponding key. The client verifies the configured host independently of DNS-SD routing hints.

The protocol context permits only `TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8`. Current OpenSSL defaults can reject its 64-bit authentication tag. The context explicitly selects the suite, group, and signature algorithm, disables renegotiation, tickets and compression, and checks every certificate in the verified path for P-256 and ECDSA/SHA-256. These settings apply only to the created context. [RFC 7251, §2](https://www.rfc-editor.org/rfc/rfc7251#section-2)

Run the identity, negative certificate-profile, handshake and peer-identity tests with the following command.

```sh
cargo test --locked --features runtime --test identity --test profile --test tls
```
