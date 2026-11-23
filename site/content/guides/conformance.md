+++
title = "CSIP procedure coverage"
description = "Inspect the measured procedures, roles and limits of the local conformance suite."
weight = 10
+++

The suite exercises 3 of the 71 procedures in chapters 5–11 of SunSpec CSIP v1.3. Each procedure counts once for the roles shown below. The denominator includes optional and hardware-dependent procedures. For certification, section 4 defines which procedures apply to each role. [SunSpec CSIP Conformance Test Procedures v1.3](https://sunspec.org/wp-content/uploads/2025/01/SunSpecCSIPConformanceTestProceduresV1.3-2.pdf)

## Exercised procedures

| Procedure | Role under test | Evidence checked |
| --- | --- | --- |
| COMM-001 | Client and server | IPv4 site-scoped multicast and unicast DNS-SD over loopback, followed by mutually authenticated GETs for DER programs, time and capability. The destination-specific receiving sockets distinguish multicast from unicast. [Packet capture procedure](@/guides/xmdns.md) |
| COMM-002 | Server | An independent client uses the configured address, ephemeral port and capability URI, reads the XML link and retrieves its target. The server records both GETs and the client verifies both responses. |
| COMM-003 | Server | An OpenSSL client records the TLS 1.2 handshake, checks the selected cipher bytes and mutual authentication messages, then verifies the DeviceCapability reply. |

## Reproduce the results

With Python 3 and OpenSSL 3 or newer on your path, run the following command from the repository root. The report lists the HTTPS exchanges and uncovered procedure IDs.

```sh
cargo test --locked --features runtime --test csip_conformance -- --nocapture
```
