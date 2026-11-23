+++
title = "Payload encodings"
description = "Check XML and EXI support before choosing a peer or targeting a server profile."
weight = 8
+++

| Media type | Support |
| --- | --- |
| `application/sep-exi` | Unsupported |
| `application/sep+xml` | Supported |

IEEE 2030.5-2018 §5.6.1 requires servers to support both XML and EXI. Clients can support either encoding. SunSpec CSIP Test Procedures v1.3 §3.2.2 restates these requirements in GEN.050 and GEN.051. A server built with this crate cannot currently meet GEN.050. [SunSpec CSIP Test Procedures v1.3](https://sunspec.org/wp-content/uploads/2025/01/SunSpecCSIPConformanceTestProceduresV1.3-2.pdf)

Request `application/sep+xml` when connecting to a server. EXI-only peers require a separate codec.
