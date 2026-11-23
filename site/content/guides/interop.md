+++
title = "Independent peers"
description = "Reproduce client and server exchanges against pinned GRIDAPPS-D implementations."
weight = 9
+++

The interoperability suite exchanges DER resources over mutually authenticated TLS 1.2 with independently maintained GRIDAPPS-D client and server implementations. Their source revisions are recorded in the peer lockfile (`tests/interop/peers.lock`).

| Rust role | What the test observes |
| --- | --- |
| Server | The Go client discovers DeviceCapability, posts its EndDevice, verifies the registration PIN, follows assignment and program links, and reads the expected maximum-power control value. The Rust handler verifies the peer LFDI and the submitted identifiers before accepting registration. |
| Client | The Go server issues a scheduled control through its own administration API. Rust follows the program's control-list link, checks the documented schema disagreement, fetches the issued control at its Location, validates its XML and reads the expected value. |

**Known peer disagreement.** The pinned Go server includes `pollRate` on `DERControlList`. The 2018 schema declares the attribute on `DERProgramList` and omits it from `DERControlList` and its base types. The test asserts the list rejection and validates the individual control obtained at the peer-issued URI. Fully automatic traversal of this peer's control list remains unavailable. [IEEE supplemental schema](https://standards.ieee.org/downloads/) · [Pinned Go list builder](https://github.com/GRIDAPPSD/ieee-2030_5-server-go/blob/209f6759e90439a9a776d07ae7cda8ebce67ab77/pkg/sep2srv/handlers/der/der.go)

## Run the exchange

Run the same two-container check used in CI. Docker Compose gives the processes a shared loopback network namespace and an ephemeral session volume. Cleanup removes the credentials generated for the run.

```sh
docker compose -f tests/interop/compose.yml up --build --abort-on-container-exit --exit-code-from rust
docker compose -f tests/interop/compose.yml down --volumes
```

For a native run with Git, Rust, Go 1.26.8 or newer, Python 3, and OpenSSL development libraries, run `python3 -B tests/interop/run.py`. Both paths generate new test certificates, construct the peer stores in a temporary directory, and verify the peer revisions before building them. The Rust harness checks that Go actually registered and ran the client test.
