+++
title = "Site-scoped discovery"
description = "Browse or advertise services across a configured multicast site and verify the exchange."
weight = 6
+++

The `runtime` feature includes an xmDNS browser and responder for the IEEE 2030.5-2018 `.site.` domain. Use `Interface::V4` with the IPv4 address of the selected interface, or `Interface::V6` with its index and global or unique-local address. Multicast goes to `239.255.255.251:5353` or `[ff05::fb]:5353`. Site boundaries and multicast routing between subnets are configured by the network operator. [SunSpec COMM-001, pp. 22–23](https://sunspec.org/wp-content/uploads/2025/01/SunSpecCSIPConformanceTestProceduresV1.3-2.pdf)

## Browse

```rust
use ieee2030_5::discovery::Service;
use ieee2030_5::xmdns::{browse, Interface, Reply};
use std::{io, net::Ipv4Addr, time::Duration};

async fn der_programs(interface: Ipv4Addr) -> io::Result<()> {
    let route = browse(
        Interface::V4(interface),
        Service::DerPrograms,
        Reply::Multicast,
        Duration::from_secs(3),
    ).await?;
    println!("{} at {}, path {}", route.host, route.address, route.resource_path);
    Ok(())
}
```

Choose `Reply::Unicast` to set the QU bit. The device-specific `edev-SFDI` subtype requires this option. The browser sends one query and waits until its deadline for a complete PTR, SRV, TXT and address chain. It checks the TXT version, HTTPS port, capability path and function-set path. Use the result as a route hint and verify the authorized server during the TLS handshake. A caller can retry on timeout.

## Advertise

Construct an `Advertisement` for the main server and each published subtype. Give each instance a unique label on the site, such as `device-000001111114` and `derp-000001111114`. Use the same fully qualified hostname and IP for that server. Pass the advertised capability path and HTTPS port in `Endpoint`, and the matching resource path for each function-set subtype. Start `Responder::bind(interface, announcements)?.run().await` in a Tokio task. Dropping the future stops the responder.

The site responder serves PTR queries with associated records in the same datagram. It uses provisioned unique labels. Deployments that need dynamic collision recovery, continuous discovery, or a cache spanning separate answers need to provide those facilities. Link-local discovery with a managed daemon is also available. [Link-local DNS-SD guide](@/guides/discovery.md)

## Verify COMM-001 on loopback

The runtime conformance test runs both endpoints over IPv4 loopback and verifies each discovered resource by GET over mutual TLS. It requests DER programs twice, time once, and the main service once. The second DER request asks for a unicast reply. All requests and the other replies are multicast. The IPv6 site transport requires a site-routable interface address and has no live loopback conformance result.

For independent inspection, start a capture on the loopback interface before running the test. Substitute `lo` for `lo0` on Linux. Stop the capture after the test exits.

```sh
tcpdump -i lo0 -n -s0 -U -w xmDNS.pcap 'udp port 5353 and src host 127.0.0.1 and (dst host 239.255.255.251 or dst host 127.0.0.1)'
```

In a second shell, run the procedure.

```sh
cargo test --features runtime --test csip_conformance procedure_coverage -- --nocapture
```

Inspect the capture. Each response should contain a PTR, SRV, TXT and A record. The QU response goes to `127.0.0.1`. Match the destination and resource name with the GET reported by the test. Capture permissions depend on the operating system.

```sh
tshark -r xmDNS.pcap -T fields -e ip.dst -e dns.flags.response -e dns.qry.name -e dns.qry.qu -e dns.resp.type -e dns.ptr.domain_name
```
