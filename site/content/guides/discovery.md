+++
title = "Link-local discovery"
description = "Advertise and locate an HTTPS endpoint on the local network using DNS-SD."
weight = 5
+++

With `runtime` enabled, create a `mdns_sd::ServiceDaemon` and call
`runtime::browse_service(&daemon, Service::DerPrograms)`. For a particular
device, use `Service::Device(sfdi)`. Keep the receiver open to observe additional
instances, address changes and removal events. Filter your own instance by its
full service name when the application runs both roles.

For a resolved instance, call `runtime::resolved_endpoint`. It validates the
TXT version, schema level, HTTPS port, capability path and any required subtype
path. Connect to a resolved address using that HTTPS port and authenticate the
expected server identity. Use the capability path as the starting point for
`client::Client::discover`. The DNS name and address are routing hints.

Publish the general service with `runtime::advertisement` and each advertised
function set with `runtime::advertise_service`, giving each a distinct instance
name and function-set path. Register the resulting records with the daemon and
unregister them on shutdown. Function-set labels follow IEEE 2030.5-2018 §7.5,
Table 17. The implementation uses link-local multicast and the `.local.` domain.
For networks using the `.site.` domain, use the site-scoped browser and responder. [Site-scoped discovery](@/guides/xmdns.md). [SunSpec CSIP Test Procedures](https://sunspec.org/wp-content/uploads/2025/01/SunSpecCSIPConformanceTestProceduresV1.3-2.pdf)

Run the multicast-to-TLS integration test locally with
`cargo test --features runtime --test discovery_lan`. It binds to loopback and
discovers the HTTPS port and capability path from the advertisement.
