+++
title = "Polling and subscriptions"
description = "Enroll a device, follow its control feed and receive authenticated change notifications."
weight = 7
+++

## Enroll and discover

Enable the `runtime` feature and configure a private CA, local certificate chain, key, server socket address and certificate name. The socket address selects where to connect. The name authenticates the endpoint. Use `runtime::tls_context` to construct the TLS context and pass it to `client::Client::new`.

For client-initiated enrollment, call `Client::register(capability_path, changed_time)`.
It POSTs an EndDevice using the certificate in the TLS context and returns the
validated resource Location. A pre-provisioned device can start with discovery.
Enable `csip-aus` and call `with_csip_aus()` on clients enrolled in that profile.

`Client::discover(capability_path, pin)` locates the registered device using its certificate identifiers, checks its registration PIN, and follows the advertised assignments and program lists. Each returned `ControlFeed` contains its program identity, primacy, control list, polling interval and the device's subscription list when available. Use `Client::controls` to visit the initial schema-checked control values. Each traversal is bounded by the client's limits.

## Polling

Pass a mutable feed to `Client::poll_controls`. It waits the current interval, refreshes the assignment and calls the visitor with the updated controls. Repeat this call to follow changes in the advertised interval or control-list URI. A removed assignment or unreachable server returns an error. The application chooses retry timing; a failed GET can occur after the feed itself was refreshed. See `tests/client.rs` for a complete polling example.

## Change notifications

1. On the publisher, provision the subscriber LFDI and its authorized callback URL, and use `ControlSubscription::new` to bind these to the subscribed list and the subscription's assigned URI. On the receiver, provision the expected publisher LFDI.
2. On the subscriber, expose an HTTPS notification endpoint using `runtime::serve`. Call `Client::subscribe_controls` with a discovered feed, the callback URL, and the publisher identity. The returned binding contains the subscription URI from the successful POST.
3. The publisher's POST handler passes the authenticated inbound LFDI and posted XML to `ControlSubscription::validate_request`. On success, register the subscription with the resource tree. Return 201 and a Location header for a newly created subscription. Return 200 with Location for an existing subscription.
4. When a tree update produces a matching subscription ID, call `notify` with the configured callback client and the total number of controls. The receiver checks the inbound LFDI, resource and subscription URI with `validate_notification`, acknowledges with 201 and Location, and queues a fresh `Client::controls` call. Notification delivery errors are returned to the publisher; applications can retry, and subscribers can continue polling.
5. Call `unsubscribe_controls` to DELETE the remote subscription. The publisher authorizes the authenticated requester and removes the subscription from its tree.

The supported wire form is an unconditional, change-only XML subscription with `encoding=0`, `level=-S1` and `limit=0`. Notifications carry a typed DERControlList summary with zero results. The reader retrieves the latest control state from its original server, so repeated change hints can be coalesced. Provision a separate trusted callback client per destination. Keep its address, certificate name and endpoint policy under local administration. See `tests/notifications.rs` for both endpoints.
