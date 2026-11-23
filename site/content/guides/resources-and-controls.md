+++
title = "Resources and DER controls"
description = "Follow resource links, page through lists and select the active distributed energy resource control."
weight = 3
+++

## Serve and traverse a resource tree

Create a `ResourceTree<T>` for the resources an authenticated client may access. Give it limits sized for the device. Publish linked resources before publishing the objects that refer to them. Use the ordered member paths and timestamp keys from the function set when publishing a list. The tree checks that each member exists and that its resource type satisfies the list schema.

A client starts at its configured `DeviceCapability` URL and follows the advertised links. Resolve relative, absolute-path and absolute HTTPS links with `resolve_href` before sending a request. The resolver checks the destination against the authenticated origin. Pass `PageQuery::parse` the query component when reading a list. A page exposes the original total in `all` and the current results in `members.len()`. Advance by the number of members returned. Keep the same `a` value between requests when paging through equal timestamps. Each read observes the current tree.

`method_mode` exposes the 2018 WADL policy for each resource and method. The tree implements bounded collection insertion, replacement, and deletion. The publisher supplies the new resource path and list position on POST. A dangling single-resource link blocks deletion until its owner updates it. `subscribe` associates a subscription ID with a path. Mutations return the matching subscription IDs for delivery. [IEEE supplemental WADL](https://standards.ieee.org/downloads/)

## Evaluate controls at an instant

Parse the program and control with `Document::parse`, obtain the generated `DERProgram` and `DERControl` views, and project the event with `schedule::from_control`. Supply the device category, first receipt time in server UTC seconds, and a stable random draw for each randomization interval. Persist these draws across polls of the same event. Each projection retains the complete mode element, including a curve link when present.

Use `schedule::effective_control` with the discovered program views, their defaults and their observed controls. It selects the default of the lowest-primacy program and evaluates the requested mode at the supplied time. Use `schedule::select` directly when the application already has projected events and its applicable default. The return value identifies the event mRID and the selected value, the fallback default, or idle. Selection uses half-open intervals. When a higher-priority overlap is known before a lower-priority event starts, the lower one is skipped. When the lower event is already active, it continues until the replacement starts. A displaced event stays displaced. Equal primacy and creation time for overlapping controls produce an explicit ambiguity error. [CSIP Implementation Guide §7.10](https://sunspec.org/wp-content/uploads/2025/01/CSIPImplementationGuidev2.103-15-2018.pdf)

Use one `Responses` instance per device and event. After each actual transition, call `acknowledge` and queue any returned POST for delivery to the event's `replyTo` link. A retry sends the queued write. Call `report` with a DER and validated availability, capability, settings or status XML to obtain its PUT target and payload.

## Apply an Australian site limit

Enable the `csip-aus` Cargo feature and parse Australian resources with `Document::parse_aus`. The supported v1.2 namespace is `https://csipaus.org/ns`. Extract the relevant limit using `ActivePower::from_control`, then use its connection-point ID and mode as the schedule key. `effective_limit` also checks that a supplied default belongs to that key. Retain the signed mantissa and decimal multiplier when the application supports fractional watts. `whole_watts` returns an error if conversion would round or overflow. [CSIP-AUS v1.2 Explainer §§6–7](https://www.csipaus.org/s/CSIP-AUS-v12-explainer-May-2025-release.pdf)

Run the in-process exchanges, receipt-order scheduling examples and extension round trips from the repository root.

```sh
cargo test --features csip-aus --test resource --test schedule --test csip_aus
```
