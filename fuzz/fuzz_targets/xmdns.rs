#![no_main]
use ieee2030_5::{discovery::Service, xmdns::resolve_packet};
use libfuzzer_sys::fuzz_target;
fuzz_target!(|bytes: &[u8]| {
    for service in [Service::Capabilities, Service::DerPrograms] {
        let _ = resolve_packet(bytes, service);
    }
});
