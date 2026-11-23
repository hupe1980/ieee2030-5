//! IEEE 2030.5 Smart Energy Profile types and protocol services.
//!
//! Parse IEEE 2030.5-2018 XML with [`codec::Document`], read a schema-generated [`model`]
//! view, or construct a checked resource with [`encode::Element`]. Use [`resource`]
//! for list access and [`schedule`] for time-dependent control selection. The
//! optional `runtime` feature supplies mutual TLS and HTTP/1.1 transport.
//! Enable `pki` for offline certificate validation.
//! The `csip-aus` feature adds Australian profile validation and site limits.
#![forbid(unsafe_code)]
#![cfg_attr(not(feature = "runtime"), no_std)]

extern crate alloc;

#[cfg(feature = "runtime")]
pub mod client;
pub mod codec;
#[cfg(feature = "csip-aus")]
pub mod csip_aus;
pub mod discovery;
pub mod encode;
pub mod model;
pub mod resource;
#[cfg(feature = "runtime")]
pub mod runtime;
pub mod schedule;
pub mod security;
#[cfg(feature = "runtime")]
pub mod xmdns;
