//! A small CTAP2 (FIDO2) authenticator on top of the vomit-core vault.
//!
//! * [`authenticator`]: the CTAP2 commands. Start reading there.
//! * [`cred`]: how credentials exist without being stored.
//! * [`crypto`]: PIN protocol 1 and ES256, on RustCrypto.
//! * [`cbor`]: the little CBOR that CTAP2 needs.
//! * [`rng`]: the random number generator.
//! * [`serve`]: the core firmware's main loop, minus the hardware.
//!
//! `no_std`, no allocation, no hardware access. Requests come from the
//! untrusted bridge, so nothing here may panic on any input.

#![cfg_attr(not(test), no_std)]

pub mod authenticator;
pub mod cbor;
pub mod cred;
pub mod crypto;
pub mod rng;
pub mod serve;
pub mod status;

pub use authenticator::{Authenticator, Platform, Presence};
