//! Crypto core for vomit-enforcer.
//!
//! * [`vault`]: uploaded seeds held in SRAM, each locked behind its own PIN,
//!   with a failure counter, self-enforced throttling and a wipe after too
//!   many wrong PINs.
//! * [`render`]: turns an unlocked seed into a passphrase.
//!
//! `no_std`, no allocation, no hardware access. The firmware decides where
//! the [`vault::Vault`] lives and feeds it the time.

#![cfg_attr(not(test), no_std)]

pub mod render;
pub mod seed;
pub mod vault;
