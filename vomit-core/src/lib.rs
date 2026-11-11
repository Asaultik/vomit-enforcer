//! Crypto core for vomit-enforcer.
//!
//! * [`vault`]: uploaded seeds in SRAM, each sealed behind its own PIN
//!   (Argon2id + ChaCha20-Poly1305), the whole vault sealed again under a
//!   rotating master key kept in the RTC backup registers. Failure counter,
//!   self-enforced lockout, wipe.
//! * [`backup`]: layout of the backup registers, behind a trait the firmware
//!   implements.
//! * [`render`]: turns an unlocked seed into a passphrase.
//!
//! `no_std`, no allocation, no hardware access. The firmware owns the
//! [`vault::Vault`] static, the backup registers, the clock and the
//! randomness, and hands them in.

#![cfg_attr(not(test), no_std)]

pub mod backup;
pub mod kdf;
pub mod render;
pub mod seed;
pub mod vault;
