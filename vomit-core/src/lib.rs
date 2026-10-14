//! Hardware-independent logic for vomit-enforcer.
//!
//! Everything in here is `no_std`, allocation free and unit tested on the
//! host. The firmware crate only glues these pieces to the STM32 peripherals.

#![cfg_attr(not(test), no_std)]

pub mod button;
pub mod dial;
pub mod entry;
pub mod kdf;
pub mod keymap;
pub mod keypad;
pub mod provision;
pub mod render;
pub mod seed;
pub mod segments;

/// Things an input frontend (dial, keypad, ...) can ask the PIN entry state
/// machine to do. Frontends translate raw hardware activity into these, so the
/// rest of the device doesn't care what the user is twiddling.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InputEvent {
    /// The value currently selected changed (dial moved). Not committed yet.
    Preview(u16),
    /// Commit a value as the next entry.
    Insert(u16),
    /// Done entering, derive and vomit.
    Submit,
    /// Drop the last committed entry.
    Backspace,
    /// Drop everything.
    Clear,
}
