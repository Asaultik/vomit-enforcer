//! The path between the USB host and the vomit-enforcer core.
//!
//! ```text
//!  host ──USB HID──► bridge (RP2040) ──UART──► core (F411)
//!        ctaphid                      frame
//! ```
//!
//! * [`ctaphid`]: the FIDO HID transport, spoken by the bridge to the host.
//! * [`frame`]: the framing on the UART between bridge and core.
//! * [`bridge`]: the bridge's whole behaviour as one state machine.
//!
//! No hardware access and no allocation, so the exact code the firmware runs
//! is also tested on a PC and driven by real FIDO clients in the simulator.
//! Every input is treated as hostile: nothing here panics on malformed data.

#![cfg_attr(not(test), no_std)]

pub mod bridge;
pub mod ctaphid;
pub mod frame;
