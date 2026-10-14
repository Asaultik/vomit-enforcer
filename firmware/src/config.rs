//! Knobs you probably want to turn. Changing anything that feeds the
//! derivation (`DIAL_STEPS`, the output format) changes every passphrase.

use vomit_core::render::{Charset, Format};

/// How many values the dial is mapped onto. Lower is faster and easier to
/// hit, higher is more entropy per entry: each entry is worth log2(steps)
/// bits, so 3 entries at 128 steps ~ 21 bits vs ~20 for a 6 digit PIN.
#[cfg(feature = "input-dial")]
pub const DIAL_STEPS: u16 = 128;
/// Hysteresis in raw ADC counts (out of 4096) before the dial switches bucket.
#[cfg(feature = "input-dial")]
pub const DIAL_HYSTERESIS: u16 = 6;
/// Flip if turning clockwise counts down.
#[cfg(feature = "input-dial")]
pub const DIAL_INVERT: bool = false;

/// Refuse to submit PINs shorter than this.
pub const MIN_ENTRIES: usize = 1;

/// Forget a half-entered PIN after this long without input.
pub const IDLE_CLEAR_MS: u64 = 30_000;

/// What gets typed. Every PIN gets the same format; different PINs give
/// different passphrases.
pub const OUTPUT: Format = Format { charset: Charset::Printable, length: 32, enter: true };

/// Delay between HID reports while typing. Some hosts (BIOS, initramfs on slow
/// boxes) drop keys if you go too fast.
pub const KEY_DELAY_MS: u64 = 8;

/// Hold the onboard KEY button (PA0) while plugging in for this long to wipe
/// the seed.
pub const WIPE_HOLD_MS: u64 = 5_000;

/// 7-segment brightness, 0..=7.
pub const DISPLAY_BRIGHTNESS: u8 = 3;

/// pid.codes test VID/PID. Fine for a personal device, get your own if you
/// ship these.
pub const USB_VID: u16 = 0x1209;
pub const USB_PID: u16 = 0x0001;
