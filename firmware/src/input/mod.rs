//! Input frontends. Each one turns its hardware into [`InputEvent`]s and
//! tells the display what to show; everything else is shared.

use vomit_core::segments::Digits;
use vomit_core::InputEvent;

#[cfg(feature = "input-dial")]
mod dial;
#[cfg(feature = "input-dial")]
pub use dial::DialFrontend as Active;

#[cfg(feature = "input-keypad")]
mod keypad;
#[cfg(all(feature = "input-keypad", not(feature = "input-dial")))]
pub use keypad::KeypadFrontend as Active;

#[cfg(all(feature = "input-dial", feature = "input-keypad"))]
compile_error!("pick one input frontend: `input-dial` or `input-keypad`");
#[cfg(not(any(feature = "input-dial", feature = "input-keypad")))]
compile_error!("enable an input frontend: `input-dial` or `input-keypad`");

pub trait Frontend {
    /// Number of distinct values one entry can take. Part of the derivation.
    const STEPS: u16;

    /// Sample the hardware. Called every few milliseconds. May emit up to two
    /// events at once (e.g. insert + submit on a long press).
    fn poll(&mut self, now_ms: u64) -> [Option<InputEvent>; 2];

    /// What the display should show, given the number of committed entries.
    fn view(&self, count: usize, now_ms: u64) -> Digits;
}
