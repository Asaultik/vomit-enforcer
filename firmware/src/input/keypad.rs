//! 3x4 phone keypad. Rows on PB12..PB15 (driven low one at a time), columns
//! on PB0, PB1, PB10 (pulled up).
//!
//! * digits  -> one entry each
//! * `#`     -> vomit
//! * `*`     -> delete last digit, hold to clear

use embassy_stm32::gpio::{Input, Output};
use vomit_core::button::{Press, PressTiming};
use vomit_core::keypad::{self, Key, KEYPAD_STEPS, LAYOUT};
use vomit_core::segments::{self, Digits};
use vomit_core::InputEvent;

use super::Frontend;

pub struct KeypadFrontend<'d> {
    rows: [Output<'d>; 4],
    cols: [Input<'d>; 3],
    timing: PressTiming,
    /// The key currently held and since when.
    held: Option<(Key, u64)>,
}

impl<'d> KeypadFrontend<'d> {
    pub fn new(mut rows: [Output<'d>; 4], cols: [Input<'d>; 3]) -> Self {
        for r in rows.iter_mut() {
            r.set_high();
        }
        Self { rows, cols, timing: PressTiming::default(), held: None }
    }

    /// First pressed key in scan order. Multi-key presses aren't a thing here.
    fn scan(&mut self) -> Option<Key> {
        let mut found = None;
        for (r, row) in self.rows.iter_mut().enumerate() {
            row.set_low();
            cortex_m::asm::delay(200); // let the line settle
            for (c, col) in self.cols.iter().enumerate() {
                if found.is_none() && col.is_low() {
                    found = Some(LAYOUT[r][c]);
                }
            }
            row.set_high();
        }
        found
    }
}

impl Frontend for KeypadFrontend<'_> {
    const STEPS: u16 = KEYPAD_STEPS;

    fn poll(&mut self, now_ms: u64) -> [Option<InputEvent>; 2] {
        let key = self.scan();
        let ev = match (self.held, key) {
            (None, Some(k)) => {
                self.held = Some((k, now_ms));
                None
            }
            (Some((k, t)), None) => {
                self.held = None;
                self.timing
                    .classify((now_ms - t) as u32)
                    .map(|p| keypad::event_for(k, p != Press::Short))
            }
            _ => None,
        };
        [ev, None]
    }

    fn view(&self, count: usize, _now_ms: u64) -> Digits {
        // Never show the digits themselves, only how many there are.
        segments::entry_view(count, None)
    }
}
