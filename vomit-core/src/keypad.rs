//! Frontend for a standard 3x4 phone keypad (0-9, `*`, `#`).
//!
//! Classic PIN behaviour: every digit is one entry (so `steps` is 10), `#`
//! submits, `*` deletes the last digit and holding `*` clears.

use crate::InputEvent;

/// Number of distinct values per entry on the keypad.
pub const KEYPAD_STEPS: u16 = 10;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Key {
    Digit(u8),
    Star,
    Hash,
}

/// Standard phone layout, row major.
pub const LAYOUT: [[Key; 3]; 4] = [
    [Key::Digit(1), Key::Digit(2), Key::Digit(3)],
    [Key::Digit(4), Key::Digit(5), Key::Digit(6)],
    [Key::Digit(7), Key::Digit(8), Key::Digit(9)],
    [Key::Star, Key::Digit(0), Key::Hash],
];

/// Translate a released key into an input event.
pub fn event_for(key: Key, long: bool) -> InputEvent {
    match key {
        Key::Digit(d) => InputEvent::Insert(d as u16),
        Key::Hash => InputEvent::Submit,
        Key::Star if long => InputEvent::Clear,
        Key::Star => InputEvent::Backspace,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mapping() {
        assert_eq!(event_for(LAYOUT[3][1], false), InputEvent::Insert(0));
        assert_eq!(event_for(Key::Hash, false), InputEvent::Submit);
        assert_eq!(event_for(Key::Star, true), InputEvent::Clear);
    }
}
