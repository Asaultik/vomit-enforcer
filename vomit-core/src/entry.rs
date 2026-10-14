//! The PIN entry state machine: collects committed values until submit.

use zeroize::Zeroize;

use crate::InputEvent;

/// Hard cap on the number of entries in one PIN.
/// 15 so the count fits in one hex digit on the display.
pub const MAX_ENTRIES: usize = 15;

/// A completed PIN: the sequence of values plus the number of values each
/// entry could take (part of the derivation, so a dial PIN `1 2 3` and a
/// keypad PIN `1 2 3` give different passphrases).
#[derive(Clone)]
pub struct Pin {
    pub steps: u16,
    len: usize,
    values: [u16; MAX_ENTRIES],
}

impl Pin {
    pub fn values(&self) -> &[u16] {
        &self.values[..self.len]
    }
}

impl Drop for Pin {
    fn drop(&mut self) {
        self.values.zeroize();
        self.len.zeroize();
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Nothing interesting, just refresh the display.
    Updated,
    /// The event was refused (buffer full, nothing to submit, ...).
    Rejected,
    /// PIN complete, go derive.
    Submitted,
}

pub struct PinEntry {
    steps: u16,
    min_entries: usize,
    preview: Option<u16>,
    pin: Pin,
}

impl PinEntry {
    pub fn new(steps: u16, min_entries: usize) -> Self {
        assert!(min_entries >= 1 && min_entries <= MAX_ENTRIES);
        Self {
            steps,
            min_entries,
            preview: None,
            pin: Pin { steps, len: 0, values: [0; MAX_ENTRIES] },
        }
    }

    pub fn count(&self) -> usize {
        self.pin.len
    }

    pub fn preview(&self) -> Option<u16> {
        self.preview
    }

    pub fn clear(&mut self) {
        self.pin.values.zeroize();
        self.pin.len = 0;
    }

    fn push(&mut self, v: u16) -> Outcome {
        if v >= self.steps || self.pin.len == MAX_ENTRIES {
            return Outcome::Rejected;
        }
        self.pin.values[self.pin.len] = v;
        self.pin.len += 1;
        Outcome::Updated
    }

    /// Feed an event. On [`Outcome::Submitted`], grab the PIN with [`Self::take`].
    pub fn handle(&mut self, ev: InputEvent) -> Outcome {
        match ev {
            InputEvent::Preview(v) => {
                self.preview = Some(v);
                Outcome::Updated
            }
            InputEvent::Insert(v) => self.push(v),
            InputEvent::Backspace => {
                if self.pin.len == 0 {
                    return Outcome::Rejected;
                }
                self.pin.len -= 1;
                self.pin.values[self.pin.len] = 0;
                Outcome::Updated
            }
            InputEvent::Clear => {
                self.clear();
                Outcome::Updated
            }
            InputEvent::Submit => {
                if self.pin.len < self.min_entries {
                    Outcome::Rejected
                } else {
                    Outcome::Submitted
                }
            }
        }
    }

    /// Move the collected PIN out, leaving the entry empty.
    pub fn take(&mut self) -> Pin {
        let pin = self.pin.clone();
        self.clear();
        pin
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_hold_insert() {
        let mut e = PinEntry::new(128, 1);
        assert_eq!(e.handle(InputEvent::Submit), Outcome::Rejected);
        e.handle(InputEvent::Insert(100));
        e.handle(InputEvent::Insert(64));
        e.handle(InputEvent::Insert(116));
        assert_eq!(e.handle(InputEvent::Submit), Outcome::Submitted);
        let pin = e.take();
        assert_eq!(pin.values(), &[100, 64, 116]);
        assert_eq!(pin.steps, 128);
        assert_eq!(e.count(), 0);
    }

    #[test]
    fn rejects_out_of_range_and_overflow() {
        let mut e = PinEntry::new(10, 1);
        assert_eq!(e.handle(InputEvent::Insert(10)), Outcome::Rejected);
        for _ in 0..MAX_ENTRIES {
            assert_eq!(e.handle(InputEvent::Insert(1)), Outcome::Updated);
        }
        assert_eq!(e.handle(InputEvent::Insert(1)), Outcome::Rejected);
    }

    #[test]
    fn backspace_and_clear() {
        let mut e = PinEntry::new(10, 1);
        e.handle(InputEvent::Insert(1));
        e.handle(InputEvent::Insert(2));
        e.handle(InputEvent::Backspace);
        assert_eq!(e.count(), 1);
        e.handle(InputEvent::Clear);
        assert_eq!(e.count(), 0);
        assert_eq!(e.handle(InputEvent::Backspace), Outcome::Rejected);
    }
}
