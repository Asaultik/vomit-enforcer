//! Rendering for a 4 digit 7-segment display (TM1637 style bit order:
//! bit0 = a ... bit6 = g, bit7 = decimal point / colon).
//!
//! ```text
//!   aaa
//!  f   b
//!   ggg
//!  e   c
//!   ddd  .
//! ```

pub type Digits = [u8; 4];

pub const DP: u8 = 0x80;
pub const BLANK: u8 = 0;
pub const DASH: u8 = 0x40;

const HEX: [u8; 16] = [
    0x3f, 0x06, 0x5b, 0x4f, 0x66, 0x6d, 0x7d, 0x07, // 0-7
    0x7f, 0x6f, 0x77, 0x7c, 0x39, 0x5e, 0x79, 0x71, // 8-9 A b C d E F
];

pub fn digit(d: u8) -> u8 {
    HEX[(d & 0xf) as usize]
}

/// Best effort letters for status messages.
pub fn glyph(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => digit(c - b'0'),
        b'A' | b'a' => 0x77,
        b'b' | b'B' => 0x7c,
        b'C' => 0x39,
        b'c' => 0x58,
        b'd' | b'D' => 0x5e,
        b'E' | b'e' => 0x79,
        b'F' | b'f' => 0x71,
        b'G' | b'g' => 0x3d,
        b'H' => 0x76,
        b'h' => 0x74,
        b'I' | b'i' => 0x06,
        b'J' | b'j' => 0x1e,
        b'L' | b'l' => 0x38,
        b'n' | b'N' => 0x54,
        b'O' => 0x3f,
        b'o' => 0x5c,
        b'P' | b'p' => 0x73,
        b'r' | b'R' => 0x50,
        b'S' | b's' => 0x6d,
        b't' | b'T' => 0x78,
        b'U' => 0x3e,
        b'u' => 0x1c,
        b'y' | b'Y' => 0x6e,
        b'-' => DASH,
        b'_' => 0x08,
        _ => BLANK,
    }
}

/// Up to 4 characters of text, left aligned.
pub fn text(s: &[u8]) -> Digits {
    let mut d = [BLANK; 4];
    for (slot, &c) in d.iter_mut().zip(s) {
        *slot = glyph(c);
    }
    d
}

/// The main entry view: number of committed entries (one hex digit, with the
/// decimal point as a separator), then the currently selected value.
///
/// `1.064` = one value entered, dial on 64.
pub fn entry_view(count: usize, value: Option<u16>) -> Digits {
    let mut d = [digit(count as u8) | DP, DASH, DASH, DASH];
    if let Some(v) = value {
        let v = v.min(999);
        d[1] = digit((v / 100) as u8);
        d[2] = digit((v / 10 % 10) as u8);
        d[3] = digit((v % 10) as u8);
    }
    d
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn view() {
        assert_eq!(entry_view(1, Some(64)), [0x06 | DP, 0x3f, 0x7d, 0x66]);
        assert_eq!(entry_view(0, None), [0x3f | DP, DASH, DASH, DASH]);
        assert_eq!(text(b"SEEd"), [0x6d, 0x79, 0x79, 0x5e]);
    }
}
