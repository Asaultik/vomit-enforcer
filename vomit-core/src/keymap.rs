//! ASCII -> USB HID keyboard usage, US layout.
//!
//! The host decides what a key code means, so a host set to a non-US layout
//! will receive a different passphrase for symbols (and `y`/`z` on QWERTZ,
//! and so on). Pick [`crate::render::Charset::Alnum`] or `Hex` if that
//! bites you, or keep the host on US while unlocking.

pub const MOD_LSHIFT: u8 = 0x02;
pub const KEY_ENTER: u8 = 0x28;

/// `(modifier, usage)` for one ASCII character.
pub fn ascii_to_hid(c: u8) -> Option<(u8, u8)> {
    let plain = |u| Some((0, u));
    let shift = |u| Some((MOD_LSHIFT, u));
    match c {
        b'a'..=b'z' => plain(0x04 + (c - b'a')),
        b'A'..=b'Z' => shift(0x04 + (c - b'A')),
        b'1'..=b'9' => plain(0x1e + (c - b'1')),
        b'0' => plain(0x27),
        b'\n' => plain(KEY_ENTER),
        b' ' => plain(0x2c),
        b'!' => shift(0x1e),
        b'@' => shift(0x1f),
        b'#' => shift(0x20),
        b'$' => shift(0x21),
        b'%' => shift(0x22),
        b'^' => shift(0x23),
        b'&' => shift(0x24),
        b'*' => shift(0x25),
        b'(' => shift(0x26),
        b')' => shift(0x27),
        b'-' => plain(0x2d),
        b'_' => shift(0x2d),
        b'=' => plain(0x2e),
        b'+' => shift(0x2e),
        b'[' => plain(0x2f),
        b'{' => shift(0x2f),
        b']' => plain(0x30),
        b'}' => shift(0x30),
        b'\\' => plain(0x31),
        b'|' => shift(0x31),
        b';' => plain(0x33),
        b':' => shift(0x33),
        b'\'' => plain(0x34),
        b'"' => shift(0x34),
        b'`' => plain(0x35),
        b'~' => shift(0x35),
        b',' => plain(0x36),
        b'<' => shift(0x36),
        b'.' => plain(0x37),
        b'>' => shift(0x37),
        b'/' => plain(0x38),
        b'?' => shift(0x38),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_printable_mapped() {
        for c in b'!'..=b'~' {
            assert!(ascii_to_hid(c).is_some(), "{}", c as char);
        }
        assert_eq!(ascii_to_hid(b'a'), Some((0, 0x04)));
        assert_eq!(ascii_to_hid(b'Z'), Some((MOD_LSHIFT, 0x1d)));
        assert_eq!(ascii_to_hid(b'0'), Some((0, 0x27)));
    }
}
