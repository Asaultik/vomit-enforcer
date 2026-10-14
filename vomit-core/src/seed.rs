//! A 32 byte seed, as uploaded by the user.

use zeroize::{Zeroize, ZeroizeOnDrop};

pub const SEED_LEN: usize = 32;

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Seed([u8; SEED_LEN]);

/// Never prints the bytes.
impl core::fmt::Debug for Seed {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Seed(..)")
    }
}

impl Seed {
    pub fn from_bytes(b: [u8; SEED_LEN]) -> Self {
        Self(b)
    }

    pub fn bytes(&self) -> &[u8; SEED_LEN] {
        &self.0
    }

    /// Parse 64 hex characters (as typed or sent over a serial link).
    pub fn from_hex(hex: &[u8]) -> Option<Self> {
        if hex.len() != 2 * SEED_LEN {
            return None;
        }
        let mut s = Seed([0; SEED_LEN]);
        for (i, pair) in hex.chunks_exact(2).enumerate() {
            s.0[i] = nibble(pair[0])? << 4 | nibble(pair[1])?;
        }
        Some(s)
    }
}

fn nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex() {
        let s = Seed::from_hex(b"000102030405060708090a0b0c0d0e0f101112131415161718191A1B1C1D1E1F").unwrap();
        assert_eq!(s.bytes()[31], 0x1f);
        assert!(Seed::from_hex(b"00").is_none());
        assert!(Seed::from_hex(&[b'g'; 64]).is_none());
    }
}
