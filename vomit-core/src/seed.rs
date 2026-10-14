//! The master seed and its layout in the RTC backup registers.
//!
//! The STM32F411 has 20 x 32-bit RTC backup registers. They live in the
//! backup domain, which keeps running off VBAT (a coin cell) when the main
//! supply is gone, and which the RTC tamper input erases *in hardware* even
//! while running from VBAT. That's the only place the seed is ever stored:
//! never flash. Pull both the USB power and the coin cell and it's gone.
//!
//! Layout (10 registers):
//! ```text
//! BKP0      magic "VOM1"
//! BKP1..=8  seed, 32 bytes, little endian words
//! BKP9      check word: first 4 bytes of SHA256("vomit-enforcer/v1/check" || seed)
//! ```

use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const BKP_WORDS: usize = 10;
const MAGIC: u32 = u32::from_le_bytes(*b"VOM1");

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Seed([u8; 32]);

impl Seed {
    pub fn from_bytes(b: [u8; 32]) -> Self {
        Self(b)
    }

    pub fn bytes(&self) -> &[u8; 32] {
        &self.0
    }

    fn check(&self) -> [u8; 4] {
        let mut h = Sha256::new();
        h.update(b"vomit-enforcer/v1/check");
        h.update(self.0);
        let d = h.finalize();
        [d[0], d[1], d[2], d[3]]
    }

    /// Short public identifier, so you can tell after re-provisioning that you
    /// loaded the same seed as before. Reveals nothing useful about the seed.
    pub fn fingerprint(&self) -> u32 {
        u32::from_be_bytes(self.check())
    }

    pub fn to_backup_words(&self) -> [u32; BKP_WORDS] {
        let mut w = [0u32; BKP_WORDS];
        w[0] = MAGIC;
        for (i, chunk) in self.0.chunks_exact(4).enumerate() {
            w[1 + i] = u32::from_le_bytes(chunk.try_into().unwrap());
        }
        w[9] = u32::from_le_bytes(self.check());
        w
    }

    /// `None` if the registers are blank (fresh battery, tamper wipe) or
    /// corrupted.
    pub fn from_backup_words(w: &[u32; BKP_WORDS]) -> Option<Self> {
        if w[0] != MAGIC {
            return None;
        }
        let mut b = [0u8; 32];
        for i in 0..8 {
            b[i * 4..i * 4 + 4].copy_from_slice(&w[1 + i].to_le_bytes());
        }
        let s = Seed(b);
        b.zeroize();
        (u32::from_le_bytes(s.check()) == w[9]).then_some(s)
    }

    /// Parse 64 hex characters.
    pub fn from_hex(hex: &[u8]) -> Option<Self> {
        if hex.len() != 64 {
            return None;
        }
        let mut b = [0u8; 32];
        for i in 0..32 {
            let (Some(hi), Some(lo)) = (nibble(hex[2 * i]), nibble(hex[2 * i + 1])) else {
                b.zeroize();
                return None;
            };
            b[i] = hi << 4 | lo;
        }
        let s = Seed(b);
        b.zeroize();
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

/// Collects junk (ADC noise LSBs, cycle counter jitter, ...) and condenses it
/// into a seed. The F411 has no hardware RNG, so this is the best we get on
/// chip; for anything you care about, generate the seed on a real computer
/// and load it with `seed <hex>`.
pub struct EntropyPool {
    hash: Sha256,
    samples: u32,
}

impl Default for EntropyPool {
    fn default() -> Self {
        Self { hash: Sha256::new(), samples: 0 }
    }
}

impl EntropyPool {
    pub fn add(&mut self, sample: u32) {
        self.hash.update(sample.to_le_bytes());
        self.samples += 1;
    }

    pub fn samples(&self) -> u32 {
        self.samples
    }

    pub fn finish(self) -> Seed {
        let mut h = self.hash;
        h.update(b"vomit-enforcer/v1/gen");
        Seed(h.finalize().into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backup_roundtrip() {
        let s = Seed::from_bytes(core::array::from_fn(|i| i as u8));
        let w = s.to_backup_words();
        let back = Seed::from_backup_words(&w).unwrap();
        assert_eq!(back.bytes(), s.bytes());
    }

    #[test]
    fn blank_or_corrupt_is_none() {
        assert!(Seed::from_backup_words(&[0; BKP_WORDS]).is_none());
        let mut w = Seed::from_bytes([1; 32]).to_backup_words();
        w[4] ^= 1;
        assert!(Seed::from_backup_words(&w).is_none());
    }

    #[test]
    fn hex() {
        let s = Seed::from_hex(b"000102030405060708090a0b0c0d0e0f101112131415161718191A1B1C1D1E1F").unwrap();
        assert_eq!(s.bytes()[31], 0x1f);
        assert!(Seed::from_hex(b"00").is_none());
        assert!(Seed::from_hex(&[b'g'; 64]).is_none());
    }
}
