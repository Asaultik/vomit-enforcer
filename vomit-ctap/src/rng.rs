//! The random number generator.
//!
//! A ChaCha20 generator with fast key erasure: every call first draws a new
//! key for itself, then the output, so learning the state later reveals
//! nothing about what was handed out before.
//!
//! It is only as good as what it is seeded with. The firmware feeds it
//! everything unpredictable it can find at boot and keeps mixing in timing
//! jitter. On a chip with a hardware random generator, feed it that.

use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::ChaCha20;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

/// Plain bytes, so the firmware can keep it in RAM that survives a reset and
/// carry the state across one. Any bit pattern is a valid (if unseeded) state.
#[repr(C)]
pub struct Drbg {
    key: [u8; 32],
    counter: u64,
}

impl Drbg {
    pub const fn new() -> Self {
        Self { key: [0; 32], counter: 0 }
    }

    /// Mix `input` into the state. Never makes the state more predictable.
    pub fn reseed(&mut self, input: &[u8]) {
        let mut h = Sha256::new();
        h.update(b"vomit-enforcer/v1/drbg");
        h.update(self.key);
        h.update(self.counter.to_le_bytes());
        h.update(input);
        self.key = h.finalize().into();
        self.counter = self.counter.wrapping_add(1);
    }

    pub fn fill(&mut self, out: &mut [u8]) {
        let mut nonce = [0u8; 12];
        nonce[..8].copy_from_slice(&self.counter.to_le_bytes());
        self.counter = self.counter.wrapping_add(1);
        let mut stream = ChaCha20::new((&self.key).into(), (&nonce).into());
        // The first 32 bytes replace the key; the caller gets what follows.
        let mut next = [0u8; 32];
        stream.apply_keystream(&mut next);
        out.fill(0);
        stream.apply_keystream(out);
        self.key = next;
        next.zeroize();
    }
}

impl Default for Drbg {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seeded(seed: &[u8]) -> Drbg {
        let mut d = Drbg::new();
        d.reseed(seed);
        d
    }

    #[test]
    fn deterministic_for_a_seed_and_never_repeats() {
        let (mut a, mut b) = (seeded(b"seed"), seeded(b"seed"));
        let (mut x, mut y, mut z) = ([0u8; 48], [0u8; 48], [0u8; 48]);
        a.fill(&mut x);
        b.fill(&mut y);
        assert_eq!(x, y);
        a.fill(&mut z);
        assert_ne!(x, z);
        assert_ne!(x, [0; 48]);
    }

    #[test]
    fn seeds_and_reseeds_change_the_stream() {
        let (mut x, mut y) = ([0u8; 32], [0u8; 32]);
        seeded(b"one").fill(&mut x);
        seeded(b"two").fill(&mut y);
        assert_ne!(x, y);

        let (mut a, mut b) = (seeded(b"seed"), seeded(b"seed"));
        b.reseed(b"jitter");
        a.fill(&mut x);
        b.fill(&mut y);
        assert_ne!(x, y);
    }

    #[test]
    fn output_does_not_contain_the_next_key() {
        let mut d = seeded(b"seed");
        let mut out = [0u8; 64];
        d.fill(&mut out);
        assert!(!out.windows(32).any(|w| w == d.key));
    }
}
