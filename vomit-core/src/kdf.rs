//! Key derivation: master seed + PIN -> per-PIN key -> output byte stream.
//!
//! There is deliberately no PIN verifier stored anywhere. *Every* PIN derives
//! *some* passphrase, so the device can't tell (and an attacker holding it
//! can't learn) which PINs are "real". Each real PIN simply maps to a
//! different passphrase, which is how multiple phrases on multiple PINs work.
//!
//! ```text
//! pin_key  = HMAC-SHA256(seed, "vomit-enforcer/v1/pin" || steps:u16be || n:u8 || v0:u16be || ...)
//! block_i  = HMAC-SHA256(pin_key, "vomit-enforcer/v1/out" || i:u32be)
//! ```

use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::entry::Pin;
use crate::seed::Seed;

type HmacSha256 = Hmac<Sha256>;

const PIN_DOMAIN: &[u8] = b"vomit-enforcer/v1/pin";
const OUT_DOMAIN: &[u8] = b"vomit-enforcer/v1/out";

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct PinKey([u8; 32]);

fn mac(key: &[u8]) -> HmacSha256 {
    // HMAC accepts keys of any length.
    HmacSha256::new_from_slice(key).unwrap()
}

pub fn derive_pin_key(seed: &Seed, pin: &Pin) -> PinKey {
    let mut m = mac(seed.bytes());
    m.update(PIN_DOMAIN);
    m.update(&pin.steps.to_be_bytes());
    m.update(&[pin.values().len() as u8]);
    for v in pin.values() {
        m.update(&v.to_be_bytes());
    }
    PinKey(m.finalize().into_bytes().into())
}

/// Endless pseudo-random byte stream keyed by a [`PinKey`].
pub struct OutputStream {
    key: PinKey,
    counter: u32,
    block: [u8; 32],
    pos: usize,
}

impl OutputStream {
    pub fn new(key: PinKey) -> Self {
        Self { key, counter: 0, block: [0; 32], pos: 32 }
    }

    pub fn next_byte(&mut self) -> u8 {
        if self.pos == self.block.len() {
            let mut m = mac(&self.key.0);
            m.update(OUT_DOMAIN);
            m.update(&self.counter.to_be_bytes());
            self.block = m.finalize().into_bytes().into();
            self.counter += 1;
            self.pos = 0;
        }
        let b = self.block[self.pos];
        self.pos += 1;
        b
    }
}

impl Drop for OutputStream {
    fn drop(&mut self) {
        self.block.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{entry::PinEntry, InputEvent};

    fn pin(steps: u16, vals: &[u16]) -> Pin {
        let mut e = PinEntry::new(steps, 1);
        for &v in vals {
            e.handle(InputEvent::Insert(v));
        }
        e.take()
    }

    fn first_bytes(seed: &Seed, p: &Pin) -> [u8; 40] {
        let mut s = OutputStream::new(derive_pin_key(seed, p));
        core::array::from_fn(|_| s.next_byte())
    }

    #[test]
    fn deterministic_and_distinct() {
        let seed = Seed::from_bytes([7; 32]);
        let a = first_bytes(&seed, &pin(128, &[100, 64, 116]));
        assert_eq!(a, first_bytes(&seed, &pin(128, &[100, 64, 116])));
        assert_ne!(a, first_bytes(&seed, &pin(128, &[100, 64, 117])));
        assert_ne!(a, first_bytes(&seed, &pin(128, &[100, 64])));
        assert_ne!(a, first_bytes(&seed, &pin(256, &[100, 64, 116])));
        assert_ne!(a, first_bytes(&Seed::from_bytes([8; 32]), &pin(128, &[100, 64, 116])));
    }

    #[test]
    fn known_answer() {
        // Pins the derivation so a refactor can't silently change every
        // passphrase. Recompute with:
        //   python3 -c 'import hmac,hashlib;k=hmac.new(bytes(32),b"vomit-enforcer/v1/pin"+bytes([0,128,3,0,100,0,64,0,116]),hashlib.sha256).digest();print(hmac.new(k,b"vomit-enforcer/v1/out"+bytes(4),hashlib.sha256).hexdigest())'
        let seed = Seed::from_bytes([0; 32]);
        let mut s = OutputStream::new(derive_pin_key(&seed, &pin(128, &[100, 64, 116])));
        let block: [u8; 32] = core::array::from_fn(|_| s.next_byte());
        let hex: std::string::String = block.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, KNOWN_ANSWER);
    }

    const KNOWN_ANSWER: &str = "309be1b78bb0030bc62a639a545bf3639e5c407772d16f07c7e1a121ca634cc8";
}
