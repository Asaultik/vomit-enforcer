//! Turns an unlocked seed into a typeable passphrase.
//!
//! ```text
//! block_i = HMAC-SHA256(seed, "vomit-enforcer/v1/out" || i:u32be)
//! ```
//! then rejection sampling into the charset, so there's no bias.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroize;

use crate::seed::Seed;

const OUT_DOMAIN: &[u8] = b"vomit-enforcer/v1/out";

/// Endless pseudo-random byte stream keyed by a seed.
pub struct OutputStream<'a> {
    seed: &'a Seed,
    counter: u32,
    block: [u8; 32],
    pos: usize,
}

impl<'a> OutputStream<'a> {
    pub fn new(seed: &'a Seed) -> Self {
        Self { seed, counter: 0, block: [0; 32], pos: 32 }
    }

    pub fn next_byte(&mut self) -> u8 {
        if self.pos == self.block.len() {
            let mut m = Hmac::<Sha256>::new_from_slice(self.seed.bytes()).unwrap();
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

impl Drop for OutputStream<'_> {
    fn drop(&mut self) {
        self.block.zeroize();
    }
}

pub const MAX_LEN: usize = 64;

#[derive(Clone, Copy, Debug)]
pub enum Charset {
    /// All 94 printable ASCII characters except space. ~6.55 bits/char.
    Printable,
    /// `A-Z a-z 0-9`. ~5.95 bits/char. Friendlier with picky password fields.
    Alnum,
    /// Lowercase hex. 4 bits/char. For things that want a raw key.
    Hex,
    Custom(&'static [u8]),
}

const ALNUM: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const HEX: &[u8] = b"0123456789abcdef";

impl Charset {
    fn len(&self) -> usize {
        match self {
            Charset::Printable => 94,
            Charset::Alnum => ALNUM.len(),
            Charset::Hex => HEX.len(),
            Charset::Custom(c) => c.len(),
        }
    }

    fn get(&self, i: usize) -> u8 {
        match self {
            Charset::Printable => b'!' + i as u8,
            Charset::Alnum => ALNUM[i],
            Charset::Hex => HEX[i],
            Charset::Custom(c) => c[i],
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Format {
    pub charset: Charset,
    pub length: usize,
}

pub struct Passphrase {
    len: usize,
    buf: [u8; MAX_LEN],
}

impl Passphrase {
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }
}

impl Drop for Passphrase {
    fn drop(&mut self) {
        self.buf.zeroize();
    }
}

/// Unbiased: bytes that would skew the distribution are thrown away
/// (rejection sampling).
pub fn render(seed: &Seed, format: &Format) -> Passphrase {
    let mut stream = OutputStream::new(seed);
    let n = format.charset.len();
    assert!((2..=256).contains(&n));
    let len = format.length.min(MAX_LEN);
    let limit = 256 - 256 % n; // largest multiple of n that fits in a byte
    let mut out = Passphrase { len, buf: [0; MAX_LEN] };
    for slot in out.buf[..len].iter_mut() {
        loop {
            let b = stream.next_byte() as usize;
            if b < limit {
                *slot = format.charset.get(b % n);
                break;
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fmt(charset: Charset, length: usize) -> Format {
        Format { charset, length }
    }

    #[test]
    fn charsets() {
        let seed = Seed::from_bytes([3; 32]);
        let p = render(&seed, &fmt(Charset::Printable, 64));
        assert_eq!(p.as_bytes().len(), 64);
        assert!(p.as_bytes().iter().all(|c| (b'!'..=b'~').contains(c)));

        let p = render(&seed, &fmt(Charset::Hex, 10));
        assert!(p.as_bytes().iter().all(|c| c.is_ascii_hexdigit()));

        let p = render(&seed, &fmt(Charset::Alnum, 100));
        assert_eq!(p.as_bytes().len(), MAX_LEN);
        assert!(p.as_bytes().iter().all(|c| c.is_ascii_alphanumeric()));
    }

    #[test]
    fn known_answer() {
        // Pins the derivation so a refactor can't silently change every
        // passphrase. First output block for an all-zero seed:
        //   python3 -c 'import hmac,hashlib;print(hmac.new(bytes(32),b"vomit-enforcer/v1/out"+bytes(4),hashlib.sha256).hexdigest())'
        let seed = Seed::from_bytes([0; 32]);
        let mut s = OutputStream::new(&seed);
        let hex: String = (0..32).map(|_| format!("{:02x}", s.next_byte())).collect();
        assert_eq!(hex, "c4523e21fb589e3fa400656e8097928b5d08a837bf5b3b2df9d630e90addf619");
    }
}
