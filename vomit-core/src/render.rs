//! Turns an unlocked seed into a typeable passphrase.
//!
//! ```text
//! k      = HKDF-SHA256(ikm = seed, info = "vomit-enforcer/v1/passphrase")
//! stream = ChaCha20(k, nonce = 0) keystream
//! ```
//! then rejection sampling into the charset, so there's no bias.
//!
//! Other outputs (raw keys, TOTP secrets, ...) should use their own HKDF label
//! via [`derive_key`], never this stream.

use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::ChaCha20;
use zeroize::Zeroize;

use crate::kdf::hkdf32_parts;
use crate::seed::Seed;

const LABEL_PREFIX: &[u8] = b"vomit-enforcer/v1/";
const PASSPHRASE: &[u8] = b"passphrase";

pub const MAX_LEN: usize = 64;

/// A 32 byte key for `purpose`, independent of the passphrase and of every
/// other purpose.
pub fn derive_key(seed: &Seed, purpose: &[u8]) -> zeroize::Zeroizing<[u8; 32]> {
    hkdf32_parts(seed.bytes(), &[LABEL_PREFIX, purpose])
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Charset {
    /// All 94 printable ASCII characters except space. ~6.55 bits/char.
    Printable,
    /// `A-Z a-z 0-9`. ~5.95 bits/char. Friendlier with picky password fields.
    Alnum,
    /// Lowercase hex. 4 bits/char. For things that want a raw key.
    Hex,
}

const ALNUM: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const HEX: &[u8] = b"0123456789abcdef";

impl Charset {
    fn len(&self) -> usize {
        match self {
            Charset::Printable => 94,
            Charset::Alnum => ALNUM.len(),
            Charset::Hex => HEX.len(),
        }
    }

    fn get(&self, i: usize) -> u8 {
        match self {
            Charset::Printable => b'!' + i as u8,
            Charset::Alnum => ALNUM[i],
            Charset::Hex => HEX[i],
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Format {
    pub charset: Charset,
    /// 1..=MAX_LEN characters.
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

impl core::fmt::Debug for Passphrase {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Passphrase({} chars)", self.len)
    }
}

pub fn render(seed: &Seed, format: &Format) -> Passphrase {
    let key = derive_key(seed, PASSPHRASE);
    let mut cipher = ChaCha20::new((&*key).into(), &[0u8; 12].into());
    drop(key);

    let n = format.charset.len();
    let len = format.length.min(MAX_LEN);
    let limit = 256 - 256 % n; // largest multiple of n that fits in a byte
    let mut out = Passphrase { len, buf: [0; MAX_LEN] };
    let mut block = [0u8; 64];
    let mut pos = block.len();
    for slot in out.buf[..len].iter_mut() {
        loop {
            if pos == block.len() {
                block = [0; 64];
                cipher.apply_keystream(&mut block);
                pos = 0;
            }
            let b = block[pos] as usize;
            pos += 1;
            if b < limit {
                *slot = format.charset.get(b % n);
                break;
            }
        }
    }
    block.zeroize();
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
    fn labels_are_independent() {
        let seed = Seed::from_bytes([3; 32]);
        assert_ne!(*derive_key(&seed, b"a"), *derive_key(&seed, b"b"));
        assert_ne!(*derive_key(&seed, b"a"), *derive_key(&seed, PASSPHRASE));
    }

    #[test]
    fn known_answer() {
        // Pins the derivation so a refactor can't silently change every
        // passphrase. Generated with tools/kat.py (Python `cryptography`).
        let p = render(&Seed::from_bytes([0; 32]), &fmt(Charset::Printable, 32));
        assert_eq!(p.as_bytes(), KA_PRINTABLE);
        let p = render(&Seed::from_bytes([0; 32]), &fmt(Charset::Hex, 16));
        assert_eq!(p.as_bytes(), KA_HEX);
    }

    const KA_PRINTABLE: &[u8] = br#"?*R+3r/dV%R!{k9e'1>WX-gK}\lLh'<S"#;
    const KA_HEX: &[u8] = b"c918f2800b17cd15";
}
