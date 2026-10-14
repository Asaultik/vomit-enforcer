//! Turns the derived byte stream into a typeable passphrase.

use zeroize::Zeroize;

use crate::kdf::OutputStream;

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
    /// Press Enter after typing.
    pub enter: bool,
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
pub fn render(stream: &mut OutputStream, format: &Format) -> Passphrase {
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
    use crate::{entry::PinEntry, kdf::derive_pin_key, seed::Seed, InputEvent};

    fn stream() -> OutputStream {
        let mut e = PinEntry::new(128, 1);
        e.handle(InputEvent::Insert(1));
        OutputStream::new(derive_pin_key(&Seed::from_bytes([3; 32]), &e.take()))
    }

    #[test]
    fn charsets() {
        let p = render(&mut stream(), &Format { charset: Charset::Printable, length: 64, enter: false });
        assert_eq!(p.as_bytes().len(), 64);
        assert!(p.as_bytes().iter().all(|c| (b'!'..=b'~').contains(c)));

        let p = render(&mut stream(), &Format { charset: Charset::Hex, length: 10, enter: false });
        assert!(p.as_bytes().iter().all(|c| c.is_ascii_hexdigit()));

        let p = render(&mut stream(), &Format { charset: Charset::Alnum, length: 100, enter: false });
        assert_eq!(p.as_bytes().len(), MAX_LEN);
        assert!(p.as_bytes().iter().all(|c| c.is_ascii_alphanumeric()));
    }
}
