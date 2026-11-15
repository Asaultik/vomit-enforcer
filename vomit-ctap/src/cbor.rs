//! Just enough CBOR for CTAP2: integers, byte and text strings, arrays, maps
//! and booleans, all with definite lengths. No floats, tags or allocation.
//!
//! The reader never trusts a length: every read is bounds-checked and nesting
//! is limited, so hostile input ends in an error code, not a panic or a deep
//! recursion. Errors are CTAP2 status codes, ready to send back.

use crate::status::{CBOR_UNEXPECTED_TYPE, INVALID_CBOR, OTHER};

pub type Result<T> = core::result::Result<T, u8>;

/// How deep [`Reader::skip`] follows arrays and maps. CTAP2 needs 4.
const MAX_DEPTH: u8 = 6;

pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn byte(&mut self) -> Result<u8> {
        let b = *self.buf.get(self.pos).ok_or(INVALID_CBOR)?;
        self.pos += 1;
        Ok(b)
    }

    fn take(&mut self, n: u64) -> Result<&'a [u8]> {
        let n = usize::try_from(n).map_err(|_| INVALID_CBOR)?;
        let end = self.pos.checked_add(n).filter(|&end| end <= self.buf.len()).ok_or(INVALID_CBOR)?;
        let bytes = &self.buf[self.pos..end];
        self.pos = end;
        Ok(bytes)
    }

    /// Major type and argument of the next item.
    fn head(&mut self) -> Result<(u8, u64)> {
        let b = self.byte()?;
        let arg = match b & 0x1F {
            n @ 0..=23 => n as u64,
            24 => self.byte()? as u64,
            25 => big_endian(self.take(2)?),
            26 => big_endian(self.take(4)?),
            27 => big_endian(self.take(8)?),
            // Reserved values and indefinite lengths.
            _ => return Err(INVALID_CBOR),
        };
        Ok((b >> 5, arg))
    }

    fn expect(&mut self, major: u8) -> Result<u64> {
        match self.head()? {
            (m, arg) if m == major => Ok(arg),
            _ => Err(CBOR_UNEXPECTED_TYPE),
        }
    }

    pub fn uint(&mut self) -> Result<u64> {
        self.expect(0)
    }

    /// An integer of either sign.
    pub fn int(&mut self) -> Result<i64> {
        let (major, arg) = self.head()?;
        let v = i64::try_from(arg).map_err(|_| INVALID_CBOR)?;
        match major {
            0 => Ok(v),
            1 => Ok(-1 - v),
            _ => Err(CBOR_UNEXPECTED_TYPE),
        }
    }

    pub fn bytes(&mut self) -> Result<&'a [u8]> {
        let n = self.expect(2)?;
        self.take(n)
    }

    /// A text string, as bytes. Nothing here needs it to be valid UTF-8.
    pub fn text(&mut self) -> Result<&'a [u8]> {
        let n = self.expect(3)?;
        self.take(n)
    }

    /// Number of items in the array that follows.
    pub fn array(&mut self) -> Result<u64> {
        self.expect(4)
    }

    /// Number of key/value pairs in the map that follows.
    pub fn map(&mut self) -> Result<u64> {
        self.expect(5)
    }

    pub fn bool(&mut self) -> Result<bool> {
        match self.byte()? {
            0xF4 => Ok(false),
            0xF5 => Ok(true),
            _ => Err(CBOR_UNEXPECTED_TYPE),
        }
    }

    /// Skip one item of any type, including everything nested in it.
    pub fn skip(&mut self) -> Result<()> {
        self.skip_nested(MAX_DEPTH)
    }

    fn skip_nested(&mut self, depth: u8) -> Result<()> {
        let (major, arg) = self.head()?;
        match major {
            0 | 1 | 7 => Ok(()),
            2 | 3 => self.take(arg).map(|_| ()),
            4 | 5 => {
                let depth = depth.checked_sub(1).ok_or(INVALID_CBOR)?;
                let items = if major == 5 { arg.checked_mul(2).ok_or(INVALID_CBOR)? } else { arg };
                // Each item is at least one byte, so a lying count runs out
                // of input long before it runs out of patience.
                for _ in 0..items {
                    self.skip_nested(depth)?;
                }
                Ok(())
            }
            // Tags are not allowed in CTAP2.
            _ => Err(INVALID_CBOR),
        }
    }

    /// The encoded bytes of the next item, to be parsed later.
    pub fn raw(&mut self) -> Result<&'a [u8]> {
        let start = self.pos;
        self.skip()?;
        Ok(&self.buf[start..self.pos])
    }
}

fn big_endian(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0, |v, &b| v << 8 | b as u64)
}

/// Writes into a fixed buffer. Running out of room is remembered and reported
/// by [`Writer::finish`], so call sites stay free of error handling.
pub struct Writer<'a> {
    buf: &'a mut [u8],
    pos: usize,
    overflow: bool,
}

impl<'a> Writer<'a> {
    pub fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, pos: 0, overflow: false }
    }

    /// Append bytes that are already encoded.
    pub fn raw(&mut self, bytes: &[u8]) {
        let end = self.pos + bytes.len();
        if self.overflow || end > self.buf.len() {
            self.overflow = true;
            return;
        }
        self.buf[self.pos..end].copy_from_slice(bytes);
        self.pos = end;
    }

    fn head(&mut self, major: u8, arg: u64) {
        let m = major << 5;
        match arg {
            0..=23 => self.raw(&[m | arg as u8]),
            24..=0xFF => self.raw(&[m | 24, arg as u8]),
            0x100..=0xFFFF => {
                self.raw(&[m | 25]);
                self.raw(&(arg as u16).to_be_bytes());
            }
            0x1_0000..=0xFFFF_FFFF => {
                self.raw(&[m | 26]);
                self.raw(&(arg as u32).to_be_bytes());
            }
            _ => {
                self.raw(&[m | 27]);
                self.raw(&arg.to_be_bytes());
            }
        }
    }

    pub fn uint(&mut self, v: u64) {
        self.head(0, v);
    }

    pub fn int(&mut self, v: i64) {
        if v >= 0 {
            self.head(0, v as u64);
        } else {
            // CBOR stores a negative n as the unsigned value -1 - n.
            self.head(1, !(v as u64));
        }
    }

    pub fn bytes(&mut self, b: &[u8]) {
        self.head(2, b.len() as u64);
        self.raw(b);
    }

    pub fn text(&mut self, s: &str) {
        self.head(3, s.len() as u64);
        self.raw(s.as_bytes());
    }

    pub fn array(&mut self, items: usize) {
        self.head(4, items as u64);
    }

    pub fn map(&mut self, pairs: usize) {
        self.head(5, pairs as u64);
    }

    pub fn bool(&mut self, b: bool) {
        self.raw(&[if b { 0xF5 } else { 0xF4 }]);
    }

    /// Bytes written, or an error if the buffer was too small.
    pub fn finish(self) -> Result<usize> {
        if self.overflow {
            Err(OTHER)
        } else {
            Ok(self.pos)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integers_roundtrip_at_every_width() {
        let mut buf = [0u8; 16];
        for v in [0u64, 23, 24, 255, 256, 65535, 65536, u32::MAX as u64, u32::MAX as u64 + 1, i64::MAX as u64] {
            let mut w = Writer::new(&mut buf);
            w.uint(v);
            let n = w.finish().unwrap();
            assert_eq!(Reader::new(&buf[..n]).uint(), Ok(v));
        }
        for v in [-1i64, -7, -24, -25, -256, -257, -65537, i64::MIN, 0, 5] {
            let mut w = Writer::new(&mut buf);
            w.int(v);
            let n = w.finish().unwrap();
            assert_eq!(Reader::new(&buf[..n]).int(), Ok(v));
        }
    }

    #[test]
    fn known_encodings() {
        // RFC 8949 appendix A.
        let mut buf = [0u8; 32];
        let mut w = Writer::new(&mut buf);
        w.uint(1000);
        w.int(-1000);
        w.bytes(&[1, 2, 3, 4]);
        w.text("IETF");
        w.array(3);
        w.map(2);
        w.bool(true);
        let n = w.finish().unwrap();
        assert_eq!(
            &buf[..n],
            &[0x19, 0x03, 0xE8, 0x39, 0x03, 0xE7, 0x44, 1, 2, 3, 4, 0x64, b'I', b'E', b'T', b'F', 0x83, 0xA2, 0xF5]
        );
        let mut r = Reader::new(&buf[..n]);
        assert_eq!(r.uint(), Ok(1000));
        assert_eq!(r.int(), Ok(-1000));
        assert_eq!(r.bytes(), Ok(&[1u8, 2, 3, 4][..]));
        assert_eq!(r.text(), Ok(&b"IETF"[..]));
        assert_eq!(r.array(), Ok(3));
        assert_eq!(r.map(), Ok(2));
        assert_eq!(r.bool(), Ok(true));
        assert_eq!(r.uint(), Err(INVALID_CBOR));
    }

    #[test]
    fn wrong_type_and_truncation() {
        assert_eq!(Reader::new(&[0x41, 0x00]).uint(), Err(CBOR_UNEXPECTED_TYPE));
        assert_eq!(Reader::new(&[0x01]).bytes(), Err(CBOR_UNEXPECTED_TYPE));
        assert_eq!(Reader::new(&[0x44, 1, 2]).bytes(), Err(INVALID_CBOR));
        assert_eq!(Reader::new(&[0x19, 0x01]).uint(), Err(INVALID_CBOR));
        assert_eq!(Reader::new(&[0x5B, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]).bytes(), Err(INVALID_CBOR));
        assert_eq!(Reader::new(&[0x5F]).bytes(), Err(INVALID_CBOR), "indefinite length");
        assert_eq!(Reader::new(&[0x1B, 0xFF, 0, 0, 0, 0, 0, 0, 0]).int(), Err(INVALID_CBOR));
        assert_eq!(Reader::new(&[0x00]).bool(), Err(CBOR_UNEXPECTED_TYPE));
    }

    #[test]
    fn skip_and_raw() {
        // {1: [2, {"a": h'00'}], 2: true} 7
        let data = [0xA2, 0x01, 0x82, 0x02, 0xA1, 0x61, b'a', 0x41, 0x00, 0x02, 0xF5, 0x07];
        let mut r = Reader::new(&data);
        assert_eq!(r.raw(), Ok(&data[..11]));
        assert_eq!(r.uint(), Ok(7));

        // Too deep, tagged, or lying about its size.
        assert_eq!(Reader::new(&[0x81; 64]).skip(), Err(INVALID_CBOR));
        assert_eq!(Reader::new(&[0xC0, 0x00]).skip(), Err(INVALID_CBOR));
        assert_eq!(
            Reader::new(&[0x9B, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00]).skip(),
            Err(INVALID_CBOR)
        );
        assert_eq!(
            Reader::new(&[0xBB, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00]).skip(),
            Err(INVALID_CBOR)
        );
    }

    #[test]
    fn writer_reports_overflow() {
        let mut buf = [0u8; 4];
        let mut w = Writer::new(&mut buf);
        w.bytes(&[0; 3]);
        assert_eq!(w.finish(), Ok(4));
        let mut w = Writer::new(&mut buf);
        w.bytes(&[0; 4]);
        w.uint(1); // nothing more is written once it has overflowed
        assert_eq!(w.finish(), Err(OTHER));
    }
}
