//! Framing on the UART between the bridge and the core.
//!
//! ```text
//! [0xA5] [kind] [id] [len lo] [len hi] [payload: len bytes] [crc lo] [crc hi]
//! ```
//!
//! The CRC is CRC-16/CCITT-FALSE over kind, id, length and payload. It guards
//! against line noise only; it is not a security measure. The core treats the
//! bridge as hostile regardless.
//!
//! `id` ties a response to its request: the bridge picks it, the core echoes
//! it, and the bridge drops anything carrying a stale one.

pub const SOF: u8 = 0xA5;
/// Largest payload, which is also the largest CTAP2 message we accept.
pub const MAX_PAYLOAD: usize = 1200;
pub const OVERHEAD: usize = 7;
pub const MAX_FRAME: usize = MAX_PAYLOAD + OVERHEAD;
/// Both firmwares use this. One full frame takes about 105 ms at this rate.
pub const BAUD: u32 = 115_200;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Kind {
    /// Bridge to core: one CTAP2 request (command byte + CBOR).
    Request = 1,
    /// Core to bridge: the reply (status byte + CBOR).
    Response = 2,
    /// Core to bridge: one byte, [`STATUS_PROCESSING`] or [`STATUS_UP_NEEDED`].
    /// The first one also acknowledges the request.
    Status = 3,
    /// Bridge to core: the host gave up on request `id`.
    Cancel = 4,
}

impl Kind {
    fn from_u8(b: u8) -> Option<Kind> {
        Some(match b {
            1 => Kind::Request,
            2 => Kind::Response,
            3 => Kind::Status,
            4 => Kind::Cancel,
            _ => return None,
        })
    }
}

// Same values as the CTAPHID keepalive status codes.
pub const STATUS_PROCESSING: u8 = 1;
pub const STATUS_UP_NEEDED: u8 = 2;

fn crc_step(mut crc: u16, byte: u8) -> u16 {
    crc ^= (byte as u16) << 8;
    for _ in 0..8 {
        crc = if crc & 0x8000 != 0 { (crc << 1) ^ 0x1021 } else { crc << 1 };
    }
    crc
}

fn crc16(data: &[u8]) -> u16 {
    data.iter().fold(0xFFFF, |crc, &b| crc_step(crc, b))
}

/// Encode one frame into `out`. `None` if the payload is too long or `out`
/// too small.
pub fn encode<'a>(kind: Kind, id: u8, payload: &[u8], out: &'a mut [u8]) -> Option<&'a [u8]> {
    let n = payload.len();
    if n > MAX_PAYLOAD || out.len() < n + OVERHEAD {
        return None;
    }
    out[0] = SOF;
    out[1] = kind as u8;
    out[2] = id;
    out[3] = n as u8;
    out[4] = (n >> 8) as u8;
    out[5..5 + n].copy_from_slice(payload);
    let crc = crc16(&out[1..5 + n]);
    out[5 + n] = crc as u8;
    out[6 + n] = (crc >> 8) as u8;
    Some(&out[..n + OVERHEAD])
}

#[derive(Debug, PartialEq, Eq)]
pub struct Frame<'a> {
    pub kind: Kind,
    pub id: u8,
    pub payload: &'a [u8],
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum State {
    Sof,
    Kind,
    Id,
    LenLo,
    LenHi,
    Payload,
    CrcLo,
    CrcHi,
}

/// Byte-at-a-time decoder. Anything that isn't a well-formed frame is dropped
/// silently and the decoder goes back to hunting for a start byte.
pub struct Decoder {
    state: State,
    kind: Kind,
    id: u8,
    len: usize,
    got: usize,
    crc: u16,
    crc_lo: u8,
    buf: [u8; MAX_PAYLOAD],
}

impl Decoder {
    pub const fn new() -> Self {
        Self { state: State::Sof, kind: Kind::Cancel, id: 0, len: 0, got: 0, crc: 0, crc_lo: 0, buf: [0; MAX_PAYLOAD] }
    }

    /// Drop a partial frame. Call after a gap on the line.
    pub fn reset(&mut self) {
        self.state = State::Sof;
    }

    /// True while in the middle of a frame.
    pub fn in_frame(&self) -> bool {
        self.state != State::Sof
    }

    pub fn push(&mut self, b: u8) -> Option<Frame<'_>> {
        match self.state {
            State::Sof => {
                if b == SOF {
                    self.state = State::Kind;
                }
            }
            State::Kind => match Kind::from_u8(b) {
                Some(k) => {
                    self.kind = k;
                    self.crc = crc_step(0xFFFF, b);
                    self.state = State::Id;
                }
                // A second start byte: the first was noise, this may be real.
                None if b == SOF => {}
                None => self.state = State::Sof,
            },
            State::Id => {
                self.id = b;
                self.crc = crc_step(self.crc, b);
                self.state = State::LenLo;
            }
            State::LenLo => {
                self.len = b as usize;
                self.crc = crc_step(self.crc, b);
                self.state = State::LenHi;
            }
            State::LenHi => {
                self.len |= (b as usize) << 8;
                self.crc = crc_step(self.crc, b);
                self.got = 0;
                self.state = if self.len > MAX_PAYLOAD {
                    State::Sof
                } else if self.len == 0 {
                    State::CrcLo
                } else {
                    State::Payload
                };
            }
            State::Payload => {
                self.buf[self.got] = b;
                self.got += 1;
                self.crc = crc_step(self.crc, b);
                if self.got == self.len {
                    self.state = State::CrcLo;
                }
            }
            State::CrcLo => {
                self.crc_lo = b;
                self.state = State::CrcHi;
            }
            State::CrcHi => {
                self.state = State::Sof;
                if u16::from_le_bytes([self.crc_lo, b]) == self.crc {
                    return Some(Frame { kind: self.kind, id: self.id, payload: &self.buf[..self.len] });
                }
            }
        }
        None
    }
}

impl Default for Decoder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode_all(dec: &mut Decoder, bytes: &[u8]) -> Vec<(Kind, u8, Vec<u8>)> {
        let mut out = vec![];
        for &b in bytes {
            if let Some(f) = dec.push(b) {
                out.push((f.kind, f.id, f.payload.to_vec()));
            }
        }
        out
    }

    #[test]
    fn crc_known_answer() {
        // CRC-16/CCITT-FALSE check value.
        assert_eq!(crc16(b"123456789"), 0x29B1);
    }

    #[test]
    fn roundtrip() {
        let mut buf = [0u8; MAX_FRAME];
        let mut dec = Decoder::new();
        for payload in [&b""[..], b"\x04", &[0xA5; 300], &[7u8; MAX_PAYLOAD]] {
            let f = encode(Kind::Request, 9, payload, &mut buf).unwrap().to_vec();
            assert_eq!(decode_all(&mut dec, &f), vec![(Kind::Request, 9, payload.to_vec())]);
        }
        assert!(encode(Kind::Request, 0, &[0; MAX_PAYLOAD + 1], &mut buf).is_none());
        assert!(encode(Kind::Request, 0, &[0; 4], &mut [0u8; 8]).is_none());
    }

    #[test]
    fn noise_then_frame() {
        let mut buf = [0u8; 32];
        let f = encode(Kind::Cancel, 3, &[], &mut buf).unwrap().to_vec();
        let mut stream = vec![0x00, 0xFF, SOF, SOF];
        stream.extend_from_slice(&f[1..]); // the second SOF above starts the real frame
        assert_eq!(decode_all(&mut Decoder::new(), &stream), vec![(Kind::Cancel, 3, vec![])]);
    }

    #[test]
    fn corruption_is_dropped_and_decoder_recovers() {
        let mut buf = [0u8; 64];
        let good = encode(Kind::Response, 1, b"hello", &mut buf).unwrap().to_vec();
        for i in 1..good.len() {
            let mut bad = good.clone();
            bad[i] ^= 0x40;
            let mut dec = Decoder::new();
            assert!(decode_all(&mut dec, &bad).is_empty(), "flipped byte {i} got through");
            // After a gap the owner resets; the next good frame must decode.
            dec.reset();
            assert_eq!(decode_all(&mut dec, &good).len(), 1);
        }
    }

    #[test]
    fn oversized_length_is_rejected() {
        let mut dec = Decoder::new();
        let n = MAX_PAYLOAD + 1;
        assert!(decode_all(&mut dec, &[SOF, 1, 0, n as u8, (n >> 8) as u8]).is_empty());
        assert!(!dec.in_frame());
    }

    #[test]
    fn random_bytes_never_panic() {
        let mut dec = Decoder::new();
        let mut x = 0x2545F491u32;
        for _ in 0..200_000 {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            // Bias towards start bytes and small values so frames get entered.
            let b = if x & 3 == 0 { SOF } else { (x >> 8) as u8 & 0x0F };
            dec.push(b);
        }
    }
}
