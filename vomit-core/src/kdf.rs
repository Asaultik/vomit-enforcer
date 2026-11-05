//! PIN stretching with Argon2id, and HKDF for everything else.

use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

pub use argon2::Block;

/// Longest PIN accepted, in values.
pub const MAX_PIN_LEN: usize = 32;
pub const SALT_LEN: usize = 16;

/// Argon2id cost. Memory is whatever block slice the caller passes in
/// (1 KiB per [`Block`]); this is only the number of passes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KdfParams {
    pub passes: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KdfError {
    BadPin,
    /// Not enough memory blocks (Argon2 needs at least 8) or bad params.
    Params,
}

/// Encode a PIN for hashing. The length prefix keeps `[1]` and `[1, 0]` apart.
fn encode_pin(pin: &[u16], out: &mut [u8; 1 + 2 * MAX_PIN_LEN]) -> Result<usize, KdfError> {
    if pin.is_empty() || pin.len() > MAX_PIN_LEN {
        return Err(KdfError::BadPin);
    }
    out[0] = pin.len() as u8;
    for (i, v) in pin.iter().enumerate() {
        out[1 + 2 * i..3 + 2 * i].copy_from_slice(&v.to_be_bytes());
    }
    Ok(1 + 2 * pin.len())
}

/// Argon2id(pin, salt) -> 32 byte key. `memory` is scratch and is zeroed
/// afterwards.
pub fn stretch_pin(
    pin: &[u16],
    salt: &[u8; SALT_LEN],
    params: KdfParams,
    memory: &mut [Block],
) -> Result<Zeroizing<[u8; 32]>, KdfError> {
    let mut buf = Zeroizing::new([0u8; 1 + 2 * MAX_PIN_LEN]);
    let n = encode_pin(pin, &mut buf)?;
    let p = Params::new(memory.len() as u32, params.passes, 1, Some(32)).map_err(|_| KdfError::Params)?;
    let mut out = Zeroizing::new([0u8; 32]);
    let r = Argon2::new(Algorithm::Argon2id, Version::V0x13, p).hash_password_into_with_memory(
        &buf[..n],
        salt,
        &mut out[..],
        &mut *memory,
    );
    // The blocks hold PIN-derived state.
    for b in memory.iter_mut() {
        b.zeroize();
    }
    r.map_err(|_| KdfError::Params)?;
    Ok(out)
}

/// HKDF-SHA256 with a domain label. Use a different label for every purpose.
pub fn hkdf32(ikm: &[u8], label: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut out = Zeroizing::new([0u8; 32]);
    // 32 bytes is always a valid HKDF-SHA256 output length.
    Hkdf::<Sha256>::new(None, ikm).expand(label, &mut out[..]).unwrap();
    out
}

/// Same, with the label built from parts (avoids a buffer at call sites).
pub fn hkdf32_parts(ikm: &[u8], label: &[&[u8]]) -> Zeroizing<[u8; 32]> {
    let mut out = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(None, ikm).expand_multi_info(label, &mut out[..]).unwrap();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const P: KdfParams = KdfParams { passes: 1 };

    #[test]
    fn deterministic_and_distinct() {
        let mut mem = [Block::default(); 8];
        let a = stretch_pin(&[100, 64, 116], &[1; 16], P, &mut mem).unwrap();
        assert_eq!(*a, *stretch_pin(&[100, 64, 116], &[1; 16], P, &mut mem).unwrap());
        assert_ne!(*a, *stretch_pin(&[100, 64, 117], &[1; 16], P, &mut mem).unwrap());
        assert_ne!(*a, *stretch_pin(&[100, 64, 116], &[2; 16], P, &mut mem).unwrap());
        assert_ne!(
            *stretch_pin(&[1], &[1; 16], P, &mut mem).unwrap(),
            *stretch_pin(&[1, 0], &[1; 16], P, &mut mem).unwrap()
        );
        assert!(mem.iter().all(|b| b.as_ref().iter().all(|&w| w == 0)));
    }

    #[test]
    fn rejects() {
        let mut mem = [Block::default(); 8];
        assert_eq!(stretch_pin(&[], &[0; 16], P, &mut mem).err(), Some(KdfError::BadPin));
        assert_eq!(stretch_pin(&[0; 33], &[0; 16], P, &mut mem).err(), Some(KdfError::BadPin));
        let mut tiny = [Block::default(); 4];
        assert_eq!(stretch_pin(&[1], &[0; 16], P, &mut tiny).err(), Some(KdfError::Params));
    }

    #[test]
    fn hkdf_known_answer() {
        // python3 -c 'import hmac,hashlib;prk=hmac.new(bytes(32),bytes(32),hashlib.sha256).digest();print(hmac.new(prk,b"label\x01",hashlib.sha256).hexdigest())'
        let k = hkdf32(&[0; 32], b"label");
        let hex: String = k.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, HKDF_KA);
        assert_eq!(*hkdf32_parts(&[0; 32], &[b"la", b"bel"]), *k);
    }

    #[test]
    fn argon2id_known_answer() {
        // tools/kat.py, Python `cryptography` Argon2id.
        let mut mem = [Block::default(); 8];
        let k = stretch_pin(&[100, 64, 116], &[1; 16], P, &mut mem).unwrap();
        let hex: String = k.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, "3a51519ab8af15a8436ba94ce8f8fccede5ed1e037e814ee8f143a3dddf14203");
    }

    const HKDF_KA: &str = "63787e3b0f7507950a3e4f321edb63b92978770da0d2b70d2a8ce1ca5b7b2413";
}
