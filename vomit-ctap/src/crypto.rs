//! The cryptography CTAP2 asks for, on top of RustCrypto:
//!
//! * PIN protocol 1: P-256 ECDH, then `SHA-256(x)` as the shared secret,
//!   AES-256-CBC with a zero IV, and HMAC-SHA-256 cut to 16 bytes.
//! * ES256 signatures (ECDSA on P-256, deterministic nonces per RFC 6979),
//!   DER-encoded as WebAuthn wants them.

use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use aes::Aes256;
use hmac::{Hmac, Mac};
use p256::ecdsa::signature::hazmat::PrehashSigner;
use p256::ecdsa::{Signature, SigningKey};
use p256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use p256::{EncodedPoint, NonZeroScalar, PublicKey};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

/// Longest DER encoding of a P-256 signature.
pub const MAX_SIG: usize = 72;

pub fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

pub fn hmac_sha256(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    // HMAC accepts keys of any length.
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(key).unwrap();
    for p in parts {
        m.update(p);
    }
    m.finalize().into_bytes().into()
}

/// PIN protocol 1 `authenticate`/`verify`: the first 16 bytes of the HMAC,
/// compared in constant time.
pub fn verify16(key: &[u8], parts: &[&[u8]], tag: &[u8]) -> bool {
    tag.len() == 16 && bool::from(hmac_sha256(key, parts)[..16].ct_eq(tag))
}

/// AES-256-CBC, zero IV, no padding, in place. Whole blocks only: a trailing
/// partial block is left untouched, and callers check lengths first.
pub fn cbc_encrypt(key: &[u8; 32], data: &mut [u8]) {
    let cipher = Aes256::new(GenericArray::from_slice(key));
    let mut prev = [0u8; 16];
    for block in data.chunks_exact_mut(16) {
        for (b, p) in block.iter_mut().zip(prev) {
            *b ^= p;
        }
        cipher.encrypt_block(GenericArray::from_mut_slice(block));
        prev.copy_from_slice(block);
    }
}

pub fn cbc_decrypt(key: &[u8; 32], data: &mut [u8]) {
    let cipher = Aes256::new(GenericArray::from_slice(key));
    let mut prev = [0u8; 16];
    for block in data.chunks_exact_mut(16) {
        let mut ciphertext = [0u8; 16];
        ciphertext.copy_from_slice(block);
        cipher.decrypt_block(GenericArray::from_mut_slice(block));
        for (b, p) in block.iter_mut().zip(prev) {
            *b ^= p;
        }
        prev = ciphertext;
    }
}

/// True if these 32 bytes are usable as a P-256 private key.
pub fn valid_scalar(bytes: &[u8; 32]) -> bool {
    NonZeroScalar::try_from(&bytes[..]).is_ok()
}

/// Affine coordinates of the public key for a private key.
pub fn public_xy(secret: &[u8; 32]) -> Option<([u8; 32], [u8; 32])> {
    let scalar = NonZeroScalar::try_from(&secret[..]).ok()?;
    let point = PublicKey::from_secret_scalar(&scalar).to_encoded_point(false);
    Some(((*point.x()?).into(), (*point.y()?).into()))
}

/// Sign the concatenation of `parts` with ES256. Returns the DER length.
pub fn sign_der(secret: &[u8; 32], parts: &[&[u8]], out: &mut [u8; MAX_SIG]) -> Option<usize> {
    Some(der_signature(&sign(secret, parts)?, out))
}

/// The signature as fixed-width `r || s`.
fn sign(secret: &[u8; 32], parts: &[&[u8]]) -> Option<[u8; 64]> {
    let key = SigningKey::from_slice(secret).ok()?;
    let signature: Signature = key.sign_prehash(&sha256(parts)).ok()?;
    let mut rs = [0u8; 64];
    rs.copy_from_slice(&signature.to_bytes());
    Some(rs)
}

/// `SEQUENCE { INTEGER r, INTEGER s }` from the fixed-width `r || s`.
fn der_signature(rs: &[u8; 64], out: &mut [u8; MAX_SIG]) -> usize {
    let mut n = 2;
    for half in rs.chunks_exact(32) {
        // DER integers are minimal and signed: drop leading zeros, then put
        // one back if the top bit would make the number look negative.
        let skip = half.iter().take(31).take_while(|&&b| b == 0).count();
        let digits = &half[skip..];
        let pad = (digits[0] & 0x80 != 0) as usize;
        out[n] = 0x02;
        out[n + 1] = (digits.len() + pad) as u8;
        out[n + 2] = 0x00;
        out[n + 2 + pad..n + 2 + pad + digits.len()].copy_from_slice(digits);
        n += 2 + pad + digits.len();
    }
    out[0] = 0x30;
    out[1] = (n - 2) as u8;
    n
}

/// Our side of the PIN protocol's key agreement.
pub struct KeyAgreement {
    secret: NonZeroScalar,
    pub x: [u8; 32],
    pub y: [u8; 32],
}

impl KeyAgreement {
    /// A fresh key pair from `random`.
    pub fn generate(random: &mut dyn FnMut(&mut [u8])) -> Self {
        loop {
            let mut bytes = Zeroizing::new([0u8; 32]);
            random(&mut bytes[..]);
            // Fails for zero and for values above the group order: about one
            // in 2^32 for honest randomness.
            let Ok(secret) = NonZeroScalar::try_from(&bytes[..]) else { continue };
            let point = PublicKey::from_secret_scalar(&secret).to_encoded_point(false);
            if let (Some(x), Some(y)) = (point.x(), point.y()) {
                return Self { secret, x: (*x).into(), y: (*y).into() };
            }
        }
    }

    /// The PIN protocol 1 shared secret with the platform's public key.
    /// `None` if that key is not a point on the curve.
    pub fn shared_secret(&self, x: &[u8; 32], y: &[u8; 32]) -> Option<Zeroizing<[u8; 32]>> {
        let point = EncodedPoint::from_affine_coordinates(x.into(), y.into(), false);
        let peer = Option::<PublicKey>::from(PublicKey::from_encoded_point(&point))?;
        let shared = p256::ecdh::diffie_hellman(&self.secret, peer.as_affine());
        Some(Zeroizing::new(sha256(&[shared.raw_secret_bytes().as_slice()])))
    }
}

impl Drop for KeyAgreement {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::signature::Verifier;
    use p256::ecdsa::VerifyingKey;

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    fn counter_rng(start: u8) -> impl FnMut(&mut [u8]) {
        let mut n = start;
        move |out: &mut [u8]| {
            for b in out {
                *b = n;
                n = n.wrapping_add(1);
            }
        }
    }

    #[test]
    fn aes256_cbc_known_answer() {
        // NIST SP 800-38A F.2.5, with the IV folded into the first block
        // (our IV is zero, so plaintext ^ IV is fed in directly).
        let key: [u8; 32] =
            unhex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4").try_into().unwrap();
        let iv = unhex("000102030405060708090a0b0c0d0e0f");
        let mut data = unhex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51");
        for (d, i) in data.iter_mut().zip(&iv) {
            *d ^= i;
        }
        let plain = data.clone();
        cbc_encrypt(&key, &mut data);
        assert_eq!(data, unhex("f58c4c04d6e5f1ba779eabfb5f7bfbd69cfc4e967edb808d679f777bc6702c7d"));
        cbc_decrypt(&key, &mut data);
        assert_eq!(data, plain);
    }

    #[test]
    fn hmac_known_answer() {
        // RFC 4231 test case 2.
        let tag = hmac_sha256(b"Jefe", &[b"what do ya want ", b"for nothing?"]);
        assert_eq!(tag.to_vec(), unhex("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"));
        assert!(verify16(b"Jefe", &[b"what do ya want for nothing?"], &tag[..16]));
        assert!(!verify16(b"Jefe", &[b"what do ya want for nothing?"], &tag[..15]));
        assert!(!verify16(b"Jefe", &[b"what do ya want for nothing!"], &tag[..16]));
    }

    #[test]
    fn der_encoding_edge_cases() {
        let mut out = [0u8; MAX_SIG];
        // Top bits set: both need a zero byte in front. The longest case.
        let n = der_signature(&[0xFF; 64], &mut out);
        assert_eq!(n, 72);
        assert_eq!(&out[..5], &[0x30, 70, 0x02, 33, 0x00]);
        assert_eq!(&out[37..40], &[0x02, 33, 0x00]);
        // Leading zeros are dropped; a zero value keeps one digit.
        let mut rs = [0u8; 64];
        rs[31] = 0x7F;
        let n = der_signature(&rs, &mut out);
        assert_eq!(&out[..n], &[0x30, 6, 0x02, 1, 0x7F, 0x02, 1, 0x00]);
        // A dropped zero exposes a high bit: put one back.
        rs[30] = 0x80;
        let n = der_signature(&rs, &mut out);
        assert_eq!(&out[..n], &[0x30, 8, 0x02, 3, 0x00, 0x80, 0x7F, 0x02, 1, 0x00]);
    }

    #[test]
    fn signatures_verify_and_are_deterministic() {
        let secret = [7u8; 32];
        let (x, y) = public_xy(&secret).unwrap();
        let key = VerifyingKey::from_encoded_point(&EncodedPoint::from_affine_coordinates(&x.into(), &y.into(), false))
            .unwrap();
        // Splitting the message differently must not change the signature,
        // and neither must signing twice (RFC 6979).
        let rs = sign(&secret, &[b"auth data", b"client hash"]).unwrap();
        assert_eq!(rs, sign(&secret, &[b"auth dataclient hash"]).unwrap());
        let sig = Signature::from_slice(&rs).unwrap();
        key.verify(b"auth dataclient hash", &sig).unwrap();
        assert!(key.verify(b"something else", &sig).is_err());

        // sign_der wraps exactly that signature.
        let mut a = [0u8; MAX_SIG];
        let mut expected = [0u8; MAX_SIG];
        let n = sign_der(&secret, &[b"auth data", b"client hash"], &mut a).unwrap();
        let m = der_signature(&rs, &mut expected);
        assert_eq!(&a[..n], &expected[..m]);

        assert!(!valid_scalar(&[0; 32]));
        assert!(!valid_scalar(&[0xFF; 32]));
        assert!(public_xy(&[0; 32]).is_none());
        assert!(sign_der(&[0; 32], &[b""], &mut a).is_none());
    }

    #[test]
    fn key_agreement_matches_on_both_sides() {
        let a = KeyAgreement::generate(&mut counter_rng(1));
        let b = KeyAgreement::generate(&mut counter_rng(101));
        let ab = a.shared_secret(&b.x, &b.y).unwrap();
        let ba = b.shared_secret(&a.x, &a.y).unwrap();
        assert_eq!(*ab, *ba);
        assert_ne!(*ab, [0; 32]);
    }

    #[test]
    fn points_off_the_curve_are_refused() {
        let a = KeyAgreement::generate(&mut counter_rng(1));
        let mut y = a.y;
        y[31] ^= 1;
        assert!(a.shared_secret(&a.x, &y).is_none());
        assert!(a.shared_secret(&[0; 32], &[0; 32]).is_none());
    }
}
