//! Credentials without storage.
//!
//! The device keeps nothing per credential. A credential ID is a random nonce
//! plus a tag, and everything else is derived from the unlocked slot seed:
//!
//! ```text
//! id          = nonce (32) || tag (16)
//! tag         = HMAC-SHA256(HKDF(seed, "…/fido2/mac"), rp_id_hash || nonce)[..16]
//! private key = HKDF(seed, "…/fido2/es256"       || rp_id_hash || nonce)
//! cred_random = HKDF(seed, "…/fido2/hmac-secret" || rp_id_hash || nonce)
//! ```
//!
//! The host stores the ID and hands it back. Only the same seed and the same
//! relying party reproduce the tag, so an ID from another device, another PIN
//! slot or another site is simply "not ours". Wipe the seed and every
//! credential made from it is gone.

use subtle::ConstantTimeEq;
use vomit_core::kdf::{hkdf32, hkdf32_parts};
use vomit_core::seed::Seed;
use zeroize::Zeroizing;

use crate::crypto;

pub const ID_LEN: usize = NONCE_LEN + TAG_LEN;
const NONCE_LEN: usize = 32;
const TAG_LEN: usize = 16;

const MAC_LABEL: &[u8] = b"vomit-enforcer/v1/fido2/mac";
const KEY_LABEL: &[u8] = b"vomit-enforcer/v1/fido2/es256";
const HMAC_SECRET_LABEL: &[u8] = b"vomit-enforcer/v1/fido2/hmac-secret";

pub struct Credential {
    pub id: [u8; ID_LEN],
    secret: Zeroizing<[u8; 32]>,
    /// The key behind the hmac-secret extension.
    pub cred_random: Zeroizing<[u8; 32]>,
}

fn tag(seed: &Seed, rp_id_hash: &[u8; 32], nonce: &[u8]) -> [u8; 32] {
    let key = hkdf32(seed.bytes(), MAC_LABEL);
    crypto::hmac_sha256(&key[..], &[rp_id_hash, nonce])
}

fn derive(seed: &Seed, rp_id_hash: &[u8; 32], id: [u8; ID_LEN]) -> Option<Credential> {
    let nonce = &id[..NONCE_LEN];
    let secret = hkdf32_parts(seed.bytes(), &[KEY_LABEL, rp_id_hash, nonce]);
    // About one derived value in 2^32 is not a valid P-256 key.
    if !crypto::valid_scalar(&secret) {
        return None;
    }
    let cred_random = hkdf32_parts(seed.bytes(), &[HMAC_SECRET_LABEL, rp_id_hash, nonce]);
    Some(Credential { id, secret, cred_random })
}

/// Make a new credential for a relying party.
pub fn create(seed: &Seed, rp_id_hash: &[u8; 32], random: &mut dyn FnMut(&mut [u8])) -> Credential {
    loop {
        let mut id = [0u8; ID_LEN];
        random(&mut id[..NONCE_LEN]);
        let t = tag(seed, rp_id_hash, &id[..NONCE_LEN]);
        id[NONCE_LEN..].copy_from_slice(&t[..TAG_LEN]);
        if let Some(c) = derive(seed, rp_id_hash, id) {
            return c;
        }
    }
}

/// Recognise one of our credential IDs. `None` for anything else.
pub fn open(seed: &Seed, rp_id_hash: &[u8; 32], id: &[u8]) -> Option<Credential> {
    let id: [u8; ID_LEN] = id.try_into().ok()?;
    let expected = tag(seed, rp_id_hash, &id[..NONCE_LEN]);
    if !bool::from(expected[..TAG_LEN].ct_eq(&id[NONCE_LEN..])) {
        return None;
    }
    derive(seed, rp_id_hash, id)
}

impl Credential {
    /// The public key's coordinates.
    pub fn public(&self) -> ([u8; 32], [u8; 32]) {
        // The secret was checked when the credential was derived.
        crypto::public_xy(&self.secret).unwrap_or(([0; 32], [0; 32]))
    }

    /// ES256 signature over the concatenation of `parts`, DER encoded.
    pub fn sign(&self, parts: &[&[u8]], out: &mut [u8; crypto::MAX_SIG]) -> usize {
        crypto::sign_der(&self.secret, parts, out).unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rng(start: u8) -> impl FnMut(&mut [u8]) {
        let mut n = start;
        move |out: &mut [u8]| {
            for b in out {
                *b = n;
                n = n.wrapping_add(1);
            }
        }
    }

    #[test]
    fn roundtrip() {
        let seed = Seed::from_bytes([1; 32]);
        let rp = [2u8; 32];
        let c = create(&seed, &rp, &mut rng(0));
        let again = open(&seed, &rp, &c.id).expect("our own credential");
        assert_eq!(c.public(), again.public());
        assert_eq!(*c.cred_random, *again.cred_random);
        assert_ne!(*c.cred_random, [0; 32]);
    }

    #[test]
    fn bound_to_seed_and_relying_party() {
        let seed = Seed::from_bytes([1; 32]);
        let rp = [2u8; 32];
        let c = create(&seed, &rp, &mut rng(0));
        assert!(open(&Seed::from_bytes([9; 32]), &rp, &c.id).is_none(), "other seed");
        assert!(open(&seed, &[3; 32], &c.id).is_none(), "other relying party");
        for i in 0..ID_LEN {
            let mut id = c.id;
            id[i] ^= 1;
            assert!(open(&seed, &rp, &id).is_none(), "byte {i} altered");
        }
        assert!(open(&seed, &rp, &c.id[..ID_LEN - 1]).is_none());
        assert!(open(&seed, &rp, &[]).is_none());
    }

    #[test]
    fn credentials_are_independent() {
        let seed = Seed::from_bytes([1; 32]);
        let rp = [2u8; 32];
        let a = create(&seed, &rp, &mut rng(0));
        let b = create(&seed, &rp, &mut rng(50));
        assert_ne!(a.id, b.id);
        assert_ne!(a.public(), b.public());
        assert_ne!(*a.cred_random, *b.cred_random);
        // Different purposes never share key material.
        assert_ne!(*a.secret, *a.cred_random);
    }
}
