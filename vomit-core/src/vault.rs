//! PIN-locked seed slots in SRAM, with throttling and wipe.
//!
//! Each slot holds one uploaded seed, encrypted under a key stretched from
//! its PIN:
//!
//! ```text
//! k_enc || k_mac = PBKDF2-HMAC-SHA256(pin, salt, iterations, 64 bytes)
//! wrapped        = seed XOR k_enc
//! tag            = HMAC-SHA256(k_mac, "vomit-enforcer/v1/slot" || slot || wrapped)
//! ```
//!
//! So a RAM dump shows no plaintext seeds. An attacker who dumps RAM can
//! still grind PINs offline against the tags; the iteration count only slows
//! that down. Keeping the RAM out of their hands is the hardware's job.
//!
//! An attempt tries every used slot, so it takes the same time whether the PIN
//! matched slot 0, slot 7 or nothing. The failure counter is bumped *before*
//! the PIN is checked and only reset on success. A reset in the middle of a
//! check can't skip the count.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::seed::{Seed, SEED_LEN};

type HmacSha256 = Hmac<Sha256>;

pub const SLOTS: usize = 8;
pub const SALT_LEN: usize = 16;
/// Longest PIN accepted, in values.
pub const MAX_PIN_LEN: usize = 32;

const MAGIC: u32 = u32::from_le_bytes(*b"VOM2");
const TAG_DOMAIN: &[u8] = b"vomit-enforcer/v1/slot";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Policy {
    /// Wrong PINs in a row before everything is wiped.
    pub max_failures: u32,
    /// Lockout after the first wrong PIN. Doubles with each further one.
    pub base_delay_ms: u64,
    /// Cap for the doubling.
    pub max_delay_ms: u64,
    /// PBKDF2 iterations per slot. Every attempt pays this for every used slot.
    pub kdf_iterations: u32,
}

impl Policy {
    pub const DEFAULT: Policy =
        Policy { max_failures: 10, base_delay_ms: 1_000, max_delay_ms: 5 * 60_000, kdf_iterations: 10_000 };

    fn delay_after(&self, failures: u32) -> u64 {
        if failures == 0 {
            return 0;
        }
        let shift = (failures - 1).min(32);
        self.base_delay_ms.saturating_mul(1u64 << shift).min(self.max_delay_ms)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StoreError {
    BadSlot,
    BadPin,
    /// Another slot already opens with this PIN.
    PinInUse,
    /// The vault was wiped (or never initialised).
    Wiped,
}

#[derive(Debug)]
pub enum Attempt {
    Unlocked { slot: usize, seed: Seed },
    Wrong { attempts_left: u32, retry_in_ms: u64 },
    /// Still locked out from the last wrong PIN. Not counted, nothing checked.
    TooSoon { retry_in_ms: u64 },
    /// That was the last allowed failure. Everything is gone.
    Wiped,
}

#[derive(Clone, Copy, Zeroize)]
#[repr(C)]
struct Slot {
    used: u32,
    salt: [u8; SALT_LEN],
    wrapped: [u8; SEED_LEN],
    tag: [u8; 32],
}

impl Slot {
    const EMPTY: Slot = Slot { used: 0, salt: [0; SALT_LEN], wrapped: [0; SEED_LEN], tag: [0; 32] };
}

/// The whole vault. Plain `repr(C)` data, so the firmware can drop it in a
/// `static` in whatever SRAM section it likes.
#[repr(C)]
pub struct Vault {
    magic: u32,
    policy: Policy,
    failures: u32,
    /// Earliest time (caller's clock, ms) the next attempt is accepted.
    locked_until_ms: u64,
    slots: [Slot; SLOTS],
}

struct Keys {
    enc: [u8; 32],
    mac: [u8; 32],
}

impl Drop for Keys {
    fn drop(&mut self) {
        self.enc.zeroize();
        self.mac.zeroize();
    }
}

fn stretch(pin: &[u16], salt: &[u8; SALT_LEN], iterations: u32) -> Keys {
    let mut pin_bytes = [0u8; 2 * MAX_PIN_LEN + 1];
    // Length prefix, so [1] and [1, 0] differ even though padding is zeros.
    pin_bytes[0] = pin.len() as u8;
    for (i, v) in pin.iter().enumerate() {
        pin_bytes[1 + 2 * i..3 + 2 * i].copy_from_slice(&v.to_be_bytes());
    }
    let mut out = [0u8; 64];
    pbkdf2::pbkdf2_hmac::<Sha256>(&pin_bytes[..1 + 2 * pin.len()], salt, iterations, &mut out);
    pin_bytes.zeroize();
    let mut k = Keys { enc: [0; 32], mac: [0; 32] };
    k.enc.copy_from_slice(&out[..32]);
    k.mac.copy_from_slice(&out[32..]);
    out.zeroize();
    k
}

fn tag(mac_key: &[u8; 32], slot: usize, wrapped: &[u8; SEED_LEN]) -> [u8; 32] {
    let mut m = HmacSha256::new_from_slice(mac_key).unwrap();
    m.update(TAG_DOMAIN);
    m.update(&[slot as u8]);
    m.update(wrapped);
    m.finalize().into_bytes().into()
}

fn xor(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    core::array::from_fn(|i| a[i] ^ b[i])
}

impl Vault {
    /// A fresh, empty vault.
    pub const fn new(policy: Policy) -> Self {
        Self { magic: MAGIC, policy, failures: 0, locked_until_ms: 0, slots: [Slot::EMPTY; SLOTS] }
    }

    /// True if this memory holds a vault that wasn't wiped. Use it on boot
    /// on memory that might be uninitialised.
    pub fn is_live(&self) -> bool {
        self.magic == MAGIC
    }

    pub fn policy(&self) -> &Policy {
        &self.policy
    }

    pub fn failures(&self) -> u32 {
        self.failures
    }

    pub fn slot_used(&self, slot: usize) -> bool {
        self.slots.get(slot).is_some_and(|s| s.used != 0)
    }

    /// Lock an uploaded seed into `slot` behind `pin`.
    ///
    /// `salt` must be fresh random bytes for every store (the F411 has no
    /// RNG, so upload it with the seed). Reusing a salt with the same PIN
    /// leaks the XOR of both seeds.
    pub fn store(&mut self, slot: usize, pin: &[u16], seed: &Seed, salt: [u8; SALT_LEN]) -> Result<(), StoreError> {
        if !self.is_live() {
            return Err(StoreError::Wiped);
        }
        if slot >= SLOTS {
            return Err(StoreError::BadSlot);
        }
        if pin.is_empty() || pin.len() > MAX_PIN_LEN {
            return Err(StoreError::BadPin);
        }
        // Two slots behind one PIN would make unlocking ambiguous.
        if self.find(pin).is_some_and(|(i, _)| i != slot) {
            return Err(StoreError::PinInUse);
        }
        let keys = stretch(pin, &salt, self.policy.kdf_iterations);
        let wrapped = xor(seed.bytes(), &keys.enc);
        self.slots[slot] = Slot { used: 1, salt, wrapped, tag: tag(&keys.mac, slot, &wrapped) };
        Ok(())
    }

    pub fn clear_slot(&mut self, slot: usize) {
        if let Some(s) = self.slots.get_mut(slot) {
            s.zeroize();
        }
    }

    /// Forget everything. The vault is dead until [`Vault::reset`].
    pub fn wipe(&mut self) {
        // Volatile writes from zeroize, so this can't be optimised out.
        for s in self.slots.iter_mut() {
            s.zeroize();
        }
        self.magic.zeroize();
        self.failures.zeroize();
        self.locked_until_ms.zeroize();
    }

    /// Bring a wiped (or uninitialised) vault back as empty, keeping nothing.
    pub fn reset(&mut self, policy: Policy) {
        self.wipe();
        *self = Vault::new(policy);
    }

    /// Check every used slot against `pin`. Returns the first match.
    fn find(&self, pin: &[u16]) -> Option<(usize, Seed)> {
        let mut found: Option<(usize, Seed)> = None;
        for (i, s) in self.slots.iter().enumerate() {
            if s.used == 0 {
                continue;
            }
            let keys = stretch(pin, &s.salt, self.policy.kdf_iterations);
            let ok: bool = tag(&keys.mac, i, &s.wrapped).ct_eq(&s.tag).into();
            if ok && found.is_none() {
                found = Some((i, Seed::from_bytes(xor(&s.wrapped, &keys.enc))));
            }
        }
        found
    }

    /// Try a PIN. `now_ms` is a monotonic clock from the firmware.
    ///
    /// The time-based lockout is only as good as that clock. Losing power wipes
    /// SRAM anyway, so resetting the clock by power cycling doesn't help an
    /// attacker.
    pub fn attempt(&mut self, pin: &[u16], now_ms: u64) -> Attempt {
        if !self.is_live() {
            return Attempt::Wiped;
        }
        if now_ms < self.locked_until_ms {
            return Attempt::TooSoon { retry_in_ms: self.locked_until_ms - now_ms };
        }

        // Count first, so a reset in the middle of checking still counts.
        self.failures = self.failures.saturating_add(1);
        if self.failures > self.policy.max_failures {
            self.wipe();
            return Attempt::Wiped;
        }

        let hit = if pin.is_empty() || pin.len() > MAX_PIN_LEN { None } else { self.find(pin) };
        match hit {
            Some((slot, seed)) => {
                self.failures = 0;
                self.locked_until_ms = 0;
                Attempt::Unlocked { slot, seed }
            }
            None if self.failures >= self.policy.max_failures => {
                self.wipe();
                Attempt::Wiped
            }
            None => {
                let delay = self.policy.delay_after(self.failures);
                self.locked_until_ms = now_ms.saturating_add(delay);
                Attempt::Wrong { attempts_left: self.policy.max_failures - self.failures, retry_in_ms: delay }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Cheap KDF so the tests run fast.
    const P: Policy = Policy { max_failures: 3, base_delay_ms: 1000, max_delay_ms: 3000, kdf_iterations: 2 };

    fn seed(b: u8) -> Seed {
        Seed::from_bytes([b; 32])
    }

    fn vault() -> Vault {
        let mut v = Vault::new(P);
        v.store(0, &[100, 64, 116], &seed(1), [1; 16]).unwrap();
        v.store(3, &[5, 5], &seed(2), [2; 16]).unwrap();
        v
    }

    #[test]
    fn unlocks_the_right_slot() {
        let mut v = vault();
        match v.attempt(&[5, 5], 0) {
            Attempt::Unlocked { slot, seed } => {
                assert_eq!(slot, 3);
                assert_eq!(seed.bytes(), &[2; 32]);
            }
            a => panic!("{a:?}"),
        }
        match v.attempt(&[100, 64, 116], 0) {
            Attempt::Unlocked { slot, seed } => {
                assert_eq!(slot, 0);
                assert_eq!(seed.bytes(), &[1; 32]);
            }
            a => panic!("{a:?}"),
        }
    }

    #[test]
    fn no_plaintext_in_ram() {
        let v = vault();
        assert_ne!(v.slots[0].wrapped, [1; 32]);
        assert_ne!(v.slots[3].wrapped, [2; 32]);
    }

    #[test]
    fn throttles_then_wipes() {
        let mut v = vault();
        assert!(matches!(v.attempt(&[1], 0), Attempt::Wrong { attempts_left: 2, retry_in_ms: 1000 }));
        // Locked out: not checked, not counted, even with the right PIN.
        assert!(matches!(v.attempt(&[5, 5], 500), Attempt::TooSoon { retry_in_ms: 500 }));
        assert_eq!(v.failures(), 1);
        assert!(matches!(v.attempt(&[2], 1000), Attempt::Wrong { attempts_left: 1, retry_in_ms: 2000 }));
        assert!(matches!(v.attempt(&[3], 3000), Attempt::Wiped));
        assert!(!v.is_live());
        assert!(!v.slot_used(0) && !v.slot_used(3));
        assert!(matches!(v.attempt(&[5, 5], 10_000), Attempt::Wiped));
        assert_eq!(v.store(0, &[1], &seed(9), [0; 16]), Err(StoreError::Wiped));
    }

    #[test]
    fn success_resets_counter() {
        let mut v = vault();
        v.attempt(&[1], 0);
        v.attempt(&[2], 1000);
        assert!(matches!(v.attempt(&[5, 5], 3000), Attempt::Unlocked { .. }));
        assert_eq!(v.failures(), 0);
        assert!(matches!(v.attempt(&[1], 3000), Attempt::Wrong { attempts_left: 2, .. }));
    }

    #[test]
    fn delay_doubles_and_caps() {
        let p = Policy { max_failures: 100, base_delay_ms: 1000, max_delay_ms: 5000, kdf_iterations: 1 };
        assert_eq!(p.delay_after(1), 1000);
        assert_eq!(p.delay_after(2), 2000);
        assert_eq!(p.delay_after(3), 4000);
        assert_eq!(p.delay_after(4), 5000);
        assert_eq!(p.delay_after(99), 5000);
    }

    #[test]
    fn store_rules() {
        let mut v = vault();
        assert_eq!(v.store(SLOTS, &[1], &seed(9), [0; 16]), Err(StoreError::BadSlot));
        assert_eq!(v.store(1, &[], &seed(9), [0; 16]), Err(StoreError::BadPin));
        assert_eq!(v.store(1, &[5, 5], &seed(9), [9; 16]), Err(StoreError::PinInUse));
        // Re-keying the same slot with its own PIN is fine.
        assert_eq!(v.store(3, &[5, 5], &seed(7), [9; 16]), Ok(()));
        // Length prefix: [5, 5, 0] is not [5, 5].
        assert_eq!(v.store(1, &[5, 5, 0], &seed(9), [9; 16]), Ok(()));
        v.clear_slot(3);
        assert!(matches!(v.attempt(&[5, 5], 0), Attempt::Wrong { .. }));
    }

    #[test]
    fn reset_after_wipe() {
        let mut v = vault();
        v.wipe();
        v.reset(P);
        assert!(v.is_live());
        assert!(!v.slot_used(0));
    }
}
