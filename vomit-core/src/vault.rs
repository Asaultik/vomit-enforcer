//! PIN-locked seed slots in SRAM, under a rotating master key that lives in
//! the backup registers.
//!
//! Two layers:
//!
//! ```text
//! inner, per slot   k_pin  = Argon2id(pin, salt)
//!                   sealed = ChaCha20-Poly1305(k_pin, nonce = slot || seal_counter,
//!                                              aad = "vomit-enforcer/v1/slot" || slot,
//!                                              seed || format)
//!
//! outer, whole vault  k_e  = master key for epoch e (backup registers)
//!                     buf  = ChaCha20-Poly1305(k_e, nonce = 0, aad = "vomit-enforcer/v1/vault" || e,
//!                                              seal_counter || 8 x slot record)
//! ```
//!
//! * Without the backup registers, SRAM is noise: not even the PIN tags can
//!   be ground offline. The RTC tamper pin wipes the registers in hardware,
//!   so a glitched CPU can't save the vault.
//! * Every change to the vault is written under a *new* master key into the
//!   other of two buffers, then committed by bumping the epoch (one register
//!   write). A reset at any point leaves one consistent vault. Since every
//!   epoch has its own key, the outer nonce can stay zero.
//! * [`Vault::rotate`] does the same with nothing changed, so every SRAM bit
//!   flips over time and nothing sits still long enough to burn in.
//! * The failure counter lives in the backup registers and is bumped before
//!   the PIN is checked. A reset can't skip or roll it back.
//! * Anything that doesn't add up (bad outer tag, corrupt counter) wipes.

use chacha20poly1305::aead::AeadInPlace;
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce, Tag};
use zeroize::{Zeroize, Zeroizing};

use crate::backup::{self, BackupStore};
use crate::kdf::{self, hkdf32_parts, Block, KdfParams, SALT_LEN};
use crate::render::{Charset, Format};
use crate::seed::{Seed, SEED_LEN};

pub use crate::kdf::MAX_PIN_LEN;

pub const SLOTS: usize = 8;
/// Least Argon2 memory accepted, in 1 KiB blocks. Use far more on the device.
pub const MIN_BLOCKS: usize = 8;
/// Least entropy [`Vault::init`] accepts, in bytes.
pub const MIN_ENTROPY: usize = 32;

const TAG_LEN: usize = 16;
const PAYLOAD_LEN: usize = SEED_LEN + 2; // seed, charset, length
const SLOT_LEN: usize = 1 + SALT_LEN + 4 + PAYLOAD_LEN + TAG_LEN;
const HDR_LEN: usize = 4;
const INNER_LEN: usize = HDR_LEN + SLOTS * SLOT_LEN;

// Offsets inside one slot record.
const S_USED: usize = 0;
const S_SALT: usize = 1;
const S_CTR: usize = S_SALT + SALT_LEN;
const S_CT: usize = S_CTR + 4;
const S_TAG: usize = S_CT + PAYLOAD_LEN;

const SLOT_AAD: &[u8] = b"vomit-enforcer/v1/slot";
const VAULT_AAD: &[u8] = b"vomit-enforcer/v1/vault";
const MASTER_INIT: &[u8] = b"vomit-enforcer/v1/master-init";
const MASTER_NEXT: &[u8] = b"vomit-enforcer/v1/master-next";

/// Fixed by the firmware, never stored in RAM where a glitch could change it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Config {
    /// Wrong PINs in a row before everything is wiped.
    pub max_failures: u32,
    /// Lockout after the first wrong PIN. Doubles with each further one.
    pub base_delay_ms: u64,
    pub max_delay_ms: u64,
    pub kdf: KdfParams,
}

impl Config {
    pub const DEFAULT: Config =
        Config { max_failures: 10, base_delay_ms: 1_000, max_delay_ms: 5 * 60_000, kdf: KdfParams { passes: 3 } };

    pub fn delay_after(&self, failures: u32) -> u64 {
        if failures == 0 {
            return 0;
        }
        let shift = (failures - 1).min(32);
        self.base_delay_ms.saturating_mul(1u64 << shift).min(self.max_delay_ms)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// No master key: never initialised, or wiped. Call [`Vault::init`].
    Dead,
    BadSlot,
    BadPin,
    BadFormat,
    /// Another slot already opens with this PIN.
    PinInUse,
    /// Argon2 couldn't run with the memory given.
    Kdf,
    /// Less than [`MIN_ENTROPY`] bytes given to [`Vault::init`].
    Entropy,
}

#[derive(Debug)]
pub enum Attempt {
    Unlocked {
        slot: usize,
        seed: Seed,
        format: Format,
    },
    Wrong {
        attempts_left: u32,
        retry_in_ms: u64,
    },
    /// Still locked out. The PIN was not checked or counted.
    TooSoon {
        retry_in_ms: u64,
    },
    /// Wiped, just now or earlier.
    Wiped,
    /// Less than [`MIN_BLOCKS`] of Argon2 memory passed in. Not counted.
    Misconfigured,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Status {
    pub used: [bool; SLOTS],
    pub failures: u32,
    pub epoch: u32,
}

/// The SRAM half of the vault. Plain `repr(C)` bytes, so the firmware can put
/// it in a `static` in a section startup code doesn't clear (survives resets,
/// not power loss). All zeros is a valid "nothing here" state.
#[repr(C)]
pub struct Vault {
    /// Caller's clock (ms). Not secret.
    locked_until_ms: u64,
    bufs: [[u8; INNER_LEN]; 2],
    tags: [[u8; TAG_LEN]; 2],
}

type Inner = Zeroizing<[u8; INNER_LEN]>;

fn blank() -> Inner {
    Zeroizing::new([0u8; INNER_LEN])
}

fn slot_rec(inner: &[u8; INNER_LEN], slot: usize) -> &[u8] {
    &inner[HDR_LEN + slot * SLOT_LEN..HDR_LEN + (slot + 1) * SLOT_LEN]
}

fn slot_rec_mut(inner: &mut [u8; INNER_LEN], slot: usize) -> &mut [u8] {
    &mut inner[HDR_LEN + slot * SLOT_LEN..HDR_LEN + (slot + 1) * SLOT_LEN]
}

fn slot_nonce(slot: usize, ctr: &[u8]) -> Nonce {
    let mut n = [0u8; 12];
    n[0] = slot as u8;
    n[1..5].copy_from_slice(ctr);
    n.into()
}

fn slot_aad(slot: usize) -> [u8; SLOT_AAD.len() + 1] {
    let mut a = [0u8; SLOT_AAD.len() + 1];
    a[..SLOT_AAD.len()].copy_from_slice(SLOT_AAD);
    a[SLOT_AAD.len()] = slot as u8;
    a
}

fn vault_aad(epoch: u32) -> [u8; VAULT_AAD.len() + 4] {
    let mut a = [0u8; VAULT_AAD.len() + 4];
    a[..VAULT_AAD.len()].copy_from_slice(VAULT_AAD);
    a[VAULT_AAD.len()..].copy_from_slice(&epoch.to_le_bytes());
    a
}

fn format_bytes(f: &Format) -> Result<[u8; 2], Error> {
    let c = match f.charset {
        Charset::Printable => 0,
        Charset::Alnum => 1,
        Charset::Hex => 2,
    };
    if f.length == 0 || f.length > crate::render::MAX_LEN {
        return Err(Error::BadFormat);
    }
    Ok([c, f.length as u8])
}

fn format_from(b: &[u8]) -> Format {
    let charset = match b[0] {
        1 => Charset::Alnum,
        2 => Charset::Hex,
        _ => Charset::Printable,
    };
    Format { charset, length: b[1] as usize }
}

impl Vault {
    /// All zeros. Not usable until [`Vault::init`].
    pub const fn new() -> Self {
        Self { locked_until_ms: 0, bufs: [[0; INNER_LEN]; 2], tags: [[0; TAG_LEN]; 2] }
    }

    // ---- outer layer -------------------------------------------------------

    /// Decrypt the active buffer into `out` (caller's buffer, so the
    /// plaintext isn't moved around the stack). `false` = no master key or
    /// tampered SRAM; `out` is zeroed then.
    fn open_into(&self, bkp: &impl BackupStore, out: &mut Inner) -> bool {
        out.zeroize();
        if !backup::is_live(bkp) {
            return false;
        }
        let e = backup::epoch(bkp);
        let k = backup::key(bkp, e);
        let i = (e & 1) as usize;
        out.copy_from_slice(&self.bufs[i]);
        let ok = ChaCha20Poly1305::new(Key::from_slice(&k[..]))
            .decrypt_in_place_detached(&Nonce::default(), &vault_aad(e), &mut out[..], Tag::from_slice(&self.tags[i]))
            .is_ok();
        if !ok {
            out.zeroize();
        }
        ok
    }

    /// Write `inner` under a fresh master key into the other buffer, then
    /// commit by bumping the epoch. `entropy` is mixed into the new key.
    fn seal_next(&mut self, bkp: &mut impl BackupStore, inner: &[u8; INNER_LEN], entropy: &[u8]) {
        let e = backup::epoch(bkp);
        let next = e.wrapping_add(1);
        let k_old = backup::key(bkp, e);
        let k_new = hkdf32_parts(&k_old[..], &[MASTER_NEXT, &next.to_le_bytes(), entropy]);
        drop(k_old);

        // 1. New key into the inactive registers, new ciphertext into the
        //    inactive buffer. Nothing committed yet: a reset here leaves the
        //    old epoch fully intact.
        backup::set_key(bkp, next, &k_new);
        let j = (next & 1) as usize;
        self.bufs[j] = *inner;
        let tag = ChaCha20Poly1305::new(Key::from_slice(&k_new[..]))
            .encrypt_in_place_detached(&Nonce::default(), &vault_aad(next), &mut self.bufs[j])
            .expect("buffer within ChaCha20-Poly1305 limits");
        self.tags[j] = tag.into();
        drop(k_new);

        // 2. Commit: one register write.
        backup::set_epoch(bkp, next);

        // 3. Forget the old epoch.
        self.drop_stale(bkp);
    }

    /// Wipe the inactive key and buffer (left over from a rotation that was
    /// interrupted after committing).
    fn drop_stale(&mut self, bkp: &mut impl BackupStore) {
        let e = backup::epoch(bkp);
        let stale = e.wrapping_add(1);
        backup::clear_key(bkp, stale);
        let j = (stale & 1) as usize;
        self.bufs[j].zeroize();
        self.tags[j].zeroize();
    }

    // ---- lifecycle ---------------------------------------------------------

    /// Factory reset: forget everything, start an empty vault under a master
    /// key derived from `entropy` (host supplied randomness + whatever noise
    /// the device can scrape together; at least 32 good bytes in total).
    pub fn init(&mut self, bkp: &mut impl BackupStore, entropy: &[u8]) -> Result<(), Error> {
        if entropy.len() < MIN_ENTROPY {
            return Err(Error::Entropy);
        }
        self.wipe(bkp);
        let k = kdf::hkdf32(entropy, MASTER_INIT);
        backup::set_key(bkp, 0, &k);
        backup::set_epoch(bkp, 0);
        backup::set_failures(bkp, 0);
        self.bufs[0] = [0; INNER_LEN];
        let tag = ChaCha20Poly1305::new(Key::from_slice(&k[..]))
            .encrypt_in_place_detached(&Nonce::default(), &vault_aad(0), &mut self.bufs[0])
            .expect("buffer within ChaCha20-Poly1305 limits");
        self.tags[0] = tag.into();
        // Live only once everything above is in place.
        backup::set_live(bkp);
        Ok(())
    }

    /// Forget everything: backup registers and SRAM. Safe to call from an
    /// interrupt (no allocation, no panics). The vault is dead afterwards.
    pub fn wipe(&mut self, bkp: &mut impl BackupStore) {
        backup::wipe(bkp);
        self.bufs.zeroize();
        self.tags.zeroize();
        self.locked_until_ms = 0;
    }

    /// Call once after every reset. Cleans up an interrupted rotation, checks
    /// that SRAM and the backup registers still belong together (wipes if
    /// not), and restarts the lockout so resetting can't skip it.
    /// Returns whether the vault is live.
    pub fn on_boot(&mut self, bkp: &mut impl BackupStore, cfg: &Config, now_ms: u64) -> bool {
        if !backup::is_live(bkp) {
            self.wipe(bkp);
            return false;
        }
        self.drop_stale(bkp);
        if !self.open_into(bkp, &mut blank()) || backup::failures(bkp) >= cfg.max_failures {
            self.wipe(bkp);
            return false;
        }
        self.locked_until_ms = now_ms.saturating_add(cfg.delay_after(backup::failures(bkp)));
        true
    }

    /// Re-encrypt everything under a new master key, so no bit in SRAM or the
    /// backup registers holds still for long. Call every few minutes.
    /// `entropy` can be weak (ADC noise, timer jitter); it's mixed in, not
    /// relied on. Returns false (and wipes) if the vault doesn't open.
    pub fn rotate(&mut self, bkp: &mut impl BackupStore, entropy: &[u8]) -> bool {
        let mut inner = blank();
        if self.open_into(bkp, &mut inner) {
            self.seal_next(bkp, &inner, entropy);
            true
        } else {
            self.wipe(bkp);
            false
        }
    }

    pub fn is_live(&self, bkp: &impl BackupStore) -> bool {
        backup::is_live(bkp)
    }

    pub fn status(&self, bkp: &impl BackupStore) -> Option<Status> {
        let mut inner = blank();
        if !self.open_into(bkp, &mut inner) {
            return None;
        }
        Some(Status {
            used: core::array::from_fn(|s| slot_rec(&inner, s)[S_USED] != 0),
            failures: backup::failures(bkp),
            epoch: backup::epoch(bkp),
        })
    }

    // ---- slots -------------------------------------------------------------

    /// Seal an uploaded seed into `slot` behind `pin`.
    ///
    /// `salt` should be fresh random bytes from the host. `memory` is Argon2
    /// scratch (1 KiB per block; more is slower to attack) and is used for
    /// every used slot, to make sure the PIN isn't already taken.
    #[allow(clippy::too_many_arguments)]
    pub fn store(
        &mut self,
        bkp: &mut impl BackupStore,
        cfg: &Config,
        memory: &mut [Block],
        slot: usize,
        pin: &[u16],
        seed: &Seed,
        format: &Format,
        salt: [u8; SALT_LEN],
        entropy: &[u8],
    ) -> Result<(), Error> {
        let mut inner = blank();
        if !self.open_into(bkp, &mut inner) {
            return Err(Error::Dead);
        }
        if memory.len() < MIN_BLOCKS {
            return Err(Error::Kdf);
        }
        if slot >= SLOTS {
            return Err(Error::BadSlot);
        }
        if pin.is_empty() || pin.len() > MAX_PIN_LEN {
            return Err(Error::BadPin);
        }
        let fmt = format_bytes(format)?;
        // Two slots behind one PIN would make unlocking ambiguous.
        match find(&inner, cfg, memory, pin)? {
            Some((s, _, _)) if s != slot => return Err(Error::PinInUse),
            _ => {}
        }

        // Fresh nonce counter for every seal, so even a reused salt+PIN never
        // repeats a (key, nonce) pair.
        let ctr = u32::from_le_bytes(inner[..HDR_LEN].try_into().unwrap()).wrapping_add(1);
        inner[..HDR_LEN].copy_from_slice(&ctr.to_le_bytes());

        let k = kdf::stretch_pin(pin, &salt, cfg.kdf, memory).map_err(|_| Error::Kdf)?;
        let rec = slot_rec_mut(&mut inner, slot);
        rec[S_USED] = 1;
        rec[S_SALT..S_CTR].copy_from_slice(&salt);
        rec[S_CTR..S_CT].copy_from_slice(&ctr.to_le_bytes());
        rec[S_CT..S_CT + SEED_LEN].copy_from_slice(seed.bytes());
        rec[S_CT + SEED_LEN..S_TAG].copy_from_slice(&fmt);
        let (head, tag_out) = rec.split_at_mut(S_TAG);
        let tag = ChaCha20Poly1305::new(Key::from_slice(&k[..]))
            .encrypt_in_place_detached(&slot_nonce(slot, &head[S_CTR..S_CT]), &slot_aad(slot), &mut head[S_CT..])
            .expect("payload within ChaCha20-Poly1305 limits");
        tag_out.copy_from_slice(&tag);
        drop(k);

        self.seal_next(bkp, &inner, entropy);
        Ok(())
    }

    pub fn clear_slot(&mut self, bkp: &mut impl BackupStore, slot: usize, entropy: &[u8]) -> Result<(), Error> {
        let mut inner = blank();
        if !self.open_into(bkp, &mut inner) {
            return Err(Error::Dead);
        }
        if slot >= SLOTS {
            return Err(Error::BadSlot);
        }
        slot_rec_mut(&mut inner, slot).zeroize();
        self.seal_next(bkp, &inner, entropy);
        Ok(())
    }

    /// Try a PIN. `now_ms` is a monotonic clock in ms.
    pub fn attempt(
        &mut self,
        bkp: &mut impl BackupStore,
        cfg: &Config,
        memory: &mut [Block],
        pin: &[u16],
        now_ms: u64,
    ) -> Attempt {
        if !backup::is_live(bkp) {
            self.wipe(bkp);
            return Attempt::Wiped;
        }
        if now_ms < self.locked_until_ms {
            return Attempt::TooSoon { retry_in_ms: self.locked_until_ms - now_ms };
        }
        if memory.len() < MIN_BLOCKS {
            // A firmware bug, not a wrong PIN: don't burn an attempt on it.
            return Attempt::Misconfigured;
        }

        // Count first, so a reset in the middle of checking still counts.
        let failures = backup::failures(bkp).saturating_add(1);
        if failures > cfg.max_failures {
            self.wipe(bkp);
            return Attempt::Wiped;
        }
        backup::set_failures(bkp, failures);
        if backup::failures(bkp) != failures {
            // The write didn't stick. Don't check a PIN we can't count.
            self.wipe(bkp);
            return Attempt::Wiped;
        }

        let mut inner = blank();
        if !self.open_into(bkp, &mut inner) {
            self.wipe(bkp);
            return Attempt::Wiped;
        }
        let hit = find(&inner, cfg, memory, pin).ok().flatten();
        inner.zeroize();

        match hit {
            Some((slot, seed, format)) => {
                backup::set_failures(bkp, 0);
                self.locked_until_ms = 0;
                Attempt::Unlocked { slot, seed, format }
            }
            None if failures >= cfg.max_failures => {
                self.wipe(bkp);
                Attempt::Wiped
            }
            None => {
                let delay = cfg.delay_after(failures);
                self.locked_until_ms = now_ms.saturating_add(delay);
                Attempt::Wrong { attempts_left: cfg.max_failures - failures, retry_in_ms: delay }
            }
        }
    }
}

impl Default for Vault {
    fn default() -> Self {
        Self::new()
    }
}

/// Check `pin` against every used slot (always all of them, so timing doesn't
/// say which one matched). Returns the first match.
fn find(
    inner: &[u8; INNER_LEN],
    cfg: &Config,
    memory: &mut [Block],
    pin: &[u16],
) -> Result<Option<(usize, Seed, Format)>, Error> {
    if pin.is_empty() || pin.len() > MAX_PIN_LEN {
        return Ok(None);
    }
    let mut found = None;
    for slot in 0..SLOTS {
        let rec = slot_rec(inner, slot);
        if rec[S_USED] == 0 {
            continue;
        }
        let salt: [u8; SALT_LEN] = rec[S_SALT..S_CTR].try_into().unwrap();
        let k = kdf::stretch_pin(pin, &salt, cfg.kdf, memory).map_err(|_| Error::Kdf)?;
        let mut payload = Zeroizing::new([0u8; PAYLOAD_LEN]);
        payload.copy_from_slice(&rec[S_CT..S_TAG]);
        let ok = ChaCha20Poly1305::new(Key::from_slice(&k[..]))
            .decrypt_in_place_detached(
                &slot_nonce(slot, &rec[S_CTR..S_CT]),
                &slot_aad(slot),
                &mut payload[..],
                Tag::from_slice(&rec[S_TAG..]),
            )
            .is_ok();
        if ok && found.is_none() {
            let seed = Seed::from_bytes(payload[..SEED_LEN].try_into().unwrap());
            found = Some((slot, seed, format_from(&payload[SEED_LEN..])));
        }
    }
    Ok(found)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backup::MemBackup;

    // Cheap KDF so the tests run fast.
    const C: Config = Config { max_failures: 3, base_delay_ms: 1000, max_delay_ms: 3000, kdf: KdfParams { passes: 1 } };
    const F: Format = Format { charset: Charset::Alnum, length: 20 };

    fn mem() -> [Block; 8] {
        [Block::default(); 8]
    }

    fn seed(b: u8) -> Seed {
        Seed::from_bytes([b; 32])
    }

    fn setup() -> (Vault, MemBackup) {
        let mut v = Vault::new();
        let mut b = MemBackup::default();
        v.init(&mut b, b"host randomness, at least 32 bytes of it!").unwrap();
        v.store(&mut b, &C, &mut mem(), 0, &[100, 64, 116], &seed(1), &F, [1; 16], b"").unwrap();
        v.store(
            &mut b,
            &C,
            &mut mem(),
            3,
            &[5, 5],
            &seed(2),
            &Format { charset: Charset::Hex, length: 64 },
            [2; 16],
            b"",
        )
        .unwrap();
        (v, b)
    }

    fn unlocked(a: Attempt) -> (usize, Seed, Format) {
        match a {
            Attempt::Unlocked { slot, seed, format } => (slot, seed, format),
            a => panic!("{a:?}"),
        }
    }

    #[test]
    fn unlocks_the_right_slot() {
        let (mut v, mut b) = setup();
        let (slot, s, f) = unlocked(v.attempt(&mut b, &C, &mut mem(), &[5, 5], 0));
        assert_eq!((slot, s.bytes(), f.length), (3, &[2; 32], 64));
        let (slot, s, f) = unlocked(v.attempt(&mut b, &C, &mut mem(), &[100, 64, 116], 0));
        assert_eq!((slot, s.bytes(), f.length), (0, &[1; 32], 20));
        assert!(matches!(f.charset, Charset::Alnum));
    }

    #[test]
    fn nothing_readable_in_sram() {
        let (v, _) = setup();
        let raw: &[u8] =
            unsafe { core::slice::from_raw_parts(&v as *const Vault as *const u8, core::mem::size_of::<Vault>()) };
        for pat in [[1u8; 8], [2u8; 8]] {
            assert!(!raw.windows(8).any(|w| w == pat));
        }
    }

    #[test]
    fn sram_alone_is_useless() {
        let (mut v, mut b) = setup();
        // Lose the backup registers (tamper pin): SRAM can't be opened.
        backup::wipe(&mut b);
        assert!(v.status(&b).is_none());
        assert!(matches!(v.attempt(&mut b, &C, &mut mem(), &[5, 5], 0), Attempt::Wiped));
    }

    #[test]
    fn throttles_then_wipes() {
        let (mut v, mut b) = setup();
        assert!(matches!(
            v.attempt(&mut b, &C, &mut mem(), &[1], 0),
            Attempt::Wrong { attempts_left: 2, retry_in_ms: 1000 }
        ));
        // Locked out: not checked, not counted, even with the right PIN.
        assert!(matches!(v.attempt(&mut b, &C, &mut mem(), &[5, 5], 500), Attempt::TooSoon { retry_in_ms: 500 }));
        assert_eq!(v.status(&b).unwrap().failures, 1);
        assert!(matches!(
            v.attempt(&mut b, &C, &mut mem(), &[2], 1000),
            Attempt::Wrong { attempts_left: 1, retry_in_ms: 2000 }
        ));
        assert!(matches!(v.attempt(&mut b, &C, &mut mem(), &[3], 3000), Attempt::Wiped));
        assert!(!v.is_live(&b));
        assert!(b.0.iter().all(|&w| w == 0));
        assert!(matches!(v.attempt(&mut b, &C, &mut mem(), &[5, 5], 10_000), Attempt::Wiped));
        assert_eq!(v.clear_slot(&mut b, 0, b""), Err(Error::Dead));
    }

    #[test]
    fn success_resets_counter() {
        let (mut v, mut b) = setup();
        v.attempt(&mut b, &C, &mut mem(), &[1], 0);
        v.attempt(&mut b, &C, &mut mem(), &[2], 1000);
        unlocked(v.attempt(&mut b, &C, &mut mem(), &[5, 5], 3000));
        assert_eq!(v.status(&b).unwrap().failures, 0);
    }

    #[test]
    fn reset_mid_check_still_counts() {
        let (mut v, mut b) = setup();
        // Simulate "counter bumped, then reset before the result": the bump
        // happens first, so just check it's there after a wrong attempt and a
        // reboot restarts the lockout.
        v.attempt(&mut b, &C, &mut mem(), &[1], 0);
        assert!(v.on_boot(&mut b, &C, 0));
        assert!(matches!(v.attempt(&mut b, &C, &mut mem(), &[5, 5], 10), Attempt::TooSoon { .. }));
        unlocked(v.attempt(&mut b, &C, &mut mem(), &[5, 5], 1000));
    }

    #[test]
    fn corrupt_counter_wipes() {
        let (mut v, mut b) = setup();
        b.0[18] = 0; // failures
        b.0[19] = 0; // check word now disagrees
        assert!(matches!(v.attempt(&mut b, &C, &mut mem(), &[5, 5], 0), Attempt::Wiped));
    }

    #[test]
    fn rotation_changes_every_byte_and_keeps_data() {
        let (mut v, mut b) = setup();
        let e0 = b.0[17];
        let before = (v.bufs, b.0);
        assert!(v.rotate(&mut b, b"adc noise"));
        assert_eq!(b.0[17], e0 + 1);
        // The live buffer moved and the old one is gone.
        assert!(v.bufs[(e0 & 1) as usize].iter().all(|&x| x == 0));
        let live = v.bufs[((e0 + 1) & 1) as usize];
        let differing = live.iter().zip(before.0[(e0 & 1) as usize].iter()).filter(|(a, b)| a != b).count();
        assert!(differing > INNER_LEN * 9 / 10);
        unlocked(v.attempt(&mut b, &C, &mut mem(), &[5, 5], 0));
    }

    #[test]
    fn interrupted_rotation_recovers() {
        // A reset after the new key and buffer were written but before the
        // epoch commit leaves junk on the inactive side. on_boot clears it
        // and the old epoch keeps working.
        let (mut v, mut b) = setup();
        let next = ((b.0[17] + 1) & 1) as usize;
        v.bufs[next] = [0xAA; INNER_LEN];
        for w in if next == 0 { 1..9 } else { 9..17 } {
            b.0[w] = 0xdead_beef;
        }
        assert!(v.on_boot(&mut b, &C, 0));
        assert!(v.bufs[next].iter().all(|&x| x == 0));
        assert!((if next == 0 { 1..9 } else { 9..17 }).all(|w| b.0[w] == 0));
        unlocked(v.attempt(&mut b, &C, &mut mem(), &[5, 5], 0));
    }

    #[test]
    fn tampered_sram_wipes() {
        let (mut v, mut b) = setup();
        let i = (b.0[17] & 1) as usize;
        v.bufs[i][100] ^= 1;
        assert!(!v.on_boot(&mut b, &C, 0));
        assert!(!v.is_live(&b));
    }

    #[test]
    fn store_rules() {
        let (mut v, mut b) = setup();
        let s = seed(9);
        assert_eq!(v.store(&mut b, &C, &mut mem(), SLOTS, &[1], &s, &F, [0; 16], b""), Err(Error::BadSlot));
        assert_eq!(v.store(&mut b, &C, &mut mem(), 1, &[], &s, &F, [0; 16], b""), Err(Error::BadPin));
        assert_eq!(v.store(&mut b, &C, &mut mem(), 1, &[5, 5], &s, &F, [9; 16], b""), Err(Error::PinInUse));
        let bad = Format { charset: Charset::Hex, length: 0 };
        assert_eq!(v.store(&mut b, &C, &mut mem(), 1, &[7], &s, &bad, [9; 16], b""), Err(Error::BadFormat));
        // Re-keying a slot with its own PIN is fine, length prefix keeps [5,5,0] apart.
        v.store(&mut b, &C, &mut mem(), 3, &[5, 5], &seed(7), &F, [9; 16], b"").unwrap();
        v.store(&mut b, &C, &mut mem(), 1, &[5, 5, 0], &s, &F, [9; 16], b"").unwrap();
        assert_eq!(v.status(&b).unwrap().used, [true, true, false, true, false, false, false, false]);
        v.clear_slot(&mut b, 3, b"").unwrap();
        assert!(matches!(v.attempt(&mut b, &C, &mut mem(), &[5, 5], 0), Attempt::Wrong { .. }));
    }

    #[test]
    fn slot_seal_known_answer() {
        // tools/kat.py seal_slot([5,5], 02*16, slot 3, ctr 1, seed 02*32, hex, 64, m=8, t=1)
        let mut v = Vault::new();
        let mut b = MemBackup::default();
        v.init(&mut b, &[7; 32]).unwrap();
        let f = Format { charset: Charset::Hex, length: 64 };
        v.store(&mut b, &C, &mut mem(), 3, &[5, 5], &seed(2), &f, [2; 16], b"").unwrap();
        let mut inner = blank();
        assert!(v.open_into(&b, &mut inner));
        let hex: String = slot_rec(&inner, 3)[S_CT..].iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex,
            "52b9a3cb9e2532b9cf49141b2ce462dc8af311f46f50b0ada83672888df07612cbb01ba8c9cc602acbdcca238f13b1a3a6b2"
        );
    }

    #[test]
    fn misuse_is_not_counted() {
        let (mut v, mut b) = setup();
        let mut small = [Block::default(); 4];
        assert!(matches!(v.attempt(&mut b, &C, &mut small, &[5, 5], 0), Attempt::Misconfigured));
        assert_eq!(v.status(&b).unwrap().failures, 0);
        assert_eq!(Vault::new().init(&mut MemBackup::default(), &[0; 31]), Err(Error::Entropy));
    }

    #[test]
    fn uninitialised_is_dead() {
        let mut v = Vault::new();
        let mut b = MemBackup::default();
        assert!(!v.on_boot(&mut b, &C, 0));
        let s = seed(1);
        assert_eq!(v.store(&mut b, &C, &mut mem(), 0, &[1], &s, &F, [0; 16], b""), Err(Error::Dead));
        assert!(matches!(v.attempt(&mut b, &C, &mut mem(), &[1], 0), Attempt::Wiped));
    }
}
