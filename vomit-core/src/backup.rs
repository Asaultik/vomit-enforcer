//! The 20 x 32-bit RTC backup registers, and what lives in them.
//!
//! The backup domain runs off VBAT and is cleared *by hardware* when the RTC
//! tamper pin fires, with no CPU involvement. So everything the SRAM vault
//! can't do without goes here: the master keys (without them the SRAM vault
//! is noise), the epoch and the failure counter (so a reset can't roll it
//! back).
//!
//! ```text
//! word 0       magic "VOM3" (written last on init, so half-initialised = dead)
//! word 1..=8   master key A (active on even epochs)
//! word 9..=16  master key B (active on odd epochs)
//! word 17      epoch
//! word 18      failures
//! word 19      !failures (a mismatch reads as "too many", so corruption wipes)
//! ```

use zeroize::Zeroizing;

pub const WORDS: usize = 20;

const MAGIC_WORD: usize = 0;
const KEY_A: usize = 1;
const KEY_B: usize = 9;
const EPOCH: usize = 17;
const FAILURES: usize = 18;
const FAILURES_CHECK: usize = 19;

const MAGIC: u32 = u32::from_le_bytes(*b"VOM3");

/// Whatever holds the backup registers. On the device that's `RTC->BKPxR`;
/// in tests it's an array.
pub trait BackupStore {
    fn read(&self, word: usize) -> u32;
    fn write(&mut self, word: usize, value: u32);
}

/// Plain RAM stand-in, for tests and simulation.
#[derive(Default)]
pub struct MemBackup(pub [u32; WORDS]);

impl BackupStore for MemBackup {
    fn read(&self, word: usize) -> u32 {
        self.0[word]
    }
    fn write(&mut self, word: usize, value: u32) {
        self.0[word] = value;
    }
}

pub(crate) fn is_live(b: &impl BackupStore) -> bool {
    b.read(MAGIC_WORD) == MAGIC
}

pub(crate) fn set_live(b: &mut impl BackupStore) {
    b.write(MAGIC_WORD, MAGIC);
}

pub(crate) fn epoch(b: &impl BackupStore) -> u32 {
    b.read(EPOCH)
}

pub(crate) fn set_epoch(b: &mut impl BackupStore, e: u32) {
    b.write(EPOCH, e);
}

fn key_base(epoch: u32) -> usize {
    if epoch & 1 == 0 {
        KEY_A
    } else {
        KEY_B
    }
}

/// Master key for `epoch` (A for even, B for odd).
pub(crate) fn key(b: &impl BackupStore, epoch: u32) -> Zeroizing<[u8; 32]> {
    let base = key_base(epoch);
    let mut k = Zeroizing::new([0u8; 32]);
    for i in 0..8 {
        k[4 * i..4 * i + 4].copy_from_slice(&b.read(base + i).to_le_bytes());
    }
    k
}

pub(crate) fn set_key(b: &mut impl BackupStore, epoch: u32, k: &[u8; 32]) {
    let base = key_base(epoch);
    for i in 0..8 {
        b.write(base + i, u32::from_le_bytes(k[4 * i..4 * i + 4].try_into().unwrap()));
    }
}

pub(crate) fn clear_key(b: &mut impl BackupStore, epoch: u32) {
    let base = key_base(epoch);
    for i in 0..8 {
        b.write(base + i, 0);
    }
}

/// `u32::MAX` if the counter and its check word disagree.
pub(crate) fn failures(b: &impl BackupStore) -> u32 {
    let f = b.read(FAILURES);
    if b.read(FAILURES_CHECK) == !f {
        f
    } else {
        u32::MAX
    }
}

pub(crate) fn set_failures(b: &mut impl BackupStore, f: u32) {
    b.write(FAILURES, f);
    b.write(FAILURES_CHECK, !f);
}

/// Zero every word, magic first so nothing half-wiped still looks live.
pub fn wipe(b: &mut impl BackupStore) {
    b.write(MAGIC_WORD, 0);
    for w in 0..WORDS {
        b.write(w, 0);
    }
}
