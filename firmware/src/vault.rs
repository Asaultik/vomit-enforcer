//! The seed in the RTC backup registers, and the RTC tamper input that erases
//! them.
//!
//! Wiring: a conductive loop (case switch, mesh, wire through the enclosure
//! screws, ...) from PC13 to GND, plus a high value pull-up (1-10 MOhm) from
//! PC13 to VBAT. Break the loop and PC13 rises, the RTC sees a tamper edge
//! and the hardware clears every backup register. This works from the coin
//! cell alone, with USB unplugged and the CPU off. Remove the Black Pill's
//! PC13 LED (or its resistor): it would fight the loop.
//!
//! The seed is never cached in RAM: every derivation reads it fresh from the
//! registers and drops (zeroizes) it right after.

use embassy_stm32::pac;
use embassy_stm32::pac::rtc::vals::{Tampflt, Tamptrg};
use vomit_core::seed::{Seed, BKP_WORDS};

/// Total backup registers on the F411.
const BKP_TOTAL: usize = 20;

fn unlock_backup_domain() {
    pac::PWR.cr1().modify(|w| w.set_dbp(true));
    while !pac::PWR.cr1().read().dbp() {}
}

/// Arm the tamper input. Needs the backup domain clocked (`LsConfig::default_lse`).
///
/// TAMPFLT = 0 means edge detection, which is what the reference manual says
/// keeps working in VBAT mode. TAMPxTRG = 0 with edge detection = rising
/// edge. RTC_TAFCR is not covered by the RTC write protection.
pub fn arm_tamper() {
    unlock_backup_domain();
    let rtc = pac::RTC;
    let cur = rtc.tafcr().read();
    if cur.tampe(0) && cur.tampflt() == Tampflt::IMMEDIATE && cur.tamptrg(0) == Tamptrg::RISING_EDGE && !cur.tamp1insel() {
        // Already armed (it survives resets on VBAT). Don't open a window by
        // toggling it.
        return;
    }
    rtc.tafcr().modify(|w| {
        w.set_tampe(0, false);
    });
    rtc.tafcr().modify(|w| {
        w.set_tamp1insel(false); // TAMP1 on PC13
        w.set_tampflt(Tampflt::IMMEDIATE);
        w.set_tamptrg(0, Tamptrg::RISING_EDGE);
        w.set_tampie(false);
    });
    rtc.tafcr().modify(|w| w.set_tampe(0, true));
}

/// Has the tamper input fired since the flag was last cleared?
pub fn tampered() -> bool {
    pac::RTC.isr().read().tampf(0)
}

/// Clear the tamper flag. The backup registers are already gone by the time
/// it's set, and they can't be written again until it's cleared.
pub fn clear_tamper_flag() {
    pac::RTC.isr().modify(|w| w.set_tampf(0, false));
}

pub fn load() -> Option<Seed> {
    let mut words = [0u32; BKP_WORDS];
    for (i, w) in words.iter_mut().enumerate() {
        *w = pac::RTC.bkpr(i).read().bkp();
    }
    let seed = Seed::from_backup_words(&words);
    zeroize::Zeroize::zeroize(&mut words);
    seed
}

pub fn is_provisioned() -> bool {
    load().is_some()
}

/// Store a seed. Returns `false` if it didn't read back correctly.
pub fn store(seed: &Seed) -> bool {
    unlock_backup_domain();
    let mut words = seed.to_backup_words();
    for (i, w) in words.iter().enumerate() {
        pac::RTC.bkpr(i).write(|r| r.set_bkp(*w));
    }
    zeroize::Zeroize::zeroize(&mut words);
    load().is_some_and(|s| s.bytes() == seed.bytes())
}

pub fn wipe() {
    unlock_backup_domain();
    for i in 0..BKP_TOTAL {
        pac::RTC.bkpr(i).write(|r| r.set_bkp(0));
    }
}
