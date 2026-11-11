//! Bench firmware for the STM32F411 "Black Pill".
//!
//! It answers the questions the security report left open with "measure on
//! silicon", and nothing else. Flash it with an ST-Link attached:
//!
//! ```sh
//! cd bench && cargo run --release
//! ```
//!
//! Logs stream over RTT (defmt). It measures:
//!
//! 1. Argon2id cost at a few (memory, passes) settings, so we can pick a point
//!    where one unlock across 8 slots is tolerable.
//! 2. One full `store` + `attempt` round-trip, the real unlock latency.
//! 3. That the RTC backup registers survive a write/read and that
//!    `backup::is_live` round-trips through real hardware registers.
//!
//! It does NOT test the tamper pin or VBAT behaviour: those need the physical
//! loop and a bench power supply (see the report, HW-02/HW-03).

#![no_std]
#![no_main]

use cortex_m::peripheral::DWT;
use embassy_executor::Spawner;
use embassy_stm32::pac;
use embassy_time::Instant;
use {defmt_rtt as _, panic_probe as _};

use vomit_core::backup::BackupStore;
use vomit_core::kdf::{stretch_pin, Block, KdfParams};
use vomit_core::render::{Charset, Format};
use vomit_core::seed::Seed;
use vomit_core::vault::{Config, Vault, SLOTS};

/// Argon2 scratch. `const fn` Block::new keeps it in .bss, off the stack.
/// 96 blocks = 96 KiB; the F411 has 128 KiB SRAM.
const MAX_BLOCKS: usize = 96;
static mut ARGON_MEM: [Block; MAX_BLOCKS] = [Block::new(); MAX_BLOCKS];

/// Live RTC backup registers (RTC_BKPxR), via the PAC. Writes need the backup
/// domain unlocked (PWR DBP + RTC write protection), done in `init_backup`.
struct RtcBackup;

impl BackupStore for RtcBackup {
    fn read(&self, word: usize) -> u32 {
        pac::RTC.bkpr(word).read().bkp()
    }
    fn write(&mut self, word: usize, value: u32) {
        pac::RTC.bkpr(word).write(|w| w.set_bkp(value));
    }
}

fn init_backup() {
    // Allow access to the backup domain.
    pac::PWR.cr1().modify(|w| w.set_dbp(true));
    while !pac::PWR.cr1().read().dbp() {}
    // Disable RTC register write protection (keys 0xCA, 0x53).
    pac::RTC.wpr().write(|w| w.set_key(0xCA));
    pac::RTC.wpr().write(|w| w.set_key(0x53));
}

fn cycles<F: FnOnce()>(f: F) -> u32 {
    let start = DWT::cycle_count();
    f();
    DWT::cycle_count().wrapping_sub(start)
}

/// A `&mut` to a prefix of the Argon2 scratch. `&mut *ptr` takes the array
/// reference first, so indexing it doesn't autoref through a raw pointer.
fn argon_mem(n: usize) -> &'static mut [Block] {
    let arr: &mut [Block; MAX_BLOCKS] = unsafe { &mut *core::ptr::addr_of_mut!(ARGON_MEM) };
    &mut arr[..n]
}

#[embassy_executor::main]
async fn main(_spawner: Spawner) {
    let _p = embassy_stm32::init(Default::default());
    let mut core = unsafe { cortex_m::Peripherals::steal() };
    core.DCB.enable_trace();
    core.DWT.enable_cycle_counter();

    // SYSCLK: default embassy-stm32 init leaves the F411 on HSI = 16 MHz.
    // ms = cycles / 16_000. We report cycles too, so the figure is clock-agnostic.
    const HZ: u32 = 16_000_000;
    defmt::info!("vomit-bench on STM32F411, assuming {} Hz SYSCLK", HZ);

    // ---- 1. Argon2id cost sweep ----
    defmt::info!("--- argon2id sweep (1 slot) ---");
    let salt = [0x5au8; 16];
    let pin = [100u16, 64, 116];
    for &(blocks, passes) in &[(8usize, 1u32), (16, 3), (32, 3), (64, 3), (96, 3), (96, 4)] {
        let mem = argon_mem(blocks);
        let c = cycles(|| {
            let _ = stretch_pin(&pin, &salt, KdfParams { passes }, mem);
        });
        defmt::info!(
            "  m={=usize} KiB t={=u32}: {=u32} cycles = {=u32} ms  (x{=usize} slots = {=u32} ms)",
            blocks,
            passes,
            c,
            c / (HZ / 1000),
            SLOTS,
            (c / (HZ / 1000)) * SLOTS as u32,
        );
    }

    // ---- 2. real vault round-trip ----
    defmt::info!("--- vault store + unlock (m=64 t=3) ---");
    init_backup();
    let cfg = Config { kdf: KdfParams { passes: 3 }, ..Config::DEFAULT };
    let mem = argon_mem(64);
    let mut bkp = RtcBackup;
    let mut vault = Vault::new();

    match vault.init(&mut bkp, &[0x11; 32]) {
        Ok(()) => defmt::info!("  init ok"),
        Err(e) => defmt::error!("  init failed: {}", defmt::Debug2Format(&e)),
    }
    let fmt = Format { charset: Charset::Printable, length: 32 };
    let t = Instant::now();
    match vault.store(&mut bkp, &cfg, mem, 0, &pin, &Seed::from_bytes([0x22; 32]), &fmt, salt, b"", 0) {
        Ok(()) => defmt::info!("  store ok in {} ms", t.elapsed().as_millis()),
        Err(e) => defmt::error!("  store failed: {}", defmt::Debug2Format(&e)),
    }
    let t = Instant::now();
    let a = vault.attempt(&mut bkp, &cfg, mem, &pin, 0);
    defmt::info!("  attempt (1 slot) in {} ms -> {}", t.elapsed().as_millis(), defmt::Debug2Format(&a));

    // ---- 3. backup register persistence ----
    defmt::info!("--- backup registers ---");
    defmt::info!("  is_live after init: {}", vault.is_live(&bkp));
    bkp.write(15, 0xDEAD_BEEF);
    let ok = bkp.read(15) == 0xDEAD_BEEF;
    defmt::info!("  BKP15 write/read: {}", if ok { "ok" } else { "FAILED" });
    defmt::info!(
        "  NOTE: power-cycle on VBAT and re-read BKP15 to confirm retention; cut the tamper loop to confirm erase."
    );

    defmt::info!("done.");
    loop {
        cortex_m::asm::wfi();
    }
}
