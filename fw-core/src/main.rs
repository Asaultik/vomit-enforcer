//! vomit-enforcer core firmware for the STM32F411 "Black Pill".
//!
//! This chip holds the vault and never touches USB. It answers FIDO2 requests
//! that arrive as frames on USART1 from the bridge. All of the logic lives in
//! `vomit-ctap` and `vomit-core`, where it is tested on a PC; this file only
//! connects it to the hardware:
//!
//! | What                | Pin  |                                             |
//! | ------------------- | ---- | ------------------------------------------- |
//! | UART to bridge, TX  | PA9  | to the bridge's RX (GP1)                    |
//! | UART to bridge, RX  | PA10 | from the bridge's TX (GP0)                  |
//! | Touch button        | PA0  | the onboard KEY, pressed = low              |
//! | Light               | PC13 | the onboard LED, on while a touch is wanted |
//!
//! ```sh
//! cd fw-core && cargo run --release     # needs the ST-Link; logs over RTT
//! ```
//!
//! Development stage. Not done yet: readout protection, the tamper input, a
//! proper random generator (the F411 has none, see `boot_entropy`).

#![no_std]
#![no_main]

use core::mem::MaybeUninit;
use core::ptr::addr_of_mut;

use cortex_m::peripheral::syst::SystClkSource;
use cortex_m::peripheral::DWT;
use cortex_m_rt::{entry, exception};
use embassy_stm32::adc::{Adc, SampleTime};
use embassy_stm32::gpio::{Input, Level, Output, Pull, Speed};
use embassy_stm32::usart::{self, BufferedUart, BufferedUartRx, BufferedUartTx};
use embassy_stm32::{bind_interrupts, pac, peripherals, rcc, Peri};
use embassy_time::Instant;
use sha2::{Digest, Sha256};
use {defmt_rtt as _, panic_probe as _};

use vomit_core::backup::BackupStore;
use vomit_core::kdf::{Block, KdfParams};
use vomit_core::vault::{Config, Vault};
use vomit_ctap::rng::Drbg;
use vomit_ctap::serve::{CoreIo, Server, Trace};
use vomit_link::frame::BAUD;

/// Argon2id memory in KiB. The chip has 128 KiB of RAM in total.
const ARGON_BLOCKS: usize = 64;

/// Measured on this chip: 64 KiB and 3 passes take about 43 ms per PIN check
/// at 96 MHz.
const CFG: Config = Config {
    max_failures: 8,
    base_delay_ms: 1_000,
    max_delay_ms: 5 * 60_000,
    admin_window_ms: 60_000,
    kdf: KdfParams { passes: 3 },
};

// These live in RAM that the startup code does not clear. The vault and the
// random generator's state therefore survive a reset (but not power loss),
// and the Argon2 scratch comes up holding whatever the RAM cells settled to
// at power-on, which is used once as entropy and then cleared.
#[link_section = ".uninit.VAULT"]
static mut VAULT: MaybeUninit<Vault> = MaybeUninit::uninit();
#[link_section = ".uninit.DRBG"]
static mut DRBG: MaybeUninit<Drbg> = MaybeUninit::uninit();
#[link_section = ".uninit.ARGON"]
static mut ARGON: MaybeUninit<[Block; ARGON_BLOCKS]> = MaybeUninit::uninit();

static mut UART_TX: [u8; 16] = [0; 16]; // the HAL wants one; see `Io::write`
static mut UART_RX: [u8; 512] = [0; 512];

bind_interrupts!(struct Irqs {
    USART1 => usart::BufferedInterruptHandler<peripherals::USART1>;
});

/// The RTC backup registers: battery-backed, and erased by the chip itself
/// when the tamper input fires. The vault's master key lives here.
struct RtcBackup;

impl BackupStore for RtcBackup {
    fn read(&self, word: usize) -> u32 {
        pac::RTC.bkpr(word).read().bkp()
    }
    fn write(&mut self, word: usize, value: u32) {
        pac::RTC.bkpr(word).write(|w| w.set_bkp(value));
    }
}

struct Io {
    rx: BufferedUartRx<'static>,
    /// Unused, but dropping it would switch the transmitter off.
    _tx: BufferedUartTx<'static>,
    button: Input<'static>,
    led: Output<'static>,
}

impl CoreIo for Io {
    fn now_ms(&mut self) -> u64 {
        Instant::now().as_millis()
    }

    fn read_byte(&mut self) -> Option<u8> {
        // Bytes are collected by the UART interrupt; this never waits. A
        // byte lost to a line error just fails its frame's checksum.
        embedded_hal_nb::serial::Read::read(&mut self.rx).ok()
    }

    fn write(&mut self, bytes: &[u8]) {
        // Straight to the transmitter, one byte at a time, waiting for room
        // by polling. The HAL's interrupt-driven transmit can stall until
        // the next received byte, which held a reply back for 40 seconds.
        // A full reply takes about 110 ms at this speed.
        let uart = pac::USART1;
        for &byte in bytes {
            while !uart.sr().read().txe() {}
            uart.dr().write(|w| w.set_dr(byte as u16));
        }
    }

    fn button_down(&mut self) -> bool {
        self.button.is_low()
    }

    fn jitter(&mut self) -> u32 {
        DWT::cycle_count()
    }

    fn indicate(&mut self, waiting_for_touch: bool) {
        // The LED is wired to light when the pin is low.
        self.led.set_level(if waiting_for_touch { Level::Low } else { Level::High });
    }

    fn idle(&mut self) {
        // Until the next interrupt: a UART byte, or the 1 ms tick.
        cortex_m::asm::wfi();
    }

    fn trace(&mut self, event: Trace) {
        match event {
            Trace::Request(command, len) => defmt::info!("request: command {=u8:#04x}, {=usize} bytes", command, len),
            Trace::Response(status, len) => defmt::info!("response: status {=u8:#04x}, {=usize} bytes", status, len),
            Trace::WaitingForTouch => defmt::info!("waiting for touch (press KEY)"),
        }
    }
}

/// 96 MHz from the internal oscillator. The core has no USB, so it does not
/// need the crystal's accuracy, and this works whatever crystal a board has.
fn clocks() -> embassy_stm32::Config {
    let mut c = embassy_stm32::Config::default();
    c.rcc.hsi = true;
    c.rcc.pll_src = rcc::PllSource::HSI;
    c.rcc.pll = Some(rcc::Pll {
        prediv: rcc::PllPreDiv::DIV8,   // 16 MHz / 8 = 2 MHz
        mul: rcc::PllMul::MUL96,        // x 96 = 192 MHz
        divp: Some(rcc::PllPDiv::DIV2), // / 2 = 96 MHz
        divq: None,
        divr: None,
    });
    c.rcc.sys = rcc::Sysclk::PLL1_P;
    c.rcc.ahb_pre = rcc::AHBPrescaler::DIV1;
    c.rcc.apb1_pre = rcc::APBPrescaler::DIV2;
    c.rcc.apb2_pre = rcc::APBPrescaler::DIV1;
    // Keep this as it is once a device holds secrets: if the RTC clock
    // setting changes, the HAL resets the backup domain, which wipes them.
    c.rcc.ls = rcc::LsConfig::default_lsi();
    c
}

/// Everything unpredictable that can be scraped together at boot, hashed.
///
/// The F411 has no hardware random generator. What it has:
/// * the power-on state of 64 KiB of RAM (a fair share of the cells settle
///   randomly each time), meaningful after a cold start only;
/// * noise in the low bits of the ADC (temperature sensor, voltage reference);
/// * the chip's serial number, which is not secret but differs per chip.
///
/// After a reset without power loss the RAM holds no fresh noise, which is why
/// the generator's own state is kept across resets and this is mixed into it.
/// A chip with a real generator (the planned STM32U585) replaces all of this.
fn boot_entropy(adc: Peri<'static, peripherals::ADC1>) -> [u8; 32] {
    let mut hash = Sha256::new();

    let ram = addr_of_mut!(ARGON) as *mut u8;
    let len = core::mem::size_of::<[Block; ARGON_BLOCKS]>();
    let mut chunk = [0u8; 64];
    for offset in (0..len).step_by(chunk.len()) {
        for (i, byte) in chunk.iter_mut().enumerate() {
            // Volatile: read what is really in the cell, whatever the
            // compiler thinks it knows about uninitialised memory.
            *byte = unsafe { ram.add(offset + i).read_volatile() };
        }
        hash.update(chunk);
    }
    // From here on the scratch is ordinary, initialised memory.
    unsafe { ram.write_bytes(0, len) };

    let mut adc = Adc::new(adc);
    let mut temperature = adc.enable_temperature();
    let mut reference = adc.enable_vrefint();
    for _ in 0..512 {
        // The shortest sample time gives the noisiest readings.
        let t = adc.blocking_read(&mut temperature, SampleTime::CYCLES3);
        let v = adc.blocking_read(&mut reference, SampleTime::CYCLES3);
        hash.update(t.to_le_bytes());
        hash.update(v.to_le_bytes());
        hash.update(DWT::cycle_count().to_le_bytes());
    }

    hash.update(embassy_stm32::uid::uid());
    hash.finalize().into()
}

#[entry]
fn main() -> ! {
    let p = embassy_stm32::init(clocks());
    let mut cortex = unsafe { cortex_m::Peripherals::steal() };
    cortex.DCB.enable_trace();
    cortex.DWT.enable_cycle_counter();
    // A 1 ms tick, so that sleeping in `idle` never lasts longer than that.
    cortex.SYST.set_clock_source(SystClkSource::Core);
    cortex.SYST.set_reload(96_000 - 1);
    cortex.SYST.clear_current();
    cortex.SYST.enable_counter();
    cortex.SYST.enable_interrupt();

    // Allow writing to the backup registers.
    pac::PWR.cr1().modify(|w| w.set_dbp(true));
    while !pac::PWR.cr1().read().dbp() {}

    let mut led = Output::new(p.PC13, Level::Low, Speed::Low); // on during start-up
    let button = Input::new(p.PA0, Pull::Up);

    // Any bit pattern is a valid state for these two, so adopting whatever
    // the RAM holds is sound. Garbage in the vault simply fails to open.
    let vault = unsafe { (*addr_of_mut!(VAULT)).assume_init_mut() };
    let drbg = unsafe { (*addr_of_mut!(DRBG)).assume_init_mut() };
    drbg.reseed(&boot_entropy(p.ADC1));
    // `boot_entropy` has just zeroed it.
    let memory = unsafe { (*addr_of_mut!(ARGON)).assume_init_mut() };

    let mut uart_config = usart::Config::default();
    uart_config.baudrate = BAUD;
    let uart = BufferedUart::new(
        p.USART1,
        p.PA10,
        p.PA9,
        unsafe { &mut *addr_of_mut!(UART_TX) },
        unsafe { &mut *addr_of_mut!(UART_RX) },
        Irqs,
        uart_config,
    )
    .unwrap();
    let (tx, rx) = uart.split();

    led.set_high();
    let io = Io { rx, _tx: tx, button, led };
    let mut server = Server::new(vault, RtcBackup, CFG, io, drbg);
    defmt::info!("vomit-enforcer core up. PIN set: {=bool}", server.authenticator().pin_is_set());

    loop {
        server.poll(memory);
    }
}

#[exception]
fn SysTick() {}
