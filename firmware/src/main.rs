//! vomit-enforcer firmware for the STM32F411 "Black Pill".
//!
//! Boot:
//! 1. Tamper flag set?       -> show `tAMP` until the button is pressed, then clear the flag.
//! 2. KEY held at power up?  -> count down, wipe the seed.
//! 3. No seed?               -> USB serial provisioning console, display `SEEd`.
//! 4. Seed present           -> USB keyboard. Enter a PIN, get a passphrase typed.

#![no_std]
#![no_main]

mod config;
mod input;
mod keyboard;
mod provision;
mod tm1637;
mod vault;

use embassy_executor::Spawner;
use embassy_stm32::adc::{Adc, AdcChannel};
use embassy_stm32::gpio::{Flex, Input, Pull};
use embassy_stm32::peripherals::USB_OTG_FS;
use embassy_stm32::rcc::{self, LsConfig};
use embassy_stm32::time::Hertz;
use embassy_stm32::{bind_interrupts, usb, Config};
use embassy_time::{Instant, Timer};
use embassy_usb::class::cdc_acm::{self, CdcAcmClass};
use embassy_usb::class::hid::{self, HidBootProtocol, HidSubclass, HidWriter};
use embassy_usb::UsbDevice;
use panic_halt as _;
use static_cell::StaticCell;
use usbd_hid::descriptor::{KeyboardReport, SerializedDescriptor};
use vomit_core::entry::{Outcome, PinEntry};
use vomit_core::kdf::{derive_pin_key, OutputStream};
use vomit_core::render::render;
use vomit_core::segments;

use crate::input::Frontend;
use crate::tm1637::Tm1637;

bind_interrupts!(struct Irqs {
    OTG_FS => usb::InterruptHandler<USB_OTG_FS>;
});

type UsbDriver = usb::Driver<'static, USB_OTG_FS>;

fn clocks() -> Config {
    let mut c = Config::default();
    // Black Pill: 25 MHz HSE -> 96 MHz SYSCLK, 48 MHz for USB.
    c.rcc.hse = Some(rcc::Hse { freq: Hertz(25_000_000), mode: rcc::HseMode::Oscillator });
    c.rcc.pll_src = rcc::PllSource::HSE;
    c.rcc.pll = Some(rcc::Pll {
        prediv: rcc::PllPreDiv::DIV25,
        mul: rcc::PllMul::MUL192,
        divp: Some(rcc::PllPDiv::DIV2),
        divq: Some(rcc::PllQDiv::DIV4),
        divr: None,
    });
    c.rcc.sys = rcc::Sysclk::PLL1_P;
    c.rcc.ahb_pre = rcc::AHBPrescaler::DIV1;
    c.rcc.apb1_pre = rcc::APBPrescaler::DIV2;
    c.rcc.apb2_pre = rcc::APBPrescaler::DIV1;
    // The 32.768 kHz LSE keeps running on VBAT, so the RTC (and its tamper
    // logic) stays alive on the coin cell. Don't change this once
    // provisioned: embassy resets the backup domain (= wipes the seed) if the
    // RTC clock config doesn't match what's already there.
    c.rcc.ls = LsConfig::default_lse();
    c
}

#[embassy_executor::task]
async fn usb_task(mut dev: UsbDevice<'static, UsbDriver>) -> ! {
    dev.run().await
}

fn usb_builder(otg: embassy_stm32::Peri<'static, USB_OTG_FS>, dp: embassy_stm32::Peri<'static, embassy_stm32::peripherals::PA12>, dm: embassy_stm32::Peri<'static, embassy_stm32::peripherals::PA11>, product: &'static str) -> embassy_usb::Builder<'static, UsbDriver> {
    static EP_OUT: StaticCell<[u8; 256]> = StaticCell::new();
    static CONFIG_DESC: StaticCell<[u8; 256]> = StaticCell::new();
    static BOS_DESC: StaticCell<[u8; 256]> = StaticCell::new();
    static MSOS_DESC: StaticCell<[u8; 0]> = StaticCell::new();
    static CONTROL: StaticCell<[u8; 64]> = StaticCell::new();

    let mut otg_config = usb::Config::default();
    // Bus powered, so VBUS is always there when we're running.
    otg_config.vbus_detection = false;
    let driver = usb::Driver::new_fs(otg, Irqs, dp, dm, EP_OUT.init([0; 256]), otg_config);

    let mut cfg = embassy_usb::Config::new(config::USB_VID, config::USB_PID);
    cfg.manufacturer = Some("vomit-enforcer");
    cfg.product = Some(product);
    cfg.max_power = 100;

    embassy_usb::Builder::new(
        driver,
        cfg,
        CONFIG_DESC.init([0; 256]),
        BOS_DESC.init([0; 256]),
        MSOS_DESC.init([0; 0]),
        CONTROL.init([0; 64]),
    )
}

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    let p = embassy_stm32::init(clocks());

    let mut display = Tm1637::new(Flex::new(p.PB6), Flex::new(p.PB7), config::DISPLAY_BRIGHTNESS);
    let key = Input::new(p.PA0, Pull::Up);

    vault::arm_tamper();

    // 1. Tamper. Make the user acknowledge it, so a wipe never goes unnoticed.
    if vault::tampered() {
        display.show(segments::text(b"tAMP"));
        while key.is_high() {
            Timer::after_millis(10).await;
        }
        while key.is_low() {
            Timer::after_millis(10).await;
        }
        vault::clear_tamper_flag();
    }

    // 2. Wipe on request.
    if key.is_low() {
        let start = Instant::now();
        loop {
            let held = start.elapsed().as_millis();
            if key.is_high() {
                break;
            }
            if held >= config::WIPE_HOLD_MS {
                vault::wipe();
                display.show(segments::text(b"dEAd"));
                while key.is_low() {
                    Timer::after_millis(10).await;
                }
                break;
            }
            let left = ((config::WIPE_HOLD_MS - held) / 1000 + 1) as u8;
            display.show([segments::glyph(b'-'), segments::glyph(b'-'), segments::glyph(b'-'), segments::digit(left)]);
            Timer::after_millis(20).await;
        }
    }

    let adc = Adc::new(p.ADC1);

    // 3. Provisioning.
    if !vault::is_provisioned() {
        display.show(segments::text(b"SEEd"));
        let mut builder = usb_builder(p.USB_OTG_FS, p.PA12, p.PA11, "vomit-enforcer (unprovisioned)");
        static CDC_STATE: StaticCell<cdc_acm::State> = StaticCell::new();
        let mut serial = CdcAcmClass::new(&mut builder, CDC_STATE.init(cdc_acm::State::new()), 64);
        spawner.spawn(usb_task(builder.build()).unwrap());
        let mut entropy = provision::Entropy { adc, pin: p.PA1.degrade_adc() };
        provision::run(&mut serial, &mut entropy).await;
    }

    // 4. Keyboard.
    let mut builder = usb_builder(p.USB_OTG_FS, p.PA12, p.PA11, "vomit-enforcer");
    static HID_STATE: StaticCell<hid::State> = StaticCell::new();
    let mut writer: keyboard::Writer = HidWriter::new(
        &mut builder,
        HID_STATE.init(hid::State::new()),
        hid::Config {
            report_descriptor: KeyboardReport::desc(),
            request_handler: None,
            poll_ms: 1,
            max_packet_size: 8,
            // Boot protocol so it also works in BIOS/UEFI and bootloaders.
            hid_subclass: HidSubclass::Boot,
            hid_boot_protocol: HidBootProtocol::Keyboard,
        },
    );
    spawner.spawn(usb_task(builder.build()).unwrap());

    #[cfg(feature = "input-dial")]
    let mut frontend = input::Active::new(adc, p.PA1.degrade_adc(), key);
    #[cfg(feature = "input-keypad")]
    let mut frontend = {
        use embassy_stm32::gpio::{Level, Output, Speed};
        let _ = (adc, key);
        input::Active::new(
            [
                Output::new(p.PB12, Level::High, Speed::Low),
                Output::new(p.PB13, Level::High, Speed::Low),
                Output::new(p.PB14, Level::High, Speed::Low),
                Output::new(p.PB15, Level::High, Speed::Low),
            ],
            [Input::new(p.PB0, Pull::Up), Input::new(p.PB1, Pull::Up), Input::new(p.PB10, Pull::Up)],
        )
    };

    let mut entry = PinEntry::new(<input::Active as Frontend>::STEPS, config::MIN_ENTRIES);
    let mut last_input = Instant::now();

    loop {
        let now = Instant::now().as_millis();

        if vault::tampered() {
            entry.clear();
            display.show(segments::text(b"tAMP"));
            // The seed is gone already. Reboot into the acknowledge screen.
            Timer::after_millis(500).await;
            cortex_m::peripheral::SCB::sys_reset();
        }

        for ev in frontend.poll(now).into_iter().flatten() {
            last_input = Instant::now();
            if entry.handle(ev) == Outcome::Submitted {
                display.show(segments::text(b"----"));
                let pin = entry.take();
                let result = match vault::load() {
                    Some(seed) => {
                        let mut stream = OutputStream::new(derive_pin_key(&seed, &pin));
                        drop(seed);
                        drop(pin);
                        let phrase = render(&mut stream, &config::OUTPUT);
                        drop(stream);
                        keyboard::type_passphrase(&mut writer, &phrase, config::OUTPUT.enter).await
                    }
                    None => Err(keyboard::TypeError::Usb),
                };
                display.show(segments::text(if result.is_ok() { b"donE" } else { b"Err " }));
                Timer::after_millis(1000).await;
            }
        }

        if entry.count() > 0 && last_input.elapsed().as_millis() > config::IDLE_CLEAR_MS {
            entry.clear();
        }

        display.show(frontend.view(entry.count(), now));
        Timer::after_millis(5).await;
    }
}
