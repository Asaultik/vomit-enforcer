//! vomit-enforcer bridge firmware for the RP2040-Zero.
//!
//! The only part of the device a host can reach. It shows up as a FIDO HID
//! device on USB, reassembles requests, and passes each one to the core as a
//! frame on UART0. It holds no secrets and does not understand the requests.
//! All of that behaviour is `vomit_link::bridge::Bridge`, tested on a PC;
//! this file moves bytes between it and the hardware.
//!
//! | What              | Pin  |                               |
//! | ----------------- | ---- | ----------------------------- |
//! | UART to core, TX  | GP0  | to the core's RX (PA10)       |
//! | UART to core, RX  | GP1  | from the core's TX (PA9)      |
//! | Status light      | GP16 | the onboard RGB LED           |
//!
//! The light: blue = powered, no host has spoken yet. Green = idle.
//! Amber = a request is with the core. Red (1 s) = the core did not answer;
//! check the three wires. White flash = the host asked us to identify.
//!
//! To flash: hold BOOT while plugging the board in, then
//! `cargo run --release` (uses picotool).

#![no_std]
#![no_main]

use embassy_executor::Spawner;
use embassy_futures::select::{select3, Either3};
use embassy_rp::peripherals::{DMA_CH0, PIO0, UART0, USB};
use embassy_rp::pio::Pio;
use embassy_rp::pio_programs::ws2812::{PioWs2812, PioWs2812Program};
use embassy_rp::uart::{self, BufferedUart};
use embassy_rp::usb::Driver;
use embassy_rp::{bind_interrupts, dma, pio, usb};
use embassy_time::{with_timeout, Duration, Instant, Timer};
use embassy_usb::class::hid::{self, HidBootProtocol, HidReaderWriter, HidSubclass};
use embassy_usb::UsbDevice;
use embedded_io_async::{Read, Write};
use smart_leds::RGB8;
use static_cell::StaticCell;
use vomit_link::bridge::Bridge;
use vomit_link::ctaphid::PACKET;
use vomit_link::frame::{BAUD, MAX_FRAME};

bind_interrupts!(struct Irqs {
    USBCTRL_IRQ => usb::InterruptHandler<USB>;
    UART0_IRQ => uart::BufferedInterruptHandler<UART0>;
    PIO0_IRQ_0 => pio::InterruptHandler<PIO0>;
    DMA_IRQ_0 => dma::InterruptHandler<DMA_CH0>;
});

/// The HID report descriptor every FIDO device uses: one 64-byte report each
/// way, on the FIDO Alliance usage page. This is how hosts recognise us.
const FIDO_REPORT_DESCRIPTOR: &[u8] = &[
    0x06, 0xD0, 0xF1, // Usage Page (FIDO Alliance)
    0x09, 0x01, //       Usage (CTAPHID)
    0xA1, 0x01, //       Collection (Application)
    0x09, 0x20, //         Usage (Data In)
    0x15, 0x00, //         Logical Minimum (0)
    0x26, 0xFF, 0x00, //   Logical Maximum (255)
    0x75, 0x08, //         Report Size (8)
    0x95, 0x40, //         Report Count (64)
    0x81, 0x02, //         Input (Data, Variable, Absolute)
    0x09, 0x21, //         Usage (Data Out)
    0x15, 0x00, //         Logical Minimum (0)
    0x26, 0xFF, 0x00, //   Logical Maximum (255)
    0x75, 0x08, //         Report Size (8)
    0x95, 0x40, //         Report Count (64)
    0x91, 0x02, //         Output (Data, Variable, Absolute)
    0xC0, //             End Collection
];

// pid.codes' ID for testing. Fine on your own desk; get one before sharing.
const USB_VID: u16 = 0x1209;
const USB_PID: u16 = 0x0001;

const OFF: RGB8 = RGB8 { r: 0, g: 0, b: 0 };
const BLUE: RGB8 = RGB8 { r: 0, g: 0, b: 12 };
const GREEN: RGB8 = RGB8 { r: 0, g: 10, b: 0 };
const AMBER: RGB8 = RGB8 { r: 14, g: 6, b: 0 };
const RED: RGB8 = RGB8 { r: 24, g: 0, b: 0 };
const WHITE: RGB8 = RGB8 { r: 16, g: 16, b: 16 };

#[embassy_executor::task]
async fn usb_task(mut device: UsbDevice<'static, Driver<'static, USB>>) -> ! {
    device.run().await
}

fn now_ms() -> u64 {
    Instant::now().as_millis()
}

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    let p = embassy_rp::init(Default::default());

    // ---- USB: one HID interface ----
    static CONFIG_DESCRIPTOR: StaticCell<[u8; 128]> = StaticCell::new();
    static BOS_DESCRIPTOR: StaticCell<[u8; 32]> = StaticCell::new();
    static MSOS_DESCRIPTOR: StaticCell<[u8; 0]> = StaticCell::new();
    static CONTROL_BUF: StaticCell<[u8; 64]> = StaticCell::new();
    static HID_STATE: StaticCell<hid::State> = StaticCell::new();

    let mut usb_config = embassy_usb::Config::new(USB_VID, USB_PID);
    usb_config.manufacturer = Some("Gibberish Inc.");
    usb_config.product = Some("Vomit Enforcer");
    usb_config.max_power = 100;
    let mut builder = embassy_usb::Builder::new(
        Driver::new(p.USB, Irqs),
        usb_config,
        CONFIG_DESCRIPTOR.init([0; 128]),
        BOS_DESCRIPTOR.init([0; 32]),
        MSOS_DESCRIPTOR.init([0; 0]),
        CONTROL_BUF.init([0; 64]),
    );
    let hid = HidReaderWriter::<_, PACKET, PACKET>::new(
        &mut builder,
        HID_STATE.init(hid::State::new()),
        hid::Config {
            report_descriptor: FIDO_REPORT_DESCRIPTOR,
            request_handler: None,
            poll_ms: 5,
            max_packet_size: PACKET as u16,
            hid_subclass: HidSubclass::No,
            hid_boot_protocol: HidBootProtocol::None,
        },
    );
    spawner.spawn(usb_task(builder.build()).unwrap());
    let (mut from_host, mut to_host) = hid.split();

    // ---- UART to the core ----
    static UART_TX: StaticCell<[u8; MAX_FRAME]> = StaticCell::new();
    static UART_RX: StaticCell<[u8; MAX_FRAME]> = StaticCell::new();
    let mut uart_config = uart::Config::default();
    uart_config.baudrate = BAUD;
    let uart = BufferedUart::new(
        p.UART0,
        p.PIN_0,
        p.PIN_1,
        Irqs,
        UART_TX.init([0; MAX_FRAME]),
        UART_RX.init([0; MAX_FRAME]),
        uart_config,
    );
    let (mut to_core, mut from_core) = uart.split();

    // ---- status light ----
    let Pio { mut common, sm0, .. } = Pio::new(p.PIO0, Irqs);
    let program = PioWs2812Program::new(&mut common);
    let mut light: PioWs2812<'_, PIO0, 0, 1, _> = PioWs2812::new(&mut common, sm0, p.DMA_CH0, Irqs, p.PIN_16, &program);
    let mut shown = OFF;
    let mut heard_from_host = false;
    let mut red_until = 0;
    let mut white_until = 0;

    static BRIDGE: StaticCell<Bridge> = StaticCell::new();
    let bridge = BRIDGE.init(Bridge::new());
    let mut packet = [0u8; PACKET];
    let mut bytes = [0u8; 64];
    let mut frame = [0u8; MAX_FRAME];

    loop {
        // Out: everything the bridge wants sent.
        while let Some(report) = bridge.poll_usb() {
            // If no program on the host has the device open, nothing reads
            // these. Don't wait forever; the reply would be stale anyway.
            let _ = with_timeout(Duration::from_millis(500), to_host.write(&report)).await;
        }
        loop {
            let n = bridge.take_uart(&mut frame);
            if n == 0 {
                break;
            }
            let _ = to_core.write_all(&frame[..n]).await;
        }

        // The light.
        let now = now_ms();
        if bridge.take_core_failed() {
            red_until = now + 1000;
        }
        if bridge.take_wink() {
            white_until = now + 300;
        }
        let colour = if now < white_until {
            WHITE
        } else if now < red_until {
            RED
        } else if bridge.busy() {
            AMBER
        } else if heard_from_host {
            GREEN
        } else {
            BLUE
        };
        if colour != shown {
            light.write(&[colour]).await;
            shown = colour;
        }

        // In: whichever comes first. All three are safe to abandon half way:
        // a report or byte that is not taken now is still there next time.
        match select3(from_host.read(&mut packet), from_core.read(&mut bytes), Timer::after_millis(5)).await {
            Either3::First(Ok(PACKET)) => {
                heard_from_host = true;
                bridge.usb_packet(&packet, now_ms());
            }
            Either3::Second(Ok(n)) => {
                let now = now_ms();
                for &byte in &bytes[..n] {
                    bridge.uart_byte(byte, now);
                }
            }
            _ => {}
        }
        bridge.tick(now_ms());
    }
}

/// There is no debugger on this board to report to. Start over.
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    cortex_m::peripheral::SCB::sys_reset()
}
