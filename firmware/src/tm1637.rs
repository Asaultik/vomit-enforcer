//! Bit-banged driver for the ubiquitous TM1637 4 digit 7-segment modules.
//! The modules carry their own pull-ups on CLK and DIO, so both lines are
//! driven open drain.

use embassy_stm32::gpio::{Flex, Pull, Speed};
use vomit_core::segments::Digits;

pub struct Tm1637<'d> {
    clk: Flex<'d>,
    dio: Flex<'d>,
    brightness: u8,
    /// What's on the glass right now, so redundant updates are skipped.
    shown: Option<Digits>,
}

/// ~5 us at 96 MHz. The TM1637 tops out around 250 kHz.
fn bit_delay() {
    cortex_m::asm::delay(480);
}

impl<'d> Tm1637<'d> {
    pub fn new(mut clk: Flex<'d>, mut dio: Flex<'d>, brightness: u8) -> Self {
        for p in [&mut clk, &mut dio] {
            p.set_high();
            p.set_as_input_output_pull(Speed::Low, Pull::Up);
        }
        Self { clk, dio, brightness: brightness.min(7), shown: None }
    }

    fn start(&mut self) {
        self.dio.set_low();
        bit_delay();
    }

    fn stop(&mut self) {
        self.clk.set_low();
        bit_delay();
        self.dio.set_low();
        bit_delay();
        self.clk.set_high();
        bit_delay();
        self.dio.set_high();
        bit_delay();
    }

    fn write_byte(&mut self, mut b: u8) {
        for _ in 0..8 {
            self.clk.set_low();
            bit_delay();
            if b & 1 != 0 {
                self.dio.set_high();
            } else {
                self.dio.set_low();
            }
            bit_delay();
            self.clk.set_high();
            bit_delay();
            b >>= 1;
        }
        // ACK clock. We don't care whether the chip acked: there's nothing
        // useful to do about a missing display.
        self.clk.set_low();
        self.dio.set_high();
        bit_delay();
        self.clk.set_high();
        bit_delay();
        self.clk.set_low();
        bit_delay();
    }

    fn command(&mut self, bytes: &[u8]) {
        self.start();
        for &b in bytes {
            self.write_byte(b);
        }
        self.stop();
    }

    pub fn show(&mut self, digits: Digits) {
        if self.shown == Some(digits) {
            return;
        }
        self.shown = Some(digits);
        // Data command: write, auto increment address.
        self.command(&[0x40]);
        // Address command starting at digit 0, then the four digits.
        self.command(&[0xc0, digits[0], digits[1], digits[2], digits[3]]);
        // Display on + brightness.
        self.command(&[0x88 | self.brightness]);
    }
}
