//! Potentiometer / analog hall effect dial on PA1 plus one insert button on
//! PA0 (the Black Pill's onboard KEY button, or an external one to GND in
//! parallel).
//!
//! * turn the dial         -> pick a value, shown on the display
//! * tap insert            -> commit it
//! * hold insert (>0.7 s)  -> commit it and vomit the passphrase
//! * hold insert (>3 s)    -> clear everything

use embassy_stm32::adc::{Adc, AnyAdcChannel, SampleTime};
use embassy_stm32::gpio::Input;
use embassy_stm32::peripherals::ADC1;
use vomit_core::button::{Press, PressTiming};
use vomit_core::dial::DialQuantizer;
use vomit_core::segments::{self, Digits};
use vomit_core::InputEvent;

use super::Frontend;
use crate::config;

pub struct DialFrontend<'d> {
    adc: Adc<'d, ADC1>,
    pin: AnyAdcChannel<'d, ADC1>,
    button: Input<'d>,
    quantizer: DialQuantizer,
    timing: PressTiming,
    pressed_at: Option<u64>,
}

impl<'d> DialFrontend<'d> {
    pub fn new(adc: Adc<'d, ADC1>, pin: AnyAdcChannel<'d, ADC1>, button: Input<'d>) -> Self {
        Self {
            adc,
            pin,
            button,
            quantizer: DialQuantizer::new(config::DIAL_STEPS, config::DIAL_HYSTERESIS).inverted(config::DIAL_INVERT),
            timing: PressTiming::default(),
            pressed_at: None,
        }
    }
}

impl Frontend for DialFrontend<'_> {
    const STEPS: u16 = config::DIAL_STEPS;

    fn poll(&mut self, now_ms: u64) -> [Option<InputEvent>; 2] {
        let raw = self.adc.blocking_read(&mut self.pin, SampleTime::CYCLES480);
        let preview = self.quantizer.update(raw).map(InputEvent::Preview);

        let down = self.button.is_low();
        let released = match (self.pressed_at, down) {
            (None, true) => {
                self.pressed_at = Some(now_ms);
                None
            }
            (Some(t), false) => {
                self.pressed_at = None;
                self.timing.classify((now_ms - t) as u32)
            }
            _ => None,
        };

        let value = self.quantizer.value().unwrap_or(0);
        match released {
            Some(Press::Short) => [Some(InputEvent::Insert(value)), None],
            Some(Press::Long) => [Some(InputEvent::Insert(value)), Some(InputEvent::Submit)],
            Some(Press::VeryLong) => [Some(InputEvent::Clear), None],
            None => [preview, None],
        }
    }

    fn view(&self, count: usize, now_ms: u64) -> Digits {
        // While the button is held, show what letting go will do.
        match self.pressed_at.and_then(|t| self.timing.pending((now_ms - t) as u32)) {
            Some(Press::Long) => segments::text(b"SEnd"),
            Some(Press::VeryLong) => segments::text(b"CLr "),
            _ => segments::entry_view(count, self.quantizer.value()),
        }
    }
}
