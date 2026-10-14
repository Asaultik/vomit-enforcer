//! Types the passphrase as a USB boot keyboard.

use embassy_stm32::usb::Driver;
use embassy_stm32::peripherals::USB_OTG_FS;
use embassy_time::{with_timeout, Duration, Timer};
use embassy_usb::class::hid::HidWriter;
use vomit_core::keymap::{ascii_to_hid, KEY_ENTER};
use vomit_core::render::Passphrase;

use crate::config;

pub type Writer = HidWriter<'static, Driver<'static, USB_OTG_FS>, 8>;

#[derive(Debug)]
pub enum TypeError {
    /// Nobody enumerated us within the timeout.
    NotConnected,
    Usb,
}

async fn report(w: &mut Writer, modifier: u8, key: u8) -> Result<(), TypeError> {
    let mut r = [0u8; 8];
    r[0] = modifier;
    r[2] = key;
    w.write(&r).await.map_err(|_| TypeError::Usb)?;
    Timer::after(Duration::from_millis(config::KEY_DELAY_MS)).await;
    Ok(())
}

pub async fn type_passphrase(w: &mut Writer, p: &Passphrase, enter: bool) -> Result<(), TypeError> {
    with_timeout(Duration::from_secs(5), w.ready()).await.map_err(|_| TypeError::NotConnected)?;
    for &c in p.as_bytes() {
        // Rendered passphrases only contain mappable characters.
        let (m, k) = ascii_to_hid(c).unwrap_or((0, 0));
        report(w, m, k).await?;
        // Release after every key so repeated characters register twice.
        report(w, 0, 0).await?;
    }
    if enter {
        report(w, 0, KEY_ENTER).await?;
        report(w, 0, 0).await?;
    }
    Ok(())
}
