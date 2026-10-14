//! Unprovisioned mode: the device enumerates as a USB serial port (and not as
//! a keyboard) and waits for a seed. See `vomit_core::provision` for the
//! commands.

use embassy_stm32::adc::{Adc, AnyAdcChannel, SampleTime};
use embassy_stm32::peripherals::{ADC1, USB_OTG_FS};
use embassy_stm32::usb::Driver;
use embassy_usb::class::cdc_acm::CdcAcmClass;
use vomit_core::provision::{self, Command};
use vomit_core::seed::{EntropyPool, Seed};

use crate::vault;

pub type Serial = CdcAcmClass<'static, Driver<'static, USB_OTG_FS>>;

pub struct Entropy<'d> {
    pub adc: Adc<'d, ADC1>,
    pub pin: AnyAdcChannel<'d, ADC1>,
}

impl Entropy<'_> {
    /// LSBs of a floating / noisy analog input and the internal temperature
    /// sensor, sampled with the fastest sample time (noisier), mixed with the
    /// cycle counter. Better than nothing; worse than your computer's RNG.
    fn collect(&mut self) -> Seed {
        let mut temp = self.adc.enable_temperature();
        let mut pool = EntropyPool::default();
        let mut dwt = unsafe { cortex_m::Peripherals::steal() }.DWT;
        dwt.enable_cycle_counter();
        while pool.samples() < 16_384 {
            let a = self.adc.blocking_read(&mut self.pin, SampleTime::CYCLES3) as u32;
            let t = self.adc.blocking_read(&mut temp, SampleTime::CYCLES3) as u32;
            pool.add(a | t << 16);
            pool.add(cortex_m::peripheral::DWT::cycle_count());
        }
        pool.finish()
    }
}

async fn write(serial: &mut Serial, s: &[u8]) {
    for chunk in s.chunks(64) {
        if serial.write_packet(chunk).await.is_err() {
            return;
        }
    }
    // A full-size packet needs a terminating zero length packet.
    if s.len() % 64 == 0 {
        let _ = serial.write_packet(&[]).await;
    }
}

async fn report_fingerprint(serial: &mut Serial, prefix: &[u8]) {
    let mut line = [0u8; 64];
    let mut n = 0;
    let fp = vault::load().map(|s| provision::fingerprint_hex(s.fingerprint()));
    let parts: [&[u8]; 3] = match &fp {
        Some(hex) => [prefix, b"seed loaded, fingerprint ", hex],
        None => [prefix, b"no seed", b""],
    };
    for p in parts.iter().chain([&&b"\r\n"[..]]) {
        line[n..n + p.len()].copy_from_slice(p);
        n += p.len();
    }
    write(serial, &line[..n]).await;
}

/// Serve the serial console forever (until `reboot`).
pub async fn run(serial: &mut Serial, entropy: &mut Entropy<'_>) -> ! {
    let mut line = [0u8; 160];
    let mut len = 0;
    loop {
        serial.wait_connection().await;
        write(serial, b"\r\nvomit-enforcer: unprovisioned. `help` for commands.\r\n> ").await;
        let mut buf = [0u8; 64];
        loop {
            let Ok(n) = serial.read_packet(&mut buf).await else { break };
            for &c in &buf[..n] {
                match c {
                    b'\r' | b'\n' => {
                        write(serial, b"\r\n").await;
                        handle(serial, entropy, &line[..len]).await;
                        zeroize::Zeroize::zeroize(&mut line);
                        len = 0;
                        write(serial, b"> ").await;
                    }
                    0x08 | 0x7f if len > 0 => {
                        len -= 1;
                        write(serial, b"\x08 \x08").await;
                    }
                    0x20..=0x7e if len < line.len() => {
                        line[len] = c;
                        len += 1;
                        // Echo, but don't splash a typed seed across the terminal scrollback.
                        let shown = if len > 5 && line.starts_with(b"seed ") { b'*' } else { c };
                        write(serial, &[shown]).await;
                    }
                    _ => {}
                }
            }
            zeroize::Zeroize::zeroize(&mut buf);
        }
    }
}

async fn handle(serial: &mut Serial, entropy: &mut Entropy<'_>, line: &[u8]) {
    let store = |seed: Seed| {
        if vault::is_provisioned() {
            Err(&b"already provisioned; wipe first (hold KEY while plugging in)\r\n"[..])
        } else if vault::store(&seed) {
            Ok(())
        } else {
            Err(&b"write failed (tamper loop open?)\r\n"[..])
        }
    };
    match provision::parse(line) {
        Ok(Command::Help) => write(serial, provision::HELP.as_bytes()).await,
        Ok(Command::Status) => report_fingerprint(serial, b"").await,
        Ok(Command::Seed(seed)) => match store(seed) {
            Ok(()) => report_fingerprint(serial, b"ok, ").await,
            Err(e) => write(serial, e).await,
        },
        Ok(Command::Gen) => {
            write(serial, b"collecting entropy...\r\n").await;
            match store(entropy.collect()) {
                Ok(()) => {
                    report_fingerprint(serial, b"ok, ").await;
                    write(serial, b"note: there is no backup of this seed. lose power, lose passphrases.\r\n").await;
                }
                Err(e) => write(serial, e).await,
            }
        }
        Ok(Command::Reboot) => {
            write(serial, b"rebooting\r\n").await;
            embassy_time::Timer::after_millis(50).await;
            cortex_m::peripheral::SCB::sys_reset();
        }
        Err(e) => {
            write(serial, e.as_bytes()).await;
            write(serial, b"\r\n").await;
        }
    }
}
