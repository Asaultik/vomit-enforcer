//! Line protocol spoken over USB serial while the device is unprovisioned.
//!
//! ```text
//! seed <64 hex chars>   load a seed you generated elsewhere (recommended)
//! gen                   generate one on chip from ADC noise (weak-ish, see EntropyPool)
//! status                show whether a seed is loaded and its fingerprint
//! reboot                restart into keyboard mode
//! ```
//!
//! There is intentionally no command to read the seed back, and the serial
//! port does not exist at all once the device is provisioned: it then boots
//! as a plain keyboard. Wiping is physical only (tamper loop, or hold the
//! button while plugging in).

use crate::seed::Seed;

pub enum Command {
    Seed(Seed),
    Gen,
    Status,
    Reboot,
    Help,
}

pub fn parse(line: &[u8]) -> Result<Command, &'static str> {
    let line = trim(line);
    let (cmd, arg) = match line.iter().position(|&c| c == b' ') {
        Some(i) => (&line[..i], trim(&line[i + 1..])),
        None => (line, &[][..]),
    };
    match cmd {
        b"seed" => Seed::from_hex(arg).map(Command::Seed).ok_or("expected 64 hex characters"),
        b"gen" => Ok(Command::Gen),
        b"status" => Ok(Command::Status),
        b"reboot" => Ok(Command::Reboot),
        b"help" | b"?" | b"" => Ok(Command::Help),
        _ => Err("unknown command, try `help`"),
    }
}

fn trim(s: &[u8]) -> &[u8] {
    let start = s.iter().position(|c| !c.is_ascii_whitespace()).unwrap_or(s.len());
    let end = s.iter().rposition(|c| !c.is_ascii_whitespace()).map_or(start, |i| i + 1);
    &s[start..end]
}

pub const HELP: &str = "commands:\r\n  seed <64 hex>  load seed\r\n  gen            generate seed on chip\r\n  status         show fingerprint\r\n  reboot         start as keyboard\r\n";

/// Formats a fingerprint as 8 hex characters.
pub fn fingerprint_hex(fp: u32) -> [u8; 8] {
    const H: &[u8] = b"0123456789abcdef";
    core::array::from_fn(|i| H[(fp >> (28 - 4 * i)) as usize & 0xf])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parsing() {
        assert!(matches!(parse(b"  status\r\n"), Ok(Command::Status)));
        assert!(matches!(parse(b"gen"), Ok(Command::Gen)));
        assert!(matches!(parse(&[b"seed ".as_slice(), &[b'a'; 64]].concat()), Ok(Command::Seed(_))));
        assert!(parse(b"seed abc").is_err());
        assert!(parse(b"rm -rf").is_err());
        assert_eq!(&fingerprint_hex(0xdeadbeef), b"deadbeef");
    }
}
