//! The core's main loop, minus the hardware.
//!
//! [`Server::poll`] reads bytes from the bridge, and for each request frame
//! acknowledges it, runs the authenticator and sends the reply. The firmware
//! supplies a [`CoreIo`] (UART, button, clock) and calls `poll` forever.
//!
//! The bridge is not trusted. All it can do here is deliver bytes, which go
//! through the frame decoder and then the authenticator's own parsing.

use vomit_core::backup::BackupStore;
use vomit_core::kdf::Block;
use vomit_core::vault::{Config, Vault};
use vomit_link::frame::{self, Decoder, Kind, MAX_FRAME, MAX_PAYLOAD, OVERHEAD, STATUS_PROCESSING, STATUS_UP_NEEDED};

use crate::authenticator::{Authenticator, Platform, Presence};
use crate::rng::Drbg;

/// How long a request waits for a touch.
pub const UP_TIMEOUT_MS: u64 = 30_000;
/// The button must be seen released, then held this long.
pub const DEBOUNCE_MS: u64 = 20;
/// How often the vault is re-encrypted under a fresh master key.
pub const ROTATE_MS: u64 = 5 * 60_000;
/// A frame with a gap this long in the middle is dropped.
pub const LINK_GAP_MS: u64 = 100;

/// The hardware, as the core's main loop sees it.
pub trait CoreIo {
    /// A clock that only goes forward.
    fn now_ms(&mut self) -> u64;
    /// The next byte from the bridge, if one is waiting. Must not block.
    fn read_byte(&mut self) -> Option<u8>;
    /// Send bytes to the bridge.
    fn write(&mut self, bytes: &[u8]);
    /// Whether the touch button is held down right now.
    fn button_down(&mut self) -> bool;
    /// Something cheap and hard to predict, such as a cycle counter. It is
    /// mixed into the random generator; it is not relied on.
    fn jitter(&mut self) -> u32 {
        0
    }
    /// Show the user whether a touch is being waited for.
    fn indicate(&mut self, _waiting_for_touch: bool) {}
    /// Nothing to do: sleep until the next interrupt, a millisecond at most.
    fn idle(&mut self) {}
}

pub struct Server<'a, B: BackupStore, IO: CoreIo> {
    auth: Authenticator<'a, B>,
    io: IO,
    drbg: &'a mut Drbg,
    decoder: Decoder,
    response: [u8; MAX_PAYLOAD],
    frame: [u8; MAX_FRAME],
    last_byte_ms: u64,
    last_rotate_ms: u64,
    up_timeout_ms: u64,
}

impl<'a, B: BackupStore, IO: CoreIo> Server<'a, B, IO> {
    /// `drbg` must already be seeded with everything unpredictable the
    /// firmware could find.
    pub fn new(vault: &'a mut Vault, bkp: B, cfg: Config, mut io: IO, drbg: &'a mut Drbg) -> Self {
        let now = io.now_ms();
        let mut host = Host { io: &mut io, drbg: &mut *drbg, id: 0, up_timeout_ms: UP_TIMEOUT_MS };
        let auth = Authenticator::new(vault, bkp, cfg, &mut host);
        Self {
            auth,
            io,
            drbg,
            decoder: Decoder::new(),
            response: [0; MAX_PAYLOAD],
            frame: [0; MAX_FRAME],
            last_byte_ms: now,
            last_rotate_ms: now,
            up_timeout_ms: UP_TIMEOUT_MS,
        }
    }

    /// Shorten the wait for a touch (for tests and the simulator).
    pub fn set_up_timeout_ms(&mut self, ms: u64) {
        self.up_timeout_ms = ms;
    }

    pub fn authenticator(&self) -> &Authenticator<'a, B> {
        &self.auth
    }

    /// Do whatever there is to do, then return. `memory` is Argon2 scratch.
    pub fn poll(&mut self, memory: &mut [Block]) {
        let mut idle = true;
        while let Some(byte) = self.io.read_byte() {
            idle = false;
            self.last_byte_ms = self.io.now_ms();
            let Some(request) = self.decoder.push(byte) else { continue };
            if request.kind != Kind::Request {
                continue; // a cancel for a request that already finished
            }
            let mut host =
                Host { io: &mut self.io, drbg: &mut *self.drbg, id: request.id, up_timeout_ms: self.up_timeout_ms };
            // The first status doubles as "request received".
            host.status(STATUS_PROCESSING);
            let n = self.auth.handle(&mut host, memory, request.payload, &mut self.response);
            if let Some(reply) = frame::encode(Kind::Response, request.id, &self.response[..n], &mut self.frame) {
                self.io.write(reply);
            }
        }

        let now = self.io.now_ms();
        if self.decoder.in_frame() && now.saturating_sub(self.last_byte_ms) > LINK_GAP_MS {
            self.decoder.reset();
        }
        self.auth.tick(now);
        if now.saturating_sub(self.last_rotate_ms) >= ROTATE_MS {
            self.last_rotate_ms = now;
            let mut noise = [0u8; 16];
            self.drbg.fill(&mut noise);
            self.auth.rotate(&noise);
        }
        if idle {
            self.io.idle();
        }
    }
}

/// The authenticator's view of the world while one request is being handled.
struct Host<'s, IO: CoreIo> {
    io: &'s mut IO,
    drbg: &'s mut Drbg,
    id: u8,
    up_timeout_ms: u64,
}

impl<IO: CoreIo> Host<'_, IO> {
    fn status(&mut self, status: u8) {
        let mut buf = [0u8; OVERHEAD + 1];
        if let Some(f) = frame::encode(Kind::Status, self.id, &[status], &mut buf) {
            self.io.write(f);
        }
    }

    fn wait_for_touch(&mut self) -> Presence {
        // The only thing the bridge may send during a request is a cancel for
        // it. That is one fixed frame, so look for exactly those bytes.
        let mut cancel = [0u8; OVERHEAD];
        let cancel_len = frame::encode(Kind::Cancel, self.id, &[], &mut cancel).map_or(0, |f| f.len());
        let mut recent = [0u8; OVERHEAD];

        let start = self.io.now_ms();
        // A button already held when the request arrives does not count: it
        // has to be released first, then pressed and held.
        let mut released = false;
        let mut down_since = None;
        loop {
            let now = self.io.now_ms();
            if now.saturating_sub(start) >= self.up_timeout_ms {
                return Presence::TimedOut;
            }
            while let Some(byte) = self.io.read_byte() {
                recent.rotate_left(1);
                recent[OVERHEAD - 1] = byte;
                if cancel_len == OVERHEAD && recent == cancel {
                    return Presence::Cancelled;
                }
            }
            if !self.io.button_down() {
                released = true;
                down_since = None;
            } else if released {
                let since = *down_since.get_or_insert(now);
                if now.saturating_sub(since) >= DEBOUNCE_MS {
                    // When exactly a human presses a button is a little
                    // entropy for free.
                    self.drbg.reseed(&self.io.jitter().to_le_bytes());
                    return Presence::Confirmed;
                }
            }
            self.io.idle();
        }
    }
}

impl<IO: CoreIo> Platform for Host<'_, IO> {
    fn now_ms(&mut self) -> u64 {
        self.io.now_ms()
    }

    fn random(&mut self, out: &mut [u8]) {
        let mut sample = [0u8; 12];
        sample[..4].copy_from_slice(&self.io.jitter().to_le_bytes());
        sample[4..].copy_from_slice(&self.io.now_ms().to_le_bytes());
        self.drbg.reseed(&sample);
        self.drbg.fill(out);
    }

    fn user_presence(&mut self) -> Presence {
        self.status(STATUS_UP_NEEDED);
        self.io.indicate(true);
        let result = self.wait_for_touch();
        self.io.indicate(false);
        self.status(STATUS_PROCESSING);
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::status;
    use std::collections::VecDeque;
    use vomit_core::backup::MemBackup;
    use vomit_core::kdf::KdfParams;

    /// A scripted world: bytes to deliver, and what the button does when.
    #[derive(Default)]
    struct FakeIo {
        now: u64,
        rx: VecDeque<u8>,
        tx: Vec<u8>,
        /// The button is down between these times.
        press: Option<(u64, u64)>,
        /// Bytes that arrive from the bridge at a given time.
        later: Vec<(u64, Vec<u8>)>,
        indicated: Vec<bool>,
    }

    impl CoreIo for &mut FakeIo {
        fn now_ms(&mut self) -> u64 {
            self.now
        }
        fn read_byte(&mut self) -> Option<u8> {
            let now = self.now;
            let (due, pending): (Vec<_>, Vec<_>) = self.later.drain(..).partition(|(at, _)| *at <= now);
            self.later = pending;
            for (_, bytes) in due {
                self.rx.extend(bytes);
            }
            self.rx.pop_front()
        }
        fn write(&mut self, bytes: &[u8]) {
            self.tx.extend_from_slice(bytes);
        }
        fn button_down(&mut self) -> bool {
            self.press.is_some_and(|(from, to)| (from..to).contains(&self.now))
        }
        fn indicate(&mut self, waiting: bool) {
            self.indicated.push(waiting);
        }
        fn idle(&mut self) {
            self.now += 1;
        }
    }

    const CFG: Config = Config {
        max_failures: 8,
        base_delay_ms: 1000,
        max_delay_ms: 60_000,
        admin_window_ms: 60_000,
        kdf: KdfParams { passes: 1 },
    };

    fn frame_bytes(kind: Kind, id: u8, payload: &[u8]) -> Vec<u8> {
        let mut buf = [0u8; MAX_FRAME];
        frame::encode(kind, id, payload, &mut buf).unwrap().to_vec()
    }

    fn frames(bytes: &[u8]) -> Vec<(Kind, u8, Vec<u8>)> {
        let mut dec = Decoder::new();
        bytes.iter().filter_map(|&b| dec.push(b).map(|f| (f.kind, f.id, f.payload.to_vec()))).collect()
    }

    /// Run one request through a fresh server and return the frames it sent.
    fn run(io: &mut FakeIo, request: &[u8]) -> Vec<(Kind, u8, Vec<u8>)> {
        let mut vault = Vault::new();
        let mut drbg = Drbg::new();
        drbg.reseed(b"test");
        let mut memory = [Block::default(); 8];
        io.rx.extend(frame_bytes(Kind::Request, 42, request));
        let mut server = Server::new(&mut vault, MemBackup::default(), CFG, &mut *io, &mut drbg);
        server.set_up_timeout_ms(500);
        server.poll(&mut memory);
        drop(server);
        frames(&io.tx)
    }

    #[test]
    fn request_is_acknowledged_then_answered() {
        let mut io = FakeIo::default();
        let out = run(&mut io, &[0x04]);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0], (Kind::Status, 42, vec![STATUS_PROCESSING]));
        assert_eq!((out[1].0, out[1].1, out[1].2[0]), (Kind::Response, 42, status::OK));
    }

    #[test]
    fn garbage_on_the_line_is_ignored() {
        let mut io = FakeIo::default();
        io.rx.extend([0xA5, 0x01, 0x00, 0xFF, 0xFF, 0x12, 0x34, 0x00, 0xA5]);
        let out = run(&mut io, &[0x04]);
        assert_eq!(out.last().unwrap().2[0], status::OK);
    }

    // authenticatorReset is the one command that asks for a touch without a
    // PIN being set, which makes it the simplest way to exercise the wait.

    #[test]
    fn touch_confirms() {
        let mut io = FakeIo { press: Some((100, 200)), ..Default::default() };
        let out = run(&mut io, &[0x07]);
        let kinds: Vec<_> = out.iter().map(|f| (f.0, f.2.clone())).collect();
        assert_eq!(
            kinds,
            vec![
                (Kind::Status, vec![STATUS_PROCESSING]),
                (Kind::Status, vec![STATUS_UP_NEEDED]),
                (Kind::Status, vec![STATUS_PROCESSING]),
                (Kind::Response, vec![status::OK]),
            ]
        );
        assert_eq!(io.indicated, vec![true, false]);
        assert!(io.now >= 100 + DEBOUNCE_MS && io.now < 200);
    }

    #[test]
    fn a_button_held_from_before_does_not_count() {
        let mut io = FakeIo { press: Some((0, 10_000)), ..Default::default() };
        let out = run(&mut io, &[0x07]);
        assert_eq!(out.last().unwrap().2, vec![status::ACTION_TIMEOUT]);
    }

    #[test]
    fn a_bounce_does_not_count() {
        let mut io = FakeIo { press: Some((100, 100 + DEBOUNCE_MS - 1)), ..Default::default() };
        let out = run(&mut io, &[0x07]);
        assert_eq!(out.last().unwrap().2, vec![status::ACTION_TIMEOUT]);
    }

    #[test]
    fn no_touch_times_out() {
        let mut io = FakeIo::default();
        let out = run(&mut io, &[0x07]);
        assert_eq!(out.last().unwrap().2, vec![status::ACTION_TIMEOUT]);
        assert!(io.now >= 500);
    }

    #[test]
    fn cancel_for_this_request_ends_the_wait() {
        let mut io = FakeIo::default();
        io.later.push((50, frame_bytes(Kind::Cancel, 42, &[])));
        let out = run(&mut io, &[0x07]);
        assert_eq!(out.last().unwrap().2, vec![status::KEEPALIVE_CANCEL]);
        assert!(io.now < 100);
    }

    #[test]
    fn cancel_for_another_request_is_ignored() {
        let mut io = FakeIo::default();
        io.later.push((50, frame_bytes(Kind::Cancel, 41, &[])));
        let out = run(&mut io, &[0x07]);
        assert_eq!(out.last().unwrap().2, vec![status::ACTION_TIMEOUT]);
    }
}
