//! Everything the bridge does, as one state machine with no I/O.
//!
//! The firmware's job is only to move bytes: USB packets and UART bytes in,
//! USB packets and UART bytes out, and a clock.
//!
//! The bridge holds no secrets and understands no CTAP2. It reassembles a
//! request, hands it to the core in one frame, keeps the host informed while
//! the core works, and passes the reply back.

use crate::ctaphid::{Action, CtapHid, PACKET};
use crate::frame::{self, Decoder, Kind, MAX_FRAME, STATUS_PROCESSING, STATUS_UP_NEEDED};

/// How often the host is told a request is still in progress.
pub const KEEPALIVE_MS: u64 = 100;
/// The core must acknowledge a request this fast, or the link is considered
/// dead and the host gets an error straight away.
pub const ACK_TIMEOUT_MS: u64 = 1_000;
/// Upper bound on any request, including waiting for a touch.
pub const CORE_TIMEOUT_MS: u64 = 45_000;
/// A frame from the core with a gap this long in the middle is dropped.
pub const LINK_GAP_MS: u64 = 100;

/// CTAP1_ERR_OTHER: what the host sees if the core never answers.
const ERR_OTHER: u8 = 0x7F;

struct Wait {
    id: u8,
    since_ms: u64,
    last_keepalive_ms: u64,
    status: u8,
    acked: bool,
}

pub struct Bridge {
    hid: CtapHid,
    dec: Decoder,
    wait: Option<Wait>,
    next_id: u8,
    /// A request frame not yet handed to the UART.
    out: [u8; MAX_FRAME],
    out_len: usize,
    /// Request id the core should be told to give up on.
    cancel: Option<u8>,
    last_byte_ms: u64,
    wink: bool,
    core_failed: bool,
}

impl Bridge {
    pub const fn new() -> Self {
        Self {
            hid: CtapHid::new(),
            dec: Decoder::new(),
            wait: None,
            next_id: 0,
            out: [0; MAX_FRAME],
            out_len: 0,
            cancel: None,
            last_byte_ms: 0,
            wink: false,
            core_failed: false,
        }
    }

    /// A 64-byte report arrived from the host.
    pub fn usb_packet(&mut self, pkt: &[u8; PACKET], now_ms: u64) {
        match self.hid.handle_packet(pkt, now_ms) {
            Action::Forward => {
                let id = self.next_id;
                self.next_id = self.next_id.wrapping_add(1);
                // Cannot fail: CTAPHID accepts nothing longer than a frame holds.
                self.out_len =
                    frame::encode(Kind::Request, id, self.hid.request(), &mut self.out).map_or(0, |f| f.len());
                self.wait = Some(Wait {
                    id,
                    since_ms: now_ms,
                    last_keepalive_ms: now_ms,
                    status: STATUS_PROCESSING,
                    acked: false,
                });
            }
            Action::Cancel => {
                if let Some(w) = &self.wait {
                    self.cancel = Some(w.id);
                }
                // The host walked away (INIT): forget the request. A late
                // reply carries an id nothing is waiting for.
                if !self.hid.is_pending() {
                    self.wait = None;
                }
            }
            Action::Wink => self.wink = true,
            Action::None => {}
        }
    }

    /// A byte arrived from the core.
    pub fn uart_byte(&mut self, byte: u8, now_ms: u64) {
        self.last_byte_ms = now_ms;
        let Some(f) = self.dec.push(byte) else { return };
        let Some(w) = &mut self.wait else { return };
        if f.id != w.id {
            return;
        }
        match f.kind {
            Kind::Response => {
                self.hid.complete(f.payload);
                self.wait = None;
            }
            Kind::Status => {
                w.acked = true;
                if let [status] = f.payload {
                    // Don't make the user wait for the next keepalive to be
                    // told to touch the device.
                    if *status == STATUS_UP_NEEDED && w.status != STATUS_UP_NEEDED {
                        w.last_keepalive_ms = now_ms;
                        self.hid.keepalive(*status);
                    }
                    w.status = *status;
                }
            }
            Kind::Request | Kind::Cancel => {}
        }
    }

    /// Call every few milliseconds.
    pub fn tick(&mut self, now_ms: u64) {
        self.hid.tick(now_ms);
        if self.dec.in_frame() && now_ms.saturating_sub(self.last_byte_ms) > LINK_GAP_MS {
            self.dec.reset();
        }
        let Some(w) = &mut self.wait else { return };
        let age = now_ms.saturating_sub(w.since_ms);
        if age > CORE_TIMEOUT_MS || (!w.acked && age > ACK_TIMEOUT_MS) {
            self.cancel = Some(w.id);
            self.wait = None;
            self.core_failed = true;
            self.hid.complete(&[ERR_OTHER]);
        } else if now_ms.saturating_sub(w.last_keepalive_ms) >= KEEPALIVE_MS {
            w.last_keepalive_ms = now_ms;
            self.hid.keepalive(w.status);
        }
    }

    /// Next report for the host, if any.
    pub fn poll_usb(&mut self) -> Option<[u8; PACKET]> {
        self.hid.poll_tx()
    }

    /// Bytes for the core, if any, copied into `out`. Returns how many.
    pub fn take_uart(&mut self, out: &mut [u8; MAX_FRAME]) -> usize {
        // A cancel is always for an older request than the one waiting to
        // go out, and the core, while it waits for a touch, throws away
        // everything but a cancel. So the cancel goes first.
        if let Some(id) = self.cancel.take() {
            return frame::encode(Kind::Cancel, id, &[], out).map_or(0, |f| f.len());
        }
        let n = core::mem::take(&mut self.out_len);
        out[..n].copy_from_slice(&self.out[..n]);
        n
    }

    /// True once per WINK from the host: blink something.
    pub fn take_wink(&mut self) -> bool {
        core::mem::take(&mut self.wink)
    }

    /// True once each time the core failed to answer (for a status light).
    pub fn take_core_failed(&mut self) -> bool {
        core::mem::take(&mut self.core_failed)
    }

    /// True while a request is with the core (for a status light).
    pub fn busy(&self) -> bool {
        self.wait.is_some()
    }
}

impl Default for Bridge {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ctaphid::tests::packets;
    use crate::ctaphid::{cmd, PACKET};

    const CID: u32 = 7;

    fn send(b: &mut Bridge, command: u8, data: &[u8], now: u64) {
        for p in packets(CID, command, data) {
            b.usb_packet(&p, now);
        }
    }

    fn uart(b: &mut Bridge) -> Vec<u8> {
        let mut buf = [0u8; MAX_FRAME];
        let n = b.take_uart(&mut buf);
        buf[..n].to_vec()
    }

    fn from_core(b: &mut Bridge, kind: Kind, id: u8, payload: &[u8], now: u64) {
        let mut buf = [0u8; MAX_FRAME];
        for &byte in frame::encode(kind, id, payload, &mut buf).unwrap() {
            b.uart_byte(byte, now);
        }
    }

    fn usb(b: &mut Bridge) -> Vec<[u8; PACKET]> {
        core::iter::from_fn(|| b.poll_usb()).collect()
    }

    fn decode(bytes: &[u8]) -> (Kind, u8, Vec<u8>) {
        let mut dec = Decoder::new();
        let f = bytes.iter().find_map(|&b| dec.push(b).map(|f| (f.kind, f.id, f.payload.to_vec())));
        f.expect("not a frame")
    }

    #[test]
    fn request_goes_to_core_and_reply_comes_back() {
        let mut b = Bridge::new();
        send(&mut b, cmd::CBOR, &[0x04], 0);
        let (kind, id, payload) = decode(&uart(&mut b));
        assert_eq!((kind, payload), (Kind::Request, vec![0x04]));
        assert!(uart(&mut b).is_empty(), "sent once");
        assert!(b.busy());

        from_core(&mut b, Kind::Status, id, &[STATUS_PROCESSING], 5);
        b.tick(KEEPALIVE_MS);
        let ka = usb(&mut b);
        assert_eq!(ka.len(), 1);
        assert_eq!(&ka[0][4..8], &[0x80 | cmd::KEEPALIVE, 0, 1, STATUS_PROCESSING]);

        // "Touch needed" is passed on at once, then repeated like any other.
        from_core(&mut b, Kind::Status, id, &[STATUS_UP_NEEDED], 150);
        let ka = usb(&mut b);
        assert_eq!((ka.len(), ka[0][7]), (1, STATUS_UP_NEEDED));
        b.tick(150 + KEEPALIVE_MS - 1);
        assert!(usb(&mut b).is_empty());
        b.tick(150 + KEEPALIVE_MS);
        assert_eq!(usb(&mut b)[0][7], STATUS_UP_NEEDED);

        from_core(&mut b, Kind::Response, id, &[0x00, 0xA0], 300);
        let out = usb(&mut b);
        assert_eq!(&out[0][4..9], &[0x80 | cmd::CBOR, 0, 2, 0x00, 0xA0]);
        assert!(!b.busy());
        b.tick(10_000);
        assert!(usb(&mut b).is_empty());
    }

    #[test]
    fn dead_core_is_reported_quickly() {
        let mut b = Bridge::new();
        send(&mut b, cmd::CBOR, &[0x04], 0);
        let (_, id, _) = decode(&uart(&mut b));
        b.tick(ACK_TIMEOUT_MS + 1);
        let out = usb(&mut b);
        // Keepalives may come first; the last packet is the error reply.
        assert_eq!(&out.last().unwrap()[4..8], &[0x80 | cmd::CBOR, 0, 1, ERR_OTHER]);
        assert!(!b.busy());
        assert!(b.take_core_failed() && !b.take_core_failed());
        assert_eq!(decode(&uart(&mut b)), (Kind::Cancel, id, vec![]));
    }

    #[test]
    fn a_cancel_goes_out_before_the_next_request() {
        let mut b = Bridge::new();
        send(&mut b, cmd::CBOR, &[0x02], 0);
        let (_, old, _) = decode(&uart(&mut b));
        // The core never answers; the host tries again before the UART is
        // served.
        b.tick(ACK_TIMEOUT_MS + 1);
        send(&mut b, cmd::CBOR, &[0x04], ACK_TIMEOUT_MS + 2);
        assert_eq!(decode(&uart(&mut b)), (Kind::Cancel, old, vec![]));
        let (kind, new, payload) = decode(&uart(&mut b));
        assert_eq!((kind, payload), (Kind::Request, vec![0x04]));
        assert_ne!(new, old);
        assert!(uart(&mut b).is_empty());
    }

    #[test]
    fn slow_core_gets_the_long_timeout() {
        let mut b = Bridge::new();
        send(&mut b, cmd::CBOR, &[0x04], 0);
        let (_, id, _) = decode(&uart(&mut b));
        from_core(&mut b, Kind::Status, id, &[STATUS_PROCESSING], 1);
        b.tick(CORE_TIMEOUT_MS);
        assert!(b.busy());
        b.tick(CORE_TIMEOUT_MS + 1);
        assert!(!b.busy());
    }

    #[test]
    fn stale_and_unsolicited_frames_are_ignored() {
        let mut b = Bridge::new();
        from_core(&mut b, Kind::Response, 0, &[0x00], 0);
        assert!(usb(&mut b).is_empty());

        send(&mut b, cmd::CBOR, &[0x04], 0);
        let (_, id, _) = decode(&uart(&mut b));
        from_core(&mut b, Kind::Response, id.wrapping_add(1), &[0x00], 1);
        assert!(usb(&mut b).is_empty());
        assert!(b.busy());
        from_core(&mut b, Kind::Response, id, &[0x00], 2);
        assert_eq!(usb(&mut b).len(), 1);
    }

    #[test]
    fn cancel_is_passed_on() {
        let mut b = Bridge::new();
        send(&mut b, cmd::CBOR, &[0x02], 0);
        let (_, id, _) = decode(&uart(&mut b));
        send(&mut b, cmd::CANCEL, &[], 10);
        assert_eq!(decode(&uart(&mut b)), (Kind::Cancel, id, vec![]));
        assert!(b.busy(), "still waiting for the core's answer");
        from_core(&mut b, Kind::Response, id, &[0x2D], 20);
        assert_eq!(usb(&mut b)[0][7], 0x2D);
    }

    #[test]
    fn abandoned_request_does_not_leak_into_the_next() {
        let mut b = Bridge::new();
        send(&mut b, cmd::CBOR, &[0x02], 0);
        let (_, old, _) = decode(&uart(&mut b));
        // The host resynchronises its channel mid-request.
        send(&mut b, cmd::INIT, &[0; 8], 5);
        assert!(!b.busy());
        assert_eq!(decode(&uart(&mut b)), (Kind::Cancel, old, vec![]));
        usb(&mut b); // the INIT reply

        send(&mut b, cmd::CBOR, &[0x04], 10);
        let (_, new, _) = decode(&uart(&mut b));
        assert_ne!(old, new);
        // The core's late answer to the old request must not answer the new one.
        from_core(&mut b, Kind::Response, old, &[0xEE], 11);
        assert!(usb(&mut b).is_empty());
        from_core(&mut b, Kind::Response, new, &[0x00], 12);
        assert_eq!(usb(&mut b)[0][7], 0x00);
    }

    #[test]
    fn wink_is_reported_once() {
        let mut b = Bridge::new();
        send(&mut b, cmd::WINK, &[], 0);
        assert!(b.take_wink());
        assert!(!b.take_wink());
    }

    #[test]
    fn half_a_frame_is_dropped_after_a_gap() {
        let mut b = Bridge::new();
        send(&mut b, cmd::CBOR, &[0x04], 0);
        let (_, id, _) = decode(&uart(&mut b));
        let mut buf = [0u8; MAX_FRAME];
        let f = frame::encode(Kind::Response, id, &[0x00], &mut buf).unwrap().to_vec();
        for &byte in &f[..4] {
            b.uart_byte(byte, 10);
        }
        b.tick(10 + LINK_GAP_MS + 1);
        // Had the first half been kept, these bytes would be read as payload.
        for &byte in &f {
            b.uart_byte(byte, 200);
        }
        assert_eq!(usb(&mut b).last().unwrap()[7], 0x00);
    }
}
