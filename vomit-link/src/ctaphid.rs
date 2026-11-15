//! CTAPHID: how FIDO messages travel in 64-byte USB HID reports.
//!
//! ```text
//! first packet:  [channel: 4] [0x80 | command] [length hi] [length lo] [57 bytes of data]
//! later packets: [channel: 4] [sequence 0..]                           [59 bytes of data]
//! ```
//!
//! This is a pure state machine: packets in via [`CtapHid::handle_packet`],
//! packets out via [`CtapHid::poll_tx`]. One request is in flight at a time.
//! While one is, other channels are told the device is busy, except for
//! `INIT`, which only allocates a channel and is always answered.

use crate::frame::MAX_PAYLOAD;

pub const PACKET: usize = 64;
/// Largest message accepted (CBOR request or ping).
pub const MAX_MSG: usize = MAX_PAYLOAD;

const INIT_DATA: usize = PACKET - 7;
const CONT_DATA: usize = PACKET - 5;
const BROADCAST: u32 = 0xFFFF_FFFF;
/// A message must arrive completely within this long.
const ASSEMBLY_TIMEOUT_MS: u64 = 1000;
const QUICK: usize = 4;

/// Commands, without the 0x80 "first packet" bit.
pub mod cmd {
    pub const PING: u8 = 0x01;
    pub const MSG: u8 = 0x03;
    pub const INIT: u8 = 0x06;
    pub const WINK: u8 = 0x08;
    pub const CBOR: u8 = 0x10;
    pub const CANCEL: u8 = 0x11;
    pub const KEEPALIVE: u8 = 0x3B;
    pub const ERROR: u8 = 0x3F;
}

pub mod err {
    pub const INVALID_CMD: u8 = 0x01;
    pub const INVALID_LEN: u8 = 0x03;
    pub const INVALID_SEQ: u8 = 0x04;
    pub const MSG_TIMEOUT: u8 = 0x05;
    pub const CHANNEL_BUSY: u8 = 0x06;
    pub const INVALID_CHANNEL: u8 = 0x0B;
}

// Capability flags in the INIT reply: we blink (WINK), speak CTAP2 (CBOR) and
// do not speak U2F (NMSG).
const CAPABILITIES: u8 = 0x01 | 0x04 | 0x08;
/// (major, minor, build) reported in the INIT reply.
const DEVICE_VERSION: [u8; 3] = [0, 1, 0];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    None,
    /// A complete CBOR request is ready in [`CtapHid::request`]; pass it on.
    Forward,
    /// The host cancelled, or abandoned, the request in flight.
    Cancel,
    /// The host asked the device to identify itself.
    Wink,
}

#[derive(Clone, Copy)]
struct Assembly {
    cid: u32,
    cmd: u8,
    total: usize,
    got: usize,
    seq: u8,
    started_ms: u64,
}

#[derive(Clone, Copy)]
struct Tx {
    cid: u32,
    cmd: u8,
    len: usize,
    pos: usize,
    seq: u8,
    started: bool,
}

pub struct CtapHid {
    next_cid: u32,
    rx_buf: [u8; MAX_MSG],
    assembling: Option<Assembly>,
    /// Channel whose CBOR request is with the core.
    pending: Option<u32>,
    request_len: usize,
    tx_buf: [u8; MAX_MSG],
    tx: Option<Tx>,
    /// Single-packet replies (errors, INIT, keepalives).
    quick: [[u8; PACKET]; QUICK],
    quick_head: usize,
    quick_len: usize,
}

impl CtapHid {
    pub const fn new() -> Self {
        Self {
            next_cid: 1,
            rx_buf: [0; MAX_MSG],
            assembling: None,
            pending: None,
            request_len: 0,
            tx_buf: [0; MAX_MSG],
            tx: None,
            quick: [[0; PACKET]; QUICK],
            quick_head: 0,
            quick_len: 0,
        }
    }

    /// The request to forward. Valid right after [`Action::Forward`].
    pub fn request(&self) -> &[u8] {
        &self.rx_buf[..self.request_len]
    }

    /// True while a CBOR request is waiting for [`CtapHid::complete`].
    pub fn is_pending(&self) -> bool {
        self.pending.is_some()
    }

    pub fn handle_packet(&mut self, pkt: &[u8; PACKET], now_ms: u64) -> Action {
        let cid = u32::from_be_bytes([pkt[0], pkt[1], pkt[2], pkt[3]]);
        if pkt[4] & 0x80 == 0 {
            self.continuation(cid, pkt)
        } else {
            self.initial(cid, pkt, now_ms)
        }
    }

    fn continuation(&mut self, cid: u32, pkt: &[u8; PACKET]) -> Action {
        // Stray continuation packets, and ones from other channels, are ignored.
        let Some(mut a) = self.assembling else { return Action::None };
        if a.cid != cid {
            return Action::None;
        }
        if pkt[4] != a.seq {
            self.assembling = None;
            self.error(cid, err::INVALID_SEQ);
            return Action::None;
        }
        let n = (a.total - a.got).min(CONT_DATA);
        self.rx_buf[a.got..a.got + n].copy_from_slice(&pkt[5..5 + n]);
        a.got += n;
        a.seq += 1;
        if a.got < a.total {
            self.assembling = Some(a);
            return Action::None;
        }
        self.assembling = None;
        self.dispatch(a.cid, a.cmd, a.total)
    }

    fn initial(&mut self, cid: u32, pkt: &[u8; PACKET], now_ms: u64) -> Action {
        let command = pkt[4] & 0x7F;
        let total = u16::from_be_bytes([pkt[5], pkt[6]]) as usize;

        // INIT allocates a channel, or resynchronises an existing one by
        // abandoning whatever that channel was doing.
        if command == cmd::INIT {
            let mut action = Action::None;
            if self.assembling.is_some_and(|a| a.cid == cid) {
                self.assembling = None;
            }
            if self.pending == Some(cid) {
                self.pending = None;
                action = Action::Cancel;
            }
            if self.tx.is_some_and(|t| t.cid == cid) {
                self.tx = None;
            }
            self.init(cid, pkt, total);
            return action;
        }
        if cid == 0 || cid == BROADCAST {
            self.error(cid, err::INVALID_CHANNEL);
            return Action::None;
        }
        if let Some(a) = self.assembling {
            if a.cid == cid {
                // A new message before the last one finished.
                self.assembling = None;
                self.error(cid, err::INVALID_SEQ);
            } else {
                self.error(cid, err::CHANNEL_BUSY);
            }
            return Action::None;
        }
        if let Some(p) = self.pending {
            if p == cid && command == cmd::CANCEL {
                return Action::Cancel;
            }
            self.error(cid, err::CHANNEL_BUSY);
            return Action::None;
        }
        if command == cmd::CANCEL {
            return Action::None; // nothing to cancel
        }
        if total > MAX_MSG {
            self.error(cid, err::INVALID_LEN);
            return Action::None;
        }
        let n = total.min(INIT_DATA);
        self.rx_buf[..n].copy_from_slice(&pkt[7..7 + n]);
        if n == total {
            return self.dispatch(cid, command, total);
        }
        self.assembling = Some(Assembly { cid, cmd: command, total, got: n, seq: 0, started_ms: now_ms });
        Action::None
    }

    fn init(&mut self, cid: u32, pkt: &[u8; PACKET], total: usize) {
        if cid == 0 {
            self.error(cid, err::INVALID_CHANNEL);
            return;
        }
        if total != 8 {
            self.error(cid, err::INVALID_LEN);
            return;
        }
        let channel = if cid == BROADCAST { self.allocate() } else { cid };
        let mut data = [0u8; 17];
        data[..8].copy_from_slice(&pkt[7..15]); // the host's nonce, echoed
        data[8..12].copy_from_slice(&channel.to_be_bytes());
        data[12] = 2; // CTAPHID protocol version
        data[13..16].copy_from_slice(&DEVICE_VERSION);
        data[16] = CAPABILITIES;
        self.quick_push(single(cid, cmd::INIT, &data));
    }

    fn allocate(&mut self) -> u32 {
        let cid = self.next_cid;
        self.next_cid = match cid.wrapping_add(1) {
            0 | BROADCAST => 1,
            n => n,
        };
        cid
    }

    fn dispatch(&mut self, cid: u32, command: u8, len: usize) -> Action {
        match command {
            cmd::PING => {
                self.tx_buf[..len].copy_from_slice(&self.rx_buf[..len]);
                self.send(cid, cmd::PING, len);
                Action::None
            }
            cmd::CBOR if len > 0 => {
                self.pending = Some(cid);
                self.request_len = len;
                Action::Forward
            }
            cmd::CBOR => {
                self.error(cid, err::INVALID_LEN);
                Action::None
            }
            cmd::WINK => {
                self.send(cid, cmd::WINK, 0);
                Action::Wink
            }
            _ => {
                self.error(cid, err::INVALID_CMD);
                Action::None
            }
        }
    }

    /// The core's reply to the pending request. Ignored if nothing is pending
    /// (the host abandoned it).
    pub fn complete(&mut self, response: &[u8]) {
        if let Some(cid) = self.pending.take() {
            let n = response.len().min(MAX_MSG);
            self.tx_buf[..n].copy_from_slice(&response[..n]);
            self.send(cid, cmd::CBOR, n);
        }
    }

    /// Tell the host the pending request is still being worked on.
    pub fn keepalive(&mut self, status: u8) {
        if let Some(cid) = self.pending {
            self.quick_push(single(cid, cmd::KEEPALIVE, &[status]));
        }
    }

    /// Call regularly: drops a half-received message that has stalled.
    pub fn tick(&mut self, now_ms: u64) {
        if let Some(a) = self.assembling {
            if now_ms.saturating_sub(a.started_ms) > ASSEMBLY_TIMEOUT_MS {
                self.assembling = None;
                self.error(a.cid, err::MSG_TIMEOUT);
            }
        }
    }

    /// Next packet for the host, if any. A multi-packet message is never
    /// interleaved with other packets: clients do not expect that.
    pub fn poll_tx(&mut self) -> Option<[u8; PACKET]> {
        if !self.tx.is_some_and(|t| t.started) {
            if let Some(p) = self.quick_pop() {
                return Some(p);
            }
        }
        let mut tx = self.tx?;
        let mut pkt = [0u8; PACKET];
        pkt[..4].copy_from_slice(&tx.cid.to_be_bytes());
        let (header, room) = if tx.started {
            pkt[4] = tx.seq;
            tx.seq = tx.seq.wrapping_add(1);
            (5, CONT_DATA)
        } else {
            pkt[4] = 0x80 | tx.cmd;
            pkt[5] = (tx.len >> 8) as u8;
            pkt[6] = tx.len as u8;
            tx.started = true;
            (7, INIT_DATA)
        };
        let n = (tx.len - tx.pos).min(room);
        pkt[header..header + n].copy_from_slice(&self.tx_buf[tx.pos..tx.pos + n]);
        tx.pos += n;
        self.tx = (tx.pos < tx.len).then_some(tx);
        Some(pkt)
    }

    fn send(&mut self, cid: u32, command: u8, len: usize) {
        self.tx = Some(Tx { cid, cmd: command, len, pos: 0, seq: 0, started: false });
    }

    fn error(&mut self, cid: u32, code: u8) {
        self.quick_push(single(cid, cmd::ERROR, &[code]));
    }

    fn quick_push(&mut self, pkt: [u8; PACKET]) {
        // If the host isn't reading, the oldest replies are the stale ones.
        if self.quick_len == QUICK {
            self.quick_head = (self.quick_head + 1) % QUICK;
            self.quick_len -= 1;
        }
        self.quick[(self.quick_head + self.quick_len) % QUICK] = pkt;
        self.quick_len += 1;
    }

    fn quick_pop(&mut self) -> Option<[u8; PACKET]> {
        if self.quick_len == 0 {
            return None;
        }
        let pkt = self.quick[self.quick_head];
        self.quick_head = (self.quick_head + 1) % QUICK;
        self.quick_len -= 1;
        Some(pkt)
    }
}

impl Default for CtapHid {
    fn default() -> Self {
        Self::new()
    }
}

/// A message that fits in one packet.
fn single(cid: u32, command: u8, data: &[u8]) -> [u8; PACKET] {
    let mut pkt = [0u8; PACKET];
    pkt[..4].copy_from_slice(&cid.to_be_bytes());
    pkt[4] = 0x80 | command;
    pkt[6] = data.len() as u8;
    pkt[7..7 + data.len()].copy_from_slice(data);
    pkt
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// What a host does: split a message into packets.
    pub fn packets(cid: u32, command: u8, data: &[u8]) -> Vec<[u8; PACKET]> {
        let mut out = vec![];
        let mut pkt = [0u8; PACKET];
        pkt[..4].copy_from_slice(&cid.to_be_bytes());
        pkt[4] = 0x80 | command;
        pkt[5] = (data.len() >> 8) as u8;
        pkt[6] = data.len() as u8;
        let n = data.len().min(INIT_DATA);
        pkt[7..7 + n].copy_from_slice(&data[..n]);
        out.push(pkt);
        for (seq, chunk) in data[n..].chunks(CONT_DATA).enumerate() {
            let mut pkt = [0u8; PACKET];
            pkt[..4].copy_from_slice(&cid.to_be_bytes());
            pkt[4] = seq as u8;
            pkt[5..5 + chunk.len()].copy_from_slice(chunk);
            out.push(pkt);
        }
        out
    }

    /// What a host does: read one whole message back. Returns (cid, command, data).
    pub fn read_message(hid: &mut CtapHid) -> Option<(u32, u8, Vec<u8>)> {
        let first = hid.poll_tx()?;
        let cid = u32::from_be_bytes(first[..4].try_into().unwrap());
        assert!(first[4] & 0x80 != 0, "expected a first packet");
        let len = u16::from_be_bytes([first[5], first[6]]) as usize;
        let mut data = first[7..7 + len.min(INIT_DATA)].to_vec();
        let mut seq = 0;
        while data.len() < len {
            let p = hid.poll_tx().expect("message cut short");
            assert_eq!(&p[..4], &first[..4], "another channel's packet inside a message");
            assert_eq!(p[4], seq);
            seq += 1;
            let n = (len - data.len()).min(CONT_DATA);
            data.extend_from_slice(&p[5..5 + n]);
        }
        Some((cid, first[4] & 0x7F, data))
    }

    fn feed(hid: &mut CtapHid, cid: u32, command: u8, data: &[u8]) -> Action {
        let mut last = Action::None;
        for p in packets(cid, command, data) {
            last = hid.handle_packet(&p, 0);
        }
        last
    }

    fn open(hid: &mut CtapHid) -> u32 {
        feed(hid, BROADCAST, cmd::INIT, &[1, 2, 3, 4, 5, 6, 7, 8]);
        let (cid, command, data) = read_message(hid).unwrap();
        assert_eq!((cid, command), (BROADCAST, cmd::INIT));
        assert_eq!(&data[..8], &[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(data.len(), 17);
        assert_eq!(data[16], CAPABILITIES);
        u32::from_be_bytes(data[8..12].try_into().unwrap())
    }

    #[test]
    fn init_allocates_distinct_channels() {
        let mut hid = CtapHid::new();
        let a = open(&mut hid);
        let b = open(&mut hid);
        assert!(a != b && a != 0 && a != BROADCAST);
    }

    #[test]
    fn ping_echoes_across_packets() {
        let mut hid = CtapHid::new();
        let cid = open(&mut hid);
        for len in [0usize, 1, 57, 58, 116, 117, 500, MAX_MSG] {
            let data: Vec<u8> = (0..len).map(|i| i as u8).collect();
            assert_eq!(feed(&mut hid, cid, cmd::PING, &data), Action::None);
            assert_eq!(read_message(&mut hid).unwrap(), (cid, cmd::PING, data));
            assert!(hid.poll_tx().is_none());
        }
    }

    #[test]
    fn cbor_is_forwarded_and_answered() {
        let mut hid = CtapHid::new();
        let cid = open(&mut hid);
        let req: Vec<u8> = (0..200).map(|i| i as u8).collect();
        assert_eq!(feed(&mut hid, cid, cmd::CBOR, &req), Action::Forward);
        assert_eq!(hid.request(), &req[..]);
        hid.keepalive(1);
        assert_eq!(read_message(&mut hid).unwrap(), (cid, cmd::KEEPALIVE, vec![1]));
        let resp: Vec<u8> = (0..300).map(|i| (i * 3) as u8).collect();
        hid.complete(&resp);
        assert_eq!(read_message(&mut hid).unwrap(), (cid, cmd::CBOR, resp));
        assert!(!hid.is_pending());
        // A late reply with nothing pending goes nowhere.
        hid.complete(&[0]);
        assert!(hid.poll_tx().is_none());
    }

    #[test]
    fn busy_and_cancel_while_pending() {
        let mut hid = CtapHid::new();
        let a = open(&mut hid);
        let b = open(&mut hid);
        assert_eq!(feed(&mut hid, a, cmd::CBOR, &[4]), Action::Forward);
        // Another channel is refused...
        assert_eq!(feed(&mut hid, b, cmd::CBOR, &[4]), Action::None);
        assert_eq!(read_message(&mut hid).unwrap(), (b, cmd::ERROR, vec![err::CHANNEL_BUSY]));
        // ...but can still open a channel.
        let c = open(&mut hid);
        assert!(c != a && c != b);
        // Cancel from the wrong channel is refused, from the right one passed on.
        assert_eq!(feed(&mut hid, b, cmd::CANCEL, &[]), Action::None);
        assert_eq!(read_message(&mut hid).unwrap(), (b, cmd::ERROR, vec![err::CHANNEL_BUSY]));
        assert_eq!(feed(&mut hid, a, cmd::CANCEL, &[]), Action::Cancel);
        assert!(hid.is_pending(), "cancel is only a request; the core still answers");
        hid.complete(&[0x2D]);
        assert_eq!(read_message(&mut hid).unwrap(), (a, cmd::CBOR, vec![0x2D]));
    }

    #[test]
    fn init_on_busy_channel_abandons_the_request() {
        let mut hid = CtapHid::new();
        let a = open(&mut hid);
        assert_eq!(feed(&mut hid, a, cmd::CBOR, &[4]), Action::Forward);
        assert_eq!(feed(&mut hid, a, cmd::INIT, &[0; 8]), Action::Cancel);
        assert!(!hid.is_pending());
        let (cid, command, data) = read_message(&mut hid).unwrap();
        assert_eq!((cid, command), (a, cmd::INIT));
        assert_eq!(&data[8..12], &a.to_be_bytes());
    }

    #[test]
    fn protocol_errors() {
        let mut hid = CtapHid::new();
        let cid = open(&mut hid);
        let expect = |hid: &mut CtapHid, on: u32, code: u8| {
            assert_eq!(read_message(hid).unwrap(), (on, cmd::ERROR, vec![code]));
        };
        // Unknown command, U2F, empty CBOR.
        feed(&mut hid, cid, 0x7A, &[]);
        expect(&mut hid, cid, err::INVALID_CMD);
        feed(&mut hid, cid, cmd::MSG, &[0, 1, 2]);
        expect(&mut hid, cid, err::INVALID_CMD);
        feed(&mut hid, cid, cmd::CBOR, &[]);
        expect(&mut hid, cid, err::INVALID_LEN);
        // Reserved channels.
        feed(&mut hid, 0, cmd::PING, &[]);
        expect(&mut hid, 0, err::INVALID_CHANNEL);
        feed(&mut hid, BROADCAST, cmd::PING, &[]);
        expect(&mut hid, BROADCAST, err::INVALID_CHANNEL);
        // INIT with the wrong length.
        feed(&mut hid, BROADCAST, cmd::INIT, &[0; 7]);
        expect(&mut hid, BROADCAST, err::INVALID_LEN);
        // Longer than we accept.
        let mut pkt = packets(cid, cmd::PING, &[])[0];
        pkt[5..7].copy_from_slice(&((MAX_MSG + 1) as u16).to_be_bytes());
        hid.handle_packet(&pkt, 0);
        expect(&mut hid, cid, err::INVALID_LEN);
        // Wrong sequence number.
        let p = packets(cid, cmd::PING, &[0; 200]);
        hid.handle_packet(&p[0], 0);
        hid.handle_packet(&p[2], 0);
        expect(&mut hid, cid, err::INVALID_SEQ);
        // A new message in the middle of one.
        hid.handle_packet(&p[0], 0);
        hid.handle_packet(&p[0], 0);
        expect(&mut hid, cid, err::INVALID_SEQ);
        // Stray continuation: ignored.
        hid.handle_packet(&p[1], 0);
        assert!(hid.poll_tx().is_none());
    }

    #[test]
    fn stalled_message_times_out() {
        let mut hid = CtapHid::new();
        let cid = open(&mut hid);
        let p = packets(cid, cmd::PING, &[0; 200]);
        hid.handle_packet(&p[0], 1000);
        hid.tick(1500);
        assert!(hid.poll_tx().is_none());
        hid.tick(2001);
        assert_eq!(read_message(&mut hid).unwrap(), (cid, cmd::ERROR, vec![err::MSG_TIMEOUT]));
        // And the channel works again.
        assert_eq!(feed(&mut hid, cid, cmd::PING, b"x"), Action::None);
        assert_eq!(read_message(&mut hid).unwrap().2, b"x");
    }

    #[test]
    fn quick_replies_never_split_a_message() {
        let mut hid = CtapHid::new();
        let a = open(&mut hid);
        feed(&mut hid, a, cmd::PING, &[9; 300]);
        let first = hid.poll_tx().unwrap();
        assert_eq!(first[4], 0x80 | cmd::PING);
        // Another channel opens while the echo is half sent.
        feed(&mut hid, BROADCAST, cmd::INIT, &[0; 8]);
        let mut rest = vec![];
        while let Some(p) = hid.poll_tx() {
            rest.push(p);
        }
        let last = rest.pop().unwrap();
        assert_eq!(last[4], 0x80 | cmd::INIT, "the INIT reply comes after the echo");
        assert!(rest.iter().all(|p| p[..4] == a.to_be_bytes() && p[4] & 0x80 == 0));
    }

    #[test]
    fn random_packets_never_panic() {
        let mut hid = CtapHid::new();
        let mut x = 0x9E3779B9u32;
        let mut next = move || {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            x
        };
        for i in 0..100_000u64 {
            let mut pkt = [0u8; PACKET];
            for b in pkt.iter_mut() {
                *b = next() as u8;
            }
            // Mostly a handful of channels, so state actually builds up.
            pkt[..4].copy_from_slice(&(next() % 4).to_be_bytes());
            if next() % 3 == 0 {
                pkt[4] = 0x80 | [cmd::PING, cmd::INIT, cmd::CBOR, cmd::CANCEL, cmd::WINK][(next() % 5) as usize];
                pkt[5] = (next() % 6) as u8;
            } else {
                pkt[4] = (next() % 4) as u8;
            }
            if hid.handle_packet(&pkt, i) == Action::Forward && next() % 2 == 0 {
                hid.complete(&[0; 400]);
            }
            hid.keepalive(1);
            hid.tick(i);
            while hid.poll_tx().is_some() {}
        }
    }
}
