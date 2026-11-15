//! vomit-enforcer on a PC.
//!
//! The same state machines the two firmwares run, wired together:
//!
//! ```text
//!  FIDO client ──unix socket──► Bridge ──in-memory "UART"──► Server (core)
//!            64-byte HID reports        frames                vault in RAM
//! ```
//!
//! Each connection to the socket behaves like one opener of the HID device:
//! it writes 64-byte reports and receives every report the device sends.
//!
//! ```sh
//! cargo run -p vomit-sim -- --socket /tmp/vomit.sock
//! ```
//!
//! Options: `--touch auto|never` (default auto: the button is "pressed"
//! shortly after a touch is asked for), `--up-timeout-ms N`,
//! `--max-failures N`, `--base-delay-ms N`, `--verbose`.

use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use vomit_core::backup::MemBackup;
use vomit_core::kdf::{Block, KdfParams};
use vomit_core::vault::{Config, Vault};
use vomit_ctap::rng::Drbg;
use vomit_ctap::serve::{CoreIo, Server, DEBOUNCE_MS};
use vomit_link::bridge::Bridge;
use vomit_link::ctaphid::PACKET;
use vomit_link::frame::{Decoder, Kind, MAX_FRAME};

/// Argon2 memory, as planned for the F411.
const ARGON_BLOCKS: usize = 64;

struct Options {
    socket: String,
    touch: bool,
    up_timeout_ms: u64,
    cfg: Config,
    verbose: bool,
}

fn options() -> Options {
    let mut o = Options {
        socket: "/tmp/vomit-sim.sock".into(),
        touch: true,
        up_timeout_ms: vomit_ctap::serve::UP_TIMEOUT_MS,
        // What the firmware uses, see fw-core.
        cfg: Config {
            max_failures: 8,
            base_delay_ms: 1_000,
            max_delay_ms: 5 * 60_000,
            admin_window_ms: 60_000,
            kdf: KdfParams { passes: 3 },
        },
        verbose: false,
    };
    let mut args = std::env::args().skip(1);
    let number = |v: Option<String>, flag: &str| -> u64 {
        v.and_then(|v| v.parse().ok()).unwrap_or_else(|| panic!("{flag} needs a number"))
    };
    while let Some(flag) = args.next() {
        match flag.as_str() {
            "--socket" => o.socket = args.next().expect("--socket needs a path"),
            "--touch" => o.touch = args.next().as_deref() != Some("never"),
            "--up-timeout-ms" => o.up_timeout_ms = number(args.next(), &flag),
            "--max-failures" => o.cfg.max_failures = number(args.next(), &flag) as u32,
            "--base-delay-ms" => o.cfg.base_delay_ms = number(args.next(), &flag),
            "--verbose" => o.verbose = true,
            other => panic!("unknown option {other}"),
        }
    }
    o
}

/// The core's hardware: a clock, two byte pipes and an imaginary button.
struct SimIo {
    start: Instant,
    from_bridge: Receiver<u8>,
    to_bridge: Sender<u8>,
    touch: bool,
    /// When the current wait for a touch began.
    waiting_since: Option<u64>,
}

impl CoreIo for SimIo {
    fn now_ms(&mut self) -> u64 {
        self.start.elapsed().as_millis() as u64
    }
    fn read_byte(&mut self) -> Option<u8> {
        self.from_bridge.try_recv().ok()
    }
    fn write(&mut self, bytes: &[u8]) {
        for &b in bytes {
            let _ = self.to_bridge.send(b);
        }
    }
    fn button_down(&mut self) -> bool {
        // Released at first, then held: what a person does when asked.
        let now = self.now_ms();
        self.touch && self.waiting_since.is_some_and(|since| now >= since + 2 * DEBOUNCE_MS)
    }
    fn jitter(&mut self) -> u32 {
        self.start.elapsed().subsec_nanos()
    }
    fn indicate(&mut self, waiting_for_touch: bool) {
        self.waiting_since = waiting_for_touch.then(|| self.now_ms());
    }
    fn idle(&mut self) {
        std::thread::sleep(Duration::from_millis(1));
    }
}

fn core_thread(o: &Options, from_bridge: Receiver<u8>, to_bridge: Sender<u8>) -> ! {
    let mut seed = [0u8; 32];
    std::fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(&mut seed)).expect("no /dev/urandom");
    let mut drbg = Drbg::new();
    drbg.reseed(&seed);

    let mut vault = Vault::new();
    let mut memory = vec![Block::default(); ARGON_BLOCKS];
    let io = SimIo { start: Instant::now(), from_bridge, to_bridge, touch: o.touch, waiting_since: None };
    let mut server = Server::new(&mut vault, MemBackup::default(), o.cfg, io, &mut drbg);
    server.set_up_timeout_ms(o.up_timeout_ms);
    loop {
        server.poll(&mut memory);
    }
}

/// Prints what crosses the "UART", one line per frame.
struct Tap {
    decoder: Decoder,
    label: &'static str,
    enabled: bool,
}

impl Tap {
    fn new(label: &'static str, enabled: bool) -> Self {
        Self { decoder: Decoder::new(), label, enabled }
    }
    fn byte(&mut self, b: u8) {
        let Some(f) = self.decoder.push(b).filter(|_| self.enabled) else { return };
        let what = match (f.kind, f.payload.first()) {
            (Kind::Request, Some(c)) => format!("command 0x{c:02x}, {} bytes", f.payload.len()),
            (Kind::Response, Some(s)) => format!("status 0x{s:02x}, {} bytes", f.payload.len()),
            (Kind::Status, Some(2)) => "waiting for touch".to_string(),
            (Kind::Status, Some(_)) => "processing".to_string(),
            _ => String::new(),
        };
        eprintln!("{} {:?} #{} {what}", self.label, f.kind, f.id);
    }
}

fn main() {
    let o = options();
    let _ = std::fs::remove_file(&o.socket);
    let listener = UnixListener::bind(&o.socket).unwrap_or_else(|e| panic!("cannot bind {}: {e}", o.socket));

    let (to_core, from_bridge) = channel::<u8>();
    let (to_bridge, from_core) = channel::<u8>();
    let (usb_in, usb_packets) = channel::<[u8; PACKET]>();
    let clients: Arc<Mutex<Vec<UnixStream>>> = Arc::default();

    // Each connection is one opener of the HID device.
    let accepted = clients.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let Ok(mut reader) = stream.try_clone() else { continue };
            accepted.lock().unwrap().push(stream);
            let usb_in = usb_in.clone();
            std::thread::spawn(move || {
                let mut pkt = [0u8; PACKET];
                while reader.read_exact(&mut pkt).is_ok() && usb_in.send(pkt).is_ok() {}
            });
        }
    });

    let verbose = o.verbose;
    std::thread::spawn(move || core_thread(&o, from_bridge, to_bridge));

    // The bridge firmware's main loop.
    let start = Instant::now();
    let mut bridge = Bridge::new();
    let mut frame = [0u8; MAX_FRAME];
    let mut down = Tap::new("bridge -> core", verbose);
    let mut up = Tap::new("core -> bridge", verbose);
    loop {
        let now = start.elapsed().as_millis() as u64;
        match usb_packets.recv_timeout(Duration::from_millis(1)) {
            Ok(pkt) => bridge.usb_packet(&pkt, now),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(_) => return,
        }
        for byte in from_core.try_iter() {
            up.byte(byte);
            bridge.uart_byte(byte, now);
        }
        bridge.tick(now);
        while let Some(pkt) = bridge.poll_usb() {
            clients.lock().unwrap().retain_mut(|c| c.write_all(&pkt).is_ok());
        }
        loop {
            let n = bridge.take_uart(&mut frame);
            if n == 0 {
                break;
            }
            for &byte in &frame[..n] {
                down.byte(byte);
                let _ = to_core.send(byte);
            }
        }
    }
}
