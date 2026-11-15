//! Tests of the authenticator that need a fake clock or hostile input.
//!
//! Protocol conformance is checked from the outside, by real FIDO clients,
//! in `tests/` at the repository root. This file covers what those cannot:
//! time passing, resets, and garbage.

use vomit_core::backup::{BackupStore, MemBackup};
use vomit_core::kdf::{Block, KdfParams};
use vomit_core::vault::{Config, Vault};
use vomit_ctap::authenticator::{Authenticator, Platform, Presence, TOKEN_TTL_MS};
use vomit_ctap::cbor::{Reader, Writer};
use vomit_ctap::crypto::{self, KeyAgreement};
use vomit_ctap::rng::Drbg;
use vomit_ctap::status;

const CFG: Config = Config {
    max_failures: 8,
    base_delay_ms: 1_000,
    max_delay_ms: 60_000,
    admin_window_ms: 60_000,
    kdf: KdfParams { passes: 1 },
};
const PIN: &[u8] = b"1234";
const RP: &str = "example.com";

struct World {
    now: u64,
    drbg: Drbg,
    presence: Presence,
    touches: u32,
}

impl World {
    fn new() -> Self {
        let mut drbg = Drbg::new();
        drbg.reseed(b"test");
        Self { now: 0, drbg, presence: Presence::Confirmed, touches: 0 }
    }
}

impl Platform for World {
    fn now_ms(&mut self) -> u64 {
        self.now
    }
    fn random(&mut self, out: &mut [u8]) {
        self.drbg.fill(out);
    }
    fn user_presence(&mut self) -> Presence {
        self.touches += 1;
        self.presence
    }
}

/// Backup registers that outlive one `Authenticator`, as the real ones do.
struct Registers<'a>(&'a mut MemBackup);

impl BackupStore for Registers<'_> {
    fn read(&self, word: usize) -> u32 {
        self.0.read(word)
    }
    fn write(&mut self, word: usize, value: u32) {
        self.0.write(word, value)
    }
}

/// A minimal FIDO host.
struct Host<'v, 'b> {
    auth: Authenticator<'v, Registers<'b>>,
    world: World,
    memory: [Block; 8],
}

impl<'v, 'b> Host<'v, 'b> {
    fn boot(vault: &'v mut Vault, registers: &'b mut MemBackup, mut world: World) -> Self {
        let auth = Authenticator::new(vault, Registers(registers), CFG, &mut world);
        Self { auth, world, memory: [Block::default(); 8] }
    }

    /// Power down or reset: the authenticator is gone, the world goes on.
    fn stop(self) -> World {
        self.world
    }

    /// Send a command, get (status, CBOR).
    fn call(&mut self, command: u8, body: impl FnOnce(&mut Writer)) -> (u8, Vec<u8>) {
        let mut request = [0u8; 1024];
        request[0] = command;
        let mut w = Writer::new(&mut request[1..]);
        body(&mut w);
        let n = 1 + w.finish().unwrap();
        self.raw(&request[..n])
    }

    fn raw(&mut self, request: &[u8]) -> (u8, Vec<u8>) {
        let mut out = [0u8; 1200];
        let n = self.auth.handle(&mut self.world, &mut self.memory, request, &mut out);
        assert!(n >= 1, "every request gets a status byte");
        (out[0], out[1..n].to_vec())
    }

    /// Run the key agreement. Returns our public key and the shared secret.
    fn agree(&mut self) -> (([u8; 32], [u8; 32]), [u8; 32]) {
        let (status, reply) = self.call(0x06, |w| {
            w.map(2);
            w.uint(1);
            w.uint(1);
            w.uint(2);
            w.uint(2);
        });
        assert_eq!(status, status::OK);
        // {1: {1: 2, 3: -25, -1: 1, -2: x, -3: y}}
        let mut r = Reader::new(&reply);
        assert_eq!((r.map(), r.uint(), r.map()), (Ok(1), Ok(1), Ok(5)));
        let (mut x, mut y) = ([0u8; 32], [0u8; 32]);
        for _ in 0..5 {
            match r.int().unwrap() {
                -2 => x.copy_from_slice(r.bytes().unwrap()),
                -3 => y.copy_from_slice(r.bytes().unwrap()),
                _ => r.skip().unwrap(),
            }
        }
        let world = &mut self.world;
        let ours = KeyAgreement::generate(&mut |out| world.drbg.fill(out));
        let shared = ours.shared_secret(&x, &y).unwrap();
        ((ours.x, ours.y), *shared)
    }

    fn set_pin(&mut self, pin: &[u8]) -> u8 {
        let (key, shared) = self.agree();
        let mut new_pin_enc = [0u8; 64];
        new_pin_enc[..pin.len()].copy_from_slice(pin);
        crypto::cbc_encrypt(&shared, &mut new_pin_enc);
        let pin_auth = crypto::hmac_sha256(&shared, &[&new_pin_enc]);
        self.call(0x06, |w| {
            w.map(5);
            w.uint(1);
            w.uint(1);
            w.uint(2);
            w.uint(3);
            w.uint(3);
            cose_key(w, &key);
            w.uint(4);
            w.bytes(&pin_auth[..16]);
            w.uint(5);
            w.bytes(&new_pin_enc);
        })
        .0
    }

    fn token(&mut self, pin: &[u8]) -> Result<[u8; 32], u8> {
        let (key, shared) = self.agree();
        let mut pin_hash_enc = [0u8; 16];
        pin_hash_enc.copy_from_slice(&crypto::sha256(&[pin])[..16]);
        crypto::cbc_encrypt(&shared, &mut pin_hash_enc);
        let (status, reply) = self.call(0x06, |w| {
            w.map(4);
            w.uint(1);
            w.uint(1);
            w.uint(2);
            w.uint(5);
            w.uint(3);
            cose_key(w, &key);
            w.uint(6);
            w.bytes(&pin_hash_enc);
        });
        if status != status::OK {
            return Err(status);
        }
        let mut r = Reader::new(&reply);
        assert_eq!((r.map(), r.uint()), (Ok(1), Ok(2)));
        let mut token = [0u8; 32];
        token.copy_from_slice(r.bytes().unwrap());
        crypto::cbc_decrypt(&shared, &mut token);
        Ok(token)
    }

    /// makeCredential. On success, the credential ID.
    fn make(&mut self, token: &[u8; 32]) -> Result<Vec<u8>, u8> {
        let cdh = [7u8; 32];
        let (status, reply) = self.call(0x01, |w| make_credential(w, &cdh, &pin_auth(token, &cdh)));
        if status != status::OK {
            return Err(status);
        }
        // {1: "packed", 2: authData, 3: {...}}; the ID sits at a fixed place.
        let mut r = Reader::new(&reply);
        assert_eq!((r.map(), r.uint(), r.text(), r.uint()), (Ok(3), Ok(1), Ok(&b"packed"[..]), Ok(2)));
        let auth_data = r.bytes().unwrap();
        Ok(auth_data[55..55 + 48].to_vec())
    }

    fn assert(&mut self, token: &[u8; 32], cred_id: &[u8], up: bool) -> u8 {
        let cdh = [9u8; 32];
        let auth = pin_auth(token, &cdh);
        self.call(0x02, |w| {
            w.map(6);
            w.uint(1);
            w.text(RP);
            w.uint(2);
            w.bytes(&cdh);
            w.uint(3);
            w.array(1);
            w.map(2);
            w.text("id");
            w.bytes(cred_id);
            w.text("type");
            w.text("public-key");
            w.uint(5);
            w.map(1);
            w.text("up");
            w.bool(up);
            w.uint(6);
            w.bytes(&auth);
            w.uint(7);
            w.uint(1);
        })
        .0
    }
}

fn cose_key(w: &mut Writer, key: &([u8; 32], [u8; 32])) {
    w.map(5);
    w.uint(1);
    w.uint(2);
    w.uint(3);
    w.int(-25);
    w.int(-1);
    w.uint(1);
    w.int(-2);
    w.bytes(&key.0);
    w.int(-3);
    w.bytes(&key.1);
}

fn pin_auth(token: &[u8; 32], client_data_hash: &[u8]) -> [u8; 16] {
    let mut auth = [0u8; 16];
    auth.copy_from_slice(&crypto::hmac_sha256(token, &[client_data_hash])[..16]);
    auth
}

fn make_credential(w: &mut Writer, cdh: &[u8], auth: &[u8]) {
    w.map(6);
    w.uint(1);
    w.bytes(cdh);
    w.uint(2);
    w.map(1);
    w.text("id");
    w.text(RP);
    w.uint(3);
    w.map(1);
    w.text("id");
    w.bytes(b"user");
    w.uint(4);
    w.array(1);
    w.map(2);
    w.text("alg");
    w.int(-7);
    w.text("type");
    w.text("public-key");
    w.uint(8);
    w.bytes(auth);
    w.uint(9);
    w.uint(1);
}

#[test]
fn get_info_is_exactly_this() {
    let (mut vault, mut registers) = (Vault::new(), MemBackup::default());
    let mut host = Host::boot(&mut vault, &mut registers, World::new());
    let (status, info) = host.raw(&[0x04]);
    assert_eq!(status, status::OK);
    let mut expected = vec![0xA6];
    expected.extend(b"\x01\x81\x68FIDO_2_0");
    expected.extend(b"\x02\x81\x6Bhmac-secret");
    expected.extend(b"\x03\x50vomit-enforcer\x00\x01");
    expected.extend(b"\x04\xA4\x62rk\xF4\x62up\xF5\x68alwaysUv\xF5\x69clientPin\xF4");
    expected.extend(b"\x05\x19\x04\xB0"); // 1200
    expected.extend(b"\x06\x81\x01");
    assert_eq!(info, expected);
}

#[test]
fn the_unlocked_seed_is_dropped_when_its_time_is_up() {
    let (mut vault, mut registers) = (Vault::new(), MemBackup::default());
    let mut host = Host::boot(&mut vault, &mut registers, World::new());
    assert_eq!(host.set_pin(PIN), status::OK);
    let token = host.token(PIN).unwrap();
    let cred = host.make(&token).unwrap();

    host.world.now += TOKEN_TTL_MS - 1;
    assert_eq!(host.assert(&token, &cred, true), status::OK);
    host.world.now += 1;
    assert_eq!(host.assert(&token, &cred, true), status::PIN_AUTH_INVALID);
    // The PIN again, and it works again.
    let token = host.token(PIN).unwrap();
    assert_eq!(host.assert(&token, &cred, true), status::OK);
}

#[test]
fn a_reset_ends_the_session_but_keeps_the_credentials() {
    let (mut vault, mut registers) = (Vault::new(), MemBackup::default());
    let mut host = Host::boot(&mut vault, &mut registers, World::new());
    assert_eq!(host.set_pin(PIN), status::OK);
    let token = host.token(PIN).unwrap();
    let cred = host.make(&token).unwrap();
    let mut world = host.stop();

    // The chip resets. SRAM and the backup registers survive that.
    world.now = 0;
    let mut host = Host::boot(&mut vault, &mut registers, world);
    assert!(host.auth.pin_is_set());
    assert_eq!(host.assert(&token, &cred, true), status::PIN_AUTH_INVALID, "the old token died with the reset");
    let token = host.token(PIN).unwrap();
    assert_eq!(host.assert(&token, &cred, true), status::OK);
}

#[test]
fn a_reset_does_not_shorten_a_lockout() {
    let (mut vault, mut registers) = (Vault::new(), MemBackup::default());
    let mut host = Host::boot(&mut vault, &mut registers, World::new());
    assert_eq!(host.set_pin(PIN), status::OK);
    assert_eq!(host.token(b"0000"), Err(status::PIN_INVALID));
    assert_eq!(host.token(b"0000"), Err(status::PIN_AUTH_BLOCKED));
    let mut world = host.stop();

    // Resetting restarts the clock, and the lockout with it.
    world.now = 0;
    let mut host = Host::boot(&mut vault, &mut registers, world);
    assert_eq!(host.token(PIN), Err(status::PIN_AUTH_BLOCKED));
    host.world.now = CFG.base_delay_ms;
    assert!(host.token(PIN).is_ok());
}

#[test]
fn power_loss_forgets_everything() {
    let (mut vault, mut registers) = (Vault::new(), MemBackup::default());
    let mut host = Host::boot(&mut vault, &mut registers, World::new());
    assert_eq!(host.set_pin(PIN), status::OK);
    let world = host.stop();

    // The backup registers lose power (or the tamper pin fires): SRAM alone
    // is worthless, and the device comes up as new.
    registers = MemBackup::default();
    let mut host = Host::boot(&mut vault, &mut registers, world);
    assert!(!host.auth.pin_is_set());
    assert_eq!(host.token(PIN), Err(status::PIN_NOT_SET));
}

#[test]
fn rotation_does_not_disturb_anything() {
    let (mut vault, mut registers) = (Vault::new(), MemBackup::default());
    let mut host = Host::boot(&mut vault, &mut registers, World::new());
    assert_eq!(host.set_pin(PIN), status::OK);
    let token = host.token(PIN).unwrap();
    let cred = host.make(&token).unwrap();
    for i in 0..5u8 {
        host.auth.rotate(&[i; 16]);
        assert_eq!(host.assert(&token, &cred, true), status::OK);
    }
    let token = host.token(PIN).unwrap();
    assert_eq!(host.assert(&token, &cred, true), status::OK);
}

#[test]
fn touch_is_asked_for_exactly_when_it_should_be() {
    let (mut vault, mut registers) = (Vault::new(), MemBackup::default());
    let mut host = Host::boot(&mut vault, &mut registers, World::new());
    assert_eq!(host.set_pin(PIN), status::OK);
    let token = host.token(PIN).unwrap();
    assert_eq!(host.world.touches, 0, "setting and entering a PIN needs no touch");
    let cred = host.make(&token).unwrap();
    assert_eq!(host.world.touches, 1);
    assert_eq!(host.assert(&token, &cred, false), status::OK);
    assert_eq!(host.world.touches, 1, "a silent assertion asks for none");
    assert_eq!(host.assert(&token, &cred, true), status::OK);
    assert_eq!(host.world.touches, 2);
    // A credential that isn't ours is refused before anyone is bothered.
    assert_eq!(host.assert(&token, &[0; 48], true), status::NO_CREDENTIALS);
    assert_eq!(host.world.touches, 2);

    host.world.presence = Presence::Cancelled;
    assert_eq!(host.make(&token), Err(status::KEEPALIVE_CANCEL));
    host.world.presence = Presence::TimedOut;
    assert_eq!(host.assert(&token, &cred, true), status::ACTION_TIMEOUT);
    assert_eq!(host.raw(&[0x07]).0, status::ACTION_TIMEOUT);
    assert!(host.auth.pin_is_set(), "no touch, no reset");
}

/// The core takes requests from the untrusted bridge. Whatever arrives, it
/// must answer with a status byte and carry on.
#[test]
fn hostile_input_never_panics() {
    let (mut vault, mut registers) = (Vault::new(), MemBackup::default());
    let mut host = Host::boot(&mut vault, &mut registers, World::new());
    assert_eq!(host.set_pin(PIN), status::OK);
    let token = host.token(PIN).unwrap();
    let cred = host.make(&token).unwrap();

    let mut x = 0x1234_5678u32;
    let mut next = move || {
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        x
    };

    // A valid request of each kind to mutate.
    let cdh = [7u8; 32];
    let mut seeds: Vec<Vec<u8>> = vec![];
    let mut buf = [0u8; 512];
    let mut w = Writer::new(&mut buf[1..]);
    make_credential(&mut w, &cdh, &pin_auth(&token, &cdh));
    let n = w.finish().unwrap();
    buf[0] = 0x01;
    seeds.push(buf[..=n].to_vec());
    let mut w = Writer::new(&mut buf[1..]);
    w.map(4);
    w.uint(1);
    w.text(RP);
    w.uint(2);
    w.bytes(&cdh);
    w.uint(3);
    w.array(1);
    w.map(1);
    w.text("id");
    w.bytes(&cred);
    w.uint(4);
    w.map(1);
    w.text("hmac-secret");
    w.map(3);
    w.uint(1);
    cose_key(&mut w, &([1; 32], [2; 32]));
    w.uint(2);
    w.bytes(&[0; 32]);
    w.uint(3);
    w.bytes(&[0; 16]);
    let n = w.finish().unwrap();
    buf[0] = 0x02;
    seeds.push(buf[..=n].to_vec());
    let mut w = Writer::new(&mut buf[1..]);
    w.map(4);
    w.uint(1);
    w.uint(1);
    w.uint(2);
    w.uint(5);
    w.uint(3);
    cose_key(&mut w, &([1; 32], [2; 32]));
    w.uint(6);
    w.bytes(&[0; 16]);
    let n = w.finish().unwrap();
    buf[0] = 0x06;
    seeds.push(buf[..=n].to_vec());

    for round in 0..6000 {
        let mut request = match round % 4 {
            // Pure noise behind a real command byte.
            0 => {
                let len = (next() % 200) as usize;
                let mut r: Vec<u8> = (0..len).map(|_| next() as u8).collect();
                r.insert(0, [1u8, 2, 4, 6, 7, 8, 0x55][(next() % 7) as usize]);
                r
            }
            _ => seeds[(next() % 3) as usize].clone(),
        };
        match round % 4 {
            // A few flipped bytes.
            1 => {
                for _ in 0..1 + next() % 4 {
                    let i = (next() as usize) % request.len();
                    request[i] ^= 1 << (next() % 8);
                }
            }
            // Cut short.
            2 => request.truncate((next() as usize) % request.len()),
            // One byte replaced with a CBOR header that lies about a length.
            3 => {
                let i = 1 + (next() as usize) % (request.len() - 1);
                request[i] = [0x5B, 0x7B, 0x9B, 0xBB, 0x9F, 0xBF, 0xFF, 0x1B, 0x3B][(next() % 9) as usize];
            }
            _ => {}
        }
        // Never a reset by accident: the wipe would make the rest boring.
        if request.first() == Some(&0x07) {
            continue;
        }
        host.world.now += 2_000; // stay clear of the lockout
        host.raw(&request);
    }
    // Still standing, and still itself (unless wrong PINs wiped it, which is
    // the designed outcome and not a failure).
    assert_eq!(host.raw(&[0x04]).0, status::OK);
}
