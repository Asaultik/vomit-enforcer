//! The CTAP2 commands.
//!
//! What this authenticator is, in FIDO terms:
//!
//! * CTAP 2.0 with PIN protocol 1, ES256 credentials and the `hmac-secret`
//!   extension. No U2F, no discoverable credentials.
//! * **Nothing works without the PIN.** The key material for every credential
//!   comes from the vault slot the PIN unlocks, and it is only held in RAM
//!   for [`TOKEN_TTL_MS`] after a correct PIN. A request without proof of the
//!   PIN is answered with "PIN required".
//! * Wrong PINs are counted, throttled and finally answered with a wipe by
//!   the vault, exactly as for any other way of entering a PIN.
//!
//! The host never sends the PIN itself, only the first 16 bytes of its
//! SHA-256. Those 16 bytes are what the vault is given as the PIN.

use vomit_core::backup::BackupStore;
use vomit_core::kdf::Block;
use vomit_core::render::{Charset, Format};
use vomit_core::seed::Seed;
use vomit_core::vault::{Attempt, Config, Vault};
use zeroize::Zeroizing;

use crate::cbor::{Reader, Result, Writer};
use crate::cred::{self, Credential};
use crate::crypto::{self, KeyAgreement};
use crate::status::*;

/// Identifies the model of authenticator. Not secret, not unique per device.
pub const AAGUID: [u8; 16] = *b"vomit-enforcer\x00\x01";
/// Largest message accepted or produced.
pub const MAX_MSG: usize = vomit_link::frame::MAX_PAYLOAD;
/// How long after a correct PIN the unlocked seed stays in RAM.
pub const TOKEN_TTL_MS: u64 = 60_000;

/// One PIN, one slot, for now.
const SLOT: usize = 0;
/// Slots carry a passphrase format for typed output. FIDO does not use it.
const FORMAT: Format = Format { charset: Charset::Printable, length: 32 };
const MIN_PIN_LEN: usize = 4;

// Authenticator data flags.
const FLAG_UP: u8 = 0x01;
const FLAG_UV: u8 = 0x04;
const FLAG_AT: u8 = 0x40;
const FLAG_ED: u8 = 0x80;

// COSE algorithm identifiers.
const ES256: i64 = -7;
const ECDH_ES_HKDF_256: i64 = -25;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Presence {
    Confirmed,
    Cancelled,
    TimedOut,
}

/// What the authenticator needs from the outside world.
pub trait Platform {
    /// A clock that only goes forward.
    fn now_ms(&mut self) -> u64;
    fn random(&mut self, out: &mut [u8]);
    /// Block until the user touches the device, the host cancels, or it
    /// takes too long.
    fn user_presence(&mut self) -> Presence;
}

/// The slot unlocked by the last correct PIN.
struct Session {
    token: Zeroizing<[u8; 32]>,
    seed: Seed,
    expires_ms: u64,
}

pub struct Authenticator<'v, B: BackupStore> {
    vault: &'v mut Vault,
    bkp: B,
    cfg: Config,
    key_agreement: KeyAgreement,
    session: Option<Session>,
}

impl<'v, B: BackupStore> Authenticator<'v, B> {
    /// Call once after every reset.
    pub fn new(vault: &'v mut Vault, mut bkp: B, cfg: Config, p: &mut impl Platform) -> Self {
        vault.on_boot(&mut bkp, &cfg, p.now_ms());
        let key_agreement = KeyAgreement::generate(&mut |out| p.random(out));
        Self { vault, bkp, cfg, key_agreement, session: None }
    }

    /// Handle one request (command byte + CBOR). Writes the response (status
    /// byte + CBOR) to `out` and returns its length. Never panics on bad input.
    pub fn handle(&mut self, p: &mut impl Platform, memory: &mut [Block], request: &[u8], out: &mut [u8]) -> usize {
        let Some((status, body_out)) = out.split_first_mut() else { return 0 };
        self.tick(p.now_ms());
        let result = match request.split_first() {
            None => Err(INVALID_LENGTH),
            Some((0x01, body)) => self.make_credential(p, body, body_out),
            Some((0x02, body)) => self.get_assertion(p, body, body_out),
            Some((0x04, _)) => self.get_info(body_out),
            Some((0x06, body)) => self.client_pin(p, memory, body, body_out),
            Some((0x07, _)) => self.reset(p),
            // getNextAssertion: there is never a second assertion.
            Some((0x08, _)) => Err(NOT_ALLOWED),
            Some(_) => Err(INVALID_COMMAND),
        };
        match result {
            Ok(n) => {
                *status = OK;
                1 + n
            }
            Err(code) => {
                *status = code;
                1
            }
        }
    }

    /// Forget the unlocked seed once its time is up. [`Self::handle`] does
    /// this too; call it while idle so the seed does not outstay its welcome.
    pub fn tick(&mut self, now_ms: u64) {
        if self.session.as_ref().is_some_and(|s| now_ms >= s.expires_ms) {
            self.session = None;
        }
    }

    /// Re-encrypt the vault under a fresh master key. Call every few minutes.
    pub fn rotate(&mut self, noise: &[u8]) {
        if self.vault.is_live(&self.bkp) {
            self.vault.rotate(&mut self.bkp, noise);
        }
    }

    pub fn pin_is_set(&self) -> bool {
        self.vault.status(&self.bkp).is_some_and(|s| s.used.iter().any(|&used| used))
    }

    fn retries(&self) -> u64 {
        let failures = self.vault.status(&self.bkp).map_or(0, |s| s.failures);
        self.cfg.max_failures.saturating_sub(failures) as u64
    }

    fn new_key_agreement(&mut self, p: &mut impl Platform) {
        self.key_agreement = KeyAgreement::generate(&mut |out| p.random(out));
    }

    // ---- authenticatorGetInfo (0x04) ---------------------------------------

    fn get_info(&self, out: &mut [u8]) -> Result<usize> {
        let mut w = Writer::new(out);
        w.map(6);
        w.uint(1); // versions
        w.array(1);
        w.text("FIDO_2_0");
        w.uint(2); // extensions
        w.array(1);
        w.text("hmac-secret");
        w.uint(3);
        w.bytes(&AAGUID);
        w.uint(4); // options
        w.map(4);
        w.text("rk");
        w.bool(false);
        w.text("up");
        w.bool(true);
        // "Never works without user verification", so hosts ask for the PIN
        // up front. That is simply how this device is.
        w.text("alwaysUv");
        w.bool(true);
        w.text("clientPin");
        w.bool(self.pin_is_set());
        w.uint(5);
        w.uint(MAX_MSG as u64);
        w.uint(6); // PIN protocols
        w.array(1);
        w.uint(1);
        w.finish()
    }

    // ---- authenticatorClientPIN (0x06) -------------------------------------

    fn client_pin(
        &mut self,
        p: &mut impl Platform,
        memory: &mut [Block],
        body: &[u8],
        out: &mut [u8],
    ) -> Result<usize> {
        let mut r = Reader::new(body);
        let (mut protocol, mut subcommand, mut key) = (None, None, None);
        let (mut pin_auth, mut new_pin_enc, mut pin_hash_enc) = (None, None, None);
        for _ in 0..r.map()? {
            match r.uint()? {
                1 => protocol = Some(r.uint()?),
                2 => subcommand = Some(r.uint()?),
                3 => key = Some(cose_key(&mut r)?),
                4 => pin_auth = Some(r.bytes()?),
                5 => new_pin_enc = Some(r.bytes()?),
                6 => pin_hash_enc = Some(r.bytes()?),
                _ => r.skip()?,
            }
        }
        if protocol.ok_or(MISSING_PARAMETER)? != 1 {
            return Err(INVALID_PARAMETER);
        }
        let mut w = Writer::new(out);
        match subcommand.ok_or(MISSING_PARAMETER)? {
            // getRetries
            1 => {
                w.map(1);
                w.uint(3);
                w.uint(self.retries());
            }
            // getKeyAgreement
            2 => {
                w.map(1);
                w.uint(1);
                write_cose_key(&mut w, ECDH_ES_HKDF_256, &self.key_agreement.x, &self.key_agreement.y);
            }
            // setPIN
            3 => {
                let (key, new_pin_enc) = (key.ok_or(MISSING_PARAMETER)?, new_pin_enc.ok_or(MISSING_PARAMETER)?);
                self.set_pin(p, memory, key, new_pin_enc, pin_auth.ok_or(MISSING_PARAMETER)?)?;
            }
            // changePIN
            4 => {
                let (key, new_pin_enc) = (key.ok_or(MISSING_PARAMETER)?, new_pin_enc.ok_or(MISSING_PARAMETER)?);
                let (pin_hash_enc, pin_auth) =
                    (pin_hash_enc.ok_or(MISSING_PARAMETER)?, pin_auth.ok_or(MISSING_PARAMETER)?);
                self.change_pin(p, memory, key, pin_hash_enc, new_pin_enc, pin_auth)?;
            }
            // getPinToken
            5 => {
                let (key, pin_hash_enc) = (key.ok_or(MISSING_PARAMETER)?, pin_hash_enc.ok_or(MISSING_PARAMETER)?);
                let token = self.get_pin_token(p, memory, key, pin_hash_enc)?;
                w.map(1);
                w.uint(2);
                w.bytes(&token);
            }
            _ => return Err(INVALID_SUBCOMMAND),
        }
        w.finish()
    }

    fn shared_secret(&self, key: ([u8; 32], [u8; 32])) -> Result<Zeroizing<[u8; 32]>> {
        self.key_agreement.shared_secret(&key.0, &key.1).ok_or(INVALID_PARAMETER)
    }

    /// Setting the first PIN creates the vault and one slot with a fresh
    /// random seed behind that PIN.
    fn set_pin(
        &mut self,
        p: &mut impl Platform,
        memory: &mut [Block],
        key: ([u8; 32], [u8; 32]),
        new_pin_enc: &[u8],
        pin_auth: &[u8],
    ) -> Result<()> {
        if self.pin_is_set() {
            return Err(PIN_AUTH_INVALID);
        }
        let shared = self.shared_secret(key)?;
        if !crypto::verify16(&shared[..], &[new_pin_enc], pin_auth) {
            return Err(PIN_AUTH_INVALID);
        }
        let pin = new_pin_hash(&shared, new_pin_enc)?;

        if !self.vault.is_live(&self.bkp) {
            let mut entropy = Zeroizing::new([0u8; 64]);
            p.random(&mut entropy[..]);
            self.vault.init(&mut self.bkp, &entropy[..]).map_err(|_| OTHER)?;
        }
        let mut seed = Zeroizing::new([0u8; 32]);
        p.random(&mut seed[..]);
        self.store(p, memory, SLOT, &pin, &Seed::from_bytes(*seed), &FORMAT)
    }

    fn store(
        &mut self,
        p: &mut impl Platform,
        memory: &mut [Block],
        slot: usize,
        pin: &[u8; 16],
        seed: &Seed,
        format: &Format,
    ) -> Result<()> {
        let (mut salt, mut noise) = ([0u8; 16], [0u8; 16]);
        p.random(&mut salt);
        p.random(&mut noise);
        let now = p.now_ms();
        self.vault
            .store(&mut self.bkp, &self.cfg, memory, slot, &pin_values(pin), seed, format, salt, &noise, now)
            .map_err(|_| OTHER)
    }

    /// Check a PIN against the vault, which counts, throttles and wipes as it
    /// sees fit. On success: which slot, its seed and its format.
    fn try_pin(
        &mut self,
        p: &mut impl Platform,
        memory: &mut [Block],
        pin: &[u8; 16],
    ) -> Result<(usize, Seed, Format)> {
        let now = p.now_ms();
        match self.vault.attempt(&mut self.bkp, &self.cfg, memory, &pin_values(pin), now) {
            Attempt::Unlocked { slot, seed, format } => Ok((slot, seed, format)),
            Attempt::TooSoon { .. } => Err(PIN_AUTH_BLOCKED),
            Attempt::Misconfigured => Err(OTHER),
            wrong @ (Attempt::Wrong { .. } | Attempt::Wiped) => {
                // A wrong PIN ends any session. The fresh key agreement key
                // means the host must start the exchange over for each guess.
                self.session = None;
                self.new_key_agreement(p);
                Err(if matches!(wrong, Attempt::Wiped) { PIN_BLOCKED } else { PIN_INVALID })
            }
        }
    }

    fn decrypt_pin_hash(shared: &[u8; 32], pin_hash_enc: &[u8]) -> Result<Zeroizing<[u8; 16]>> {
        let mut hash = Zeroizing::new([0u8; 16]);
        if pin_hash_enc.len() != hash.len() {
            return Err(INVALID_PARAMETER);
        }
        hash.copy_from_slice(pin_hash_enc);
        crypto::cbc_decrypt(shared, &mut hash[..]);
        Ok(hash)
    }

    /// A correct PIN unlocks the slot's seed into RAM and returns a token (to
    /// the host, encrypted) that later requests must prove they hold.
    fn get_pin_token(
        &mut self,
        p: &mut impl Platform,
        memory: &mut [Block],
        key: ([u8; 32], [u8; 32]),
        pin_hash_enc: &[u8],
    ) -> Result<[u8; 32]> {
        if !self.pin_is_set() {
            return Err(PIN_NOT_SET);
        }
        let shared = self.shared_secret(key)?;
        let pin = Self::decrypt_pin_hash(&shared, pin_hash_enc)?;
        let (_, seed, _) = self.try_pin(p, memory, &pin)?;

        let mut token = Zeroizing::new([0u8; 32]);
        p.random(&mut token[..]);
        let mut encrypted = *token;
        crypto::cbc_encrypt(&shared, &mut encrypted);
        self.session = Some(Session { token, seed, expires_ms: p.now_ms().saturating_add(TOKEN_TTL_MS) });
        Ok(encrypted)
    }

    /// The same seed behind a new PIN: credentials keep working.
    fn change_pin(
        &mut self,
        p: &mut impl Platform,
        memory: &mut [Block],
        key: ([u8; 32], [u8; 32]),
        pin_hash_enc: &[u8],
        new_pin_enc: &[u8],
        pin_auth: &[u8],
    ) -> Result<()> {
        if !self.pin_is_set() {
            return Err(PIN_NOT_SET);
        }
        let shared = self.shared_secret(key)?;
        if !crypto::verify16(&shared[..], &[new_pin_enc, pin_hash_enc], pin_auth) {
            return Err(PIN_AUTH_INVALID);
        }
        let old = Self::decrypt_pin_hash(&shared, pin_hash_enc)?;
        let (slot, seed, format) = self.try_pin(p, memory, &old)?;
        let new = new_pin_hash(&shared, new_pin_enc)?;
        // Tokens handed out under the old PIN are no longer good.
        self.session = None;
        self.store(p, memory, slot, &new, &seed, &format)
    }

    // ---- authenticatorReset (0x07) -----------------------------------------

    /// Forget everything. Needs a touch, so software on the host alone
    /// cannot do it.
    fn reset(&mut self, p: &mut impl Platform) -> Result<usize> {
        presence(p)?;
        self.vault.wipe(&mut self.bkp);
        self.session = None;
        self.new_key_agreement(p);
        Ok(0)
    }

    // ---- shared by makeCredential and getAssertion -------------------------

    /// Credentials need the slot seed, which is only in RAM after a correct
    /// PIN. So the request must prove it holds this session's PIN token by
    /// MACing its client data hash with it. Returns the seed.
    fn authorize(
        &mut self,
        p: &mut impl Platform,
        pin_auth: Option<&[u8]>,
        pin_protocol: Option<u64>,
        client_data_hash: &[u8],
    ) -> Result<Seed> {
        let pin_set = self.pin_is_set();
        let Some(pin_auth) = pin_auth else {
            return Err(if pin_set { PIN_REQUIRED } else { PIN_NOT_SET });
        };
        if pin_auth.is_empty() {
            // How a host asks "is this the device you mean?": wait for a
            // touch, then report only whether a PIN exists.
            presence(p)?;
            return Err(if pin_set { PIN_INVALID } else { PIN_NOT_SET });
        }
        if !pin_set {
            return Err(PIN_NOT_SET);
        }
        let session = self.session.as_ref().ok_or(PIN_AUTH_INVALID)?;
        if pin_protocol != Some(1) || !crypto::verify16(&session.token[..], &[client_data_hash], pin_auth) {
            return Err(PIN_AUTH_INVALID);
        }
        Ok(session.seed.clone())
    }

    // ---- authenticatorMakeCredential (0x01) --------------------------------

    fn make_credential(&mut self, p: &mut impl Platform, body: &[u8], out: &mut [u8]) -> Result<usize> {
        let mut r = Reader::new(body);
        let (mut client_data_hash, mut rp_id, mut user, mut es256) = (None, None, false, None);
        let (mut exclude, mut hmac_secret, mut opts) = (None, false, Options::default());
        let (mut pin_auth, mut pin_protocol) = (None, None);
        for _ in 0..r.map()? {
            match r.uint()? {
                1 => client_data_hash = Some(r.bytes()?),
                2 => rp_id = Some(text_entry(&mut r, b"id")?),
                3 => {
                    // The user's name and ID would only matter for
                    // credentials stored on the device.
                    r.skip()?;
                    user = true;
                }
                4 => es256 = Some(offers_es256(&mut r)?),
                5 => exclude = Some(r.raw()?),
                6 => hmac_secret = wants_hmac_secret(&mut r)?,
                7 => opts = options(&mut r)?,
                8 => pin_auth = Some(r.bytes()?),
                9 => pin_protocol = Some(r.uint()?),
                _ => r.skip()?,
            }
        }
        let client_data_hash = client_data_hash.ok_or(MISSING_PARAMETER)?;
        let rp_id = rp_id.ok_or(MISSING_PARAMETER)?;
        if !user {
            return Err(MISSING_PARAMETER);
        }
        if !es256.ok_or(MISSING_PARAMETER)? {
            return Err(UNSUPPORTED_ALGORITHM);
        }
        // No credentials stored on the device and no fingerprint reader. An
        // explicit "false" for either is fine.
        if opts.rk == Some(true) || opts.uv == Some(true) {
            return Err(UNSUPPORTED_OPTION);
        }
        if opts.up == Some(false) {
            return Err(INVALID_OPTION);
        }

        let seed = self.authorize(p, pin_auth, pin_protocol, client_data_hash)?;
        let rp_id_hash = crypto::sha256(&[rp_id]);
        if let Some(list) = exclude {
            if find_credential(&seed, &rp_id_hash, list)?.is_some() {
                presence(p)?;
                return Err(CREDENTIAL_EXCLUDED);
            }
        }
        presence(p)?;

        let credential = cred::create(&seed, &rp_id_hash, &mut |out| p.random(out));
        let (x, y) = credential.public();

        // rpIdHash | flags | signCount | aaguid | idLen | id | public key | extensions
        let mut auth_data = [0u8; 224];
        let mut w = Writer::new(&mut auth_data);
        w.raw(&rp_id_hash);
        w.raw(&[FLAG_UP | FLAG_UV | FLAG_AT | if hmac_secret { FLAG_ED } else { 0 }]);
        w.raw(&[0; 4]); // no signature counter: nothing is stored per credential
        w.raw(&AAGUID);
        w.raw(&(cred::ID_LEN as u16).to_be_bytes());
        w.raw(&credential.id);
        write_cose_key(&mut w, ES256, &x, &y);
        if hmac_secret {
            w.map(1);
            w.text("hmac-secret");
            w.bool(true);
        }
        let n = w.finish()?;
        let auth_data = &auth_data[..n];

        // "Packed" self attestation: signed with the new credential's own key.
        let mut signature = [0u8; crypto::MAX_SIG];
        let sig_len = credential.sign(&[auth_data, client_data_hash], &mut signature);

        let mut w = Writer::new(out);
        w.map(3);
        w.uint(1);
        w.text("packed");
        w.uint(2);
        w.bytes(auth_data);
        w.uint(3);
        w.map(2);
        w.text("alg");
        w.int(ES256);
        w.text("sig");
        w.bytes(&signature[..sig_len]);
        w.finish()
    }

    // ---- authenticatorGetAssertion (0x02) ----------------------------------

    fn get_assertion(&mut self, p: &mut impl Platform, body: &[u8], out: &mut [u8]) -> Result<usize> {
        let mut r = Reader::new(body);
        let (mut rp_id, mut client_data_hash, mut allow, mut hmac_secret) = (None, None, None, None);
        let (mut opts, mut pin_auth, mut pin_protocol) = (Options::default(), None, None);
        for _ in 0..r.map()? {
            match r.uint()? {
                1 => rp_id = Some(r.text()?),
                2 => client_data_hash = Some(r.bytes()?),
                3 => allow = Some(r.raw()?),
                4 => hmac_secret = hmac_secret_input(&mut r)?,
                5 => opts = options(&mut r)?,
                6 => pin_auth = Some(r.bytes()?),
                7 => pin_protocol = Some(r.uint()?),
                _ => r.skip()?,
            }
        }
        let rp_id = rp_id.ok_or(MISSING_PARAMETER)?;
        let client_data_hash = client_data_hash.ok_or(MISSING_PARAMETER)?;
        if opts.uv == Some(true) {
            return Err(UNSUPPORTED_OPTION);
        }

        let seed = self.authorize(p, pin_auth, pin_protocol, client_data_hash)?;
        let rp_id_hash = crypto::sha256(&[rp_id]);
        // Nothing is stored here, so without a list of credential IDs to
        // check there is nothing to find.
        let credential = match allow {
            Some(list) => find_credential(&seed, &rp_id_hash, list)?,
            None => None,
        }
        .ok_or(NO_CREDENTIALS)?;

        // "up": false is a silent check that a credential is ours.
        let up = opts.up != Some(false);
        if up {
            presence(p)?;
        }

        // rpIdHash | flags | signCount | extensions
        let mut auth_data = [0u8; 128];
        let mut w = Writer::new(&mut auth_data);
        w.raw(&rp_id_hash);
        w.raw(&[FLAG_UV | if up { FLAG_UP } else { 0 } | if hmac_secret.is_some() { FLAG_ED } else { 0 }]);
        w.raw(&[0; 4]);
        if let Some(input) = &hmac_secret {
            let mut output = Zeroizing::new([0u8; 64]);
            let n = self.hmac_secret(&credential, input, &mut output)?;
            w.map(1);
            w.text("hmac-secret");
            w.bytes(&output[..n]);
        }
        let n = w.finish()?;
        let auth_data = &auth_data[..n];

        let mut signature = [0u8; crypto::MAX_SIG];
        let sig_len = credential.sign(&[auth_data, client_data_hash], &mut signature);

        let mut w = Writer::new(out);
        w.map(3);
        w.uint(1);
        w.map(2);
        w.text("id");
        w.bytes(&credential.id);
        w.text("type");
        w.text("public-key");
        w.uint(2);
        w.bytes(auth_data);
        w.uint(3);
        w.bytes(&signature[..sig_len]);
        w.finish()
    }

    /// The hmac-secret extension: `HMAC-SHA256(cred_random, salt)` for one or
    /// two 32-byte salts, with salts and outputs encrypted under the PIN
    /// protocol's shared secret. This is the value a disk-unlock key is made
    /// from. Returns the output length.
    fn hmac_secret(&self, credential: &Credential, input: &HmacSecretInput, out: &mut [u8; 64]) -> Result<usize> {
        let n = input.salt_enc.len();
        if n != 32 && n != 64 {
            return Err(INVALID_LENGTH);
        }
        let shared = self.shared_secret(input.key)?;
        if !crypto::verify16(&shared[..], &[input.salt_enc], input.salt_auth) {
            return Err(PIN_AUTH_INVALID);
        }
        out[..n].copy_from_slice(input.salt_enc);
        crypto::cbc_decrypt(&shared, &mut out[..n]);
        for salt in out[..n].chunks_exact_mut(32) {
            let output = crypto::hmac_sha256(&credential.cred_random[..], &[&*salt]);
            salt.copy_from_slice(&output);
        }
        crypto::cbc_encrypt(&shared, &mut out[..n]);
        Ok(n)
    }
}

fn presence(p: &mut impl Platform) -> Result<()> {
    match p.user_presence() {
        Presence::Confirmed => Ok(()),
        Presence::Cancelled => Err(KEEPALIVE_CANCEL),
        Presence::TimedOut => Err(ACTION_TIMEOUT),
    }
}

/// The vault takes a PIN as a list of numbers; give it the hash, a byte each.
fn pin_values(hash: &[u8; 16]) -> [u16; 16] {
    hash.map(u16::from)
}

/// Decrypt a new PIN (64 bytes, zero padded), check it, and reduce it to the
/// 16-byte hash the host will present from then on.
fn new_pin_hash(shared: &[u8; 32], new_pin_enc: &[u8]) -> Result<Zeroizing<[u8; 16]>> {
    let mut pin = Zeroizing::new([0u8; 64]);
    if new_pin_enc.len() != pin.len() {
        return Err(INVALID_PARAMETER);
    }
    pin.copy_from_slice(new_pin_enc);
    crypto::cbc_decrypt(shared, &mut pin[..]);
    let len = pin.iter().position(|&b| b == 0).ok_or(PIN_POLICY_VIOLATION)?;
    // At least four characters, counting a multi-byte UTF-8 character once.
    if pin[..len].iter().filter(|&&b| b & 0xC0 != 0x80).count() < MIN_PIN_LEN {
        return Err(PIN_POLICY_VIOLATION);
    }
    let digest = Zeroizing::new(crypto::sha256(&[&pin[..len]]));
    let mut hash = Zeroizing::new([0u8; 16]);
    hash.copy_from_slice(&digest[..16]);
    Ok(hash)
}

#[derive(Default)]
struct Options {
    rk: Option<bool>,
    uv: Option<bool>,
    up: Option<bool>,
}

fn options(r: &mut Reader) -> Result<Options> {
    let mut o = Options::default();
    for _ in 0..r.map()? {
        match r.text()? {
            b"rk" => o.rk = Some(r.bool()?),
            b"uv" => o.uv = Some(r.bool()?),
            b"up" => o.up = Some(r.bool()?),
            _ => r.skip()?,
        }
    }
    Ok(o)
}

/// The text value stored under `key` in the map that follows.
fn text_entry<'a>(r: &mut Reader<'a>, key: &[u8]) -> Result<&'a [u8]> {
    let mut found = None;
    for _ in 0..r.map()? {
        if r.text()? == key {
            found = Some(r.text()?);
        } else {
            r.skip()?;
        }
    }
    found.ok_or(MISSING_PARAMETER)
}

/// Whether the list of acceptable key types includes ES256.
fn offers_es256(r: &mut Reader) -> Result<bool> {
    let mut found = false;
    for _ in 0..r.array()? {
        let (mut alg, mut kind) = (None, None);
        for _ in 0..r.map()? {
            match r.text()? {
                b"alg" => alg = Some(r.int()?),
                b"type" => kind = Some(r.text()?),
                _ => r.skip()?,
            }
        }
        found |= alg == Some(ES256) && kind == Some(&b"public-key"[..]);
    }
    Ok(found)
}

/// Whether makeCredential's extensions ask for hmac-secret.
fn wants_hmac_secret(r: &mut Reader) -> Result<bool> {
    let mut wanted = false;
    for _ in 0..r.map()? {
        if r.text()? == b"hmac-secret" {
            wanted = r.bool()?;
        } else {
            r.skip()?;
        }
    }
    Ok(wanted)
}

struct HmacSecretInput<'a> {
    key: ([u8; 32], [u8; 32]),
    salt_enc: &'a [u8],
    salt_auth: &'a [u8],
}

/// getAssertion's hmac-secret input, if its extensions carry one.
fn hmac_secret_input<'a>(r: &mut Reader<'a>) -> Result<Option<HmacSecretInput<'a>>> {
    let mut found = None;
    for _ in 0..r.map()? {
        if r.text()? != b"hmac-secret" {
            r.skip()?;
            continue;
        }
        let (mut key, mut salt_enc, mut salt_auth) = (None, None, None);
        for _ in 0..r.map()? {
            match r.uint()? {
                1 => key = Some(cose_key(r)?),
                2 => salt_enc = Some(r.bytes()?),
                3 => salt_auth = Some(r.bytes()?),
                _ => r.skip()?,
            }
        }
        found = Some(HmacSecretInput {
            key: key.ok_or(MISSING_PARAMETER)?,
            salt_enc: salt_enc.ok_or(MISSING_PARAMETER)?,
            salt_auth: salt_auth.ok_or(MISSING_PARAMETER)?,
        });
    }
    Ok(found)
}

/// The first credential in a list of descriptors that is ours for this
/// relying party.
fn find_credential(seed: &Seed, rp_id_hash: &[u8; 32], list: &[u8]) -> Result<Option<Credential>> {
    let mut r = Reader::new(list);
    for _ in 0..r.array()? {
        let mut id = None;
        for _ in 0..r.map()? {
            if r.text()? == b"id" {
                id = Some(r.bytes()?);
            } else {
                r.skip()?;
            }
        }
        if let Some(credential) = id.and_then(|id| cred::open(seed, rp_id_hash, id)) {
            return Ok(Some(credential));
        }
    }
    Ok(None)
}

/// The coordinates of a P-256 public key in COSE form.
fn cose_key(r: &mut Reader) -> Result<([u8; 32], [u8; 32])> {
    let (mut x, mut y) = (None, None);
    for _ in 0..r.map()? {
        match r.int()? {
            -2 => x = Some(r.bytes()?),
            -3 => y = Some(r.bytes()?),
            _ => r.skip()?,
        }
    }
    let coordinate = |c: Option<&[u8]>| -> Result<[u8; 32]> {
        c.ok_or(MISSING_PARAMETER)?.try_into().map_err(|_| INVALID_PARAMETER)
    };
    Ok((coordinate(x)?, coordinate(y)?))
}

fn write_cose_key(w: &mut Writer, alg: i64, x: &[u8; 32], y: &[u8; 32]) {
    w.map(5);
    w.uint(1); // key type: elliptic curve with x and y
    w.uint(2);
    w.uint(3);
    w.int(alg);
    w.int(-1); // curve: P-256
    w.uint(1);
    w.int(-2);
    w.bytes(x);
    w.int(-3);
    w.bytes(y);
}
