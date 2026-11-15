"""End to end against libfido2, the C library behind systemd-cryptenroll,
systemd-cryptsetup, OpenSSH's security-key support and pam-u2f.

libfido2 lets a program supply its own read/write functions for a device. We
point those at the simulator, so the real library does everything else: the
HID packet framing, the PIN protocol, hmac-secret. The tests then make the
same calls, in the same order, that systemd and OpenSSH make.

Needs the shared library: `apt install libfido2-1`, or set LIBFIDO2 to its
path. Without it these tests are skipped.
"""

import ctypes
import ctypes.util
import os
import time
import unittest
from ctypes import POINTER, byref, c_bool, c_char_p, c_int, c_size_t, c_ubyte, c_void_p

from sim import Sim, read_packet

# From <fido/param.h>, <fido/types.h> and <fido/err.h>.
COSE_ES256 = -7
FIDO_EXT_HMAC_SECRET = 0x01
FIDO_EXT_CRED_PROTECT = 0x02
FIDO_CRED_PROT_UV_REQUIRED = 0x03
OMIT, FALSE, TRUE = 0, 1, 2
OK = 0
ERR_RX = -2
ERR_UNSUPPORTED_OPTION = 0x2B
ERR_NO_CREDENTIALS = 0x2E
ERR_PIN_INVALID = 0x31
ERR_PIN_AUTH_BLOCKED = 0x34
ERR_PIN_NOT_SET = 0x35
ERR_PIN_REQUIRED = 0x36
ERR_ACTION_TIMEOUT = 0x3A

OPEN = ctypes.CFUNCTYPE(c_void_p, c_char_p)
CLOSE = ctypes.CFUNCTYPE(None, c_void_p)
READ = ctypes.CFUNCTYPE(c_int, c_void_p, POINTER(c_ubyte), c_size_t, c_int)
WRITE = ctypes.CFUNCTYPE(c_int, c_void_p, POINTER(c_ubyte), c_size_t)


class Io(ctypes.Structure):
    _fields_ = [("open", OPEN), ("close", CLOSE), ("read", READ), ("write", WRITE)]


def load():
    path = os.environ.get("LIBFIDO2") or ctypes.util.find_library("fido2")
    if not path:
        raise unittest.SkipTest("libfido2 not found: install it or set LIBFIDO2=/path/to/libfido2.so")
    lib = ctypes.CDLL(path)

    def declare(name, restype, *argtypes):
        fn = getattr(lib, name)
        fn.restype, fn.argtypes = restype, list(argtypes)

    P = c_void_p
    declare("fido_init", None, c_int)
    declare("fido_strerr", c_char_p, c_int)
    declare("fido_dev_new", P)
    declare("fido_dev_free", None, POINTER(P))
    declare("fido_dev_set_io_functions", c_int, P, POINTER(Io))
    declare("fido_dev_set_timeout", c_int, P, c_int)
    declare("fido_dev_open", c_int, P, c_char_p)
    declare("fido_dev_close", c_int, P)
    declare("fido_dev_is_fido2", c_bool, P)
    declare("fido_dev_has_pin", c_bool, P)
    declare("fido_dev_set_pin", c_int, P, c_char_p, c_char_p)
    declare("fido_dev_get_retry_count", c_int, P, POINTER(c_int))
    declare("fido_dev_reset", c_int, P)
    declare("fido_dev_get_cbor_info", c_int, P, P)
    declare("fido_cbor_info_new", P)
    declare("fido_cbor_info_free", None, POINTER(P))
    declare("fido_cbor_info_extensions_ptr", POINTER(c_char_p), P)
    declare("fido_cbor_info_extensions_len", c_size_t, P)
    declare("fido_cbor_info_options_name_ptr", POINTER(c_char_p), P)
    declare("fido_cbor_info_options_value_ptr", POINTER(c_bool), P)
    declare("fido_cbor_info_options_len", c_size_t, P)
    declare("fido_cred_new", P)
    declare("fido_cred_free", None, POINTER(P))
    declare("fido_cred_set_type", c_int, P, c_int)
    declare("fido_cred_set_rp", c_int, P, c_char_p, c_char_p)
    declare("fido_cred_set_clientdata_hash", c_int, P, c_char_p, c_size_t)
    declare("fido_cred_set_user", c_int, P, c_char_p, c_size_t, c_char_p, c_char_p, c_char_p)
    declare("fido_cred_set_extensions", c_int, P, c_int)
    declare("fido_cred_set_prot", c_int, P, c_int)
    declare("fido_cred_set_rk", c_int, P, c_int)
    declare("fido_cred_set_uv", c_int, P, c_int)
    declare("fido_dev_make_cred", c_int, P, P, c_char_p)
    declare("fido_cred_id_ptr", POINTER(c_ubyte), P)
    declare("fido_cred_id_len", c_size_t, P)
    declare("fido_cred_pubkey_ptr", POINTER(c_ubyte), P)
    declare("fido_cred_pubkey_len", c_size_t, P)
    declare("fido_cred_x5c_ptr", POINTER(c_ubyte), P)
    declare("fido_cred_fmt", c_char_p, P)
    declare("fido_cred_flags", ctypes.c_uint8, P)
    declare("fido_cred_verify_self", c_int, P)
    declare("fido_assert_new", P)
    declare("fido_assert_free", None, POINTER(P))
    declare("fido_assert_set_rp", c_int, P, c_char_p)
    declare("fido_assert_set_clientdata_hash", c_int, P, c_char_p, c_size_t)
    declare("fido_assert_allow_cred", c_int, P, c_char_p, c_size_t)
    declare("fido_assert_set_extensions", c_int, P, c_int)
    declare("fido_assert_set_hmac_salt", c_int, P, c_char_p, c_size_t)
    declare("fido_assert_set_up", c_int, P, c_int)
    declare("fido_assert_set_uv", c_int, P, c_int)
    declare("fido_dev_get_assert", c_int, P, P, c_char_p)
    declare("fido_assert_count", c_size_t, P)
    declare("fido_assert_flags", ctypes.c_uint8, P, c_size_t)
    declare("fido_assert_hmac_secret_ptr", POINTER(c_ubyte), P, c_size_t)
    declare("fido_assert_hmac_secret_len", c_size_t, P, c_size_t)
    declare("fido_assert_verify", c_int, P, c_size_t, c_int, P)
    declare("es256_pk_new", P)
    declare("es256_pk_free", None, POINTER(P))
    declare("es256_pk_from_ptr", c_int, P, c_char_p, c_size_t)
    lib.fido_init(1 if os.environ.get("FIDO_DEBUG") else 0)
    return lib


class Device:
    """A libfido2 device handle whose I/O goes to the simulator."""

    def __init__(self, lib, sim):
        self.lib = lib
        self.sock = sim.connect()
        # libfido2 keeps pointers to these, so they must outlive the handle.
        self.io = Io(OPEN(lambda path: 1), CLOSE(lambda handle: None), READ(self._read), WRITE(self._write))
        self.dev = c_void_p(lib.fido_dev_new())
        assert lib.fido_dev_set_io_functions(self.dev, byref(self.io)) == OK
        assert lib.fido_dev_set_timeout(self.dev, 20_000) == OK
        r = lib.fido_dev_open(self.dev, b"sim")
        assert r == OK, lib.fido_strerr(r)

    def _read(self, handle, buf, length, ms):
        try:
            data = read_packet(self.sock, None if ms < 0 else ms / 1000)
        except (TimeoutError, OSError):
            return -1
        ctypes.memmove(buf, data, len(data))
        return len(data)

    def _write(self, handle, buf, length):
        # The first byte is the HID report number (0); the report follows.
        try:
            self.sock.sendall(bytes(buf[1:length]))
        except OSError:
            return -1
        return length

    def close(self):
        self.lib.fido_dev_close(self.dev)
        self.lib.fido_dev_free(byref(self.dev))
        self.sock.close()

    def features(self):
        """systemd's verify_features(): what the device says it can do."""
        lib = self.lib
        info = c_void_p(lib.fido_cbor_info_new())
        assert lib.fido_dev_get_cbor_info(self.dev, info) == OK
        ext = lib.fido_cbor_info_extensions_ptr(info)
        extensions = [ext[i].decode() for i in range(lib.fido_cbor_info_extensions_len(info))]
        names, values = lib.fido_cbor_info_options_name_ptr(info), lib.fido_cbor_info_options_value_ptr(info)
        options = {names[i].decode(): bool(values[i]) for i in range(lib.fido_cbor_info_options_len(info))}
        lib.fido_cbor_info_free(byref(info))
        return extensions, options


def blob(ptr, length):
    return bytes(ptr[:length])


class WithDevice(unittest.TestCase):
    ARGS: tuple = ()

    @classmethod
    def setUpClass(cls):
        cls.lib = load()

    def setUp(self):
        self.sim = Sim(*self.ARGS)
        self.addCleanup(self.sim.close)
        self.dev = self.open()

    def open(self) -> Device:
        dev = Device(self.lib, self.sim)
        self.addCleanup(dev.close)
        return dev

    def check(self, r, expected=OK):
        self.assertEqual(r, expected, f"got {self.lib.fido_strerr(r).decode()}, wanted {self.lib.fido_strerr(expected).decode()}")

    # -- the calls systemd makes, with systemd's parameters -------------------

    RP = b"io.systemd.cryptsetup"
    ZERO_HASH = bytes(32)

    def new_cred(self, extensions=FIDO_EXT_HMAC_SECRET, rp=RP, cdh=ZERO_HASH):
        lib = self.lib
        c = c_void_p(lib.fido_cred_new())
        self.addCleanup(lambda: lib.fido_cred_free(byref(c)))
        if extensions & FIDO_EXT_CRED_PROTECT:
            self.check(lib.fido_cred_set_prot(c, FIDO_CRED_PROT_UV_REQUIRED))
        self.check(lib.fido_cred_set_extensions(c, extensions))
        self.check(lib.fido_cred_set_rp(c, rp, b"Encrypted Volume"))
        self.check(lib.fido_cred_set_type(c, COSE_ES256))
        user_id = os.urandom(16)
        self.check(lib.fido_cred_set_user(c, user_id, len(user_id), b"root", b"root", None))
        self.check(lib.fido_cred_set_clientdata_hash(c, cdh, len(cdh)))
        self.check(lib.fido_cred_set_rk(c, FALSE))
        self.check(lib.fido_cred_set_uv(c, FALSE))
        return c

    def new_assert(self, cred_id, salt=None, up=TRUE, rp=RP, cdh=ZERO_HASH):
        lib = self.lib
        a = c_void_p(lib.fido_assert_new())
        self.addCleanup(lambda: lib.fido_assert_free(byref(a)))
        if salt is not None:
            self.check(lib.fido_assert_set_extensions(a, FIDO_EXT_HMAC_SECRET))
            self.check(lib.fido_assert_set_hmac_salt(a, salt, len(salt)))
        self.check(lib.fido_assert_set_rp(a, rp))
        self.check(lib.fido_assert_set_clientdata_hash(a, cdh, len(cdh)))
        self.check(lib.fido_assert_allow_cred(a, cred_id, len(cred_id)))
        self.check(lib.fido_assert_set_up(a, up))
        return a

    def secret(self, a):
        return blob(self.lib.fido_assert_hmac_secret_ptr(a, 0), self.lib.fido_assert_hmac_secret_len(a, 0))


class Cryptenroll(WithDevice):
    """systemd-cryptenroll --fido2-device=... followed by unlocking at boot."""

    PIN = b"123456"

    def test_enroll_then_unlock(self):
        lib, dev = self.lib, self.dev.dev
        self.check(lib.fido_dev_set_pin(dev, self.PIN, None))  # fido2-token -S

        # ---- enrolment: fido2_generate_hmac_hash() ----
        enroll = self.open()
        self.assertTrue(lib.fido_dev_is_fido2(enroll.dev))
        extensions, options = enroll.features()
        self.assertIn("hmac-secret", extensions)
        self.assertEqual(options, {"rk": False, "up": True, "alwaysUv": True, "clientPin": True})

        salt = os.urandom(32)
        # systemd also asks for credProtect when a PIN is used. We don't
        # offer that extension, which a token is free to do.
        c = self.new_cred(FIDO_EXT_HMAC_SECRET | FIDO_EXT_CRED_PROTECT)
        # First without a PIN; the token says it wants one.
        self.check(lib.fido_dev_make_cred(enroll.dev, c, None), ERR_PIN_REQUIRED)
        # "Please enter security token PIN:"
        self.check(lib.fido_dev_make_cred(enroll.dev, c, self.PIN))
        cred_id = blob(lib.fido_cred_id_ptr(c), lib.fido_cred_id_len(c))
        self.assertEqual(len(cred_id), 48)

        a = self.new_assert(cred_id, salt)
        self.check(lib.fido_dev_get_assert(enroll.dev, a, self.PIN))
        self.assertEqual(lib.fido_assert_count(a), 1)
        enrolled = self.secret(a)
        self.assertEqual(len(enrolled), 32)
        # This secret becomes a LUKS key slot; cred_id and salt go in the header.

        # ---- unlock, later, from a fresh process: fido2_use_hmac_hash() ----
        boot = self.open()
        extensions, options = boot.features()
        self.assertTrue(options["clientPin"], "systemd refuses PIN-enrolled volumes on a token with no PIN")

        # Pre-flight: "is this credential on this token?", silently.
        # With the PIN, we can say yes without asking for a touch...
        probe = self.new_assert(cred_id, up=FALSE)
        self.check(lib.fido_dev_get_assert(boot.dev, probe, self.PIN))
        self.assertEqual(lib.fido_assert_flags(probe, 0) & 0x05, 0x04, "user verified, not present")
        # ...and no for a credential that is not ours.
        stranger = self.new_assert(os.urandom(48), up=FALSE)
        self.check(lib.fido_dev_get_assert(boot.dev, stranger, self.PIN), ERR_NO_CREDENTIALS)
        # Without the PIN we cannot tell, and say that a PIN is needed.
        blind = self.new_assert(cred_id, up=FALSE)
        self.check(lib.fido_dev_get_assert(boot.dev, blind, None), ERR_PIN_REQUIRED)

        # The real thing.
        a = self.new_assert(cred_id, salt)
        self.check(lib.fido_dev_get_assert(boot.dev, a, None), ERR_PIN_REQUIRED)
        self.check(lib.fido_dev_get_assert(boot.dev, a, self.PIN))
        self.assertEqual(self.secret(a), enrolled, "the volume key is reproduced")

        # A different salt (another volume) gives a different key.
        b = self.new_assert(cred_id, os.urandom(32))
        self.check(lib.fido_dev_get_assert(boot.dev, b, self.PIN))
        self.assertNotEqual(self.secret(b), enrolled)

    def test_enroll_without_a_pin_on_the_token(self):
        c = self.new_cred()
        self.check(self.lib.fido_dev_make_cred(self.dev.dev, c, None), ERR_PIN_NOT_SET)
        _, options = self.dev.features()
        self.assertFalse(options["clientPin"])

    def test_explicit_false_options_are_accepted(self):
        # systemd sets rk and uv to an explicit "false", and unlocks with an
        # explicit up=true. Some tokens choke on that; make sure we don't.
        lib, dev = self.lib, self.dev.dev
        self.check(lib.fido_dev_set_pin(dev, self.PIN, None))
        c = self.new_cred()
        self.check(lib.fido_dev_make_cred(dev, c, self.PIN))
        cred_id = blob(lib.fido_cred_id_ptr(c), lib.fido_cred_id_len(c))
        a = self.new_assert(cred_id, os.urandom(32), up=TRUE)
        self.check(lib.fido_assert_set_uv(a, FALSE))
        self.check(lib.fido_dev_get_assert(dev, a, self.PIN))
        # Asking for built-in user verification (a fingerprint, say), which
        # we do not have. With a PIN, libfido2 sends the PIN proof and drops
        # the option, so it only reaches us when no PIN is given.
        a = self.new_assert(cred_id, os.urandom(32))
        self.check(lib.fido_assert_set_uv(a, TRUE))
        self.check(lib.fido_dev_get_assert(dev, a, None), ERR_UNSUPPORTED_OPTION)
        self.check(lib.fido_dev_get_assert(dev, a, self.PIN))


class WrongPin(WithDevice):
    ARGS = ("--base-delay-ms", "150")
    PIN = b"123456"

    def test_wrong_pin_then_lockout_then_recovery(self):
        lib, dev = self.lib, self.dev.dev
        self.check(lib.fido_dev_set_pin(dev, self.PIN, None))
        c = self.new_cred()
        self.check(lib.fido_dev_make_cred(dev, c, self.PIN))
        cred_id = blob(lib.fido_cred_id_ptr(c), lib.fido_cred_id_len(c))
        retries = c_int()
        self.check(lib.fido_dev_get_retry_count(dev, byref(retries)))
        self.assertEqual(retries.value, 8)

        a = self.new_assert(cred_id, os.urandom(32))
        # "PIN incorrect, please try again."
        self.check(lib.fido_dev_get_assert(dev, a, b"000000"), ERR_PIN_INVALID)
        self.check(lib.fido_dev_get_retry_count(dev, byref(retries)))
        self.assertEqual(retries.value, 7)
        # Too soon: refused without being checked or counted.
        self.check(lib.fido_dev_get_assert(dev, a, self.PIN), ERR_PIN_AUTH_BLOCKED)
        self.check(lib.fido_dev_get_retry_count(dev, byref(retries)))
        self.assertEqual(retries.value, 7)
        time.sleep(0.2)
        self.check(lib.fido_dev_get_assert(dev, a, self.PIN))
        self.check(lib.fido_dev_get_retry_count(dev, byref(retries)))
        self.assertEqual(retries.value, 8)

    def test_change_pin(self):
        lib, dev = self.lib, self.dev.dev
        self.check(lib.fido_dev_set_pin(dev, self.PIN, None))
        self.check(lib.fido_dev_set_pin(dev, b"new-pin", self.PIN))  # fido2-token -C
        c = self.new_cred()
        self.check(lib.fido_dev_make_cred(dev, c, self.PIN), ERR_PIN_INVALID)
        time.sleep(0.2)
        self.check(lib.fido_dev_make_cred(dev, c, b"new-pin"))


class Ssh(WithDevice):
    """ssh-keygen -t ecdsa-sk, then signing in with the key."""

    PIN = b"123456"
    APPLICATION = b"ssh:"

    def test_keygen_and_sign(self):
        lib, dev = self.lib, self.dev.dev
        self.check(lib.fido_dev_set_pin(dev, self.PIN, None))

        # sk_enroll(): no PIN at first, then again once the user has typed it.
        challenge = os.urandom(32)
        c = self.new_cred(extensions=0, rp=self.APPLICATION, cdh=challenge)
        self.check(lib.fido_cred_set_uv(c, OMIT))
        self.check(lib.fido_dev_make_cred(dev, c, None), ERR_PIN_REQUIRED)
        self.check(lib.fido_dev_make_cred(dev, c, self.PIN))
        # No attestation certificate, so OpenSSH checks the self attestation.
        self.assertFalse(lib.fido_cred_x5c_ptr(c))
        self.assertEqual(lib.fido_cred_fmt(c), b"packed")
        self.check(lib.fido_cred_verify_self(c))
        key_handle = blob(lib.fido_cred_id_ptr(c), lib.fido_cred_id_len(c))
        public = blob(lib.fido_cred_pubkey_ptr(c), lib.fido_cred_pubkey_len(c))
        self.assertEqual(len(public), 64)

        # sk_sign(): same dance, then the server verifies the signature.
        message = os.urandom(32)
        a = self.new_assert(key_handle, rp=self.APPLICATION, cdh=message)
        self.check(lib.fido_dev_get_assert(dev, a, None), ERR_PIN_REQUIRED)
        self.check(lib.fido_dev_get_assert(dev, a, self.PIN))
        self.assertEqual(lib.fido_assert_flags(a, 0) & 0x05, 0x05, "user present and verified")
        pk = c_void_p(lib.es256_pk_new())
        self.addCleanup(lambda: lib.es256_pk_free(byref(pk)))
        self.check(lib.es256_pk_from_ptr(pk, public, len(public)))
        self.check(lib.fido_assert_verify(a, 0, COSE_ES256, pk))

        # The same signature does not verify for another application.
        other = self.new_assert(key_handle, rp=b"ssh:other", cdh=message)
        self.check(lib.fido_dev_get_assert(dev, other, self.PIN), ERR_NO_CREDENTIALS)


class Housekeeping(WithDevice):
    def test_reset(self):
        lib, dev = self.lib, self.dev.dev
        self.check(lib.fido_dev_set_pin(dev, b"123456", None))
        self.assertTrue(self.open().features()[1]["clientPin"])
        self.check(lib.fido_dev_reset(dev))  # fido2-token -R
        self.assertFalse(self.open().features()[1]["clientPin"])


class NoTouch(WithDevice):
    ARGS = ("--touch", "never", "--up-timeout-ms", "300")

    def test_timeout_is_the_code_systemd_explains(self):
        lib, dev = self.lib, self.dev.dev
        self.check(lib.fido_dev_set_pin(dev, b"123456", None))
        c = self.new_cred()
        # "Token action timeout. (User didn't interact with token quickly enough.)"
        self.check(lib.fido_dev_make_cred(dev, c, b"123456"), ERR_ACTION_TIMEOUT)


class DeadCore(unittest.TestCase):
    """What the host sees if the bridge is alive but the core is not."""

    def test_open_fails_cleanly(self):
        # Covered at the state-machine level in vomit-link (the bridge answers
        # with an error within a second). Here: libfido2 survives a device
        # that drops the connection in the middle of a request.
        lib = load()
        sim = Sim()
        dev = Device(lib, sim)
        sim.close()
        info = c_void_p(lib.fido_cbor_info_new())
        self.assertNotEqual(lib.fido_dev_get_cbor_info(dev.dev, info), OK)
        lib.fido_cbor_info_free(byref(info))
        dev.close()


if __name__ == "__main__":
    unittest.main()
