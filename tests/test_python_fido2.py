"""End to end against python-fido2, Yubico's FIDO2 client library.

It speaks to the simulator through its own CTAPHID code, so everything from
packet framing to the hmac-secret output is checked by an implementation that
shares no code with ours.
"""

import hashlib
import os
import time
import unittest

from fido2.attestation import PackedAttestation
from fido2.client import DefaultClientDataCollector, Fido2Client, UserInteraction
from fido2.ctap import CtapError
from fido2.ctap2 import ClientPin, Ctap2
from fido2.ctap2.extensions import HmacSecretExtension
from fido2.ctap2.pin import PinProtocolV1
from fido2.hid import CtapHidDevice
from fido2.hid.base import CtapHidConnection, HidDescriptor
from fido2.utils import websafe_decode
from fido2.webauthn import (
    PublicKeyCredentialCreationOptions,
    PublicKeyCredentialDescriptor,
    PublicKeyCredentialParameters,
    PublicKeyCredentialRequestOptions,
    PublicKeyCredentialRpEntity,
    PublicKeyCredentialType,
    PublicKeyCredentialUserEntity,
)

from sim import Sim, read_packet

ERR = CtapError.ERR
RP = {"id": "example.com", "name": "Example"}
USER = {"id": b"user-id", "name": "tik"}
ES256 = [{"type": "public-key", "alg": -7}]
PIN = "1234"


class SocketConnection(CtapHidConnection):
    def __init__(self, sock):
        self.sock = sock

    def read_packet(self):
        return read_packet(self.sock, timeout=60)

    def write_packet(self, data):
        self.sock.sendall(data)

    def close(self):
        self.sock.close()


def open_device(sim: Sim) -> CtapHidDevice:
    descriptor = HidDescriptor("sim", 0x1209, 0x0001, 64, 64, "vomit-enforcer", None)
    return CtapHidDevice(descriptor, SocketConnection(sim.connect()))


def expect_error(test, code, fn, *args, **kwargs):
    with test.assertRaises(CtapError) as caught:
        fn(*args, **kwargs)
    test.assertEqual(caught.exception.code, code, f"got {caught.exception.code!r}")


class Host:
    """What a FIDO platform does, step by step, using python-fido2's pieces."""

    def __init__(self, sim):
        self.dev = open_device(sim)
        self.ctap = Ctap2(self.dev)
        self.protocol = PinProtocolV1()
        self.pin = ClientPin(self.ctap, self.protocol)

    def make(self, pin=PIN, cdh=None, extensions=None, options=None, exclude=None, rp=RP):
        cdh = cdh or os.urandom(32)
        token = self.pin.get_pin_token(pin)
        return cdh, self.ctap.make_credential(
            cdh,
            rp,
            USER,
            ES256,
            exclude_list=exclude,
            extensions=extensions,
            options=options,
            pin_uv_param=self.protocol.authenticate(token, cdh),
            pin_uv_protocol=1,
        )

    def get(self, cred_id, pin=PIN, salts=None, options=None, rp_id=RP["id"]):
        """Returns (client data hash, assertion, decrypted hmac-secret output or None)."""
        cdh = os.urandom(32)
        token = self.pin.get_pin_token(pin)
        extensions, shared = None, None
        if salts:
            key_agreement, shared = self.pin._get_shared_secret()
            salt_enc = self.protocol.encrypt(shared, b"".join(salts))
            extensions = {"hmac-secret": {1: key_agreement, 2: salt_enc, 3: self.protocol.authenticate(shared, salt_enc)}}
        assertion = self.ctap.get_assertion(
            rp_id,
            cdh,
            allow_list=[{"type": "public-key", "id": cred_id}],
            extensions=extensions,
            options=options,
            pin_uv_param=self.protocol.authenticate(token, cdh),
            pin_uv_protocol=1,
        )
        output = None
        if salts:
            output = self.protocol.decrypt(shared, assertion.auth_data.extensions["hmac-secret"])
        return cdh, assertion, output


def raw_set_pin(host, pin: bytes):
    """setPIN without python-fido2's own checks, so the device's are tested."""
    key_agreement, shared = host.pin._get_shared_secret()
    new_pin_enc = host.protocol.encrypt(shared, pin.ljust(64, b"\0"))
    host.ctap.client_pin(
        1,
        ClientPin.CMD.SET_PIN,
        key_agreement=key_agreement,
        new_pin_enc=new_pin_enc,
        pin_uv_param=host.protocol.authenticate(shared, new_pin_enc),
    )


def raw_change_pin(host, old: str, new: bytes):
    key_agreement, shared = host.pin._get_shared_secret()
    pin_hash_enc = host.protocol.encrypt(shared, hashlib.sha256(old.encode()).digest()[:16])
    new_pin_enc = host.protocol.encrypt(shared, new.ljust(64, b"\0"))
    host.ctap.client_pin(
        1,
        ClientPin.CMD.CHANGE_PIN,
        key_agreement=key_agreement,
        pin_hash_enc=pin_hash_enc,
        new_pin_enc=new_pin_enc,
        pin_uv_param=host.protocol.authenticate(shared, new_pin_enc + pin_hash_enc),
    )


class WithSim(unittest.TestCase):
    ARGS: tuple = ()

    def setUp(self):
        self.sim = Sim(*self.ARGS)
        self.addCleanup(self.sim.close)
        self.host = Host(self.sim)


class Transport(WithSim):
    def test_ping_of_every_awkward_length(self):
        for n in (0, 1, 57, 58, 116, 117, 1000, 1200):
            data = os.urandom(n)
            self.assertEqual(self.host.dev.ping(data), data)

    def test_ping_too_long_is_refused(self):
        expect_error(self, ERR.INVALID_LENGTH, self.host.dev.ping, b"x" * 1201)
        self.assertEqual(self.host.dev.ping(b"still alive"), b"still alive")

    def test_wink(self):
        self.host.dev.wink()

    def test_two_openers_get_their_own_channels(self):
        a, b = self.host.dev, open_device(self.sim)
        self.assertNotEqual(a._channel_id, b._channel_id)


class Info(WithSim):
    def test_get_info(self):
        info = self.host.ctap.get_info()
        self.assertEqual(info.versions, ["FIDO_2_0"])
        self.assertEqual(info.extensions, ["hmac-secret"])
        self.assertEqual(bytes(info.aaguid), b"vomit-enforcer\x00\x01")
        self.assertEqual(info.options, {"rk": False, "up": True, "alwaysUv": True, "clientPin": False})
        self.assertEqual(info.max_msg_size, 1200)
        self.assertEqual(info.pin_uv_protocols, [1])

    def test_unknown_command(self):
        expect_error(self, ERR.INVALID_COMMAND, self.host.ctap.send_cbor, 0x55)

    def test_malformed_requests_get_an_error_not_silence(self):
        for body in (b"", b"\xff", b"\xa1", b"\x9f\x00", b"\xa1\x01" + b"\x81" * 40, os.urandom(300)):
            for command in (1, 2, 6):
                response = self.host.dev.call(0x10, bytes([command]) + body)
                self.assertEqual(len(response), 1, f"command {command}, body {body[:8].hex()}")
                self.assertNotEqual(response[0], 0)
        self.assertEqual(self.host.dev.ping(b"still alive"), b"still alive")


class NoPinYet(WithSim):
    def test_nothing_works_without_a_pin(self):
        cdh = os.urandom(32)
        expect_error(self, ERR.PIN_NOT_SET, self.host.ctap.make_credential, cdh, RP, USER, ES256)
        expect_error(self, ERR.PIN_NOT_SET, self.host.ctap.get_assertion, "example.com", cdh)
        expect_error(self, ERR.PIN_NOT_SET, self.host.pin.get_pin_token, PIN)
        self.assertEqual(self.host.pin.get_pin_retries()[0], 8)

    def test_pin_policy(self):
        expect_error(self, ERR.PIN_POLICY_VIOLATION, raw_set_pin, self.host, b"123")
        # Three characters are three characters, however many bytes they take.
        expect_error(self, ERR.PIN_POLICY_VIOLATION, raw_set_pin, self.host, "äää".encode())
        # No terminating zero: not a valid padded PIN.
        expect_error(self, ERR.PIN_POLICY_VIOLATION, raw_set_pin, self.host, b"x" * 64)
        self.assertFalse(self.host.ctap.get_info().options["clientPin"])
        self.host.pin.set_pin("ääää")
        self.assertTrue(self.host.ctap.get_info().options["clientPin"])
        self.host.pin.get_pin_token("ääää")

    def test_set_pin_only_once(self):
        self.host.pin.set_pin(PIN)
        expect_error(self, ERR.PIN_AUTH_INVALID, self.host.pin.set_pin, "5678")
        self.host.pin.get_pin_token(PIN)


class WithPin(WithSim):
    def setUp(self):
        super().setUp()
        self.host.pin.set_pin(PIN)


class Credentials(WithPin):
    def test_make_credential(self):
        cdh, att = self.host.make(extensions={"hmac-secret": True})
        self.assertEqual(att.fmt, "packed")
        ad = att.auth_data
        self.assertEqual(ad.rp_id_hash, hashlib.sha256(b"example.com").digest())
        self.assertTrue(ad.is_user_present() and ad.is_user_verified())
        self.assertEqual(ad.counter, 0)
        self.assertEqual(ad.extensions, {"hmac-secret": True})
        self.assertEqual(bytes(ad.credential_data.aaguid), b"vomit-enforcer\x00\x01")
        self.assertEqual(len(ad.credential_data.credential_id), 64)
        self.assertEqual(ad.credential_data.public_key[3], -7)
        # Self attestation: signed by the new credential's own key.
        self.assertEqual(set(att.att_stmt), {"alg", "sig"})
        PackedAttestation().verify(att.att_stmt, ad, cdh)
        ad.credential_data.public_key.verify(ad + cdh, att.att_stmt["sig"])

    def test_without_extension_no_extension_output(self):
        _, att = self.host.make()
        self.assertIsNone(att.auth_data.extensions)
        self.assertFalse(att.auth_data.flags & 0x80)

    def test_assertion_verifies(self):
        _, att = self.host.make()
        cred = att.auth_data.credential_data
        cdh, assertion, _ = self.host.get(cred.credential_id)
        self.assertEqual(assertion.credential["id"], cred.credential_id)
        self.assertEqual(assertion.auth_data.rp_id_hash, hashlib.sha256(b"example.com").digest())
        self.assertTrue(assertion.auth_data.is_user_present() and assertion.auth_data.is_user_verified())
        assertion.verify(cdh, cred.public_key)

    def test_silent_assertion_has_no_user_presence(self):
        _, att = self.host.make()
        cred = att.auth_data.credential_data
        cdh, assertion, _ = self.host.get(cred.credential_id, options={"up": False})
        self.assertFalse(assertion.auth_data.is_user_present())
        self.assertTrue(assertion.auth_data.is_user_verified())
        assertion.verify(cdh, cred.public_key)

    def test_credentials_are_distinct_and_bound_to_their_site(self):
        _, a = self.host.make()
        _, b = self.host.make()
        ca, cb = a.auth_data.credential_data, b.auth_data.credential_data
        self.assertNotEqual(ca.credential_id, cb.credential_id)
        self.assertNotEqual(ca.public_key, cb.public_key)
        expect_error(self, ERR.NO_CREDENTIALS, self.host.get, ca.credential_id, rp_id="evil.example")
        expect_error(self, ERR.NO_CREDENTIALS, self.host.get, os.urandom(64))
        expect_error(self, ERR.NO_CREDENTIALS, self.host.get, b"short")

    def test_allow_list_with_strangers_finds_ours(self):
        _, att = self.host.make()
        cred = att.auth_data.credential_data
        cdh = os.urandom(32)
        token = self.host.pin.get_pin_token(PIN)
        allow = [{"type": "public-key", "id": os.urandom(n)} for n in (16, 48, 64, 80)]
        allow.insert(2, {"type": "public-key", "id": cred.credential_id})
        assertion = self.host.ctap.get_assertion(
            "example.com", cdh, allow_list=allow, pin_uv_param=self.host.protocol.authenticate(token, cdh), pin_uv_protocol=1
        )
        self.assertEqual(assertion.credential["id"], cred.credential_id)
        assertion.verify(cdh, cred.public_key)

    def test_no_allow_list_means_no_credentials(self):
        cdh = os.urandom(32)
        token = self.host.pin.get_pin_token(PIN)
        auth = self.host.protocol.authenticate(token, cdh)
        expect_error(self, ERR.NO_CREDENTIALS, self.host.ctap.get_assertion, "example.com", cdh, pin_uv_param=auth, pin_uv_protocol=1)

    def test_exclude_list(self):
        _, att = self.host.make()
        mine = {"type": "public-key", "id": att.auth_data.credential_data.credential_id}
        other = {"type": "public-key", "id": os.urandom(64)}
        expect_error(self, ERR.CREDENTIAL_EXCLUDED, self.host.make, exclude=[other, mine])
        self.host.make(exclude=[other])
        # The same ID does not exclude anything for another site.
        self.host.make(exclude=[mine], rp={"id": "other.example", "name": "Other"})

    def test_options(self):
        expect_error(self, ERR.UNSUPPORTED_OPTION, self.host.make, options={"rk": True})
        expect_error(self, ERR.UNSUPPORTED_OPTION, self.host.make, options={"uv": True})
        expect_error(self, ERR.INVALID_OPTION, self.host.make, options={"up": False})
        # Explicit "false" is what systemd-cryptenroll sends.
        _, att = self.host.make(options={"rk": False, "uv": False})
        cred = att.auth_data.credential_data
        expect_error(self, ERR.UNSUPPORTED_OPTION, self.host.get, cred.credential_id, options={"uv": True})

    def test_unsupported_algorithm(self):
        cdh = os.urandom(32)
        token = self.host.pin.get_pin_token(PIN)
        auth = self.host.protocol.authenticate(token, cdh)
        eddsa = [{"type": "public-key", "alg": -8}]
        expect_error(
            self, ERR.UNSUPPORTED_ALGORITHM, self.host.ctap.make_credential, cdh, RP, USER, eddsa, pin_uv_param=auth, pin_uv_protocol=1
        )
        # ES256 anywhere in the list will do.
        self.host.ctap.make_credential(cdh, RP, USER, eddsa + ES256, pin_uv_param=auth, pin_uv_protocol=1)

    def test_large_request_spanning_many_packets(self):
        user = {"id": os.urandom(64), "name": "n" * 64, "displayName": "d" * 64}
        exclude = [{"type": "public-key", "id": os.urandom(64)} for _ in range(10)]
        cdh = os.urandom(32)
        token = self.host.pin.get_pin_token(PIN)
        att = self.host.ctap.make_credential(
            cdh, RP, user, ES256, exclude_list=exclude, pin_uv_param=self.host.protocol.authenticate(token, cdh), pin_uv_protocol=1
        )
        PackedAttestation().verify(att.att_stmt, att.auth_data, cdh)


class HmacSecret(WithPin):
    def setUp(self):
        super().setUp()
        _, att = self.host.make(extensions={"hmac-secret": True})
        self.cred = att.auth_data.credential_data.credential_id

    def test_same_salt_same_secret(self):
        salt = os.urandom(32)
        _, a1, first = self.host.get(self.cred, salts=[salt])
        _, _, second = self.host.get(self.cred, salts=[salt])
        self.assertEqual(len(first), 32)
        self.assertEqual(first, second)
        self.assertTrue(a1.auth_data.flags & 0x80)

    def test_different_salt_or_credential_different_secret(self):
        salt = os.urandom(32)
        _, _, base = self.host.get(self.cred, salts=[salt])
        _, _, other_salt = self.host.get(self.cred, salts=[os.urandom(32)])
        _, att = self.host.make(extensions={"hmac-secret": True})
        _, _, other_cred = self.host.get(att.auth_data.credential_data.credential_id, salts=[salt])
        self.assertEqual(len({base, other_salt, other_cred}), 3)

    def test_two_salts(self):
        s1, s2 = os.urandom(32), os.urandom(32)
        _, _, both = self.host.get(self.cred, salts=[s1, s2])
        _, _, one = self.host.get(self.cred, salts=[s1])
        _, _, two = self.host.get(self.cred, salts=[s2])
        self.assertEqual(both, one + two)

    def test_survives_a_reconnect_and_a_pin_change(self):
        salt = os.urandom(32)
        _, _, before = self.host.get(self.cred, salts=[salt])
        self.host.pin.change_pin(PIN, "new-pin")
        again = Host(self.sim)
        _, _, after = again.get(self.cred, pin="new-pin", salts=[salt])
        self.assertEqual(before, after)

    def test_tampered_salt_is_refused(self):
        cdh = os.urandom(32)
        token = self.host.pin.get_pin_token(PIN)
        key_agreement, shared = self.host.pin._get_shared_secret()
        salt_enc = self.host.protocol.encrypt(shared, os.urandom(32))
        bad_auth = bytes(16)
        for ext, code in (
            ({1: key_agreement, 2: salt_enc, 3: bad_auth}, ERR.PIN_AUTH_INVALID),
            ({1: key_agreement, 2: salt_enc[:16], 3: self.host.protocol.authenticate(shared, salt_enc[:16])}, ERR.INVALID_LENGTH),
            ({1: key_agreement, 2: salt_enc}, ERR.MISSING_PARAMETER),
        ):
            expect_error(
                self,
                code,
                self.host.ctap.get_assertion,
                "example.com",
                cdh,
                allow_list=[{"type": "public-key", "id": self.cred}],
                extensions={"hmac-secret": ext},
                pin_uv_param=self.host.protocol.authenticate(token, cdh),
                pin_uv_protocol=1,
            )

    def test_output_is_hmac_of_the_salt_under_one_stable_key(self):
        # We cannot see the key, but HMAC is a function: the same salt in the
        # second position must give the same 32 bytes as in the first.
        s1, s2 = os.urandom(32), os.urandom(32)
        _, _, ab = self.host.get(self.cred, salts=[s1, s2])
        _, _, ba = self.host.get(self.cred, salts=[s2, s1])
        self.assertEqual(ab[:32], ba[32:])
        self.assertEqual(ab[32:], ba[:32])


class PinHandling(WithSim):
    # Short lockouts so the test doesn't take minutes.
    ARGS = ("--base-delay-ms", "150")

    def setUp(self):
        super().setUp()
        self.host.pin.set_pin(PIN)

    def test_request_without_pin_proof(self):
        cdh = os.urandom(32)
        expect_error(self, ERR.PUAT_REQUIRED, self.host.ctap.make_credential, cdh, RP, USER, ES256)
        expect_error(self, ERR.PUAT_REQUIRED, self.host.ctap.get_assertion, "example.com", cdh)

    def test_forged_or_stale_pin_proof(self):
        cdh = os.urandom(32)
        forged = dict(pin_uv_param=bytes(16), pin_uv_protocol=1)
        # No token has been issued at all.
        expect_error(self, ERR.PIN_AUTH_INVALID, self.host.ctap.make_credential, cdh, RP, USER, ES256, **forged)
        token = self.host.pin.get_pin_token(PIN)
        expect_error(self, ERR.PIN_AUTH_INVALID, self.host.ctap.make_credential, cdh, RP, USER, ES256, **forged)
        # A proof for one request does not work for another.
        auth = self.host.protocol.authenticate(token, cdh)
        expect_error(
            self, ERR.PIN_AUTH_INVALID, self.host.ctap.make_credential, os.urandom(32), RP, USER, ES256, pin_uv_param=auth, pin_uv_protocol=1
        )
        # The wrong protocol number.
        expect_error(self, ERR.PIN_AUTH_INVALID, self.host.ctap.make_credential, cdh, RP, USER, ES256, pin_uv_param=auth, pin_uv_protocol=2)
        self.host.ctap.make_credential(cdh, RP, USER, ES256, pin_uv_param=auth, pin_uv_protocol=1)

    def test_empty_pin_proof_is_a_selection_probe(self):
        cdh = os.urandom(32)
        expect_error(self, ERR.PIN_INVALID, self.host.ctap.make_credential, cdh, RP, USER, ES256, pin_uv_param=b"", pin_uv_protocol=1)

    def test_wrong_pin_counts_down_and_locks_out(self):
        self.assertEqual(self.host.pin.get_pin_retries()[0], 8)
        expect_error(self, ERR.PIN_INVALID, self.host.pin.get_pin_token, "0000")
        self.assertEqual(self.host.pin.get_pin_retries()[0], 7)
        # Straight away, even the right PIN is refused and nothing is counted.
        expect_error(self, ERR.PIN_AUTH_BLOCKED, self.host.pin.get_pin_token, PIN)
        self.assertEqual(self.host.pin.get_pin_retries()[0], 7)
        time.sleep(0.2)
        self.host.pin.get_pin_token(PIN)
        self.assertEqual(self.host.pin.get_pin_retries()[0], 8)

    def test_wrong_pin_ends_the_session(self):
        cdh = os.urandom(32)
        token = self.host.pin.get_pin_token(PIN)
        auth = self.host.protocol.authenticate(token, cdh)
        expect_error(self, ERR.PIN_INVALID, self.host.pin.get_pin_token, "0000")
        expect_error(self, ERR.PIN_AUTH_INVALID, self.host.ctap.make_credential, cdh, RP, USER, ES256, pin_uv_param=auth, pin_uv_protocol=1)

    def test_change_pin(self):
        _, att = self.host.make()
        cred = att.auth_data.credential_data
        expect_error(self, ERR.PIN_INVALID, self.host.pin.change_pin, "0000", "5678")
        time.sleep(0.2)
        expect_error(self, ERR.PIN_POLICY_VIOLATION, raw_change_pin, self.host, PIN, b"12")
        self.host.pin.change_pin(PIN, "5678")
        expect_error(self, ERR.PIN_INVALID, self.host.pin.get_pin_token, PIN)
        time.sleep(0.2)
        # Same seed behind the new PIN: the credential still works.
        cdh, assertion, _ = self.host.get(cred.credential_id, pin="5678")
        assertion.verify(cdh, cred.public_key)


class Wipe(WithSim):
    ARGS = ("--base-delay-ms", "1", "--max-failures", "3")

    def test_too_many_wrong_pins_wipe_everything(self):
        self.host.pin.set_pin(PIN)
        _, att = self.host.make()
        cred = att.auth_data.credential_data.credential_id

        for expected in (ERR.PIN_INVALID, ERR.PIN_INVALID, ERR.PIN_BLOCKED):
            time.sleep(0.02)
            expect_error(self, expected, self.host.pin.get_pin_token, "0000")

        # The device is as new: no PIN, and the right one is no use any more.
        self.assertFalse(self.host.ctap.get_info().options["clientPin"])
        expect_error(self, ERR.PIN_NOT_SET, self.host.pin.get_pin_token, PIN)
        # A new PIN (even the same one) makes a new seed: the old credential is gone.
        self.host.pin.set_pin(PIN)
        expect_error(self, ERR.NO_CREDENTIALS, self.host.get, cred)

    def test_reset_needs_a_touch_and_wipes(self):
        self.host.pin.set_pin(PIN)
        _, att = self.host.make()
        cred = att.auth_data.credential_data.credential_id
        seen = []
        self.host.ctap.reset(on_keepalive=seen.append)
        self.assertIn(2, seen, "the host was told a touch is needed")
        self.assertFalse(self.host.ctap.get_info().options["clientPin"])
        self.host.pin.set_pin("abcd")
        expect_error(self, ERR.NO_CREDENTIALS, self.host.get, cred, pin="abcd")


class NoTouch(WithSim):
    ARGS = ("--touch", "never", "--up-timeout-ms", "400")

    def setUp(self):
        super().setUp()
        self.host.pin.set_pin(PIN)

    def test_no_touch_times_out(self):
        seen = []
        cdh = os.urandom(32)
        token = self.host.pin.get_pin_token(PIN)
        auth = self.host.protocol.authenticate(token, cdh)
        start = time.time()
        expect_error(
            self,
            ERR.ACTION_TIMEOUT,
            self.host.ctap.make_credential,
            cdh,
            RP,
            USER,
            ES256,
            pin_uv_param=auth,
            pin_uv_protocol=1,
            on_keepalive=seen.append,
        )
        self.assertGreater(time.time() - start, 0.35)
        self.assertEqual(seen[-1], 2, "keepalives said: waiting for touch")
        # Reset is not possible without a touch either.
        expect_error(self, ERR.ACTION_TIMEOUT, self.host.ctap.reset)
        self.assertTrue(self.host.ctap.get_info().options["clientPin"])

    def test_host_can_cancel_the_wait(self):
        import threading

        cdh = os.urandom(32)
        token = self.host.pin.get_pin_token(PIN)
        auth = self.host.protocol.authenticate(token, cdh)
        cancel = threading.Event()
        threading.Timer(0.1, cancel.set).start()
        start = time.time()
        expect_error(
            self, ERR.KEEPALIVE_CANCEL, self.host.ctap.make_credential, cdh, RP, USER, ES256, pin_uv_param=auth, pin_uv_protocol=1, event=cancel
        )
        self.assertLess(time.time() - start, 0.35, "cancelled before the timeout")


class FullClient(WithSim):
    """The way an application uses python-fido2: one high-level client object."""

    class Interaction(UserInteraction):
        def __init__(self):
            self.touches = 0

        def prompt_up(self):
            self.touches += 1

        def request_pin(self, permissions, rp_id):
            return PIN

    def test_register_then_authenticate_with_hmac_secret(self):
        self.host.pin.set_pin(PIN)
        ui = self.Interaction()
        client = Fido2Client(
            open_device(self.sim),
            DefaultClientDataCollector("https://example.com"),
            user_interaction=ui,
            extensions=[HmacSecretExtension(allow_hmac_secret=True)],
        )
        registration = client.make_credential(
            PublicKeyCredentialCreationOptions(
                rp=PublicKeyCredentialRpEntity(id="example.com", name="Example"),
                user=PublicKeyCredentialUserEntity(id=b"user-id", name="tik"),
                challenge=os.urandom(32),
                pub_key_cred_params=[PublicKeyCredentialParameters(type=PublicKeyCredentialType.PUBLIC_KEY, alg=-7)],
                extensions={"hmacCreateSecret": True},
            )
        )
        att = registration.response.attestation_object
        self.assertTrue(registration.client_extension_results.get("hmacCreateSecret"))
        cred = att.auth_data.credential_data
        PackedAttestation().verify(att.att_stmt, att.auth_data, registration.response.client_data.hash)

        salt = os.urandom(32)
        outputs = []
        for _ in range(2):
            selection = client.get_assertion(
                PublicKeyCredentialRequestOptions(
                    challenge=os.urandom(32),
                    rp_id="example.com",
                    allow_credentials=[PublicKeyCredentialDescriptor(type=PublicKeyCredentialType.PUBLIC_KEY, id=cred.credential_id)],
                    extensions={"hmacGetSecret": {"salt1": salt}},
                )
            )
            result = selection.get_response(0)
            response = result.response
            cred.public_key.verify(response.authenticator_data + response.client_data.hash, response.signature)
            outputs.append(websafe_decode(result.client_extension_results["hmacGetSecret"]["output1"]))
        self.assertEqual(outputs[0], outputs[1])
        self.assertEqual(len(outputs[0]), 32)
        self.assertGreaterEqual(ui.touches, 3)


if __name__ == "__main__":
    unittest.main()
