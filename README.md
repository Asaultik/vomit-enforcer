# vomit-enforcer

A pathetic attempt at an STM32-based security key that, once you authenticate,
derives a secret and hands it to the machine being unlocked. Several secrets
behind several PINs, always-powered anti-tamper, and losing power means the
secrets are gone.

It started as a keyboard emulator that types passphrases. It now speaks FIDO2,
so `systemd-cryptenroll`, OpenSSH and browsers can use it as they would a
YubiKey. Typed passphrases remain a planned fallback for things FIDO2 does not
reach (BIOS prompts, GRUB).

> /!\ AI SLOP AHEAD. Work in progress, built up piece by piece. Read the code
> before trusting it with anything.

## Status

| Part | State |
| --- | --- |
| Vault and key derivation (`vomit-core`) | Tested on a PC. Ran on a real F411 in the bench firmware. |
| FIDO2 logic (`vomit-link`, `vomit-ctap`) | Tested on a PC, including against python-fido2 and libfido2. |
| Firmware (`fw-core`, `fw-bridge`) | Compiles. **Has not run on hardware yet.** |
| Tamper input, readout protection, enclosure | Not started. |
| PIN on the device itself (dial) | Not started. For now the host asks for the PIN, as with any FIDO2 key. |

One thing to know before you enrol a real disk: **this device forgets
everything when it loses power.** That is the point of it. A LUKS volume
enrolled with it must keep another way in (a passphrase or recovery key).

## How it fits together

```
 HOST                    RP2040 "bridge"                    STM32F411 "core"
 (systemd, ssh,          not trusted, holds no secrets      trusted, holds the vault
  browser)
     │                  ┌───────────────────────┐         ┌──────────────────────────┐
     │   USB FIDO HID   │ USB device            │  UART   │ frame parser             │
     ├─────────────────►│ CTAPHID: channels,    ├────────►│ CTAP2 commands           │
     │◄─────────────────┤ reassembly, keepalive │◄────────┤ credentials (P-256)      │
     │                  │ framing               │ 3 wires │ vault                    │
                        └───────────────────────┘         │ button = "touch"         │
                                                          └──────────────────────────┘
                                          ▲
                        later: isolator and tamper shell go here
```

The bridge is the only part a host can reach. It reassembles a request and
passes it to the core as one checksummed frame. The core treats every byte from
the bridge as hostile. The secret a host finally receives is encrypted between
the host and the core, so the bridge only carries ciphertext for it.

| Directory | What | Runs on |
| --- | --- | --- |
| [`vomit-core`](vomit-core) | The vault: PIN-locked seeds, failure counter, wipe, key rotation. | anywhere (`no_std`) |
| [`vomit-link`](vomit-link) | CTAPHID, the UART frame format, and the bridge as one state machine. | anywhere (`no_std`) |
| [`vomit-ctap`](vomit-ctap) | The CTAP2 authenticator and the core's main loop, minus hardware. | anywhere (`no_std`) |
| [`sim`](sim) | Bridge and core wired together on a PC, USB side on a Unix socket. | PC |
| [`tests`](tests) | End-to-end tests driving the simulator with real FIDO clients. | PC |
| [`fw-core`](fw-core) | Core firmware: UART, button, LED, backup registers. | STM32F411 Black Pill |
| [`fw-bridge`](fw-bridge) | Bridge firmware: USB HID, UART, status light. | RP2040-Zero |
| [`bench`](bench) | Measures Argon2id on the F411. | STM32F411 Black Pill |
| [`tools/kat.py`](tools/kat.py) | Independent Python implementation of the vault's derivations. | PC |

The two firmwares are thin: they move bytes between the hardware and state
machines that live in the `no_std` crates. That is why nearly everything can be
tested without a board.

## What kind of FIDO2 key it is

* CTAP 2.0, PIN protocol 1, ES256 credentials, the `hmac-secret` extension
  (which is what `systemd-cryptenroll` builds a disk key from). No U2F.
* **Nothing works without the PIN.** A credential's key is derived from the
  vault slot that the PIN unlocks, and that seed is only held in RAM for 60
  seconds after a correct PIN. The device says so up front (`alwaysUv`).
* **Nothing is stored per credential.** A credential ID is a random nonce plus
  a tag; the private key is re-derived from the seed, the site and the nonce
  ([`cred.rs`](vomit-ctap/src/cred.rs)). So there are no "resident" keys, and
  wiping the seed kills every credential at once.
* Wrong PINs go through the vault: counted before they are checked, a growing
  lockout after each, and a full wipe after eight in a row.
* A touch means the KEY button on the core board. A button already held down
  does not count.
* One PIN and one slot for now. The vault has eight; using the rest over FIDO2
  is not designed yet.

## Try it on a PC

Everything except the two `main.rs` files runs here.

```sh
nix-shell                                   # or install Rust, python-fido2 and libfido2 yourself
cargo test                                  # unit tests for the three library crates
cargo build -p vomit-sim
python3 -m unittest discover -s tests -v    # 47 end-to-end tests
python3 tools/kat.py --check
```

The end-to-end tests start the simulator and talk to it with:

* **python-fido2** (Yubico's client library), through its own CTAPHID code;
* **libfido2** (the C library behind `systemd-cryptenroll`, `systemd-cryptsetup`
  and OpenSSH), making the same calls in the same order as those programs:
  enrol with a PIN, the silent "is this credential yours?" probe at unlock,
  then the real unlock; and `ssh-keygen -t ecdsa-sk` followed by a signature.

To poke at it by hand: `cargo run -p vomit-sim -- --verbose` and connect to
`/tmp/vomit-sim.sock` (see [`tests/sim.py`](tests/sim.py)).

## Try it on hardware

You need an STM32F411 Black Pill with an ST-Link, and an RP2040-Zero.

### Wiring

| Black Pill (core) | RP2040-Zero (bridge) |
| --- | --- |
| PA9 (TX) | GP1 (RX) |
| PA10 (RX) | GP0 (TX) |
| GND | GND |
| 5V | 5V |

Only the Zero plugs into the PC; it powers the Black Pill through the 5V wire.
Keep the ST-Link on the Black Pill for flashing and logs, but connect only its
SWDIO, SWCLK and GND: with the board powered from the Zero, leave the
ST-Link's 3.3V wire off.

### Step 1: the bridge alone

Hold BOOT on the Zero while plugging it in, then:

```sh
cd fw-bridge
cargo build --release
sudo $(which picotool) load -v -x -t elf target/thumbv6m-none-eabi/release/fw-bridge
```

The light turns blue. Then:

```sh
fido2-token -L                     # should list it: vendor 0x1209, product 0x0001
```

With no core attached, `fido2-token -I /dev/hidrawN` fails after about a second
and the light flashes red. That is the expected result for this step.

### Step 2: the core

```sh
cd fw-core
cargo build --release
sudo $(which probe-rs) run --chip STM32F411CEUx target/thumbv7em-none-eabihf/release/fw-core
```

Leave that running; it prints a line per request. In another terminal:

```sh
fido2-token -I /dev/hidrawN        # device info: FIDO_2_0, hmac-secret, clientPin false
fido2-token -S /dev/hidrawN        # set a PIN (4 characters or more)
```

### Step 3: unlock a (throwaway) LUKS volume

```sh
truncate -s 32M /tmp/test.img
cryptsetup luksFormat --type luks2 /tmp/test.img
sudo systemd-cryptenroll --fido2-device=auto /tmp/test.img
```

It asks for the image's passphrase, then the token PIN, then a touch (press
KEY when the LED lights) twice: once to create the credential and once to
derive the key. To unlock:

```sh
sudo /usr/lib/systemd/systemd-cryptsetup attach vomit-test /tmp/test.img - fido2-device=auto
sudo /usr/lib/systemd/systemd-cryptsetup detach vomit-test
```

(On NixOS the binary is under `/run/current-system/systemd/lib/systemd/`.)

If a step fails, the core's log shows the last command and the status it
answered with. That, and the exact error on the PC, is what to look at.

### The bridge's light

| Colour | Meaning |
| --- | --- |
| Blue | Powered. No program on the host has talked to it yet. |
| Green | Idle. |
| Amber | A request is with the core. |
| Red, one second | The core did not answer. Check the three wires and that it is running. |
| White flash | The host asked the device to identify itself. |

If red and green look swapped, the LED on your board uses the other colour
order.

## The vault

### Where secrets live

| What | Where | Survives reset | Survives power loss | Wiped by |
| --- | --- | --- | --- | --- |
| Master keys A/B, epoch, failure counter | RTC backup registers (80 B) | yes | on VBAT only | tamper pin **in hardware**, firmware |
| Vault: 8 slots, sealed twice | SRAM the startup code leaves alone | yes | no | firmware |
| Unlocked seed | RAM, for at most 60 s after a correct PIN | no | no | timeout, wrong PIN, reset |

### Two layers

```text
per slot     k_pin = Argon2id(pin, salt)
             slot  = ChaCha20-Poly1305(k_pin, nonce = slot || seal_counter, seed || format)

whole vault  k_e   = master key for epoch e, in the backup registers
             vault = ChaCha20-Poly1305(k_e, all slots)
```

* **SRAM without the backup registers is noise.** Even the PIN tags are
  encrypted under the master key, so a RAM dump alone can't be brute-forced.
* **Wrong PINs are counted before they're checked**, in the backup
  registers. A reset can't skip the count or roll it back, and the lockout
  restarts after every reset.
* **Every change is written under a new master key** into the other of two
  buffers, then committed with a single register write. A reset at any point
  leaves one consistent vault.
* **Rotation** does the same with nothing changed, every five minutes, so no
  bit sits still long enough to burn into the RAM.
* **Anything inconsistent wipes:** a bad vault tag, or a failure counter that
  disagrees with its check word.
* **Changing slots needs a recent correct PIN**, or an empty vault.
* Known-answer tests pin every derivation against
  [`tools/kat.py`](tools/kat.py).

Measured on the F411 (bench firmware): Argon2id with 64 KiB and 3 passes takes
about 4.1 million cycles, 43 ms at 96 MHz.

## Known weak spots

These are understood and not yet dealt with.

* **The STM32F4's readout protection can be glitched**, after which the debug
  port reads both the RAM and the backup registers. Until there is a tamper
  shell that makes reaching the chip destroy the keys, a lab can get in. The
  plan is an STM32U585 (hardware tamper mesh support, real random generator)
  inside a shielded, meshed enclosure.
* **The F411 has no hardware random generator.** The firmware seeds a ChaCha20
  generator from the power-on state of 64 KiB of RAM, ADC noise and timing
  jitter. Better than nothing; not something to bet on.
* **The bridge can interfere.** It cannot read the secrets it carries, but the
  key exchange between host and core is not authenticated (that is how the
  FIDO2 PIN protocol works), so a bridge with malicious firmware could sit in
  the middle of it.
* **The PIN is typed on the host** for now, where a keylogger can see it.
  Entering it on the device is the plan.
* **A silent probe without the PIN is answered with "PIN required".** Programs
  that insist on probing without a PIN (OpenSSH, when several security keys
  are plugged in at once) will not pick this device.

## Open decisions

1. **More than one PIN over FIDO2:** the vault has eight slots; how to
   provision the others is undecided.
2. **Duress PIN:** none for now.
3. **Uploading your own seed** instead of a device-generated one.
4. **Cold-boot threshold** for the thermal sensor: needs measuring.

## To do: the host may be tampered with (important)

The device cannot tell whether the machine it unlocks has been tampered with.
Planned, not designed in detail yet:

* **Disk unlock: TPM quote attestation.** The device sends a nonce; the
  initrd returns a TPM2 quote over PCR 7 (maybe 4 and 11) signed by an
  attestation key enrolled earlier; the core verifies the P-256 signature,
  nonce and PCR values before releasing the secret. Proves the boot chain,
  not that nothing got in after boot. Needs a host-side helper and a way to
  carry it over FIDO2 (or beside it).
* **Signing: trusted display and confirm on the device**, so the host cannot
  show one thing and sign another.
* **Login:** FIDO2 origin binding already covers it.
* **A policy per secret** (attestation + touch, touch only, ...), decided
  early because it shapes the slot format.

## License

GPL-3.0
