# vomit-enforcer

A pathetic attempt at an STM32F4 based keyboard emulator that, upon
authentication, derives a passphrase and vomits it into whatever you're
unlocking. Multiple phrases on multiple PINs, always-powered anti-tamper, and
power off guarantees the secrets are lost.

> /!\ AI SLOP AHEAD. Unit tested on the host and compiles for the target, but
> **nobody has run this on real hardware yet**. Read the code before you trust
> it with anything.

## How it works

```
 dial / keypad ──► PIN (e.g. 100 · 064 · 116) ──┐
                                               ▼
 RTC backup registers (VBAT) ──► seed ──► HMAC-SHA256 ──► passphrase ──► USB keyboard
         ▲
 tamper loop on PC13 ── broken? hardware wipes the registers, even on battery
```

* **No stored PINs.** Every PIN derives *some* passphrase:
  `HMAC-SHA256(seed, steps ‖ n ‖ values)`, then HMAC in counter mode, rendered
  without bias into the configured charset. The device can't tell a "right"
  PIN from a "wrong" one, and neither can anyone holding it. Only the thing
  you're unlocking can. Each of your PINs gives a different passphrase, so you
  get multiple phrases on multiple PINs for free.
* **The seed only lives in the RTC backup registers.** These run off the coin
  cell when USB is unplugged. The RTC tamper input erases them in hardware, with
  no firmware involved and the CPU off. Lose USB power and the coin cell and
  the seed is gone. It is never written to flash.
* **No serial port once provisioned.** An unprovisioned device enumerates as
  a USB serial console that accepts a seed. A provisioned one enumerates only
  as a boot-protocol keyboard, so it also works in BIOS/UEFI and initramfs
  prompts. Nothing reads the seed back, ever.

## Hardware

| Part | Notes |
| --- | --- |
| STM32F411CEU6 "Black Pill" (WeAct) | 25 MHz HSE + 32.768 kHz LSE crystals, both needed |
| CR2032 + holder on **VBAT** | Keeps the backup domain and tamper logic alive. Check that your board doesn't tie VBAT to 3V3, so the cell actually backs it |
| TM1637 4 digit 7-segment module | Get one with decimal points, not the clock one with only a colon |
| 10 kΩ potentiometer **or** analog hall sensor / magnetic encoder (e.g. AS5600 OUT) | Dial input. Any 0-3.3 V signal works |
| Push button | Insert button. The onboard KEY button works too |
| 3x4 phone keypad | Only for the keypad variant |
| Tamper loop + 1-10 MΩ resistor | Case switch, wire mesh, a wire threaded through the enclosure screws... |

### Wiring

| Signal | Pin |
| --- | --- |
| Dial wiper / sensor out | PA1 |
| Insert button (to GND) | PA0, which is also the onboard KEY |
| TM1637 CLK / DIO | PB6 / PB7 |
| Tamper loop | PC13 to loop to GND, plus a 1-10 MΩ pull-up from PC13 to **VBAT** |
| Keypad rows 1-4 | PB12, PB13, PB14, PB15 |
| Keypad cols 1-3 | PB0, PB1, PB10 |
| USB | the Black Pill's USB-C |

**Tamper loop:** while the loop is closed, PC13 sits at GND. Cut it and the
pull-up raises PC13. The RTC sees the rising edge and clears all backup
registers. It runs off the coin cell, so it works unplugged. A 10 MΩ pull-up
draws 0.3 µA, which is nothing next to a CR2032. **Remove the Black Pill's
PC13 LED or its resistor**, or it will fight the loop. Run the loop wherever
someone opening the case has to cut it.

## Build & flash

```sh
rustup target add thumbv7em-none-eabihf
cargo install probe-rs-tools          # or flash the .elf/.bin any other way

cd firmware
cargo run --release                   # dial variant (default)
cargo run --release --no-default-features --features input-keypad
```

Host tests for all the logic (derivation, rendering, PIN entry, dial quantizer,
...):

```sh
cd vomit-core && cargo test
```

### Lock the chip

Once you're happy, set **readout protection**. Without it, anyone with an
ST-Link can read the backup registers over SWD while the device is running:

```sh
# Level 1: debugger can't read memory; going back to level 0 mass-erases flash.
STM32_Programmer_CLI -c port=SWD -ob RDP=0xBB
# Level 2: permanent. SWD is gone for good, no more reflashing, ever.
STM32_Programmer_CLI -c port=SWD -ob RDP=0xCC
```

## Usage

### 1. Provision

Fresh coin cell, or after a wipe: the display shows `SEEd` and the device
shows up as a USB serial port.

```sh
python3 -c 'import secrets; print(secrets.token_hex(32))'   # keep this somewhere safe (or don't)
picocom /dev/ttyACM0
> seed 9f3c...64 hex chars...
ok, seed loaded, fingerprint 1a2b3c4d
> reboot
```

`gen` generates a seed on the chip instead, from ADC noise and timing jitter
(the F411 has no hardware RNG). Nobody, you included, ever sees that seed. If
the device loses power, every passphrase is gone for good. That's either a
feature or a disaster, depending on what you're locking.

The fingerprint lets you check that a re-provisioned device has the same
seed as before.

### 2. Unlock things (dial variant)

The display shows `N.VVV`: `N` is how many values you have entered (hex,
up to 15) and `VVV` is the value the dial points at.

| Do | Get |
| --- | --- |
| turn the dial | pick 0-127 |
| tap insert | commit the value (`N` goes up) |
| hold insert, >0.7 s (`SEnd`) | commit the value **and** type the passphrase |
| hold insert, >3 s (`CLr`) | forget everything entered |
| wait 30 s | half-entered PIN forgotten |

So `100 insert 064 insert 116 hold insert` types the passphrase for
`100·64·116`.

### 2b. Keypad variant

Each digit is one entry. `#` types the passphrase, `*` deletes the last digit,
and holding `*` clears. The display shows only how many digits you've
entered, never the digits.

### 3. Getting a passphrase into an account

Enter your PIN with the cursor in the "new password" field, and the
passphrase gets typed there. Use another PIN for another account. The
device never needs to know which PINs are in use.

### Wiping

* Break the tamper loop. On next boot the display shows `tAMP` until you press
  KEY.
* Or hold KEY while plugging in, and keep holding through the 5 s countdown.
  The display shows `dEAd`.
* Or remove both USB power and the coin cell.

## How long should the PIN be?

Each dial entry is worth log2(128) = 7 bits.

| PIN | Combinations | Bits |
| --- | --- | --- |
| 6 digit numeric PIN | 10⁶ | 19.9 |
| **3 dial entries @128** | 2.1 × 10⁶ | **21** |
| 4 dial entries @128 | 2.7 × 10⁸ | 28 |
| 6 lowercase letters | 3.1 × 10⁸ | 28.2 |
| 6 printable ASCII | 6.9 × 10¹¹ | 39.3 |
| 6 dial entries @128 | 4.4 × 10¹² | 42 |

So yes: 3 entries beats a 6 digit PIN but loses to a 6 character password.

What the PIN protects against depends on the attacker:

* **Holds the device, can't read the seed:** they must try every guess
  against the real target, which rate-limits them. Short PINs are fine.
* **Has extracted the seed** (no RDP, or a lab with a decapper) **and has
  something to check guesses against**, like a LUKS header or a password
  hash: they brute-force the PIN offline, and 2²¹ takes no time. Tamper
  protection and RDP are what stop this, not PIN length.

Dropping `DIAL_STEPS` (in `firmware/src/config.rs`) makes entry faster and
lowers the bits per entry. Changing it, the output format, or the seed changes
every passphrase.

## Caveats (non-exhaustive)

* **Keyboard layout:** the host decides what a keycode means. The passphrase
  is typed as a US layout. On other layouts, symbols (and `y`/`z` on QWERTZ)
  come out different, *consistently*, so it still works as long as you always
  use the same layout. Or set `Charset::Alnum` / `Hex` in `config.rs`.
* The tamper behaviour, especially in VBAT mode, comes from reading RM0383
  and has not been tested on hardware yet. Test it: provision, cut the loop
  with USB unplugged, plug back in, and expect `tAMP` and then `SEEd`.
* embassy resets the backup domain at boot if the RTC clock config changes.
  Don't change `rcc.ls` on a provisioned device unless you want a wipe.
* Cold-boot / SRAM remanence: derived material is zeroized right after use,
  but this is a hobby project, not a smartcard.
* If the LSE crystal doesn't start, the firmware hangs at boot with a blank
  display.

## Layout

```
vomit-core/   no_std logic, host-tested: kdf, render, PIN entry, dial, keypad, keymap, display font, provisioning protocol
firmware/     embassy app for the F411: TM1637 driver, RTC vault/tamper, input frontends, USB HID/CDC
```

To add another input frontend (rotary encoder, capacitive wheel, ...),
implement `firmware/src/input::Frontend`. It turns hardware into
`InputEvent`s and says what the display should show.

## License

GPL-3.0
