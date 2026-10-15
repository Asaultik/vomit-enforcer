# vomit-enforcer

A pathetic attempt at an STM32F4 based keyboard emulator that, upon
authentication, derives a passphrase or key and vomits it into the device being
unlocked. Multiple phrases on multiple PINs, always-powered anti-tamper, and
losing power guarantees the secrets are lost.

> /!\ AI SLOP AHEAD. Work in progress, built up piece by piece.

## Status

Only the crypto core exists so far: [`vomit-core`](vomit-core), `no_std`, no
allocation, host-tested. No firmware yet.

```sh
cd vomit-core && cargo test
python3 tools/kat.py        # independent reference implementation (needs `cryptography`)
```

## Planned hardware

```
[ host ] ══USB-C══ [ CH9329 ] ── isolated UART ──║ case ║── [ STM32F411 ] ── sensors, mesh, LiPo, cap bank
                    outside                                  inside, tamper-guarded, = the secure element
```

The F411 never connects electrically to the outside world except through the
isolated UART. The CH9329 turns UART frames into USB keyboard input.

## Crypto core

### Where secrets live

| What | Where | Survives reset | Survives power loss | Wiped by |
| --- | --- | --- | --- | --- |
| Master keys A/B, epoch, failure counter | RTC backup registers (80 B) | yes | on VBAT only | tamper pin **in hardware**, firmware |
| Vault: 8 slots, sealed twice | SRAM (`.noinit`-style static) | yes | no | firmware |
| Unlocked seed, passphrase | stack, zeroized after use | no | no | — |

### Two layers

```text
per slot     k_pin = Argon2id(pin, salt)
             slot  = ChaCha20-Poly1305(k_pin, nonce = slot || seal_counter, seed || format)

whole vault  k_e   = master key for epoch e, in the backup registers
             vault = ChaCha20-Poly1305(k_e, all slots)

output       k_out = HKDF-SHA256(seed, "vomit-enforcer/v1/<purpose>")
             passphrase = ChaCha20(k_out) keystream, rejection-sampled into the charset
```

* **SRAM without the backup registers is noise.** Even the PIN tags are
  encrypted under the master key, so a RAM dump alone can't be brute-forced.
  The RTC tamper pin clears the registers in hardware, so glitching the CPU
  can't save the vault.
* **Wrong PINs are counted before they're checked**, in the backup
  registers. A reset can't skip the count or roll it back. Lockout doubles
  (1 s, 2 s, 4 s, ... capped at 5 min) and restarts after every reset.
  10 wrong in a row wipes everything.
* **Every change is written under a new master key** into the other of two
  buffers, then committed with a single register write (the epoch). A reset
  at any point leaves one consistent vault.
* **`rotate()`** does the same with nothing changed. Call it every few
  minutes and every bit in SRAM and the key registers flips, so nothing
  burns in.
* **Anything inconsistent wipes:** a bad vault tag, or a failure counter
  that disagrees with its check word.
* Every attempt runs Argon2id against every used slot, so timing doesn't reveal
  which one matched.
* Known-answer tests pin every derivation against
  [`tools/kat.py`](tools/kat.py), which uses Python's `cryptography` package
  as an independent implementation.

### API sketch

```rust
static mut VAULT: Vault = Vault::new();       // in a section startup doesn't zero
let mut argon_mem = [Block::default(); 64];   // 64 KiB Argon2 scratch

vault.on_boot(&mut bkp, &CFG, now_ms);                 // after every reset
vault.init(&mut bkp, &host_random_32_bytes)?;          // factory reset
vault.store(&mut bkp, &CFG, &mut argon_mem, slot, &pin, &seed, &format, salt, &noise)?;
match vault.attempt(&mut bkp, &CFG, &mut argon_mem, &pin, now_ms) {
    Attempt::Unlocked { slot, seed, format } => render(&seed, &format),
    Attempt::Wrong { attempts_left, retry_in_ms } => ...,
    Attempt::TooSoon { retry_in_ms } => ...,  // locked out, PIN not checked or counted
    Attempt::Wiped => ...,
    Attempt::Misconfigured => ...,            // firmware bug, not counted
}
vault.rotate(&mut bkp, &noise);               // every few minutes
vault.wipe(&mut bkp);                         // tamper / brownout interrupt
```

## Open decisions

1. **Host access:** may anyone with the cable `STORE` / `RESET`, or only in a
   setup mode entered on the dial?
2. **Overwriting a used slot:** currently allowed without that slot's PIN.
   Require it?
3. **Duress PIN:** none for now.
4. **Confirm before typing** (`SEnd?` + tap): planned yes.
5. **Per-slot output format:** implemented (charset + length per slot).
6. **Argon2id cost on the F411:** 64 KiB × 3 passes is a placeholder. Needs
   measuring on the chip, since every attempt pays it once per used slot.
7. **Cold-boot threshold** for the thermal sensor: needs measuring.

## License

GPL-3.0
