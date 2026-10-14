# vomit-enforcer

A pathetic attempt at an STM32F4 based keyboard emulator that, upon
authentication, derives a passphrase or key and vomits it into the device being
unlocked. Multiple phrases on multiple PINs, always-powered anti-tamper, and
losing power guarantees the secrets are lost.

> /!\ AI SLOP AHEAD. Work in progress, built up piece by piece.

## Status

Only the crypto core exists so far: [`vomit-core`](vomit-core), `no_std`,
host-tested. No firmware yet.

## Crypto core

### Vault ([`vault.rs`](vomit-core/src/vault.rs))

Uploaded seeds sit in a plain `repr(C)` `Vault` struct that the firmware places
in SRAM. Each of the 8 slots holds one seed locked behind its own PIN:

```text
k_enc || k_mac = PBKDF2-HMAC-SHA256(pin, salt, iterations, 64)
wrapped        = seed XOR k_enc
tag            = HMAC-SHA256(k_mac, "vomit-enforcer/v1/slot" || slot || wrapped)
```

A PIN is a sequence of `u16` values (dial positions, keypad digits, ...).

```rust
static mut VAULT: Vault = Vault::new(Policy::DEFAULT);

vault.store(slot, &[100, 64, 116], &seed, salt)?;   // seed + salt uploaded by the user
match vault.attempt(&pin, now_ms) {
    Attempt::Unlocked { slot, seed } => { /* render + type */ }
    Attempt::Wrong { attempts_left, retry_in_ms } => {}
    Attempt::TooSoon { retry_in_ms } => {}          // locked out, PIN not checked
    Attempt::Wiped => {}                            // too many failures, everything zeroed
}
vault.clear_slot(slot);
vault.wipe();
```

* **Wrong PINs are detected.** The vault counts consecutive failures, imposes
  a doubling lockout (1 s, 2 s, 4 s, ... capped at 5 min) and wipes every
  slot after `max_failures` (default 10). A correct PIN resets the count.
* The counter goes up *before* the PIN is checked, so cutting power or
  resetting in the middle of a check doesn't skip it.
* Every attempt checks every used slot, so timing doesn't reveal which slot
  matched.
* Seeds are encrypted at rest, so a RAM dump shows no plaintext. Someone with
  a RAM dump can still grind PINs offline against the tags; PBKDF2 only slows
  them. Keeping the SRAM out of reach (tamper response, power loss wipes) is
  the hardware's job.
* `salt` comes from outside (the F411 has no RNG). Use a fresh random one for
  every store.

### Passphrase ([`render.rs`](vomit-core/src/render.rs))

`render(&seed, &Format { charset, length })` expands the seed with HMAC-SHA256
in counter mode, then maps it onto `Printable` (94 chars), `Alnum`, `Hex` or a
custom charset by rejection sampling, so there's no bias.

```sh
cd vomit-core && cargo test
```

## License

GPL-3.0
