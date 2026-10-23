# e3-crypto

## Purpose

Local encryption for saved operator identities and secret shares. It provides password sources, an
Argon2-derived AES-GCM `Cipher`, and encrypted byte wrappers. Threshold BFV calculations belong in
[e3-trbfv](../trbfv/README.md), not this crate.

## Map

| Location                                         | Responsibility                                                          |
| ------------------------------------------------ | ----------------------------------------------------------------------- |
| [`password_manager.rs`](src/password_manager.rs) | Async password sources and exclusive, permission-restricted file setup. |
| [`cipher.rs`](src/cipher.rs)                     | Argon2 derivation and nonce-prefixed AES-GCM bytes.                     |
| [`sensitive.rs`](src/sensitive.rs)               | Encrypted wrappers and zeroizing plaintext access.                      |

Password loading derives a local cipher key once. Encryption stores a fresh nonce with the
authenticated ciphertext; accessing `SensitiveBytes` decrypts into a short-lived buffer. This
protects saved bytes, not a peer's authorization to supply them.

## Protect local bytes

```rust
use e3_crypto::{Cipher, SensitiveBytes};

async fn round_trip(password: &str) -> anyhow::Result<()> {
    let cipher = Cipher::from_password(password).await?;
    let secret = SensitiveBytes::new(vec![1, 2, 3], &cipher)?;
    let clear = secret.access(&cipher)?;
    assert_eq!(clear.as_slice(), &[1, 2, 3]);
    Ok(())
}
```

In production, obtain the password through `Cipher::from_file` or `Cipher::from_env` rather than
hard-coding it. `Cipher::new` accepts a custom `PasswordManager`; built-ins support in-memory,
environment, and file sources. File password creation refuses overwrite and uses restrictive Unix
permissions.

`SensitiveBytes` serializes encrypted bytes. `access()` returns a zeroizing plaintext buffer;
`access_raw()` instead makes the caller responsible for cleanup. Low-level `encrypt_data` zeroizes
its successful input and returns nonce-prefixed authenticated ciphertext. The current password
derivation uses a fixed application salt, not a per-record random salt. Keep passwords and decrypted
buffers out of logs and ordinary snapshots.

## Tests

Run `cargo test --locked -p e3-crypto`. Inline tests cover cipher round trips, wrong passwords, and
encrypted wrappers. No chain or prover is required. Password-file operations use Unix permissions
and are also exercised through [CLI secret commands](../cli/tests/cli_secrets.rs). Saved ciphertext
and KDF choices are durable compatibility boundaries; see
[upgrades](../../docs/architecture/upgrades.md) before changing stored data. See
[AGENTS.md](AGENTS.md) for cipher/secret-handling change guidance.
