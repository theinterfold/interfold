# e3-crypto

This crate owns local secret-at-rest encryption and password sources, not threshold protocol math.

- Argon2 parameters, the current fixed application salt, and nonce-prefixed AES-GCM bytes determine
  whether saved identities/shares can still decrypt. Altering them requires an explicit migration,
  not merely updating round-trip tests. The fixed-salt limitation is not a per-record random salt.
- Preserve fresh nonces, authenticated decryption errors, and zeroization of successful encryption
  inputs. Prefer `SensitiveBytes::access`'s zeroizing result; `access_raw` transfers cleanup to the
  caller and must not leak plaintext into tracing or snapshots.
- File password setup refuses overwrite and creates restrictive Unix permissions before writing. Do
  not replace exclusive creation with an existence check followed by truncation.
- An encrypted wrapper records ciphertext, not authorization to deserialize arbitrary peer data.
  Keep caller-side authentication and size validation at their boundaries.

Use the [README tests](README.md#tests). Password-file changes need Unix permission/exclusive-create
coverage as well as cipher round trips. See [upgrades](../../docs/architecture/upgrades.md) for
saved-state changes.
