# e3-committee-hash

This crate is the shared Rust owner of EVM committee and decryption-domain hash bytes.

- Committee hashing consumes the supplied order of raw addresses. Sorting, ABI-padding each address,
  or deduplicating here changes the hash rather than normalizing input.
- Keep committee-hash limb alignment and decryption-domain ABI encoding byte-identical to their
  Solidity counterparts; Noir consumes the split limbs, not an independently reduced digest.
- Preserve deployment, chain, E3, ciphertext, committee, and public-key binding in the decryption
  domain. A convenience overload must not omit context that prevents cross-request replay.
- Keep this deterministic helper free of provider lookups; callers supply canonical chain context.

Run `cargo test --locked -p e3-committee-hash`, retaining cross-language vectors. Hash-layout
changes also need the affected Solidity/Noir coverage and compatibility review in
[threshold decryption](../../docs/architecture/threshold-decryption.md).
