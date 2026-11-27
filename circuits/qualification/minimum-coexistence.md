# Minimum coexistence rehearsal — 2026-11-25–26

[#2461](https://github.com/theinterfold/interfold/issues/2461), based on `262600ea7` after
[#2542](https://github.com/theinterfold/interfold/pull/2542). All four cases use Minimum (`N=3`,
`H=2`, `T=1`), `fhe.rs` v0.6.0, Noir `1.0.0-rc.3` and bb `6.0.0`. The
[configuration catalogue](../../packages/interfold-contracts/crypto-config.json) records the full
request identities. SS uses archived circuit pairs. Both synchronized Minimum profiles use
source-built DKG and decryption candidates with admission disabled.

| Profile            | Archive or candidate manifests                                                                                                                    | Observed result                                                                               |
| ------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------- |
| `ss-insecure-64`   | `5c2ddf13094ffd62`                                                                                                                                | Actor tally 13/13; Hardhat verified DKG and decryption (3,123,547 / 3,441,009 estimated gas). |
| `ss-secure-8192`   | `b8e9f16872abb1a5`                                                                                                                                | Actor tally 14/14; Hardhat verified DKG and decryption (3,123,486 / 3,441,216 estimated gas). |
| `sync-insecure-64` | [DKG `5e218a8d126e3ac0`](sync-insecure-64/minimum/dkg-publication.json) · [decryption `77b36076c8a3bcfc`](sync-insecure-64/minimum/manifest.json) | Signed DKG → encrypted `19 + 18` → mined `37` (3,873,356 / 3,636,788 gas).                    |
| `sync-secure-8192` | [DKG `43b10e3e9f98f147`](sync-secure-8192/minimum/dkg-publication.json) · [decryption `9459c4e7b6c0edeb`](sync-secure-8192/minimum/manifest.json) | Signed DKG → encrypted `19 + 18` → mined `37` (3,873,406 / 3,636,824 gas).                    |

For both SS archives, `check-layouts` passed and the named VK commitments matched the
[deployment catalogue](../vk-commitments.json). `qualify-vk-commitments` rederived the recursive and
EVM keys for both aggregators (four per profile) and reproduced both Solidity verifiers. The
[SS actor and contract replay](../../crates/zk/benchmarks/README.md#protocol-gas-replay-and-report)
used full aggregation and each run's own proof export. With one configured job, the secure actor
test took 1,250.53 s; the guarded Cargo command peaked at 18.91 GiB (debug build). The separate
insecure standby run tallied 14/14.

For each synchronized profile the registry verified ordered H consent, and the later plaintext
receipt belonged to the same E3. The gas figures exclude key-chunk transactions. The secure run
reconstructed all 368,670 native key bytes from the mined chunks. The two decryption outer VKs are
identical; the C6 and C7 pins each differ. The four recorded manifests come from a final source
rebuild that verified the signed-run proofs and reproduced their circuit JSON, keys and generated
Solidity byte for byte. See the
[signed proof costs](../benchmarks/synchronized-decryption.md#signed-dkg-through-mined-plaintext--2026-11-26-2549).
`pnpm test:sync-prf` matched all 15 Rust/Noir mask vectors (eight base, five Micro, two
secure-moduli).

## Where substitutions were rejected

- The native profile and authority tests rejected another protocol/configuration, E3 or chain,
  noncanonical H and substituted commitment rows. The BFV decoder rejected a nonzero ciphertext
  level; the projection required both the confirmed Keccak hash and SAFE commitment for exactly one
  ciphertext.
- In the signed rehearsals, only `[0,2]` consented. Owner `1` saved and reopened its setup for their
  batch both when `KeyPublished` preceded dispatch and when its join was in flight. The collector
  rejected a non-designated owner and a designated owner's altered row/proof. After promotion,
  demotion and reopen, `[0,2]` decrypted one ciphertext from the same pinned input sequences. The
  writer rejected changed public inputs and plaintext.
- A second finalized E3 with the same committee, profile and verifier rejected the signed DKG
  publication (`InvalidPublication`). The decryption verifier accepted the matching domain, then
  returned `DomainBindingMismatch` when only the E3 ID used to hash the domain changed. The genuine
  proof and lookup of the signed authority stayed fixed.
- The secure request rejected the genuine insecure DKG and decryption exports. Replacing only C6,
  only C7, or both child pins returned `VkHashMismatch`. With the secure public inputs held fixed,
  both generated Solidity verifiers also rejected the corresponding insecure proof bytes.
- The compute gate (`e3-multithread`, `effect_gate::`, 28 tests) cancelled unfinished leaf work for
  the synchronized request while preserving the outside owner's in-flight join. A delayed signing
  context that completed the authority projection cancelled the losing batch. The node collector
  (`e3-zk-prover`, `actors::node_proof_aggregator::`, 51 tests) reopened pending inputs with a fresh
  correlation; reopening a completed join delivered the saved proof locally without proving again.
  Failure and completion each retired pending work.
- The SS snapshot/rotation tests checked each E3's configuration, ciphertext verifier, parameter
  hash and DKG fold verifier. A request already at `CiphertextReady` finished under its original
  decryption verifier after rotation to a rejecting replacement. The SS router tests rejected mixed
  child pins and wrong input lengths. With the
  [explicit folded fixture](../../packages/interfold-contracts/test/fixtures/bfv_vk_binding/README.md)
  and the hydrated insecure Minimum pair, all three `BfvVkBindingIntegration` tests ran with pending
  tests forbidden. The SS replay tool rejected the fresh insecure DKG proof against the secure
  catalogue and a genuine synchronized decryption proof against the SS C6/C7 pins, both before
  calling a contract. The synchronized registry tests rejected wrong request/consent domains, owner,
  roster, batch, key bindings and verifier; a refused controller callback reverted publication.
- The schema layout lock and ABI-enabled profile identity tests passed. In the earlier
  [two-build reopen](https://github.com/theinterfold/interfold/pull/2551#issuecomment-7159928763),
  the new binary rejected a retired allocation without changing its bytes. Replay does not authorize
  another draw.

The [keyshare rehearsal](../../crates/orchestration/keyshare/README.md#tests) seeds committee
finalization and the ciphertext checkpoint, including the selected decryption wrapper address. The
wrapper checks that request's signed registry authority; automatic verifier selection at production
request creation is outside this rehearsal. The SS actor runs use simulated transport; their
exported proofs are replayed against local contracts. These results do not establish an admitted
synchronized request, mixed-version operation or independent cryptographic review. The
[rollout proposal](../../docs/architecture/upgrades.md#synchronized-minimum-rollout-proposal-v1-pending-review)
records the outstanding approvals, SS drain policy and rollback.
