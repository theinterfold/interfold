# e3-trckks — Threshold CKKS for Interfold

Threshold CKKS integration crate: the CKKS analogue of `e3-trbfv`. Wraps
`fhe::ckks` + `fhe::trckks` (from the fhe.rs fork) in serializable
request/response job payloads matching the shape the node actors consume.

## Status: experimental (dev branch)

- Uses **insecure dev parameters** (`insecure_512_params`, N=512). Not
  production security.
- Share matrices travel **unencrypted** in `GenPkShareAndSkSssResponse`;
  production must wrap them per recipient like `e3_trbfv::shares::Encrypted`.
- Smudging bits are caller-chosen; the IND-CPA-D flooding analysis that
  derives the correct bound for a given circuit is an open parameterization
  task (see `fhe::trckks` module docs).
- RISC Zero guest integration deferred: `policy` runs the Secure Process
  computations in plain Rust.

## Modules

- `config` — `TrCkksConfig` (serialized params + committee shape), dev presets.
- `dkg` — dealing (`gen_pk_share_and_sk_sss`), public-key aggregation,
  collected-share aggregation. CRP-seed based: all members derive the common
  random polynomial from one public 32-byte seed.
- `threshold_decryption` — per-party decryption shares and the final
  Lagrange/CRT combine + CKKS decode to `Vec<f64>`.
- `policy` — evaluation policies: `sum_policy`, `statistics_policy`
  (sum + relinearized sum-of-squares), `masked_difference_policy` (auction
  comparisons).

## End-to-end tests

**One-command e2e** (CRISP-style staged script, from the repo root):

```bash
pnpm test:ckks-e2e            # everything: crypto tests, demos, node e2e, ZK circuits
./scripts/ckks-e2e.sh --quick        # skip fhe.rs unit tests
./scripts/ckks-e2e.sh --demos-only   # just the auction + statistics demos
./scripts/ckks-e2e.sh --circuits-only # just witness-gen + nargo execute + noir tests
```

The script runs: (1) fhe.rs ckks/trckks unit tests, (2) the sealed-bid
auction and private-statistics demos with real output, (3) the `e3-trckks`
job-payload pipeline tests, (4) fresh witness generation + `nargo execute`
for all three CKKS circuits with a configs-drift check, and (5) the full
Noir test suite.

`cargo test -p e3-trckks --release` runs three full pipelines
(DKG → encrypt → policy → threshold decrypt), all through the serialized
job payloads:

- `e2e_sum_policy` — encrypted aggregation.
- `e2e_statistics_policy` — mean/variance with multiparty relinearization.
- `e2e_auction_policy` — sealed-bid Vickrey auction via masked comparisons.

The matching Noir circuits live in
`circuits/lib/src/core/threshold/user_data_encryption_ckks_ct0.nr` (Greco-style
encryption proof; ct1 reuses the BFV circuit) and
`decrypted_shares_aggregation_ckks.nr` (share combine without BFV decode);
`share_decryption.nr` is scheme-agnostic and reused as-is.
