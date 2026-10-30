# e3-zk-config

## Purpose

This crate owns circuit identity/variants, static BFV configuration, and public-input layouts. Each
circuit family derives its bounds and widths from existing BFV parameters. `Configs::for_preset`
constructs the parameters for a supported preset; `Configs::new` uses an existing parameter owner.

`Configs::render` produces the Noir configuration declarations. This path does not need sample data,
secret keys, witness preparation, or a prover. C1, C2, C5, and C7 use the canonical committee enum.

Constructors reject unsupported degrees, plaintext moduli, CRT bases, and sampler variances. They
retain the supplied parameter `Arc`. Both existing insecure DKG builder profiles remain supported.
C3 and user-data encryption derive `k0is` once per configuration and share them with bounds,
rendering, and witness preparation.

C6 and C7 carry `max_msg_non_zero_coeffs`. Its default matches the compiled message width of 50. A
different host width requires matching C6/C7 artifacts and matching public-input consumers. Changing
this field does not change an existing compiled ABI.

`field` owns shared BN254 field literals. Witness JSON encoding belongs to `e3-zk-witness`.

## Map and API

| Location                                                                 | Responsibility                                                     |
| ------------------------------------------------------------------------ | ------------------------------------------------------------------ |
| [circuit.rs](src/circuit.rs)                                             | Circuit identities, artifact paths, targets, and layout selection. |
| [parameters.rs](src/parameters.rs)                                       | Supported parameter, CRT-basis, and sampler validation.            |
| [metadata.rs](src/metadata.rs), [output_layout.rs](src/output_layout.rs) | Circuit labels and exported public-input layouts.                  |
| [dkg/](src/dkg), [threshold/](src/threshold)                             | Per-circuit Configs, bounds, widths, and Noir rendering.           |
| [parity.rs](src/dkg/share_computation/parity.rs)                         | Canonical committee parity material.                               |
| [field.rs](src/field.rs)                                                 | Shared BN254 field constants.                                      |

Use the circuit family's `Configs::new` with an existing BFV parameter owner, or `for_preset` for a
named preset. Constructors validate before deriving bounds; `render` produces static declarations.
Pass that same configuration to [witness preparation](../witness/README.md), rather than
constructing another parameter set in a caller.

The insecure profile remains degree 128 (`InsecureThreshold`/`InsecureDkg`, artifact label
`insecure`). Its l-BFV labels use the same parameter tuple, so C3/C4/C7 configurations constructed
from existing owners must retain the request label with `with_preset`. `for_preset` does this
automatically. C2 stores the explicit preset and canonical chunk size; `with_chunk_size` selects a
different compiled profile. `chunks::c2_chunk_size` is the shared sizing rule.

`threshold::{lbfv_pk_aggregation,rlk_generation,rlk_aggregation}` own static l-BFV row constants.
L-BFV public-key generation reuses `threshold::pk_generation::Configs`. These configurations retain
their supplied parameter `Arc`, validate it before arithmetic, and render without private samples.

Import `CircuitName` and `CircuitVariant` here, including from build/prover consumers. Their serde
order and names, artifact paths, verifier-target strings, and layout mappings are compatibility
contracts, not labels to rename during cleanup. Proof payloads and signed `ProofType` remain in
`e3-events`.

## Tests

Run `cargo test --locked -p e3-zk-config`. Inline suites cover layouts, supported/rejected parameter
and sampler profiles, C3 identities, and level-zero rounding constants. Run
`pnpm test:circuit-build` for parity/bounds/rendering integration and the affected witness suite for
shape/encoding behavior. Neither replaces real-proof acceptance. [AGENTS.md](AGENTS.md) owns change
guidance.
