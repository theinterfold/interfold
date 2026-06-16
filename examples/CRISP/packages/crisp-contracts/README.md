# Solidity Contracts

This directory contains the Solidity contracts for CRISP - Coercion-Resistant Impartial Selection
Protocol.

Contracts are built and tested with [Hardhat](https://hardhat.org). Tests are defined in the `test`
directory.

## Running Tests

To run contract tests from the CRISP example root (`examples/CRISP/`):

```bash
pnpm test:contracts
```

Alternatively, you can run tests directly from this directory:

```bash
pnpm test
```

## Deployment

Local deploy is driven by **`../../crisp.dev.env`** (see
**[../../docs/PROOF_AGGREGATION_AND_ZK.md](../../docs/PROOF_AGGREGATION_AND_ZK.md)**):

- `pnpm dev:setup` — applies profile, builds DKG circuits when
  `CRISP_PROOF_AGGREGATION_ENABLED=true`
- `pnpm dev:up` → `scripts/crisp_deploy.sh` — sets `ENABLE_ZK_VERIFICATION` from the same file

### CRISP-only deploy (Interfold already deployed)

```bash
pnpm deploy:contracts          # production RISC0 verifier
pnpm deploy:contracts:full     # also deploy Interfold stack (no ZK unless ENABLE_ZK_VERIFICATION=true)
```

## CRISP Program

This is the main logic of CRISP - an interfold program for secure voting.

It exposes two main functions:

- `validate` - that is called when a new E3 instance is requested on Interfold
  (`Interfold.request`).
- `verify` - that is called when the ciphertext output is published on Interfold
  (`Interfold.publishCiphertextOutput`). This function ensures that the ciphertext output is valid.
  CRISP uses Risc0 as the compute provider for running the FHE program, thus the proof will be a
  Risc0 proof.
- `validateInput` - validate the input data that is submitted to the E3 instance. It is called by
  the Interfold contract when a new input is published (`Interfold.publishInput`). In CRISP, the
  data providers (the ones submitting the inputs) are the voters, and the input submitted is the
  vote itself. The logic checks that gating conditions are satisfied and that the ciphertext is
  constructed correctly using
  [Greco](https://github.com/gnosisguild/interfold/tree/main/circuits/crates/libs/greco). See the
  Greco [paper](https://eprint.iacr.org/2024/594).
