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

- `pnpm dev:setup` — applies profile, builds DKG circuits when `CRISP_SKIP_PROOF_AGGREGATION=false`
- `pnpm dev:up` → `scripts/crisp_deploy.sh` — sets `ENABLE_ZK_VERIFICATION` from the same file

### CRISP-only deploy (Interfold already deployed)

```bash
pnpm deploy:contracts          # production RISC0 verifier
pnpm deploy:contracts:full     # also deploy Interfold stack (no ZK unless ENABLE_ZK_VERIFICATION=true)
```

## CRISP Program

This is the main logic of CRISP - an interfold program for secure voting.

It exposes three main functions:

- `validate` - that is called when a new E3 instance is requested on Interfold
  (`Interfold.request`).
- `verify` - that is called when the ciphertext output is published on Interfold
  (`Interfold.publishCiphertextOutput`). This function ensures that the ciphertext output is valid.
  CRISP uses Risc0 as the compute provider for running the FHE program, thus the proof will be a
  Risc0 proof.
- `publishInput` - accepts an input for the E3 instance. Data providers call it on this contract
  directly. In CRISP, the data providers are the voters and the input is the vote itself. The
  function checks the stage and the input window, resolves the voter's eligibility from the census,
  and verifies a Noir proof over nine public inputs, which is what establishes that the ciphertext
  was encrypted correctly under the committee public key
  (`examples/CRISP/packages/crisp-contracts/contracts/CRISPProgram.sol:493-554`, paths from the
  repository root). The verifier is the one the round's census selects: `CRISPVerifier.sol` for a
  census posted as a Merkle root, `CRISPOnchainVerifier.sol` for one read from token balances on
  chain. Both files declare a contract named `HonkVerifier`, which is why they are named by file.
  The Greco relations that proof checks are built by
  `crates/zk-helpers/src/circuits/threshold/user_data_encryption/` and proved by the circuits under
  `circuits/bin/threshold/`. See the Greco [paper](https://eprint.iacr.org/2024/594).
