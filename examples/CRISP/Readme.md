# CRISP - Coercion-Resistant Impartial Selection Protocol

CRISP (Coercion-Resistant Impartial Selection Protocol) is a secure protocol for digital
decision-making, leveraging fully homomorphic encryption (FHE) and distributed threshold
cryptography (DTC) to enable verifiable secret ballots. Built with Interfold, CRISP safeguards
democratic systems and decision-making applications against coercion, manipulation, and other
vulnerabilities. To learn more about CRISP, you can read our
[blog post](https://blog.interfold.gg/crisp-private-voting-secret-ballot-fhe-zkp-mpc/) or visit the
[documentation](https://docs.theinterfold.com/CRISP/introduction).

## Project Structure

CRISP follows a modern structure with clear separation of concerns, consistent with the Interfold
root structure.

```bash
CRISP/
├── client/                  # React frontend application (Vite + @crisp-e3/sdk)
├── server/                  # Rust coordination server & CLI
├── program/                 # FHE program for encrypted computation + RISC Zero verification
├── packages/
│   ├── crisp-contracts/     # CRISP program contract + Hardhat deployment scripts
│   └── crisp-sdk/           # TypeScript helpers to generate a ZK proof
├── crates/                  # Rust libraries used by the server
├── circuits/                # Noir zero-knowledge circuits
├── scripts/                 # Development scripts for running, testing, and deployment
├── interfold.config.yaml      # Local ciphernode network config
└── docker-compose.yaml      # Optional multi-node deployment
```

You can have an extended explanation of the single folders in the dedicated
[documentation](https://docs.theinterfold.com/CRISP/introduction#project-structure).

## Prerequisites

Before getting started, ensure you have installed:

- [Rust](https://rust-lang.org/tools/install/)
- [Foundry](https://getfoundry.sh)
- [RiscZero](https://dev.risczero.com/api/zkvm/install)
- [NodeJS](https://nodejs.org/en/download)
- [pnpm](https://pnpm.io)
- [MetaMask](https://metamask.io)
- Noir toolchain ([`nargo`](https://noir-lang.org/docs/getting_started/quick_start),
  [`bb`](https://barretenberg.aztec.network/docs/getting_started))

## Quick Start

The simplest way to run CRISP is:

```bash
# Optional: choose local profile (copied to crisp.dev.env on first setup)
cp crisp.dev.env.example crisp.dev.env
# Edit CRISP_PROOF_AGGREGATION_ENABLED and CRISP_BFV_PRESET (see docs/PROOF_AGGREGATION_AND_ZK.md)

# Install dependencies and build everything (applies crisp.dev.env → server/.env)
pnpm dev:setup

# Start all services (Hardhat, contracts, ciphernodes, program server, coordination server, and UI)
pnpm dev:up
```

`dev:up` runs `scripts/dev.sh`, which:

1. Starts the Hardhat node in `packages/crisp-contracts`
2. Deploys all contracts (Interfold, CRISPProgram, verifiers, registries) via
   `scripts/crisp_deploy.sh`
3. Starts ciphernodes using `interfold.config.yaml` via `scripts/dev_cipher.sh`
4. Launches the program server via `scripts/dev_program.sh`
5. Starts the coordination server (Rust) via `scripts/dev_server.sh` on port `4000`
6. Starts the React client via `scripts/dev_client.sh` on port `3000`

All services run concurrently and will automatically restart if needed.

### Running Individual Components

While `pnpm dev:up` runs everything together, you can also run components separately:

```bash
# Start only the Hardhat node
cd packages/crisp-contracts && pnpm hardhat node

# Start only the ciphernodes (requires Hardhat running)
./scripts/dev_cipher.sh

# Start only the program server (requires ciphernodes)
./scripts/dev_program.sh

# Start only the coordination server (requires program server)
./scripts/dev_server.sh

# Start only the client (requires coordination server)
./scripts/dev_client.sh
```

### Additional Commands

```bash
# Recompile Noir circuits and generate verifiers
pnpm compile:circuits

# Open the interactive CLI to start voting rounds
pnpm cli

# Run end-to-end tests
pnpm test:e2e
```

## Configuration

### Ciphernode Configuration

The `interfold.config.yaml` file in the CRISP root directory configures the ciphernode network. By
default, it runs in development mode with fake proofs for fast local development:

```yaml
program:
  dev: true # Uses fake zkVM proofs (fast for development)
```

### Boundless Configuration

For production-grade zero-knowledge proofs with [Boundless](https://docs.beboundless.xyz/), update
`interfold.config.yaml`:

```yaml
program:
  dev: false # Disable dev mode to use real proofs
  risc0:
    risc0_dev_mode: 0 # 0 = production (Boundless), 1 = dev mode
    boundless:
      rpc_url: 'https://sepolia.infura.io/v3/YOUR_KEY' # RPC endpoint
      private_key: 'YOUR_PRIVATE_KEY' # Wallet with funds for proving
      pinata_jwt: 'YOUR_PINATA_JWT' # Required for uploading programs to IPFS
      program_url: 'https://gateway.pinata.cloud/ipfs/YOUR_CID' # Pre-uploaded program URL
      onchain: true # true = onchain requests, false = offchain
```

> **_Note:_** For production proving with Boundless, you need:
>
> - An RPC endpoint (e.g., Infura, Alchemy) with funds
> - A private key with sufficient ETH/tokens for proof generation
> - A Pinata JWT for uploading programs to IPFS (get one at [pinata.cloud](https://pinata.cloud))
> - Pre-uploaded program URL to avoid uploading the ~40MB program at runtime

#### Uploading Your Program to IPFS

When you make changes to the guest program in `program/`, you need to upload it to IPFS to get a
program URL:

1. First, configure your Pinata JWT in `interfold.config.yaml` (as shown above)

2. Build and upload your program:

   ```bash
   # This compiles the guest program and uploads it to IPFS via Pinata
   interfold program upload
   ```

3. The command will output an IPFS hash like `QmXxx...`. Update your `interfold.config.yaml` with
   the full URL:

   ```yaml
   program_url: 'https://gateway.pinata.cloud/ipfs/QmXxx...'
   ```

> **_Important:_** Every time you modify the guest program code in `program/`, you must rebuild and
> re-upload it to IPFS, then update the `program_url` in your configuration. This ensures Boundless
> uses your latest program version.

### Environment Variables

The `pnpm dev:setup` command automatically creates `.env` files for the server and client from the
`.env.example` templates (if they don't already exist).

After `pnpm dev:up`, contract addresses are written automatically to `interfold.config.yaml`,
`server/.env`, and `client/.env` (no manual copy from `deployed_contracts.json`).

### DKG proof aggregation and on-chain ZK

Edit **`crisp.dev.env`** (created from `crisp.dev.env.example` on first `pnpm dev:setup`):

| Variable                          | Default        | Effect                                                                                                          |
| --------------------------------- | -------------- | --------------------------------------------------------------------------------------------------------------- |
| `CRISP_BFV_PRESET`                | `insecure-512` | DKG circuit build preset when aggregation is on                                                                 |
| `CRISP_PROOF_AGGREGATION_ENABLED` | `false`        | Synced to `server/.env`; controls DKG circuit build, deploy (`ENABLE_ZK_VERIFICATION`), and runtime aggregation |

`pnpm dev:setup` applies this profile (build DKG circuits when needed, sync `server/.env`).
`pnpm dev:up` deploys contracts using the same flags.

See **[docs/PROOF_AGGREGATION_AND_ZK.md](./docs/PROOF_AGGREGATION_AND_ZK.md)** for modes, address
sync, and troubleshooting (`VkHashMismatch`, etc.).

### Vercel (CRISP client)

Deploy from **`examples/CRISP/client`**. The build uses the published **`@crisp-e3/sdk@0.9.0`** on
npm (`pnpm install --ignore-workspace`), not the monorepo workspace — so it does not compile Noir
circuits on Vercel.

- **Project root directory:** `examples/CRISP/client`
- **`vercel build` in CI:** run from the **repository root** (not `cd examples/CRISP/client` first)
- Optional Vercel env: `ENABLE_EXPERIMENTAL_COREPACK=1`

Commit `examples/CRISP/client/pnpm-lock.yaml` after dependency bumps
(`pnpm install --ignore-workspace` in that directory) for reproducible installs.

## Publishing packages to npm

In order to publish a new version of the CRISP packages to npm, you can use:

```sh
pnpm publish:packages x.x.x # where x.x.x is the new version
```

## Contributing

We welcome and encourage community contributions to this repository. Please ensure that you read and
understand the [Contributor License Agreement (CLA)](https://github.com/gnosisguild/CLA) before
submitting any contributions.

### Branch Cleanup Policy

To help keep the repository clean and maintainable, we automatically delete merged branches after
**7 days**.  
You can control this behavior using **PR labels**:

| Label            | Effect                                        |
| ---------------- | --------------------------------------------- |
| `keep-branch`    | ❌ Branch will not be deleted                 |
| `archive-branch` | 🏷️ Branch will be **tagged** and then deleted |
| _no label_       | 🗑️ Branch will be deleted (no tag preserved)  |

> Only apply these labels **before merging** your PR if you want to preserve history or keep the
> branch alive.

## Security and Liability

This project is provided **WITHOUT ANY WARRANTY**; without even the implied warranty of
**MERCHANTABILITY** or **FITNESS FOR A PARTICULAR PURPOSE**.

## License

This repository is licensed under the [LGPL-3.0+ license](LICENSE).
