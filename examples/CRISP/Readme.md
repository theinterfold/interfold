# CRISP - Coercion-Resistant Impartial Selection Protocol

CRISP (Coercion-Resistant Impartial Selection Protocol) is a secret-ballot voting protocol built
with the Interfold. It uses fully homomorphic encryption (FHE) and distributed threshold
cryptography (DTC). Each voter encrypts a ballot in the browser. The Secure Process adds the
encrypted ballots, and a threshold committee of ciphernodes decrypts only the combined result, which
is public. On-chain contracts verify the proofs of the tally and of its decryption.

Vote masking makes receipts weaker, which makes coercion and vote buying more difficult. These
protections depend on the conditions in
[Privacy limits](https://docs.theinterfold.com/CRISP/introduction#privacy-limits). To learn more
about CRISP, read our
[blog post](https://blog.theinterfold.com/crisp-private-voting-secret-ballot-fhe-zkp-mpc/) or the
[documentation](https://docs.theinterfold.com/CRISP/introduction).

## Project Structure

CRISP follows a modern structure with clear separation of concerns, consistent with the Interfold
root structure.

```bash
CRISP/
├── client/                  # React frontend application (Vite + @crisp-e3/sdk)
├── server/                  # Rust coordination server & CLI
├── program/                 # FHE policy proved with OpenVM
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

- [Rust](https://rust-lang.org/tools/install/) — see `rust-toolchain.toml` for the pinned version
- [Foundry](https://getfoundry.sh)
- [NodeJS](https://nodejs.org/en/download) — CI uses 22.x (`NODE_VERSION` in
  `.github/workflows/ci.yml`). Odd-numbered releases such as 25.x make Hardhat print an unsupported
  version warning on every invocation
- [pnpm](https://pnpm.io)
- [MetaMask](https://metamask.io)
- [`yq`](https://github.com/mikefarah/yq) — `scripts/dev_cipher.sh` reads node addresses with it
- Noir toolchain: [`nargo`](https://noir-lang.org/docs/installation) and
  [`bb`](https://barretenberg.aztec.network/docs/getting_started). Install the versions CI pins,
  since other versions may not compile the circuits:
  - `nargo`: `noirup -v v1.0.0-beta.26` (`NOIR_TOOLCHAIN` in `.github/workflows/ci.yml`)
  - `bb`: version and per-platform checksums live in `crates/zk-prover/versions.json`

Local development runs the unproved development runner unless `CRISP_REAL_PROOFS=1` (see
`crisp.dev.env.example`). Real proofs use OpenVM: build the workers, configure `program.openvm` in
`interfold.config.yaml`, and run `interfold program compile`. Follow
[`crates/openvm-prover/README.md`](../../crates/openvm-prover/README.md). A machine with a working
CUDA GPU proves on it when the CUDA worker is configured; any other machine proves on the CPU.

The CRISP deployment reads the receipt identity `interfold program compile` wrote, unless
`OPENVM_APP_EXE_COMMIT`, `OPENVM_APP_VM_COMMIT`, and either `OPENVM_VERIFIER_ARTIFACT` with
`OPENVM_VERIFIER_SHA256` or `OPENVM_HALO2_VERIFIER` with `OPENVM_HALO2_RUNTIME_CODE_HASH` are set.
Outside `CRISP_UNPROVED_TEST=1` on the local chain, it never selects a mock compute verifier.

## Quick Start

The simplest way to run CRISP is:

```bash
# From the repository root
cd examples/CRISP

# Optional: choose local profile (copied to crisp.dev.env on first setup)
cp crisp.dev.env.example crisp.dev.env
# Edit CRISP_SKIP_PROOF_AGGREGATION and CRISP_BFV_PRESET (see docs/PROOF_AGGREGATION_AND_ZK.md)

# Install dependencies and build everything (creates server/.env from the example if missing)
pnpm dev:setup

# Start all services (Hardhat, contracts, ciphernodes, program server, coordination server, and UI)
pnpm dev:up
```

The program server accepts caller-supplied HTTP(S) callback URLs. It is a development-only test
service, does not authenticate callers or allowlist callback destinations, and must stay isolated
from production and untrusted networks.

`dev:up` runs `scripts/dev.sh`, which:

1. Starts the Hardhat node in `packages/crisp-contracts`
2. Deploys all contracts (Interfold, CRISPProgram, verifiers, registries) via
   `scripts/crisp_deploy.sh`
3. Watches the local mock randomness provider and fulfills each request in a later block
4. Starts ciphernodes using `interfold.config.yaml` via `scripts/dev_cipher.sh`
5. Launches the program server via `scripts/dev_program.sh`
6. Starts the coordination server (Rust) via `scripts/dev_server.sh` on port `4000`
7. Starts the React client via `scripts/dev_client.sh` on port `3000`

All services run concurrently and will automatically restart if needed.

### Running Individual Components

While `pnpm dev:up` runs everything together, you can also run components separately:

```bash
# Start only the Hardhat node
cd packages/crisp-contracts && pnpm hardhat node

# Start only the ciphernodes (requires Hardhat running).
# The argument is the ready-file the script creates once the nodes are registered.
./scripts/dev_cipher.sh ./.interfold/ready

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

The `interfold.config.yaml` file in the CRISP root directory configures the ciphernode network. It
sets `program.dev: false`. The local scripts override that with `E3_PROGRAM__DEV=true` unless
`CRISP_REAL_PROOFS=1`, so a local round uses the unproved development runner by default.

### OpenVM configuration

The real-proof compute service uses OpenVM. CRISP's guest is `examples/CRISP/guest`, and its
service is `.interfold/support/openvm`; both link `program/`, the processor and policy the contract
agrees with. Follow the [OpenVM guide](../../crates/openvm-prover/README.md) to build the workers,
then run `interfold program compile` for the guest, keys, identity and service.

Set `program.dev: false` and supply deployment-local `program.openvm.prover_bin` and, on a GPU
machine, `program.openvm.prover_bin_cuda` paths. Do not put account keys, proving artifacts, or
machine-specific values in the shared configuration.

A new OpenVM deployment requires matching receipt and ciphertext-duty verifiers. Existing RISC Zero
deployments do not become compatible by changing the service configuration. Drain active rounds and
use a separate reviewed migration before changing a live verifier route. The old Boundless upload
and auction settings are not used by this backend.

### Encrypted-object data availability

Local development uses `DATA_AVAILABILITY_MODE=mock`. The mock keeps the full input and aggregate
ciphertext in the CRISP server database and produces a deterministic local receipt. It does not
model VectorX latency or Avail fees.

Sepolia and Ethereum mainnet use Avail. Sepolia uses a mock RISC Zero verifier, so the CRISP
contract and the protocol ciphertext verifier on Sepolia accept dev-mode RISC Zero proofs. Ethereum
mainnet uses real RISC Zero verification. CRISPProgram on Sepolia is
`0x9Dc6edB343A89a25dC8bEF324F721Cca78E86AFD`, and its Avail data availability verifier is
`AvailVectorXDataAvailabilityVerifier` (`0x099b65d98773c0219467dc00DE11022c2d055Fbc`). The two Noir
verifiers of this CRISPProgram come from the circuits of commit `8abc2fdb7`, which published
`@crisp-e3/sdk` 0.24.0. Thus a Sepolia client must prove with SDK 0.24.0. The circuits in this
directory are newer, and their ballot proofs do not pass these verifiers. Before starting the CRISP
server:

1. Register an Avail App ID for CRISP.
2. Fund a dedicated Avail account that can pay for every `submit_data` transaction.
3. Keep the server database durable. It stores each pending publication until its VectorX proof is
   available and resumes the job after a restart.
4. Deploy CRISP with `INPUT_AVAILABILITY_SIGNER` set to the Ethereum address derived from the
   server's `PRIVATE_KEY`. On every network, the server `PRIVATE_KEY` must be the key of the signer
   address that CRISPProgram stores.
   The current Sepolia deployment used `USE_MOCKS=true MOCK_DATA_AVAILABILITY=false` with the
   earlier RISC Zero backend. `USE_MOCKS=true` deploys the mock voting token and selects the mock
   data-availability verifier, unless `MOCK_DATA_AVAILABILITY=false` keeps Avail. It does not
   select a compute mock: every network except the isolated local chain deploys the real OpenVM
   receipt verifier. Ciphernodes read all inputs on a chain from one data-availability source, so
   keep Avail on a shared network.
5. Schedule voting after the current on-chain committee setup budget. The server reads that bound
   from `CRISPProgram.earliestVotingStart()` and adds `VOTING_START_BUFFER_SECONDS` for transaction
   mining. `E3_DURATION` starts at that fixed voting time; it covers voting plus the VectorX
   finalization tail, not committee setup.

The server signs a 10-minute commitment payload only after it stores and validates the complete
ciphertext. If the commitment does not reach Ethereum before that payload expires, the server waits
for Ethereum finality, releases the uncommitted bytes, and lets the voter stage the vote again.

```dotenv
# Sepolia + Avail Turing
DATA_AVAILABILITY_MODE=avail
AVAIL_RPC_URL=https://turing-rpc.avail.so/rpc
AVAIL_BRIDGE_API_URL=https://turing-bridge-api.avail.so
AVAIL_APP_ID=<registered-app-id>
AVAIL_SEED=<dedicated-funded-secret-uri>
AVAIL_PROOF_LEAD_SECONDS=10800
# Unfinished objects are refused once they reach this capacity. Size it for the largest supported
# round and monitor the server volume. Default: 1 GiB.
DATA_AVAILABILITY_MAX_PENDING_BYTES=1073741824
# Input-window duration after voting starts. The minimum production example is 4 hours:
# 1 hour voting + 3 hours VectorX finalization. Twelve hours provides 9 hours of voting.
E3_DURATION=43200
# Extra time for the E3 request transaction to be mined before the fixed voting start.
# Default: 120 seconds.
VOTING_START_BUFFER_SECONDS=120

# Required by the cron client and the protected POST /rounds/request endpoint.
# Use a nonempty secret whenever the endpoint is exposed.
CRON_API_KEY=<random-secret>

# Remote cron targets must use HTTPS. Plain HTTP is accepted only for loopback development.
INTERFOLD_SERVER_URL=https://crisp.example

# Ethereum mainnet uses these two endpoints instead:
# AVAIL_RPC_URL=https://avail-rpc.publicnode.com/
# AVAIL_BRIDGE_API_URL=https://bridge-api.avail.so
```

Do not embed `CRON_API_KEY` in a browser bundle. Use it only from protected automation. The cron
client and SDK round-request method reject remote plain HTTP and redirects before they send the
secret. Plain HTTP is accepted only for `localhost`, `127.0.0.0/8`, and `[::1]` development
endpoints.

DAO deployments can set `DEFER_PROTOCOL_WIRING=true` to deploy CRISP before the governance wiring
transaction. On Ethereum mainnet, the deployment also requires `ALLOW_MAINNET_DEFERRED_WIRING=true`
as an explicit acknowledgement that CRISP is unusable until the DAO batch is executed and validated.
Keep E3 requests paused throughout that interval.

The server first validates the Noir proof and durably stores the exact encrypted bytes. It signs a
compact proof commitment only after storage succeeds. The server relays that commitment, or the
voter submits it from their wallet, and the voter can then leave. Relaying is configurable in
`server/.env.example`, and it is off on Ethereum mainnet by default. The server publishes the
ciphertext to Avail, waits for the official VectorX proof, and finalizes the input without the
voter. The proof transaction reserves the input's tree index immediately, so masks and revotes can
still extend it during the VectorX wait. CRISP refuses the aggregate computation while any input is
not finalized.

The relay has per-slot and per-round limits, and anyone can use up the relayed inputs of a slot with
masks. Past a limit, the voter's wallet sends the commitment, which shows the voter's address. The
voter must confirm it before the commitment cutoff of the round: stay on the page, or come back and
repeat the action. Otherwise the input is lost.

Each distinct input gets its own job, so a pending mask cannot block a vote for the same slot. The
service limits the total bytes held by unfinished jobs, which bounds abandoned signed inputs without
deleting data that Ethereum already accepted. After Avail and Ethereum accept an object, the service
removes its staging copy because Avail is then the recovery source.

The aggregate ciphertext follows the Avail and VectorX path after its OpenVM proof is ready.

Each accepted Ethereum reference contains `keccak256(exact bytes)`. The CRISP server and ciphernodes
re-hash retrieved bytes before they use them. An App ID helps indexing, but it is not a security
boundary.

### Environment Variables

The `pnpm dev:setup` command automatically creates `.env` files for the server and client from the
`.env.example` templates (if they don't already exist).

After `pnpm dev:up`, contract addresses are written automatically to `interfold.config.yaml`,
`server/.env`, and `client/.env` (no manual copy from `deployed_contracts.json`).

### DKG proof aggregation and on-chain ZK

Edit **`crisp.dev.env`** (created from `crisp.dev.env.example` on first `pnpm dev:setup`):

| Variable                       | Default        | Effect                                                                |
| ------------------------------ | -------------- | --------------------------------------------------------------------- |
| `CRISP_BFV_PRESET`             | `insecure-512` | BFV preset for aggregation circuits and the server `E3_PARAM_SET`     |
| `CRISP_SKIP_PROOF_AGGREGATION` | `true`         | Ciphernode-only local-dev skip; also selects mock verifier deployment |

`pnpm dev:setup` applies this profile and builds recursive circuits only when needed. `pnpm dev:up`
deploys contracts using the same flags.

**Re-run `pnpm dev:setup` after changing `CRISP_SKIP_PROOF_AGGREGATION`.** The setting is only
honoured by an `interfold` binary built with the matching `test-only-skip-proof-aggregation` Cargo
feature, so `dev:setup` selects that feature from the profile and reinstalls the CLI. Running
`dev:up` against a binary from the other profile makes every ciphernode exit at startup;
`dev_cipher.sh` now aborts with the node status table instead of continuing. Note that
`~/.cargo/bin/interfold` is shared — a `dev:setup` in `templates/default` or another example
overwrites the binary this profile installed.

See **[docs/PROOF_AGGREGATION_AND_ZK.md](./docs/PROOF_AGGREGATION_AND_ZK.md)** for modes, address
sync, and troubleshooting (`VkHashMismatch`, etc.).

### Vercel (CRISP client)

Deploy from **`examples/CRISP/client`**. The build uses the published **`@crisp-e3/sdk`** package on
npm (`pnpm install --ignore-workspace`), not the monorepo workspace. The published SDK package
already contains the staged preset circuits, so Vercel does not compile Noir circuits.

- **Project root directory:** `examples/CRISP/client`
- **`vercel build` in CI:** run from the **repository root** (not `cd examples/CRISP/client` first)
- Optional Vercel env: `ENABLE_EXPERIMENTAL_COREPACK=1`

Commit `examples/CRISP/client/pnpm-lock.yaml` after dependency bumps
(`pnpm install --ignore-workspace` in that directory) for reproducible installs.

## Publishing packages to npm

In order to publish a new version of the CRISP packages to npm, select the release channel:

```sh
pnpm publish:packages --channel prod x.x.x
pnpm publish:packages --channel testing x.x.x-insecure.0
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

This repository is licensed under the [LGPL-3.0+ license](../../LICENSE.md).
