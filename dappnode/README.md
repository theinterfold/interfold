# Interfold Ciphernode – DAppNode Package

Run an Interfold ciphernode on DAppNode.

This package wraps the `interfold` CLI in a DAppNode service so users can run a ciphernode with a
simple UI form (setup wizard) instead of hand-crafting configs and Docker commands.

## Networks

This is a **single-configuration** package: the same package can be pointed at different networks by
changing the config in the DAppNode UI.

You choose:

- `NETWORK` (e.g. `sepolia`, `mainnet`, `localhost`)
- The RPC URL [remote procedure call endpoint]
- Contract addresses and deploy blocks

All of these are set in the setup wizard or in the package config after installation.

## Files

Package layout (from the `dappnode/` directory):

```text
dappnode/
├── Dockerfile            # Builds the DAppNode image from the upstream ciphernode image
├── docker-compose.yml    # DAppNode service definition (single variant)
├── dappnode_package.json # Package metadata (name, version, links, backup, etc.)
├── setup-wizard.yml      # DAppNode UI form -> configuration and credential upload
├── entrypoint.sh         # Startup script (validates env, renders config, runs interfold)
├── healthcheck.sh        # Local process, credential, config, and QUIC listener checks
├── config.template.yaml  # Interfold config template (filled via envsubst)
├── releases.json         # Release metadata used by DAppNode
└── avatar-default.png    # Icon shown in the DAppNode UI
```

Non-secret configuration is supplied through environment variables. Credentials use DAppNode's
`fileUpload` setup-wizard target and are copied to `/run/secrets/secrets.json` before startup; they
are never accepted through container environment variables.

## Quick Start

### For DAppNode Users

Once this package is published to the DAppStore:

1. Open your DAppNode UI (`http://my.dappnode`).
2. Search for **“Interfold Ciphernode”** and install the package.
3. The **setup wizard** will prompt you for:
   - `RPC_URL` – WebSocket RPC endpoint (e.g. `wss://ethereum-sepolia-rpc.publicnode.com`)
   - `CHAIN_ID` – expected numeric chain ID for that RPC (Sepolia: `11155111`)
   - `REORG_CONFIRMATIONS` – positive finality depth (Sepolia default: `64`)
   - `NETWORK` – e.g. `sepolia`, `mainnet`, `localhost`
   - Contract addresses + deploy blocks
   - A required ciphernode credentials JSON file
   - Optional peers

4. Confirm and finish the installation.
5. Go to **Packages → interfold-ciphernode.public.dappnode.eth → Logs** to verify the node started
   correctly.

Until it’s in the public store, you can install it by IPFS hash:

- Build it with the SDK (see “For Developers”).
- Paste the resulting `/ipfs/...` hash into the DAppNode installer UI (“Install from IPFS hash”).

---

### For Developers

You’ll typically:

- Build the package with the DAppNode SDK.
- Install it on a DAppNode box (device or VM) from the resulting IPFS hash.
- Iterate on the entrypoint, config template, and setup wizard.

#### 1. Build the package

From the `dappnode/` directory:

```bash
cd dappnode
npx @dappnode/dappnodesdk@latest build -p remote
```

This will:

- Validate `docker-compose.yml`, `setup-wizard.yml`, and `dappnode_package.json`
- Build a multi-arch Docker image for `ciphernode.interfold-ciphernode.public.dappnode.eth`
- Upload the release to the DAppNode IPFS node
- Print an `/ipfs/<hash>` you can use to install the package

#### 2. Install on your DAppNode instance

In your browser (connected to your DAppNode):

- Open the installer URL that the SDK prints, **or**
- Go to the DAppNode UI → Installer → “Install from IPFS hash” and paste the `/ipfs/<hash>`.

Fill in the wizard fields, then install.

#### 3. Debugging and iteration

- Use the package **Logs** tab to inspect `entrypoint.sh` and `interfold` output.

- If something is wrong in the generated config, `docker exec` into the container and inspect:

  ```bash
  docker exec -it <ciphernode-container> cat /data/config.yaml
  ```

- Edit `entrypoint.sh`, `config.template.yaml`, or `setup-wizard.yml` locally, then rebuild with:

  ```bash
  npx @dappnode/dappnodesdk@latest build -p remote
  ```

- Reinstall with the new IPFS hash.

## Configuration

Non-secret runtime configuration is provided through environment variables:

### Core

- **`RPC_URL`** (required) WebSocket RPC endpoint for the chain (e.g.
  `wss://ethereum-sepolia-rpc.publicnode.com`).
- **`CHAIN_ID`** (required) Numeric chain ID that the RPC must report. Startup fails if it is
  missing or mismatched.
- **`REORG_CONFIRMATIONS`** (required) Positive number of blocks an EVM event must be buried before
  ingestion. The shipped Sepolia configuration uses `64`.

- **`NETWORK`** Logical network name written into the Interfold config (e.g. `sepolia`, `mainnet`,
  `localhost`).

- **`NODE_ADDRESS`** Optional Ethereum address to bind the node to. Leave empty to let Interfold
  handle it.

- **`QUIC_PORT`** Internal UDP port used for QUIC [Quick UDP Internet Connections] P2P networking.
  Default in this package: `37173`.

- **`LOG_LEVEL`** One of `info`, `debug`, `trace`. Mapped internally to `-v`, `-vv`, or `-vvv` when
  calling `interfold start`.

- **`EXTRA_OPTS`** Extra flags appended to the `interfold start` CLI.

### Contracts

Used to populate the `chains[0].contracts` section in `config.yaml`:

- `INTERFOLD_CONTRACT`
- `CIPHERNODE_REGISTRY_CONTRACT`
- `BONDING_REGISTRY_CONTRACT`
- `SLASHING_MANAGER_CONTRACT`
- `INTERFOLD_DEPLOY_BLOCK`
- `CIPHERNODE_REGISTRY_DEPLOY_BLOCK`
- `BONDING_REGISTRY_DEPLOY_BLOCK`
- `SLASHING_MANAGER_DEPLOY_BLOCK`

These are all required in the setup wizard so that the node can index chain events from the correct
block heights.

### Credentials file

Create a local JSON file containing the password and operator key:

```json
{
  "password": "a strong encryption password",
  "private_key": "0x<64 hex characters>"
}
```

Upload it in the setup wizard as **Ciphernode Credentials JSON**. DAppNode copies it to
`/run/secrets/secrets.json` before starting the container. The entrypoint validates a maximum size
of 16 KiB, required fields, a minimum 16-byte password, and key encodings, then runs the exact
commands supported by the pinned Interfold v0.4.0 image. Any failed command aborts startup. The
wallet command atomically derives and stores both the Ethereum and libp2p identities. Both keys are
encrypted in `/data`; the password key is stored separately with mode `0400`. After successful
persistence, the entrypoint removes
the combined plaintext upload. Provisioning sends the secrets through the CLI's hidden TTY prompts
over stdin; plaintext credentials are never placed in process arguments or container environment
variables.

Legacy three-field files containing `network_private_key` are accepted for upgrade compatibility,
but v0.4.0 ignores that obsolete field on a fresh setup. When encrypted identity state already
exists, a matching upload is removed without rewriting either identity; a password mismatch fails
closed.

The Ethereum key must correspond to `NODE_ADDRESS`. Keep an encrypted offline backup of this JSON;
do not paste its contents into package environment variables, `EXTRA_OPTS`, logs, or support
bundles. On an ordinary restart, persisted credential state is reused from `/data` and the upload is
not required again. Uploading a different password while state already exists fails closed.

### Peers

- **`PEERS`** Comma-separated list of peer multiaddresses, for example:

  ```text
  /dns4/cn1/udp/37173/quic-v1,/dns4/cn2/udp/37173/quic-v1
  ```

  The entrypoint splits this on commas, trims spaces, and turns each into a `--peer` flag:

  ```bash
  interfold start ... --peer /dns4/cn1/udp/37173/quic-v1 --peer /dns4/cn2/udp/37173/quic-v1
  ```

If a variable is not set in the wizard, it still appears (with its default) in the package config
screen after installation, as per DAppNode’s env behavior.

## How It Works Internally

At container startup, `entrypoint.sh`:

1. Validates `RPC_URL` is non-empty and starts with `ws://` or `wss://`.
2. Applies sensible defaults for `NETWORK`, `QUIC_PORT`, and `LOG_LEVEL`.
3. Uses `envsubst` to render `config.template.yaml` into `/data/config.yaml`, substituting:

- node address and ports
- network name and RPC URL
- contract addresses and deploy blocks

4. Validates the uploaded credential file and programs the password plus atomic wallet/network
   identity. An isolated Expect helper feeds hidden prompts from stdin and failures stop startup.
5. Builds CLI args, including verbosity and `--peer` flags from `PEERS`.
6. Executes:

   ```bash
   interfold start --config /data/config.yaml ...
   ```

The state and databases live under `/data` inside the container, which is backed by the
`ciphernode_data` Docker volume and listed as a backup target in `dappnode_package.json`. The
password key lives separately at `/run/interfold/key` on `ciphernode_secrets` and is deliberately
excluded from that encrypted-state backup. Securely escrow the password outside DAppNode; restoring
only `/data` cannot unlock the node. New ciphertext uses a versioned envelope with a fresh random
Argon2id salt, while legacy ciphertext is read only for migration and is upgraded on its next write.

### Legacy upgrade boundary

DAppNode package v0.2.3 is the required bridge from the shipped v0.1.8 package to later binaries. On
its first start it atomically renames the custom-config state root from `/data/.enclave` to
`/data/.interfold`, refusing to proceed if both roots exist. The v0.2.3 binary then stamps schema
version 1 using its release-era compatibility behavior. Interfold v0.4.0 uses schema version 2 and
intentionally rejects schema 1 because keyshare state changed incompatibly. There is no in-place
v0.2.3-to-v0.4.0 state migration: finish or canonically fail active E3s, keep a verified backup, and
perform a controlled fresh resync. Never wipe in-flight threshold-share state as an upgrade shortcut.

## Health semantics

Interfold v0.4.0 does not yet expose a complete protocol-readiness endpoint. The package health
check therefore uses local signals: PID 1 must be the expected
`interfold start` command using `/data/config.yaml`, the protected config/password files must exist,
the v0.4.0 Sled/event-log directories must be initialized, and the configured QUIC UDP listener must
be bound. This detects the old false-positive case where an unrelated process matched `pgrep`, as
well as missing credentials, uninitialized persistence, and a dead network listener.

This remains a liveness/startup check, not proof of canonical chain sync, healthy RPC responses,
honest peers, registration, or safe protocol participation. Operators must inspect logs and on-chain
status before treating the node as protocol-ready.

## Data & Ports

- **Data volume**: `ciphernode_data` → `/data` This is where Interfold stores its databases and
  state.

- **Ports**:
  - **UDP 37173** – QUIC P2P networking (host and container).

If you change `QUIC_PORT` in the config, you must also adjust the `ports:` mapping in
`docker-compose.yml` in a derived package.

## Publishing

To publish this package to the public DAppStore so others can install it:

```bash
npx @dappnode/dappnodesdk@latest publish \
  --type=<patch|minor|major> \
  --eth-provider=<your ETH RPC> \
  --content-provider=<your IPFS API> \
  --developer-address=<publisher address>
```

The SDK will guide you through signing and broadcasting the on-chain transaction that registers the
new package version.

## Links

- [Interfold Docs](https://docs.interfold.network)
- [DAppNode Package Development – Single Configuration](https://docs.dappnode.io/docs/dev/package-development/single-configuration/)
- [DAppNode Docker Compose Reference](https://docs.dappnode.io/docs/dev/references/docker-compose/)
- [DAppNode Setup Wizard Reference](https://docs.dappnode.io/docs/dev/references/setup-wizard/)
- [Interfold GitHub Repository](https://github.com/gnosisguild/interfold)
