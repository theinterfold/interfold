# Interfold Ciphernode for Dappnode

Run an Interfold ciphernode and monitor it in Dappnode.

## Install

1. Select a synced execution client in Dappnode **Stakers**. Enable its WebSocket RPC.
2. Install the Mainnet or Sepolia package using its IPFS hash.
3. On first installation, upload your `secrets.json` file.
4. Open the package **Operator Dashboard** link and follow the [operator setup steps](getting-started.md).

The package supplies the network settings and uses your selected Dappnode execution client.

| Network | Operator Dashboard | Node dashboard | UDP port |
| ------- | -------------- | -------------- | -------- |
| Mainnet | [Open](https://dashboard.theinterfold.com/#operator) | [Open](http://interfold-ciphernode-mainnet.dappnode:8081) | 37173 |
| Sepolia | [Open](https://testnet-dashboard.theinterfold.com/#operator) | [Open](http://interfold-ciphernode-sepolia.dappnode:8081) | 37174 |

Use the remote **Operator Dashboard** to interact with contracts. Connect through the Dappnode LAN
or VPN to open the local **Node dashboard**.

## Credentials and backups

Create `secrets.json` with an encryption password and a dedicated operator private key:

```json
{
  "password": "a strong encryption password",
  "private_key": "0x<64 hexadecimal characters>"
}
```

Keep an encrypted backup offline. The node saves its encrypted identity and deletes the uploaded
file. For updates, leave the credential upload empty. Updates and restarts reuse the saved identity.

The package **Backup** includes the configuration, encryption password, and node database with
the encrypted operator and network keys. It excludes downloaded circuits and prover caches.
The database also contains committee state that a password file alone cannot restore.

Stop the node before a backup. Keep the backup encrypted offline; it contains the password that
unlocks the keys. Restore it to the same network package. Mainnet and Sepolia use separate data volumes.

## Custom RPC

Change `RPC_URL` in package **Config** to use another endpoint. Use `ws://` or `wss://` for the
package network. The endpoint must also accept HTTP at the same host, port, and path.

The Dappnode defaults work with the client's separate HTTP and WebSocket ports automatically.

## Local development

Run from the repository root. Builds require Docker. The hardening test requires `jq`, `envsubst`,
Python `PyYAML`, and `websocket-client`.

```bash
npm ci --ignore-scripts --prefix dappnode
pnpm --dir dappnode check
pnpm --dir dappnode test
pnpm --dir dappnode build --skip_upload
```

The final command builds both packages for `linux/amd64` and saves them locally. Run
`pnpm --dir dappnode build` to upload them to IPFS and obtain installation hashes.

Package files stay in `dappnode/`. The image extends the pinned Interfold image and copies deployment
settings from the repository's `deployments/manifest.json`.
