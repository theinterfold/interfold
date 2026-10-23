# Interfold Ciphernode for Dappnode

Run an Interfold ciphernode and monitor it in Dappnode.

## Install

1. Select a synced execution client in Dappnode **Stakers**. Enable its WebSocket RPC.
2. Install the Mainnet or Sepolia package using its IPFS hash.
3. On first installation, upload your `secrets.json` file.
4. Open the package **Operator Dashboard** link and follow the
   [operator setup steps](getting-started.md).

The package supplies the network settings and uses your selected Dappnode execution client.

| Network | Operator Dashboard                                           | Node dashboard                                            | UDP port |
| ------- | ------------------------------------------------------------ | --------------------------------------------------------- | -------- |
| Mainnet | [Open](https://dashboard.theinterfold.com/#operator)         | [Open](http://interfold-ciphernode-mainnet.dappnode:8081) | 37173    |
| Sepolia | [Open](https://testnet-dashboard.theinterfold.com/#operator) | [Open](http://interfold-ciphernode-sepolia.dappnode:8081) | 37174    |

Use the remote **Operator Dashboard** to interact with contracts. Connect through the Dappnode LAN
or VPN to open the local **Node dashboard**. The Node dashboard has no login, and every container on
the Dappnode network can also reach it. If its proxy cannot start, the node runs without it.

## Credentials and backups

Create `secrets.json` with an encryption password and a dedicated operator private key:

```json
{
  "password": "a strong encryption password",
  "private_key": "0x<64 hexadecimal characters>"
}
```

Keep an encrypted backup offline. The node saves its encrypted identity and deletes the uploaded
file. If startup stops before that, for example because the RPC check fails, the file stays in
`/data` until a start succeeds. For updates, leave the credential upload empty. Updates and restarts
reuse the saved identity. If the database exists without its credential key, startup stops and asks
for the complete backup instead of creating another identity.

The package **Backup** includes the configuration, encryption password, and node database with the
encrypted operator and network keys. It excludes downloaded circuits and prover caches. The database
also contains committee state that a password file alone cannot restore.

Stop the node before a backup. Keep the backup encrypted offline; it contains the password that
unlocks the keys. Restore it to the same network package. Mainnet and Sepolia use separate data
volumes.

## Updates and maintenance

To upgrade, wait until the **Updates** view of the Node dashboard shows no active E3. Then update
the package in Dappnode. The package restarts the node with the new release.

When a release raises the storage schema, the package resets the node state before the node starts.
The reset keeps the operator key and the libp2p key, and the node then syncs again from the chain.
This needs a node release with `interfold node reset-data --if-schema-older`. On v0.19.0, use the
[one-off reset](https://docs.theinterfold.com/operate/upgrades#reset-node-state) instead.

The reset refuses while the node holds a key share for an E3 that it has not seen complete, or slash
reports that it has not sent. The node then stays stopped, and the log lists each E3 or chain. Do
the checks in
[If the command refuses](https://docs.theinterfold.com/operate/upgrades#if-the-command-refuses).
Where they say to start the release that the node ran before, install the previous package version,
so that the node finishes its work or sends its reports. Set `ALLOW_ACTIVE_E3S_RESET` to `true` in
package **Config** only where they say to add `--allow-active-e3s`. The node then deletes those key
shares and reports. Set it back to `false` after the node starts.

To repair a state that `interfold node validate` reports, stop the package. Then run its image in a
one-off container with the package volume:

```bash
docker run --rm --volumes-from <stopped-package-container> --workdir /data \
  --entrypoint interfold <package-image> node validate --repair --config /data/config.yaml
```

To leave the network, complete the
[exit checklist](https://docs.theinterfold.com/operate/exits-and-slashing#exit-checklist) before you
remove the package. The package volume holds the operator key, and its removal does not run the
checks of `interfold nodes purge`. To change the operator key or the password, exit first, then
install the package with a new volume.

## Custom RPC

Change `RPC_URL` in package **Config** to use another endpoint. Use `ws://` or `wss://` for the
package network. The endpoint must also accept HTTP at the same host, port, and path.

The Dappnode defaults work with the client's separate HTTP and WebSocket ports automatically.

## Local development

Run from the repository root. `check`, `build`, and `test:image` require Docker with Compose. The
hardening test requires `jq`, `envsubst`, Python `PyYAML`, and `websocket-client`.

```bash
npm ci --ignore-scripts --prefix dappnode
pnpm --dir dappnode check
pnpm --dir dappnode test
pnpm --dir dappnode build --skip_upload
pnpm --dir dappnode test:image
```

`build --skip_upload` builds both packages for `linux/amd64` and saves them locally. `test:image`
then starts the Mainnet image against a test execution client. Run `pnpm --dir dappnode build` to
upload the packages to IPFS and obtain installation hashes.

Package files stay in `dappnode/`. The image extends the pinned Interfold image and copies
deployment settings from the repository's `deployments/manifest.json`.
