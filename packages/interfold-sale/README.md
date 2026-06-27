# Interfold Sale

React console for the FOLD CCA sale rehearsal and launch.

The app reads the generated deployment manifest from:

```text
public/sale/deployment.json
```

The contracts script writes that file automatically after `pnpm sale --action deploy` or
`pnpm sale --action full-test`.

## Run

```bash
pnpm install
pnpm dev
```

## Build

```bash
pnpm build
```

The UI uses public RPC defaults for Sepolia/mainnet reads and only needs a connected wallet for
transactions.
