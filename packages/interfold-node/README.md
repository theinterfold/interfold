# Interfold Node Observatory

The local ciphernode operator dashboard. The React source is built by Vite into
`crates/dashboard/assets/`; the Rust dashboard server embeds those production assets into the
`interfold` binary.

Protocol history comes from the node's durable EventStore. Operational tracing logs come from the
bounded log collector. These are intentionally separate: an application log is not a protocol
ledger.

```bash
pnpm --filter @interfold/node-dashboard build
pnpm --filter @interfold/node-dashboard dev
```

The development server proxies `/api` to `http://127.0.0.1:9092`. Change the proxy port in
`vite.config.ts` if the node's configured dashboard port differs.

The production server binds to loopback because event payloads and node diagnostics are detailed and
the dashboard has no authentication layer.
