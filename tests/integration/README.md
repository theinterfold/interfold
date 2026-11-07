# Integration Tests

Run the v2 scenario (a local chain, five nodes, one Minimum committee, one decryption):

```
pnpm test:integration
```

[v2.sh](v2.sh) says how to run its variants: the operators' CLI (`V2_CLI=true`), a restart of the
decryption aggregator (`V2_RESTART=true`), and real proofs (`V2_NOIR_DIR`).

`pnpm test:integration prebuild` builds the fixtures that CI's proof jobs download.

The local `ciphernode:admin-add` task funds each operator as its own bond owner. This gives the
committee distinct owners under the on-chain seat cap. To test shared ownership, pass
`--bond-owner-address <address>` to that task. The cap still applies to those operators.
