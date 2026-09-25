# Integration Tests

You can run these tests like so:

Run all tests:

```
pnpm test:integration
```

Run an individual test:

```
pnpm test:integration <test-name>
```

`<test-name>` is `base`, `persist`, `net`, or `prebuild` (build fixtures only; used by CI).

Eg.

```
pnpm test:integration net
```

The local `ciphernode:admin-add` task funds each operator as its own bond owner. This gives the
committee distinct owners under the on-chain seat cap. To test shared ownership, pass
`--bond-owner-address <address>` to that task. The cap still applies to those operators.
