# Integration Tests

You can run these tests like so:

Run all tests:

```
pnpm test:integration
```

Run an individual test:

Supported scenarios are `base`, `persist`, and `net`. The default command runs `persist`, `base`,
and `net` after one prebuild. Unknown scenario names fail before the prebuild starts. The `prebuild`
entry point prepares fixtures without running a scenario; CI uses this command.

```
pnpm test:integration <test-name>
```

Eg.

```
pnpm test:integration net
```

The `base` and `persist` fixtures reserve 60 seconds for the committee request. The input window
then covers `INTEGRATION_DKG_TIMEOUT` plus 300 seconds for restart and input preparation. After key
publication, the fixtures advance Anvil to the input start if necessary. They advance to the input
end before ciphertext publication. The proof-enabled mock forwards its input directly to ciphertext
publication, so that call also requires the input end. Contract deadlines do not change.
