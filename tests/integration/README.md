# Integration Tests

You can run these tests like so:

Run all tests:

```
pnpm test:integration
```

Run an individual test:

Supported scenarios are `base`, `persist`, and `net`. The default command runs `persist`, `base`,
and `net` after one prebuild. Unknown scenario names fail before the prebuild starts.

```
pnpm test:integration <test-name>
```

Eg.

```
pnpm test:integration net
```
