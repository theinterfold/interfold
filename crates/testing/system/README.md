# e3-tests

## Purpose

The fixture binary that the [integration scripts](../../../tests/integration) use: `fake_encrypt`
encrypts a requester's input to the committee's public key with the production parameter codecs and
commitments. `src/main.rs` intentionally does no work.

```sh
cargo build --locked -p e3-tests --bin fake_encrypt
```

[`docker/test-ciphernode-entrypoint.sh`](docker/test-ciphernode-entrypoint.sh) tests which state
location the ciphernode image's entrypoint script uses.

The fixture ownership decisions are recorded in the
[testing domain](../../../docs/architecture/repository-testing.md#fixture-ownership-2325). See
[AGENTS.md](AGENTS.md) before adding dependencies.
