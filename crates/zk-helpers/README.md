# e3-zk-helpers

ZK circuit helpers, artifact generation, and committee-size definitions.

## zk_cli

```bash
# List circuits
cargo run -p e3-zk-helpers --bin zk_cli -- --list_circuits

# Generate Prover.toml + configs.nr for a circuit
cargo run -p e3-zk-helpers --bin zk_cli -- --circuit pk-generation --preset insecure --committee minimum

# C2 chunked configs (default: 512 coefficients)
cargo run -p e3-zk-helpers --bin zk_cli -- --circuit share-computation --preset secure --inputs secret-key --chunk-size 512

# Micro or small committee (must match active circuits lib selection)
cargo run -p e3-zk-helpers --bin zk_cli -- --circuit pk-generation --preset insecure --committee micro
cargo run -p e3-zk-helpers --bin zk_cli -- --circuit pk-generation --preset insecure --committee small
```

| Flag                 | Description                                                                                                  |
| -------------------- | ------------------------------------------------------------------------------------------------------------ |
| `--circuit <name>`   | Circuit to generate artifacts for                                                                            |
| `--preset <name>`    | BFV preset: `insecure` (512), `secure` (8192), or aliases `2` / `80`                                         |
| `--committee <name>` | Committee size: `minimum` (default), `micro`, or `small` — must match `circuits/lib` active committee        |
| `--chunk-size <n>`   | C2 coefficient chunk size; only `512` is supported (the compiled chunk layout is pinned to 512 coefficients) |
