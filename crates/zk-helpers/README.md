# e3-zk-helpers

ZK circuit computation, witness encoding, commitments, and artifact generation.

## Ownership

| Owner                    | Responsibility                                                              |
| ------------------------ | --------------------------------------------------------------------------- |
| `e3-committee`           | Committee types, canonical values, and honest-roster selection              |
| `e3-bfv-math`            | BFV scaling, plaintext decoding, modulus arithmetic, and coefficient widths |
| `e3-polynomial`          | Negacyclic folding, modular inverse, and coefficient representations        |
| `encoding`               | Canonical signed-field values and JSON witness shapes                       |
| `committee`              | Compatibility with the compiled circuit committee                           |
| `metadata`               | Circuit names, prefixes, parameter types, and witness families              |
| `packing` and `circuits` | Noir packing, commitments, computation, sampling, and code generation       |

## zk-cli

Run these commands from the repository root:

```bash
pnpm zk list

pnpm zk generate --circuit pk-generation --preset insecure --committee minimum --toml

pnpm zk generate --circuit share-encryption --preset insecure --committee micro --inputs secret-key --toml --no-configs

pnpm zk vk-hash path/to/first.vk_hash path/to/second.vk_hash

pnpm zk vk-hash --bfv-tree path/to/artifact-pair

pnpm zk parity-matrices --committee minimum
```

`generate` always samples circuit data and computes both artifacts. By default, it writes only
`configs.nr` to `output/`. Use `--toml` to also write `Prover.toml`. With `--toml --no-configs`, it
writes only `Prover.toml`. Use `--output <path>` to select another directory.

`--preset` accepts `insecure` (degree 512), `secure` (degree 8192), or aliases `2` and `80`.
`--committee` accepts `minimum` (default), `micro`, or `small`. The committee must match the
compiled Noir circuits.

When you request `Prover.toml`, `share-computation`, `share-encryption`, and `share-decryption`
require `--inputs secret-key|smudging-noise`. Config-only generation defaults to `secret-key` for
these circuits.

`vk-hash` preserves input order and rejects files outside the canonical 32-byte field encoding.
`--bfv-tree` reads the complete recursive key tree and prints the `nodes_fold` and `c6_fold` hashes
as JSON.

`parity-matrices` writes both preset files under `circuits/lib/src/configs/committee/<name>/`. Use
`--output-root <path>` to select another root that contains the committee directory. To change the
active committee or preset, use `pnpm build:circuits`, not direct edits to generated files.
