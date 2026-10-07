# CRISP program

The program implements CRISP's FHE processor and input policy. The OpenVM guest proves their
execution. The native host uses the same source to derive the ciphertext and expected journal.

CRISP does not sum every published entry. Its input policy validates commitments and follows each
slot's parent chain. Only the current valid head contributes to the encrypted tally. Every published
entry remains bound into the reconstructed input root.

The proof binds the chain, Interfold address, full E3 ID, encryption scheme, committee key
commitment, ciphertext hash, SAFE commitment, parameter hash, and input root.

## Live compute flow

The CRISP server sends the indexed inputs to the program server after the input deadline. The OpenVM
worker returns a verified proof. The program server delivers the ciphertext, commitment, and proof
envelope by HTTP callback.

CRISP validates the callback, obtains the output's availability receipt, and publishes the output
reference. Both the protocol and application verifier must pass before the E3 reaches
`CiphertextReady`. Threshold decryption follows separately.

## Build and run

Follow [the OpenVM instructions](../../../crates/openvm-prover/README.md). Configure
`program.openvm` with the worker paths, then run `interfold program compile` in `examples/CRISP`.
The guest in `examples/CRISP/guest` and the service in `.interfold/support/openvm` both link this
crate.

For a local round with real proofs, set `CRISP_REAL_PROOFS=1` in `crisp.dev.env`, then from
`examples/CRISP` run:

```sh
pnpm dev:setup   # also runs `interfold program compile`
pnpm dev:up      # deploys the receipt verifier for the compiled guest and starts the services
```

Without `CRISP_REAL_PROOFS=1`, these scripts run the unproved development runner. The OpenVM service
listens on `127.0.0.1:13151`.

## Fresh test inputs

From the repository root:

```sh
pnpm openvm fixture <vote-count> <new-output-directory>
```

The fixture generator creates fresh secure-8192 test ballots and checks the native aggregate and
tally. It does not produce ballot, DKG, or threshold-decryption proofs. Keep its output under
`target/` or outside the repository.
