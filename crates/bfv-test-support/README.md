# e3-bfv-test-support

Unpublished artificial encrypted-ballot fixtures shared by TrBFV's isolated integration suite and
the multi-node system suite. Consumers use dev-dependencies only.

`generate_ciphertexts` encrypts random bits using the supplied public key and its exact parameters;
`run_application` tallies them column-wise. These functions model sample computation, not proof
validity, input admission, or a production application. No parameter table, codec, commitment,
threshold reconstruction, event system or node assembly is implemented here.

## Tests

```sh
cargo test --locked -p e3-bfv-test-support
cargo test --locked -p e3-trbfv --test integration
```

The TrBFV scenario tests encrypted ballots through production share generation and threshold
decryption. Its share fixtures are private under `trbfv/tests/common`. Full composition belongs to
[e3-tests](../tests/README.md); real-proof evidence requires the matching external artifacts/tools.
