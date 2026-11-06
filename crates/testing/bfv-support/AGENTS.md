# e3-bfv-test-support

Keep only the shared artificial-ballot family here, using the caller's public key/parameters and FHE
primitives. Do not add node, event, prover, EVM, or threshold-share orchestration dependencies. This
package stays unpublished and consumers use dev-dependencies.

Preserve randomized encryption and tally shape. Parameter/codec/commitment rules remain at their
production owners; a fixture must not become a second protocol implementation. Use the
[README tests](README.md#tests); sample encryption is not proof acceptance.
