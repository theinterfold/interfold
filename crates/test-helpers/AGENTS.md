# e3-test-helpers

Keep reusable fixtures and low-level harness adapters here; complete multi-node composition belongs
in `e3-tests` to avoid dragging the builder back into lower-level tests.

- Never add an `e3-ciphernode-builder` dependency here: owner tests already depend on helpers and
  can create cycles through event-system. Use its public lower-level composition boundaries.
- Isolate event buses and derive separate RNG mutexes per simulated node. Cloning one shared RNG
  serializes worker execution and can make concurrency tests accidentally test a single lock.
- Mock libp2p/application outputs model transport/computation, not peer authorization or proof
  validity. Assert the actual owner boundary rather than promoting helpers to protocol policy.
- Tool discovery can permit a test to skip when bb/Anvil is absent. Report skips explicitly;
  successful helper initialization is not evidence that a real proof or chain test executed.

Run `cargo test --locked -p e3-test-helpers` after root `pnpm evm:build` / `pnpm fixtures:build`
preparation, with solc/jq and Anvil for chain paths. Transitive prover build side effects are
documented in [zk-prover](../zk-prover/AGENTS.md); integration scenarios belong in
[e3-tests](../tests/AGENTS.md).
