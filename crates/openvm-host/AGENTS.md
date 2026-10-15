# e3-openvm-host

This is the native Secure Process/worker adapter; the separate worker owns OpenVM SDK execution.

- Run the same processor and policy natively and in the guest. The worker must verify against the
  expected domain-bound journal before a seal is accepted; process exit success is not enough.
- Preserve startup artifact checks, absolute worker/config paths, and per-operation deadlines.
  Timeout cleanup must stop the worker rather than leave an unbounded proving process behind.
- Auto backend selection may fall back to CPU after a failed CUDA probe; explicit CUDA must fail if
  unavailable. Never turn resource failure into a mock proof or skip verification.
- Preserve two-pass selected-input ordering and the shared `e3-openvm-types` framing. The host's
  memory usage is not the guest's streaming memory bound.

Run `cargo test --locked -p e3-openvm-host` for worker/config adapter coverage. Real proving, guest
parity, and contract acceptance need the pinned tools/artifacts in the
[OpenVM README](../openvm-prover/README.md); fake worker tests do not validate a receipt.
