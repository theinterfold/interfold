# interfold-openvm-prover

This worker is an excluded, independent Cargo workspace. It deliberately isolates the OpenVM SDK and
CPU/CUDA proving process from the root runtime; see [README.md](README.md) for setup and usage.

- Use the README's pinned Rust/OpenVM tools and setup artifacts. Root `cargo -p` cannot select this
  package. Keep CPU and CUDA target directories separate; CUDA needs the toolkit/driver at
  build/run.
- Configuration binds application/executable commitments, aggregation keys, verifier artifact, and
  checksums. A matching file checksum alone is not proof of trusted setup or guest compatibility.
- Preserve exact host/guest journal verification before writing a seal, including existing-proof
  verification. `execute` checks guest parity without proving and must not be reported as a proof.
- Keep bounded artifact/input reads, checked item framing, and fail-closed GPU probing. Do not make
  a CUDA/resource error select unproved execution.

Use the [README worker tests/prerequisites](README.md#tests). Real receipt changes require the
prepared proof/contract flow, not just worker unit tests; see
[encrypted computation](../../docs/architecture/encrypted-computation.md).
