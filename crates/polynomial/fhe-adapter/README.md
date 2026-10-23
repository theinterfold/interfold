# e3-polynomial-fhe

## Purpose

One-way conversion from fhe-math ring polynomials into the parent's exact-integer `Polynomial` /
`CrtPolynomial` types. This is a separate package in the root workspace, not a feature or nested
workspace of `e3-polynomial`.

## Map

[`src/lib.rs`](src/lib.rs) implements two stages: `ToPowerBasisPoly` obtains coefficient form from
supported FHE representations, and `FromFhePolynomial` reads it as separate CRT rows or
reconstructed integers. Destination containers/arithmetic live in the parent package; witness
conventions live in the ZK consumer. This crate has no runtime actors or generation step.

## Conversion API

Import `e3_polynomial_fhe::FromFhePolynomial` and call `Polynomial::from_fhe_polynomial(&poly)` or
`CrtPolynomial::from_fhe_polynomial(&poly)`. Inputs implementing `ToPowerBasisPoly` include
power-basis, NTT, NTT-Shoup, and references to those types. Transformed representations are
converted before coefficients are read.

- `CrtPolynomial` retains separate modulus rows in their original order.
- `Polynomial` reconstructs nonnegative integers modulo the combined coefficient modulus Q.
- Both retain native ascending coefficient order and shape.

The conversion does **not** reverse, center, pack, or encode a circuit witness. Arithmetic in
[e3-polynomial](../README.md) uses descending coefficients, so consumers must explicitly cross that
ordering boundary before arithmetic. [e3-zk-witness](../../zk/witness/README.md) owns the
circuit-specific reversal/centering and witness encoding rather than this generic adapter.

In a workspace package, depend on both `e3-polynomial` and `e3-polynomial-fhe` with
`workspace = true`; import the trait from the latter and destination types from the former. The
[adapter implementation](src/lib.rs) contains the complete supported conversion surface.

## Tests

`cargo test --locked -p e3-polynomial-fhe` compiles this root workspace package and its test target;
it currently has no dedicated tests. Conversion behavior is exercised by
[witness preparation tests](../../zk/witness/README.md#tests), including witness coefficient and
commitment calculations. Parent polynomial tests cover arithmetic, not FHE conversion. See
[AGENTS.md](AGENTS.md) for representation/order changes.
