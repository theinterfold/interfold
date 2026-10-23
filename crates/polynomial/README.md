# Integer polynomial arithmetic

## Purpose

This folder is the `e3-polynomial` package. Its child `fhe-adapter/` is the separate
`e3-polynomial-fhe` package. Both are direct members of the root workspace; there is no nested
workspace.

- `e3-polynomial` owns exact signed-integer coefficient arithmetic and CRT limb containers.
  `Polynomial` owns coefficient reversal, reduction, and centering. `CrtPolynomial` delegates these
  transforms to its ordered limbs. Neither type depends on FHE, circuits, or actors.
- `fhe-adapter/` (`e3-polynomial-fhe`) reads fhe.rs polynomials as native ascending coefficients,
  either per CRT limb or reconstructed modulo Q. Import `FromFhePolynomial` to use these
  conversions.

The main consumers construct ZK witnesses. They need integer quotients that modular FHE arithmetic
discards. For example, `div_exact(&q)` returns the coefficient-wise quotient and rejects any nonzero
remainder. Generic polynomial long division is a private test reference, not a public API.

Arithmetic uses descending coefficients. Constructors retain input order and padding; conversion
from fhe.rs retains its native ascending order. Callers reverse coefficients explicitly before
descending-order arithmetic. The optional `serde` feature preserves coefficient and limb shapes.

Circuit-specific reversal, centering, packing, and JSON encoding belong to `e3-zk-witness`. The
adapter performs no witness encoding and exposes no test-only reverse conversion.

Production consumers are ZK circuit computations, runtime proof-input preparation, raw-share
commitment verification, and CRISP ciphertext-addition witnesses. Integer arithmetic belongs below
the ZK layer because these consumers need its exact coefficient values, not a witness encoding API.

Each CRT limb is one residue polynomial for its modulus. The `limbs` field retains its serialized
name, vector order, and coefficient padding. It is not a machine-word representation of one
coefficient.

The circuit-specific `fold_negacyclic` helper belongs to `e3-zk-witness`. It is crate-private and
requires exactly `2N-1` descending coefficients. Scalar residue and inverse operations use
`num_integer::Integer::mod_floor` and `num_bigint::BigInt::modinv` directly.

## Map

| Location                                     | Responsibility                                                                |
| -------------------------------------------- | ----------------------------------------------------------------------------- |
| [`polynomial.rs`](src/polynomial.rs)         | Signed-integer arithmetic, reversal, centering/reduction, and exact division. |
| [`crt_polynomial.rs`](src/crt_polynomial.rs) | Ordered limb operations and per-limb modulus/shape validation.                |
| [`lib.rs`](src/lib.rs)                       | Public types/errors.                                                          |
| [`fhe-adapter/`](fhe-adapter/README.md)      | Separate workspace package for reading FHE representations.                   |

## Usage

```rust
use e3_polynomial::Polynomial;
use num_bigint::BigInt;

let polynomial = Polynomial::new(vec![BigInt::from(6), BigInt::from(4)]);
let quotient = polynomial.div_exact(&BigInt::from(2)).unwrap();
assert_eq!(quotient, Polynomial::new(vec![BigInt::from(3), BigInt::from(2)]));
```

Here the coefficient vector means `6x + 4`; the operation is exact integer division, not division in
an FHE residue ring. Circuit callers add their own order/centering/packing at the next boundary.

## Tests

```bash
cargo test --locked -p e3-polynomial --all-features
```

Tests compare bounded integer multiplication with an independent arithmetic reference and pin signed
division, limb routing, and centering boundaries. ZK folding tests retain an independent test-only
long-division reference. No external chain/proof tooling is required. [AGENTS.md](AGENTS.md) covers
arithmetic/shape changes.
