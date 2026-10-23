# Parity Matrix Library

## Purpose

A library for generating parity matrices for linear subspaces of Z_q^{n+1} consisting of polynomial
evaluations. Designed for cryptographic applications, particularly in homomorphic encryption and
error-correcting codes.

## Map

| Location                                             | Responsibility                                                                                      |
| ---------------------------------------------------- | --------------------------------------------------------------------------------------------------- |
| [`matrix.rs`](src/matrix.rs)                         | Validated matrix types, generator construction, Gaussian elimination/null space, and parity checks. |
| [`math.rs`](src/math.rs)                             | Modular powers/inverses and finite-field arithmetic errors.                                         |
| [`errors.rs`](src/errors.rs), [`lib.rs`](src/lib.rs) | Typed errors and public exports.                                                                    |

The workflow builds the evaluation generator, derives a deterministic null-space basis, and checks
that its product with the generator transpose vanishes. The artifact CLI consumes these rows; this
library does not write Noir configuration files itself.

## Features

- Generator matrix construction for polynomial evaluation subspaces
- Null space computation using Gaussian elimination over finite fields
- Parity matrix verification
- **Type-safe matrix types** with dimension validation at construction
- Support for arbitrary modulus q using `num-bigint`

## Mathematical Background

This library generates parity matrices for the linear subspace of Z_q^{n+1} consisting of polynomial
evaluations of degree at most t at points 0, 1, ..., n.

### Generator Matrix

The generator matrix G has dimensions (t+1) × (n+1), where:

- Each row i corresponds to evaluations of `x^i` at points 0, 1, ..., n
- `G[i][j] = j^i mod q`
- For polynomials of degree t, we have t+1 coefficients (a_0, ..., a_t)

### Parity Matrix

The parity matrix H is the null space of the generator matrix G, satisfying:

- H · G^T = 0 (mod q)
- Dimensions: (n+1 - (t+1)) × (n+1)

### Constraint

The degree t must satisfy: **t ≤ (n-1)/2**

This ensures the subspace has a non-trivial parity check matrix.

## Installation

Inside this workspace, add:

```toml
[dependencies]
e3-parity-matrix = { workspace = true }
```

## Usage

### Library Usage

```rust
use e3_parity_matrix::{ParityMatrixConfig, build_generator_matrix, null_space, verify_parity_matrix};
use num_bigint::BigUint;

// Configure parameters
let config = ParityMatrixConfig {
    q: BigUint::from(101u128),  // Modulus
    t: 4,                        // Polynomial degree
    n: 10,                       // Number of points
};

// Build generator matrix (returns ParityMatrix with validated dimensions)
let g = build_generator_matrix(&config)?;
assert_eq!(g.rows(), 5);  // t+1 = 5
assert_eq!(g.cols(), 11); // n+1 = 11

// Compute parity matrix (null space)
let h = null_space(&g, &config.q)?;

// Verify correctness (dimension compatibility checked automatically)
let is_valid = verify_parity_matrix(&g, &h, &config.q)?;
assert!(is_valid);
```

### Type-Safe Matrix Types

The library provides `ParityMatrix` for type-safe matrix operations with dimension validation:

```rust
use e3_parity_matrix::ParityMatrix;
use num_bigint::BigUint;

// Create a matrix with dimension validation
let data = vec![
    vec![BigUint::from(1u32), BigUint::from(2u32)],
    vec![BigUint::from(3u32), BigUint::from(4u32)],
];
let matrix = ParityMatrix::new(data)?;

// Access dimensions safely
assert_eq!(matrix.rows(), 2);
assert_eq!(matrix.cols(), 2);

// Invalid dimensions are caught at construction
let invalid = vec![
    vec![BigUint::from(1u32), BigUint::from(2u32)],
    vec![BigUint::from(3u32)],  // Wrong length!
];
assert!(ParityMatrix::new(invalid).is_err()); // Dimension mismatch error
```

## Type Safety

The library uses type-safe matrix wrappers (`ParityMatrix`) that:

- **Validate dimensions at construction** - prevents malformed matrices
- **Check dimension compatibility** - operations verify dimensions match
- **Provide clear error messages** - dimension mismatches are caught early with helpful context
- **Enable safe access** - explicit `rows()` and `cols()` methods instead of ambiguous indexing

All matrix operations automatically validate dimension compatibility, preventing common errors like:

- Mismatched matrix dimensions in operations
- Inconsistent row lengths
- Out-of-bounds access patterns

## Testing

From the repository root:

```bash
cargo test --locked -p e3-parity-matrix
```

Run tests with verbose output:

```bash
cargo test --locked -p e3-parity-matrix -- --nocapture
```

Inline `matrix.rs` cases check dimensions, independent parity identities, and rejection of
higher-degree evaluations over small/large fields. `math.rs` covers invertible/noninvertible and
boundary moduli. No FHE runtime or prover is required. Generated-output integration is in the
[circuit builder](../zk/build/README.md); change guidance is in [AGENTS.md](AGENTS.md).

## API Reference

### Matrix Operations

- `build_generator_matrix(config)` - Builds generator matrix G with dimensions (t+1) × (n+1)
- `null_space(matrix, q)` - Computes null space (parity matrix) of a matrix
- `verify_parity_matrix(g, h, q)` - Verifies that H · G^T = 0 (mod q)

### Matrix Types

- `ParityMatrix` - Type-safe matrix wrapper with runtime dimension validation
- `MatrixLike` - Trait for generic matrix operations

All functions return `ParityMatrix` instances with validated dimensions.
