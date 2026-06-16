# Polynomial Library

A polynomial library with big integer coefficients designed for cryptographic applications,
particularly lattice-based cryptography and homomorphic encryption schemes.

## Features

- Uses `num-bigint` for coefficient representation.
- Addition, subtraction, multiplication, division reduction modulo cyclotomic polynomials and prime
  moduli.
- Utilities for coefficient range validation.
- Optional serde support for polynomial serialization.

### Mathematical Background

This library implements polynomial arithmetic over the ring of integers, with support for modular
reduction operations commonly used in:

- **Lattice-based cryptography**: Polynomial rings over cyclotomic fields
- **Homomorphic encryption**: BFV, BGV, and CKKS schemes
- **Zero-knowledge proofs**: Polynomial commitment schemes

### Performance

The library is optimized for cryptographic workloads with:

- Efficient coefficient storage and manipulation
- Optimized modular reduction algorithms
- Minimal memory allocations
- Horner's method for polynomial evaluation

## Usage

### Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
polynomial = { git = "https://github.com/gnosisguild/interfold", path = "crates/polynomial" }
```

For serialization support, enable the `serde` feature:

```toml
[dependencies]
polynomial = { git = "https://github.com/gnosisguild/interfold", path = "crates/polynomial", features = ["serde"] }
```

### Testing

Run the test suite:

```bash
cargo test
```

Run tests with verbose output:

```bash
cargo test -- --nocapture
```

### Benchmarks

Run benchmarks:

```bash
cargo bench
```

### Quick Start

```rust
use polynomial::Polynomial;
use num_bigint::BigInt;

// Create polynomials
let poly1 = Polynomial::new(vec![BigInt::from(1), BigInt::from(2), BigInt::from(3)]);
let poly2 = Polynomial::new(vec![BigInt::from(1), BigInt::from(1)]);

// Perform arithmetic
let sum = poly1.add(&poly2);
let product = poly1.mul(&poly2);

// Modular reduction
let modulus = BigInt::from(7);
let reduced = poly1.reduce_and_center(&modulus);

println!("Sum: {}", sum);
println!("Product: {}", product);
println!("Reduced: {}", reduced);
```
