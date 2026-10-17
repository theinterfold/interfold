# FHE Parameters Library

A Rust library for managing BFV (Brakerski-Fan-Vercauteren) homomorphic encryption parameters. This
library provides preset configurations, parameter builders, and a search module for finding optimal
parameters that satisfy security constraints.

**Key Features:**

- **Preset Configurations**: Pre-configured BFV parameters for common use cases (secure/insecure,
  threshold/DKG)
- **Parameter Builders**: Functions to construct `BfvParameters` from presets or custom parameter
  sets
- **Parameter Search**: Algorithm to find optimal BFV parameters using NTT-friendly primes with
  exact arithmetic
- **CLI Tool**: Command-line interface for searching and validating BFV parameters interactively
- **ABI Encoding**: Optional Solidity ABI encoding/decoding for smart contract integration

## Overview

The `fhe-params` crate provides a complete solution for managing BFV parameters in the Interfold FHE
system. It supports two main workflows:

1. **Using Presets**: Quick access to pre-validated parameter sets for production or testing
2. **Custom Search**: Finding optimal parameters for specific security and performance requirements

## Modules

### Presets (`presets`)

Pre-configured BFV parameter sets for PVSS (Public Verifiable Secret Sharing) protocol:

- **`BfvPreset::SecureThreshold8192`** (default): Production-ready threshold BFV parameters
  (degree 8192)
- **`BfvPreset::SecureDkg8192`**: Production-ready DKG parameters (degree 8192)
- **`BfvPreset::InsecureThreshold64`**: Testing-only threshold BFV parameters (degree 64)
- **`BfvPreset::InsecureDkg64`**: Testing-only DKG parameters (degree 64)

In the PVSS protocol, two types of BFV parameters are needed:

- **Threshold BFV Parameters**: Used for threshold encryption/decryption operations (Phases 2-3-4)
- **DKG Parameters**: Used during Distributed Key Generation (Phases 0-1) for encrypting secret
  shares

### Builder (`builder`)

Functions to construct `BfvParameters` instances:

- `build_bfv_params()` / `build_bfv_params_arc()`: Build from a `BfvParamSet`
- `build_bfv_params_from_set()` / `build_bfv_params_from_set_arc()`: Build from preset metadata
- `build_pair_for_preset()`: Build both threshold and DKG parameter pairs for a preset

### Parameter utilities (`utils`)

This module owns centered Q residues, `k0_i`, and coefficient widths. Bound widths borrow unsigned
integers and use at least one bit. BFV callers borrow Q from the full level-zero context; C7
computes its Q inverse with `BigUint::modinv`. Callers use standard integer operations for division
and residues. Parameter search computes both with `Integer::div_rem`; plaintext moduli retain their
full `u128` precision. Plaintext decoding uses `fhe_traits::FheDecoder` directly; it is not
parameter-derived arithmetic.

Centered Q residues use the caller's reduced residue and retain the full positive `u64` modulus
domain. They use arbitrary-precision floor-modulus arithmetic, not the FHE primitive's restricted
62-bit constructor. This scalar derivation does not depend on polynomial coefficient transforms.

### Search (`search`)

A comprehensive module for searching optimal BFV parameters that satisfy security constraints.

#### Overview

The search module implements exact arithmetic using `BigUint` for precise security analysis. It
searches through NTT-friendly primes (40-63 bits) to find parameter sets that satisfy multiple
security equations.

The library implements security analysis from:

- https://eprint.iacr.org/2024/1285.pdf (BFV security)

#### Security Constraints

The search validates four key security equations:

- **Equation 1**: `2*(B_C + n*B_sm) < Δ` (decryption correctness). With `mult_depth > 0`, `B_C` is
  the noise after the multiplications (below), and `B_sm` follows from it.
- **Equation 2**: `2*d*n*B ≤ B_Enc * 2^{-λ}` (encryption noise bound)
- **Equation 3**: `B_sm = 2^{λ+1} * d * B_C` (smudging noise bound, the same bound that fhe.rs and
  the C1 circuit config use)
- **Equation 4**: `log2(q) ≤ max_log2_q(d)` (RLWE security). For B = 20 and B_χ = 1,
  `search::security` holds the largest log2(q) with at least 128 bits of security at each
  d = 4096 ... 32768. The values come from the lattice-estimator. For other B, B_χ or d, the search
  uses `d ≥ 37.5*log2(q/B) + 75` and the CLI prints a warning. That formula allows 5 to 9 more bits
  of q than the estimator.

#### Search Parameters

The `BfvSearchConfig` struct defines the search constraints:

- **`n`**: Number of parties (ciphernodes)
- **`z`**: Number of votes (also used as plaintext modulus k)
- **`k`**: Plaintext modulus (plaintext space)
- **`lambda`**: Statistical security parameter (negl(λ) = 2^{-λ})
- **`b`**: Bound on error distribution ψ (e.g., 20 for CBD with σ≈3.2)
- **`b_chi`**: Bound on distribution χ used for secret key generation
- **`min_margin`**: Minimum correctness margin in bits, `log2(Δ) - log2(LHS)`
- **`d`**: Ring dimension. `None` searches d = 8192, 16384 and 32768
- **`insecure`**: Skip the security limit (Eq4). Only for insecure test presets
- **`min_prime_bits`**: Smallest prime bit-length for both parameter sets (10 to 60)
- **`mult_depth`**: Levels of multiplication and relinearization after the `z` additions. `0` is
  summation only
- **`verbose`**: Enable detailed search process output

Without `d`, the search tries d = 8192, 16384 and 32768 in that order. For d ≥ 8192 it uses the
prime table (primes ≡ 1 mod 16384, filtered to ≡ 1 mod 2d). For a smaller d it generates the
largest NTT-friendly primes of each bit-length with fhe-math.

#### Multiplication

The circuit is `z` fresh ciphertexts added together, then `mult_depth` levels of multiplication and
relinearization. Each level applies the Prop. 20 recursion
`B_C(i+1) = 2·k·d²·‖sk‖·B_C(i) + B_relin`, with `‖sk‖ = n·B_χ`. The relinearization noise is
Eq. 30, `d·l·‖sk‖·B_g·B_agg + 2·d²·l²·‖sk‖²·B_g·B_agg`, where `l` is the number of moduli,
`B_g` is the largest modulus (RNS gadget base), and `B_agg = n·B` because the n ciphernodes make
the relinearization key together. Additions after a multiplication are not in this model.

```bash
# 3 additions, then depth 3: 5 × 59-bit primes at d = 16384
cargo run --bin search_params --package e3-fhe-params -- \
    --n 20 --k 1000 --z 3 --mult-depth 3 --lambda 50
```

#### Search Algorithm

The `bfv_search()` function implements a search algorithm that:

1. Iterates through polynomial degrees `d` (powers of 2), or uses the given `d`
2. Tries 3 to 6 primes, and for each count the prime bit-lengths from `min_prime_bits` up to 60
3. In each bit-length, takes the largest primes whose product q is under the Eq4 limit
4. Validates that q against Eq1 (noise bound). If it fails, moves to the next bit-length

Returns the first feasible parameter set found, or an error if none exist.

**Note**: Some resulting parameter sets from this search are hardcoded as presets in the
`presets.rs` file for production use (e.g., `BfvPreset::SecureThreshold8192`).

#### Search Result

The `BfvSearchResult` contains:

- **`d`**: Chosen degree
- **`q_bfv`**: Ciphertext modulus (product of selected primes)
- **`selected_primes`**: NTT-friendly primes used
- **`qi_values()`**: Prime values as `Vec<u64>` for BFV parameter construction
- **Noise budgets**: `b_enc_min`, `b_fresh`, `b_c`, `b_sm_min`
- **Validation logs**: `lhs_log2`, `rhs_log2` for equation satisfaction details

### Encoding (`encoding`) - Optional Feature

When the `abi-encoding` feature is enabled, provides functions for encoding/decoding BFV parameters
using Solidity ABI format:

- `encode_bfv_params()`: Encode parameters to ABI bytes
- `decode_bfv_params()` / `decode_bfv_params_arc()`: Decode ABI bytes to parameters

This enables serialization for smart contracts and cross-platform parameter exchange.

## Usage

### Using Presets

```rust
use e3_fhe_params::{BfvPreset, build_bfv_params_arc, builder::build_pair_for_preset};
use std::sync::Arc;

fn example() -> Result<(), e3_fhe_params::PresetError> {
    // Build threshold BFV parameters
    let params = build_bfv_params_arc(BfvPreset::SecureThreshold8192)?;

    // Build both threshold and DKG parameter pairs
    let (threshold_params, dkg_params) = build_pair_for_preset(BfvPreset::SecureThreshold8192)?;

    Ok(())
}
```

### Custom Parameter Sets

```rust
use e3_fhe_params::{BfvParamSet, build_bfv_params_from_set_arc};

let param_set = BfvParamSet {
    degree: 8192,
    plaintext_modulus: 100,
    moduli: &[0x0008000000820001, 0x0010000000060001],
    error1_variance: Some("3"),
};

let params = build_bfv_params_from_set_arc(&param_set)?;
```

### Parameter Search

#### Using the Library

```rust
use e3_fhe_params::search::bfv::{BfvSearchConfig, bfv_search};

let config = BfvSearchConfig {
    n: 100,           // Number of parties
    z: 1000,          // Number of votes
    k: 1000,          // Plaintext modulus
    lambda: 80,      // Security parameter
    b: 20,            // Error bound
    b_chi: 1,         // Secret key bound
    min_margin: 2.0,  // Correctness margin in bits
    verbose: true,    // Show detailed output
};

match bfv_search(&config) {
    Ok(result) => {
        println!("Found parameters with degree: {}", result.d);
        println!("Ciphertext modulus: {}", result.q_bfv);
        println!("Primes: {:?}", result.qi_values());
    }
    Err(e) => {
        eprintln!("Search failed: {}", e);
    }
}
```

#### Using the CLI Tool

The crate includes a command-line tool `search_params` for searching BFV parameters interactively:

```bash
# Build the binary
cargo build --bin search_params --package e3-fhe-params

# Run with default parameters (the SecureThreshold8192 search inputs)
cargo run --bin search_params --package e3-fhe-params

# Run with custom parameters
cargo run --bin search_params --package e3-fhe-params -- \
    --n 100 \
    --z 100 \
    --k 100 \
    --lambda 80 \
    --b 20 \
    --b-chi 1

# Enable verbose output to see the search process
cargo run --bin search_params --package e3-fhe-params -- \
    --n 100 --z 100 --k 100 --lambda 80 --verbose
```

**CLI Options:**

The defaults are the search inputs of `SecureThreshold8192` (`constants::search_defaults`).

- `--n <N>`: Number of parties (ciphernodes). Default: `20`
- `--z <Z>`: Number of fresh ciphertext additions (number of votes). The search uses
  `max(k, z)` as the plaintext modulus. Default: `100000`
- `--k <K>`: Plaintext modulus (plaintext space). Default: `17000000`
- `--lambda <LAMBDA>`: Statistical security parameter λ (negl(λ) = 2^{-λ}). Default: `45`
- `--b <B>`: Bound on error distribution ψ (e.g., 20 for CBD with σ≈3.2). Default: `20`
- `--b-chi <B_CHI>`: Bound on distribution χ for secret key generation. Default: `1`
- `--min-margin <BITS>`: Minimum correctness margin in bits. Default: `2`
- `--d <D>`: Ring dimension (power of two). Default: try 8192, 16384 and 32768
- `--insecure <true|false>`: Skip the security limit. Use only for insecure test presets.
  Default: `false`
- `--min-prime-bits <BITS>`: Smallest prime bit-length for both parameter sets. Default: `50`
- `--mult-depth <D>`: Levels of multiplication after the `z` additions. Default: `0`
- `--verbose`: Enable verbose output showing detailed search process
- `--help`: Show help message
- `--version`: Show version information

**Example: Reproducing Production Preset**

A run with the defaults gives the `SecureThreshold8192` preset as the first set and the
`SecureDkg8192` preset as the second set:

```bash
cargo run --bin search_params --package e3-fhe-params
```

- Degree: 8192
- First set: 3 NTT-friendly 60-bit primes, `ERROR1_VARIANCE` from `Var(e_1)`
- Second set: 2 NTT-friendly 62-bit primes, plaintext modulus = largest first-set prime
- All noise budgets and validation metrics

The insecure presets `InsecureThreshold64` and `InsecureDkg64` come from the insecure search
inputs (`constants::insecure_search_defaults`, λ = 2) at d = 64:

```bash
cargo run --bin search_params --package e3-fhe-params -- \
    --n 19 --lambda 2 --d 64 --insecure true --min-prime-bits 12
```

The tests `search_reproduces_secure_presets` and `search_reproduces_insecure_presets` keep the
search and the preset constants in sync.

**Output Format:**

The CLI displays:

- **First BFV Parameter Set**: The main threshold encryption parameters with all noise budgets
- **Second BFV Parameter Set**: Additional parameters for simpler conditions (if found)
- Distribution types (CBD/Uniform) and variance values for error bounds
- Complete parameter details including moduli, noise budgets, and validation metrics

### ABI Encoding/Decoding

```rust
#[cfg(feature = "abi-encoding")]
use e3_fhe_params::{BfvPreset, build_bfv_params_arc, encode_bfv_params, decode_bfv_params, decode_bfv_params_arc};

// Build parameters from a preset
let params = build_bfv_params_arc(BfvPreset::SecureThreshold8192)?;

// Encode parameters to ABI bytes for smart contract use
let encoded_bytes = encode_bfv_params(&params);

// Decode back to parameters
let decoded_params = decode_bfv_params(&encoded_bytes)?;

// Or decode directly to Arc for thread-safe shared ownership
let decoded_params_arc = decode_bfv_params_arc(&encoded_bytes)?;

// Verify roundtrip
assert_eq!(decoded_params.degree(), params.degree());
assert_eq!(decoded_params.plaintext(), params.plaintext());
assert_eq!(decoded_params.moduli(), params.moduli());
```
