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
- **`BfvPreset::InsecureThreshold512`**: Testing-only threshold BFV parameters (degree 512)
- **`BfvPreset::InsecureDkg512`**: Testing-only DKG parameters (degree 512)

In the PVSS protocol, two types of BFV parameters are needed:

- **Threshold BFV Parameters**: Used for threshold encryption/decryption operations (Phases 2-3-4)
- **DKG Parameters**: Used during Distributed Key Generation (Phases 0-1) for encrypting secret
  shares

### Builder (`builder`)

Functions to construct `BfvParameters` instances:

- `build_bfv_params()` / `build_bfv_params_arc()`: Build from a `BfvParamSet`
- `build_bfv_params_from_set()` / `build_bfv_params_from_set_arc()`: Build from preset metadata
- `build_pair_for_preset()`: Build both threshold and DKG parameter pairs for a preset

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

- **Equation 1**: `2*(B_C + n*B_sm) < Δ` (decryption correctness)
- **Equation 2**: `2*d*n*B ≤ B_Enc * 2^{-λ}` (encryption noise bound)
- **Equation 3**: `B_C ≤ B_sm * 2^{-λ}` (ciphertext noise bound)
- **Equation 4**: `d ≥ 37.5*log2(q/B) + 75` (degree constraint)

#### Search Parameters

The `BfvSearchConfig` struct defines the search constraints:

- **`n`**: Number of parties (ciphernodes)
- **`z`**: Number of votes (also used as plaintext modulus k)
- **`k`**: Plaintext modulus (plaintext space)
- **`lambda`**: Statistical security parameter (negl(λ) = 2^{-λ})
- **`b`**: Bound on error distribution ψ (e.g., 20 for CBD with σ≈3.2)
- **`b_chi`**: Bound on distribution χ used for secret key generation
- **`verbose`**: Enable detailed search process output

The search iterates through polynomial degrees `d` (powers of 2: 1024, 2048, 4096, 8192, 16384,
32768).

#### Search Algorithm

The `bfv_search()` function implements a search algorithm that:

1. Iterates through polynomial degrees `d` (powers of 2)
2. For each `d`, finds the maximum `q` under the Eq4 constraint
3. Validates the candidate against Eq1 (noise bound)
4. Refines the result by decreasing `q` to find minimal valid parameters

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

# Run with default parameters
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

- `--n <N>`: Number of parties (ciphernodes). Default: `1000`
- `--z <Z>`: Number of fresh ciphertext additions (number of votes). Also used as plaintext modulus
  k. Default: `1000`
- `--k <K>`: Plaintext modulus (plaintext space). Default: `1000`
- `--lambda <LAMBDA>`: Statistical security parameter λ (negl(λ) = 2^{-λ}). Default: `80`
- `--b <B>`: Bound on error distribution ψ (e.g., 20 for CBD with σ≈3.2). Default: `20`
- `--b-chi <B_CHI>`: Bound on distribution χ for secret key generation. Default: `1`
- `--verbose`: Enable verbose output showing detailed search process
- `--help`: Show help message
- `--version`: Show version information

**Example: Reproducing Production Preset**

The production preset `SecureThresholdBfv8192` can be reproduced using:

```bash
cargo run --bin search_params --package e3-fhe-params -- \
    --n 100 \
    --z 100 \
    --k 100 \
    --lambda 80 \
    --b 20 \
    --b-chi 1
```

This will output the same parameter set as the preset, including:

- Degree: 8192
- 4 NTT-friendly primes (52-53 bits each)
- All noise budgets and validation metrics
- A second parameter set (if found)

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
