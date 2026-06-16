# FHE Compute Manager

This project provides a flexible and efficient framework for managing Secure Programs (SP) of the
[Interfold Protocol](interfold.gg). It supports both sequential and parallel processing, with the
ability to integrate various compute providers.

## Features

- Support for both sequential and parallel FHE computations
- Flexible integration of different compute providers
- Merkle tree generation for input verification
- Ciphertext hashing for output verification

## Installation

To use this library, add it to your `Cargo.toml`:

```toml
[dependencies]
e3-compute-provider = { git = "https://github.com/gnosisguild/interfold.git", path = "crates/compute-provider"}
```

## Usage

To use the library, follow these steps:

1. Create an instance of the `ComputeManager` with your desired configuration.
2. Call the `start` method to begin the computation process.
3. The method will return the computed ciphertext and the corresponding proof.

```rust
use anyhow::Result;
use e3_compute_provider::{ComputeInput, ComputeManager, ComputeProvider, ComputeResult, FHEInputs};
use voting_core::fhe_processor;

// Define your Risc0Provider struct and implement the ComputeProvider trait
pub fn run_compute(params: FHEInputs) -> Result<(Risc0Output, Vec<u8>)> {
    let risc0_provider = Risc0Provider;
    let mut provider = ComputeManager::new(risc0_provider, params, fhe_processor, false, None);
    let output = provider.start();
    Ok(output)
}
```

## Risc0 Example

Here's a more detailed example of how to use the Compute Manager with Risc0:

```rust
use e3_compute_provider::{ComputeInput, ComputeManager, ComputeProvider, ComputeResult, FHEInputs};
use methods::VOTING_ELF;
use risc0_ethereum_contracts::groth16;
use risc0_zkvm::{default_prover, ExecutorEnv, ProverOpts, VerifierContext};
use serde::{Deserialize, Serialize};

pub struct Risc0Provider;
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Risc0Output {
    pub result: ComputeResult,
    pub seal: Vec<u8>,
}

impl ComputeProvider for Risc0Provider {
    type Output = Risc0Output;
    fn prove(&self, input: &ComputeInput) -> Self::Output {
        // Implementation details
    }
}
pub fn run_compute(params: FHEInputs) -> Result<(Risc0Output, Vec<u8>)> {
    let risc0_provider = Risc0Provider;
    let mut provider = ComputeManager::new(risc0_provider, params, fhe_processor, false, None);
    let output: (Risc0Output, Vec<u8>) = provider.start();
    Ok(output)
}
```

This example demonstrates how to create a Risc0Provider, use it with the ComputeManager, and measure
the execution time of the computation.

## Configuration

The `ComputeManager::new()` function takes several parameters:

- `provider`: An instance of your compute provider (e.g., `Risc0Provider`)
- `fhe_inputs`: The FHE inputs for the computation
- `fhe_processor`: A function to process the FHE inputs
- `use_parallel`: A boolean indicating whether to use parallel processing
- `batch_size`: An optional batch size for parallel processing, must be a power of 2
