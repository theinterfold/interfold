# FHE Compute Manager

This project provides a framework for managing Secure Programs (SP) of the
[Interfold Protocol](https://theinterfold.com), with the ability to integrate various compute
providers.

## Features

- Flexible integration of different compute providers
- Merkle tree generation for input verification
- Ciphertext hashing for output verification
- Per-program input policies that decide the leaf layout and which inputs the computation sees

## Installation

To use this library, add it to your `Cargo.toml`:

```toml
[dependencies]
e3-compute-provider = { git = "https://github.com/theinterfold/interfold.git" }
```

## Usage

To use the library, follow these steps:

1. Create an instance of the `ComputeManager` with your compute provider and inputs.
2. Call the `start` method with your E3 program's `InputPolicy`.
3. The method returns the provider output together with the computed ciphertext bytes.

```rust
use e3_compute_provider::{ComputeError, ComputeManager, ComputeProvider, FHEInputs, InputPolicy};
use my_program::fhe_processor;

pub fn run_compute<P>(params: FHEInputs, provider: P) -> Result<(P::Output, Vec<u8>), ComputeError>
where
    P: ComputeProvider + Send + Sync,
{
    let mut manager = ComputeManager::new(provider, params, fhe_processor);
    manager.start(InputPolicy::default())
}
```

`fhe_processor` is your own function. It must match the exported `FHEProcessor` alias,
`fn(FHEProcessorInput) -> Vec<u8>`. The selected ciphertexts arrive one at a time through an
iterator, each with its on-chain index, so a zkVM guest never holds the whole round:

```rust
use e3_compute_provider::FHEProcessorInput;
use fhe::bfv::Ciphertext;
use fhe_traits::{DeserializeParametrized, Serialize};

pub fn fhe_processor(input: FHEProcessorInput<'_>) -> Vec<u8> {
    let mut sum = Ciphertext::zero(input.params);
    for (bytes, _index) in input.ciphertexts {
        sum += &Ciphertext::from_bytes(&bytes, input.params).unwrap();
    }
    sum.to_bytes()
}
```

The processor must read every item. Keep per-input state small: the OpenVM guest has 512 MiB of
memory for the whole computation.

## Input policies

`InputPolicy` carries the two answers that differ between E3 programs:

- `leaf` builds a tree leaf. It must equal what the E3 program builds on chain for the same input.
- `select` chooses which inputs the computation runs over, by index.

Both are plain function pointers, so a policy is a value rather than a trait implementation:

```rust
pub type LeafFn = fn(&PublishedInput) -> Result<String, ComputeError>;
pub type SelectFn = fn(&[InputRecord]) -> Vec<usize>;
```

A leaf is returned as hex, already reduced into the BN254 scalar field. `leaf_from_digest` does that
reduction, so a program hashing its own fields does not restate the modulus:

```rust
use e3_compute_provider::policy::{all_inputs, leaf_from_digest, InputPolicy, PublishedInput};
use e3_compute_provider::ComputeError;
use sha2::{Digest, Sha256};

fn my_leaf(input: &PublishedInput) -> Result<String, ComputeError> {
    let digest = Sha256::digest([&input.ciphertext_hash[..], input.metadata].concat());
    Ok(leaf_from_digest(&digest))
}

pub fn policy() -> InputPolicy {
    InputPolicy {
        leaf: my_leaf,
        select: all_inputs,
    }
}
```

`PublishedInput` carries the input's `index`, its `ciphertext` bytes and their Keccak-256
`ciphertext_hash`, the `commitment` the program stored when it stores one, whatever `metadata` it
published, and `recomputed`, the commitment derived from the bytes. `matches_commitment()` compares
`commitment` against `recomputed`.

`select` receives an `InputRecord` per input: the same fields without the ciphertext bytes. The
Secure Process reads each ciphertext once to build its leaf and does not keep it, so selection works
on what remains. The selected ciphertexts are read again, and each is refused unless it hashes to
the `ciphertext_hash` of its first read.

`InputPolicy::default()` is the behaviour every E3 program had before policies existed. The leaf is
the ciphertext's own SAFE commitment, and every input is computed over. A program whose contract
inserts something else, or that treats a second input from one participant as a replacement,
supplies its own.

A policy cannot supply a root or drop an input from the tree. Every published ciphertext gets a leaf
built from its own bytes, whatever `select` then decides to compute over.

When your E3 program publishes a commitment or other data alongside each ciphertext, build the
manager with `with_published` so the policy can read it:

```rust
let mut manager = ComputeManager::with_published(provider, params, published, fhe_processor);
```

## Implementing a provider

`ComputeProvider` has one method and one associated type. Everything else is yours to choose:

```rust
use e3_compute_provider::{ComputeInput, ComputeProvider, InputPolicy};

pub struct MyProvider;

pub struct MyOutput {
    pub proof: Vec<u8>,
}

impl ComputeProvider for MyProvider {
    type Output = MyOutput;

    fn prove(&self, input: &ComputeInput, policy: InputPolicy) -> Self::Output {
        // Prove that `input` produced its committed result under `policy`, however your
        // backend does that, and return whatever the caller needs.
        MyOutput { proof: Vec::new() }
    }
}
```

`prove` receives the policy rather than choosing one. A prover that picked its own would select a
different input set from the one `start` returned the ciphertext for.

## The Secure Process

`SecureProcess` is the computation every provider must reproduce. It reads a round in two passes:
every ciphertext in index order (`absorb`), then the selected ones again (`select`, then `finish`).
Only one ciphertext is held at a time, which is how the OpenVM guest proves rounds larger than its
memory. `ComputeInput::run` runs the same code over a round held in memory, and
`ComputeInput::run_selected` also returns the indices of the second pass.

The OpenVM provider is `e3-openvm-host`. It runs the program natively, writes the guest's input
stream, and calls the separate `interfold-openvm-prover` worker, which returns a verified EVM
receipt. See `crates/openvm-prover/README.md`.

## Configuration

`ComputeManager::new()` takes three parameters:

- `provider`: An instance of your compute provider (e.g., `MyProvider`)
- `fhe_inputs`: The FHE inputs for the computation
- `fhe_processor`: A function to process the FHE inputs

`ComputeManager::with_published()` takes the same three, plus `published`: one `PublishedData` entry
per ciphertext, in the same order as `fhe_inputs.ciphertexts`.
