// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use alloy_primitives::utils::{parse_ether, parse_units};
use alloy_signer_local::PrivateKeySigner;
use anyhow::{Context, Error, Result};
use bincode::serialize;
use boundless_market::{
    client::ClientError,
    contracts::{boundless_market::MarketError, FulfillmentData},
    request_builder::OfferParams,
    storage::storage_provider_from_env,
    Client,
};
use e3_compute_provider::{
    ComputeInput, ComputeManager, ComputeProvider, ComputeResult, FHEInputs,
};
use e3_user_program::fhe_processor;
use methods::PROGRAM_ELF;
use risc0_ethereum_contracts::groth16;
use risc0_zkvm::{default_prover, ExecutorEnv, ProverOpts, VerifierContext};
use std::error::Error as _;
use std::time::{Duration, Instant};
use url::Url;

pub struct BoundlessProvider;

#[derive(Debug, Clone)]
pub enum BoundlessOutput {
    Success {
        result: ComputeResult,
        bytes: Vec<u8>,
        seal: Vec<u8>,
    },
    Error {
        error: String,
    },
}

#[derive(Debug)]
pub enum ComputeError {
    BoundlessFailed(String),
    Other(String),
}

impl ComputeProvider for BoundlessProvider {
    type Output = BoundlessOutput;

    fn prove(&self, input: &ComputeInput) -> Self::Output {
        let is_dev_mode =
            std::env::var("RISC0_DEV_MODE").unwrap_or_else(|_| "0".to_string()) == "1";

        if is_dev_mode {
            println!("Dev mode: Using fake proof");
            fake_prove(input)
        } else {
            println!("Using Boundless for proving");
            tokio::runtime::Handle::current().block_on(boundless_prove(input))
        }
    }
}

fn encode_input(input: &[u8]) -> Result<Vec<u8>, Error> {
    Ok(bytemuck::pod_collect_to_vec(&risc0_zkvm::serde::to_vec(
        input,
    )?))
}

/// Dev mode: return fake proof without executing
fn fake_prove(input: &ComputeInput) -> BoundlessOutput {
    println!("Generating fake proof for dev mode");

    // Execute the program with the input
    let result = input.process(fhe_processor);

    // Serialize the result as journal bytes
    let journal_bytes = bincode::serialize(&result).unwrap_or_default();

    BoundlessOutput::Success {
        result,
        bytes: journal_bytes,
        seal: vec![], // No seal in dev mode
    }
}

fn to_output_error<E: std::fmt::Display>(e: E) -> BoundlessOutput {
    BoundlessOutput::Error {
        error: e.to_string(),
    }
}

/// Read optional environment variable as f64, returning None if unset or invalid.
fn env_opt_f64(key: &str) -> Option<f64> {
    std::env::var(key).ok().and_then(|v| v.parse().ok())
}

/// Read optional environment variable as u64 (seconds), returning None if unset or invalid.
fn env_opt_secs(key: &str) -> Option<u64> {
    std::env::var(key).ok().and_then(|v| v.parse().ok())
}

/// Build the OfferParams from environment variables, using sensible defaults.
fn build_offer() -> Result<OfferParams> {
    let min_price = if let Some(v) = env_opt_f64("BOUNDLESS_MIN_PRICE_ETH") {
        if v.is_sign_negative() || v.is_nan() {
            anyhow::bail!("BOUNDLESS_MIN_PRICE_ETH must be a non-negative number, got: {}", v);
        }
        parse_ether(&format!("{}", v)).context("Invalid BOUNDLESS_MIN_PRICE_ETH")?
    } else {
        parse_ether("0.00005").context("Invalid default min_price")?
    };
    let max_price = if let Some(v) = env_opt_f64("BOUNDLESS_MAX_PRICE_ETH") {
        if v.is_sign_negative() || v.is_nan() {
            anyhow::bail!("BOUNDLESS_MAX_PRICE_ETH must be a non-negative number, got: {}", v);
        }
        parse_ether(&format!("{}", v)).context("Invalid BOUNDLESS_MAX_PRICE_ETH")?
    } else {
        parse_ether("0.002").context("Invalid default max_price")?
    };
    let timeout = env_opt_secs("BOUNDLESS_TIMEOUT_SECS")
        .map(|v| v as u32)
        .unwrap_or(10 * 60);
    let lock_timeout = env_opt_secs("BOUNDLESS_LOCK_TIMEOUT_SECS")
        .map(|v| v as u32)
        .unwrap_or(5 * 60);
    let ramp_up = env_opt_secs("BOUNDLESS_RAMP_UP_SECS")
        .map(|v| v as u32)
        .unwrap_or(1 * 60);
    let zkc = env_opt_f64("BOUNDLESS_LOCK_COLLATERAL_ZKC").unwrap_or(2.0);
    if zkc.is_sign_negative() || zkc.is_nan() {
        anyhow::bail!("BOUNDLESS_LOCK_COLLATERAL_ZKC must be a non-negative number, got: {}", zkc);
    }
    let collateral: alloy_primitives::U256 =
        parse_units(&format!("{}", zkc), 18).context("Invalid BOUNDLESS_LOCK_COLLATERAL_ZKC")?.into();

    Ok(OfferParams::builder()
        .min_price(min_price)
        .max_price(max_price)
        .timeout(timeout)
        .lock_timeout(lock_timeout)
        .ramp_up_period(ramp_up)
        .lock_collateral(collateral)
        .into())
}

async fn boundless_prove(input: &ComputeInput) -> BoundlessOutput {
    match boundless_prove_inner(input).await {
        Ok(output) => output,
        Err(e) => {
            // Print the full error chain so the root cause is visible in logs.
            eprintln!("✗ Boundless proof request FAILED:");
            eprintln!("  Error: {:#}", e);
            let mut source = e.source();
            while let Some(s) = source {
                eprintln!("  Caused by: {}", s);
                source = s.source();
            }
            to_output_error(e)
        }
    }
}

async fn boundless_prove_inner(input: &ComputeInput) -> Result<BoundlessOutput> {
    println!("Submitting proof request to Boundless...");

    let rpc_url = std::env::var("RPC_URL")
        .context("RPC_URL not set")?
        .parse()
        .context("Invalid RPC_URL")?;

    let private_key: PrivateKeySigner = std::env::var("PRIVATE_KEY")
        .context("PRIVATE_KEY not set")?
        .parse()
        .context("Invalid PRIVATE_KEY")?;

    let storage_provider = match storage_provider_from_env() {
        Ok(provider) => Some(provider),
        Err(e) => {
            eprintln!("Warning: Failed to get storage provider: {}", e);
            None
        }
    };

    // Diagnostic: log what we're connecting to (key and API path never logged).
    println!(
        "Boundless client: caller={}, storage_provider={}",
        private_key.address(),
        storage_provider.is_some(),
    );

    let client = Client::builder()
        .with_rpc_url(rpc_url)
        .with_private_key(private_key)
        .with_storage_provider(storage_provider)
        .build()
        .await
        .context("Failed to build Boundless client")?;

    let input_bytes = encode_input(&serialize(input).unwrap()).context("Failed to encode input")?;

    let program_url = std::env::var("PROGRAM_URL").ok();
    let stdin_size = input_bytes.len();

    let request = if let Some(ref url) = program_url {
        println!("Using pre-uploaded program: {}", url);
        let parsed_url = url.parse::<Url>().context("Failed to parse program URL")?;

        client
            .new_request()
            .with_program_url(parsed_url)
            .context("Failed to create new request")?
            .with_stdin(input_bytes)
            .with_offer(build_offer()?)
    } else {
        println!(
            "Warning: Uploading {}MB program at runtime",
            PROGRAM_ELF.len() / 1_000_000
        );
        client
            .new_request()
            .with_program(PROGRAM_ELF)
            .with_stdin(input_bytes)
            .with_offer(build_offer()?)
    };

    let onchain =
        std::env::var("BOUNDLESS_ONCHAIN").unwrap_or_else(|_| "true".to_string()) == "true";

    println!(
        "Boundless submission: onchain={}, program_url={:?}, stdin_size={}",
        onchain, program_url, stdin_size,
    );

    let (request_id, expires_at) = if onchain {
        println!("Building request...");
        let proof_request = match client.build_request(request).await {
            Ok(r) => {
                println!("✓ Request built successfully (id: {:x})", r.id);
                r
            }
            Err(e) => {
                eprintln!("✗ Build request FAILED:");
                eprintln!("  Debug: {:?}", e);
                eprintln!("  Display: {:#}", e);
                let mut source = e.source();
                while let Some(s) = source {
                    eprintln!("  Caused by: {}", s);
                    source = s.source();
                }
                return Err(anyhow::anyhow!("Failed to build request: {:#}", e));
            }
        };

        println!("Submitting onchain (request id: {:x})...", proof_request.id);
        match client.submit_request_onchain(&proof_request).await {
            Ok(result) => {
                println!("✓ Onchain submission successful");
                result
            }
            Err(e) => {
                eprintln!("✗ Onchain submission FAILED:");
                eprintln!("  Display: {:#}", e);
                let mut source = e.source();
                while let Some(s) = source {
                    eprintln!("  Caused by: {}", s);
                    source = s.source();
                }
                return Err(anyhow::anyhow!("Failed to submit onchain: {:#}", e));
            }
        }
    } else {
        println!("Submitting offchain...");
        match client.submit_offchain(request).await {
            Ok(result) => {
                println!("✓ Offchain submission successful");
                result
            }
            Err(e) => {
                eprintln!("✗ Offchain submission FAILED:");
                eprintln!("  Error: {:#}", e);
                let mut source = e.source();
                while let Some(s) = source {
                    eprintln!("  Caused by: {}", s);
                    source = s.source();
                }
                return Err(anyhow::anyhow!("Failed to submit offchain: {:#}", e));
            }
        }
    };

    println!("Request ID: {:x}, waiting for fulfillment...", request_id);

    let fulfillment = match client
        .wait_for_request_fulfillment(request_id, Duration::from_secs(5), expires_at)
        .await
    {
        Ok(fulfillment) => fulfillment,
        Err(ClientError::MarketError(MarketError::RequestHasExpired(_))) => {
            return Ok(BoundlessOutput::Error {
                error: format!(
                    "Boundless request expired: no prover picked up the request. Request ID: {:x}",
                    request_id
                ),
            });
        }
        Err(e) => return Err(e).context("Failed to wait for fulfillment")?,
    };

    println!("Proof received from Boundless!");
    let data = fulfillment.data();
    let (_, journal) = match data {
        Ok(FulfillmentData::ImageIdAndJournal(image_id, journal)) => (image_id, journal),
        _ => {
            return Ok(BoundlessOutput::Error {
                error: "Invalid fulfillment data".to_string(),
            });
        }
    };

    let decoded_journal: ComputeResult = risc0_zkvm::serde::from_slice(&journal)
        .map_err(|e| anyhow::anyhow!("Failed to decode journal: {}", e))?;

    Ok(BoundlessOutput::Success {
        result: decoded_journal,
        bytes: journal.to_vec(),
        seal: fulfillment.seal.to_vec(),
    })
}

pub struct Risc0Provider;

#[derive(Debug, Clone)]
pub struct Risc0Output {
    pub result: ComputeResult,
    pub bytes: Vec<u8>,
    pub seal: Vec<u8>,
}

impl ComputeProvider for Risc0Provider {
    type Output = Risc0Output;

    fn prove(&self, input: &ComputeInput) -> Self::Output {
        let encoded_input = encode_input(&serialize(input).unwrap()).unwrap();
        let env = ExecutorEnv::builder()
            .write_slice(&encoded_input)
            .build()
            .unwrap();

        let receipt = default_prover()
            .prove_with_ctx(
                env,
                &VerifierContext::default(),
                PROGRAM_ELF,
                &ProverOpts::groth16(),
            )
            .unwrap()
            .receipt;

        let decoded_journal = receipt.journal.decode().unwrap();

        // Check if RISC0_DEV_MODE is set to "1" (dev mode)
        // If dev mode: return empty seal (fake proof)
        // Otherwise: return real groth16 proof
        let is_dev_mode = std::env::var("RISC0_DEV_MODE").unwrap_or_default() == "1";

        let seal = if is_dev_mode {
            println!("RISC0_DEV_MODE=1: Using fake proof (empty seal)");
            vec![]
        } else {
            println!("RISC0_DEV_MODE=0 or unset: Generating real Groth16 proof");
            groth16::encode(receipt.inner.groth16().unwrap().seal.clone()).unwrap()
        };

        Risc0Output {
            result: decoded_journal,
            bytes: receipt.journal.bytes.clone(),
            seal,
        }
    }
}

pub fn run_compute(
    params: FHEInputs,
) -> std::result::Result<(BoundlessOutput, Vec<u8>), ComputeError> {
    let boundless_provider = BoundlessProvider;

    let mut provider = ComputeManager::new(
        boundless_provider,
        params.clone(),
        fhe_processor,
        false,
        None,
    );

    // Start timer
    let start_time = Instant::now();

    let output = provider.start();

    // Capture end time and calculate the duration
    let elapsed_time = start_time.elapsed();

    // Convert the elapsed time to minutes and seconds
    let minutes = elapsed_time.as_secs() / 60;
    let seconds = elapsed_time.as_secs() % 60;

    println!(
        "Prove function execution time: {} minutes and {} seconds",
        minutes, seconds
    );

    // Check if the output indicates failure
    match output.0 {
        BoundlessOutput::Success { .. } => Ok(output),
        BoundlessOutput::Error { error } => Err(ComputeError::BoundlessFailed(error)),
    }
}

pub fn run_risc0_compute(
    params: FHEInputs,
) -> std::result::Result<(Risc0Output, Vec<u8>), ComputeError> {
    let risc0_provider = Risc0Provider;

    let mut provider =
        ComputeManager::new(risc0_provider, params.clone(), fhe_processor, false, None);

    let output = provider.start();

    Ok(output)
}
