// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use alloy_primitives::{
    utils::{parse_ether, parse_units},
    Bytes, B256,
};
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::SolValue;
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
    ComputeInput, ComputeManager, ComputeProvider, FHEInputs, InputPolicy, PublishedData,
};
use e3_support_types::{ComputeDomain, ComputeGuestInput, ComputeJournal};
use e3_user_program::{fhe_processor, policy};
use methods::PROGRAM_ELF;
use risc0_ethereum_contracts::groth16;
use risc0_zkvm::{default_prover, ExecutorEnv, ProverOpts, VerifierContext};
use std::error::Error as _;
use std::time::{Duration, Instant};
use url::Url;

pub struct BoundlessProvider {
    domain: ComputeDomain,
}

#[derive(Debug, Clone)]
pub enum BoundlessOutput {
    Success {
        result: ComputeJournal,
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

/// The compute provider has its own error type; this one is the host's public surface.
///
/// Flattened to a string rather than re-exported so the host's callers do not have to depend on
/// the provider crate to match on a failure.
impl From<e3_compute_provider::ComputeError> for ComputeError {
    fn from(error: e3_compute_provider::ComputeError) -> Self {
        ComputeError::Other(error.to_string())
    }
}

impl ComputeProvider for BoundlessProvider {
    type Output = BoundlessOutput;

    fn prove(&self, input: &ComputeInput, policy: InputPolicy) -> Self::Output {
        let is_dev_mode =
            std::env::var("RISC0_DEV_MODE").unwrap_or_else(|_| "0".to_string()) == "1";

        if is_dev_mode {
            println!("Dev mode: Using fake proof");
            fake_prove(input, &self.domain, policy)
        } else {
            println!("Using Boundless for proving");
            tokio::runtime::Handle::current().block_on(boundless_prove(input, &self.domain))
        }
    }
}

fn encode_journal(result: &ComputeJournal) -> Result<Vec<u8>, Error> {
    Ok(bytemuck::pod_collect_to_vec(&risc0_zkvm::serde::to_vec(
        result,
    )?))
}

fn encode_guest_input(input: &ComputeGuestInput) -> Result<Vec<u8>, Error> {
    // Boundless passes these bytes directly to guest stdin. A RISC Zero serde wrapper would store
    // each bincode byte in a 32-bit word and would add no integrity or decoding guarantee.
    serialize(input).context("Failed to serialize guest input")
}

/// Dev mode: return fake proof without executing
fn fake_prove(
    input: &ComputeInput,
    domain: &ComputeDomain,
    policy: InputPolicy,
) -> BoundlessOutput {
    println!("Generating fake proof for dev mode");

    // Execute the program with the input. The policy is the caller's, so dev mode computes the same
    // result the guest would rather than silently falling back to the default.
    let processed = match input.process(fhe_processor, policy) {
        Ok(processed) => processed,
        Err(error) => return to_output_error(Error::from(error)),
    };

    let result = match ComputeJournal::new(domain.clone(), processed) {
        Ok(result) => result,
        Err(error) => return to_output_error(error),
    };

    let journal_bytes = match encode_journal(&result) {
        Ok(bytes) => bytes,
        Err(error) => return to_output_error(error),
    };

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

/// Read an optional floating-point environment variable.
fn env_opt_f64(key: &str) -> Result<Option<f64>> {
    match std::env::var(key) {
        Ok(value) => Ok(Some(
            value
                .parse()
                .with_context(|| format!("{key} must be a number"))?,
        )),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(error) => Err(error).with_context(|| format!("failed to read {key}")),
    }
}

/// Read an optional whole-second environment variable.
fn env_opt_secs(key: &str) -> Result<Option<u64>> {
    match std::env::var(key) {
        Ok(value) => {
            Ok(Some(value.parse().with_context(|| {
                format!("{key} must be a whole number of seconds")
            })?))
        }
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(error) => Err(error).with_context(|| format!("failed to read {key}")),
    }
}

const DEFAULT_BOUNDLESS_MIN_PRICE_ETH: &str = "0.00005";
const DEFAULT_BOUNDLESS_MAX_PRICE_ETH: &str = "0.004";
const DEFAULT_BOUNDLESS_TIMEOUT_SECS: u64 = 8 * 60 * 60;
const DEFAULT_BOUNDLESS_LOCK_TIMEOUT_SECS: u64 = 4 * 60 * 60;
const DEFAULT_BOUNDLESS_RAMP_UP_SECS: u64 = 2 * 60 * 60;
const DEFAULT_BOUNDLESS_LOCK_COLLATERAL_ZKC: f64 = 100.0;

/// Build the OfferParams from environment variables, using sensible defaults.
fn build_offer() -> Result<OfferParams> {
    build_offer_from_values(
        env_opt_f64("BOUNDLESS_MIN_PRICE_ETH")?,
        env_opt_f64("BOUNDLESS_MAX_PRICE_ETH")?,
        env_opt_secs("BOUNDLESS_TIMEOUT_SECS")?,
        env_opt_secs("BOUNDLESS_LOCK_TIMEOUT_SECS")?,
        env_opt_secs("BOUNDLESS_RAMP_UP_SECS")?,
        env_opt_f64("BOUNDLESS_LOCK_COLLATERAL_ZKC")?,
    )
}

fn build_offer_from_values(
    min_price_eth: Option<f64>,
    max_price_eth: Option<f64>,
    timeout_secs: Option<u64>,
    lock_timeout_secs: Option<u64>,
    ramp_up_secs: Option<u64>,
    lock_collateral_zkc: Option<f64>,
) -> Result<OfferParams> {
    let min_price = if let Some(value) = min_price_eth {
        if value.is_sign_negative() || !value.is_finite() {
            anyhow::bail!(
                "BOUNDLESS_MIN_PRICE_ETH must be a non-negative number, got: {}",
                value
            );
        }
        parse_ether(&value.to_string()).context("Invalid BOUNDLESS_MIN_PRICE_ETH")?
    } else {
        parse_ether(DEFAULT_BOUNDLESS_MIN_PRICE_ETH).context("Invalid default min_price")?
    };
    let max_price = if let Some(value) = max_price_eth {
        if value.is_sign_negative() || !value.is_finite() {
            anyhow::bail!(
                "BOUNDLESS_MAX_PRICE_ETH must be a non-negative number, got: {}",
                value
            );
        }
        parse_ether(&value.to_string()).context("Invalid BOUNDLESS_MAX_PRICE_ETH")?
    } else {
        parse_ether(DEFAULT_BOUNDLESS_MAX_PRICE_ETH).context("Invalid default max_price")?
    };

    if min_price > max_price {
        anyhow::bail!("BOUNDLESS_MIN_PRICE_ETH must not exceed BOUNDLESS_MAX_PRICE_ETH");
    }

    let timeout = u32::try_from(timeout_secs.unwrap_or(DEFAULT_BOUNDLESS_TIMEOUT_SECS))
        .context("BOUNDLESS_TIMEOUT_SECS exceeds the supported range")?;
    let lock_timeout =
        u32::try_from(lock_timeout_secs.unwrap_or(DEFAULT_BOUNDLESS_LOCK_TIMEOUT_SECS))
            .context("BOUNDLESS_LOCK_TIMEOUT_SECS exceeds the supported range")?;
    let ramp_up = u32::try_from(ramp_up_secs.unwrap_or(DEFAULT_BOUNDLESS_RAMP_UP_SECS))
        .context("BOUNDLESS_RAMP_UP_SECS exceeds the supported range")?;

    if lock_timeout == 0 || lock_timeout >= timeout {
        anyhow::bail!("BOUNDLESS_LOCK_TIMEOUT_SECS must be greater than zero and less than BOUNDLESS_TIMEOUT_SECS");
    }
    if ramp_up > lock_timeout {
        anyhow::bail!("BOUNDLESS_RAMP_UP_SECS must not exceed BOUNDLESS_LOCK_TIMEOUT_SECS");
    }

    let zkc = lock_collateral_zkc.unwrap_or(DEFAULT_BOUNDLESS_LOCK_COLLATERAL_ZKC);
    if zkc.is_sign_negative() || !zkc.is_finite() {
        anyhow::bail!(
            "BOUNDLESS_LOCK_COLLATERAL_ZKC must be a non-negative number, got: {}",
            zkc
        );
    }
    let collateral: alloy_primitives::U256 = parse_units(&format!("{}", zkc), 18)
        .context("Invalid BOUNDLESS_LOCK_COLLATERAL_ZKC")?
        .into();

    Ok(OfferParams::builder()
        .min_price(min_price)
        .max_price(max_price)
        .timeout(timeout)
        .lock_timeout(lock_timeout)
        .ramp_up_period(ramp_up)
        .lock_collateral(collateral)
        .into())
}

async fn boundless_prove(input: &ComputeInput, domain: &ComputeDomain) -> BoundlessOutput {
    match boundless_prove_inner(input, domain).await {
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

async fn boundless_prove_inner(
    input: &ComputeInput,
    domain: &ComputeDomain,
) -> Result<BoundlessOutput> {
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

    let guest_input = ComputeGuestInput {
        domain: domain.clone(),
        input: input.clone(),
    };
    let input_bytes = encode_guest_input(&guest_input)?;

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

    let request = request.with_groth16_proof();

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

    let decoded_journal: ComputeJournal = risc0_zkvm::serde::from_slice(&journal)
        .map_err(|e| anyhow::anyhow!("Failed to decode journal: {}", e))?;

    Ok(BoundlessOutput::Success {
        result: decoded_journal,
        bytes: journal.to_vec(),
        seal: fulfillment.seal.to_vec(),
    })
}

pub struct Risc0Provider {
    domain: ComputeDomain,
}

#[derive(Debug, Clone)]
pub struct Risc0Output {
    pub result: ComputeJournal,
    pub bytes: Vec<u8>,
    pub seal: Vec<u8>,
}

impl ComputeProvider for Risc0Provider {
    type Output = Risc0Output;

    fn prove(&self, input: &ComputeInput, _policy: InputPolicy) -> Self::Output {
        // The policy is not forwarded: the guest calls the user program's own `policy()`, so
        // passing one here would let host and guest disagree about the leaves and the selection.
        let guest_input = ComputeGuestInput {
            domain: self.domain.clone(),
            input: input.clone(),
        };
        let encoded_input = encode_guest_input(&guest_input).unwrap();
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

        let decoded_journal: ComputeJournal = receipt.journal.decode().unwrap();

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
    domain: ComputeDomain,
    published: Vec<PublishedData>,
) -> std::result::Result<(BoundlessOutput, Vec<u8>), ComputeError> {
    let boundless_provider = BoundlessProvider { domain };

    // `with_published` rather than `new`: the policy reads this to rebuild the leaves the E3
    // program's contract built. Passing an empty vec is the same as `new`, which is what a program
    // using the default policy wants.
    let mut provider = ComputeManager::with_published(
        boundless_provider,
        params.clone(),
        published,
        fhe_processor,
    );

    // Start timer
    let start_time = Instant::now();

    let output = provider.start(policy())?;

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
    match &output.0 {
        BoundlessOutput::Success { .. } => Ok(output),
        BoundlessOutput::Error { error } => Err(ComputeError::BoundlessFailed(error.clone())),
    }
}

pub fn run_risc0_compute(
    params: FHEInputs,
    domain: ComputeDomain,
    published: Vec<PublishedData>,
) -> std::result::Result<(Risc0Output, Vec<u8>), ComputeError> {
    let risc0_provider = Risc0Provider { domain };

    let mut provider =
        ComputeManager::with_published(risc0_provider, params.clone(), published, fhe_processor);

    Ok(provider.start(policy())?)
}

pub fn encode_compute_proof(
    seal: &[u8],
    result: &ComputeJournal,
) -> std::result::Result<Vec<u8>, ComputeError> {
    if result.params_hash.len() != 32 || result.merkle_root.len() != 32 {
        return Err(ComputeError::Other(
            "Compute journal context must contain two 32-byte values".to_string(),
        ));
    }
    Ok((
        Bytes::copy_from_slice(seal),
        B256::from_slice(&result.params_hash),
        B256::from_slice(&result.merkle_root),
    )
        .abi_encode_params())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bincode::deserialize;
    use risc0_zkvm::sha::{Impl, Sha256};

    fn risc0_vec32(value: &[u8]) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(132);
        encoded.extend_from_slice(&32_u32.to_le_bytes());
        for byte in value {
            encoded.extend_from_slice(&u32::from(*byte).to_le_bytes());
        }
        encoded
    }

    #[test]
    fn boundless_offer_defaults_fit_secure_compute() {
        let offer = build_offer_from_values(None, None, None, None, None, None).unwrap();

        assert_eq!(
            offer.min_price,
            Some(parse_ether(DEFAULT_BOUNDLESS_MIN_PRICE_ETH).unwrap())
        );
        assert_eq!(
            offer.max_price,
            Some(parse_ether(DEFAULT_BOUNDLESS_MAX_PRICE_ETH).unwrap())
        );
        assert_eq!(offer.timeout, Some(DEFAULT_BOUNDLESS_TIMEOUT_SECS as u32));
        assert_eq!(
            offer.lock_timeout,
            Some(DEFAULT_BOUNDLESS_LOCK_TIMEOUT_SECS as u32)
        );
        assert_eq!(
            offer.ramp_up_period,
            Some(DEFAULT_BOUNDLESS_RAMP_UP_SECS as u32)
        );
        assert_eq!(
            offer.lock_collateral,
            Some(parse_units("100", 18).unwrap().into())
        );
    }

    #[test]
    fn boundless_offer_rejects_invalid_deadlines() {
        let error = build_offer_from_values(None, None, Some(60), Some(60), None, None)
            .expect_err("equal lock and total deadlines must fail");

        assert!(error
            .to_string()
            .contains("BOUNDLESS_LOCK_TIMEOUT_SECS must be greater than zero"));
    }

    #[test]
    fn guest_input_uses_direct_bincode() {
        let input = ComputeGuestInput {
            domain: ComputeDomain::new(
                31_337,
                "0x1111111111111111111111111111111111111111",
                "7",
                &[0x22; 32],
                &[0x33; 32],
            )
            .unwrap(),
            input: ComputeInput {
                fhe_inputs: FHEInputs {
                    ciphertexts: vec![(vec![0xaa; 32], 0)],
                    params: vec![0xbb; 16],
                },
                published: vec![PublishedData {
                    commitment: Some([0xcc; 32]),
                    metadata: vec![0xdd; 25],
                }],
            },
        };

        let encoded = encode_guest_input(&input).unwrap();
        let decoded: ComputeGuestInput = deserialize(&encoded).unwrap();
        let legacy: Vec<u8> =
            bytemuck::pod_collect_to_vec(&risc0_zkvm::serde::to_vec(&encoded).unwrap());

        assert_eq!(decoded.domain.e3_id, input.domain.e3_id);
        assert_eq!(
            decoded.input.fhe_inputs.ciphertexts,
            input.input.fhe_inputs.ciphertexts
        );
        assert_eq!(legacy.len(), encoded.len() * 4 + 4);
    }

    #[test]
    fn compute_result_journal_matches_crisp_layout() {
        let domain = ComputeDomain::new(
            31_337,
            "0x1111111111111111111111111111111111111111",
            "7",
            &[0x22; 32],
            &[0x33; 32],
        )
        .unwrap();
        let result = ComputeJournal::new(
            domain,
            e3_compute_provider::ComputeResult {
                ciphertext_hash: (0_u8..32).collect(),
                ciphertext_commitment: (32_u8..64).collect(),
                params_hash: hex::decode(
                    "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
                )
                .unwrap(),
                merkle_root: hex::decode(
                    "2134e76ac5d21aab186c2be1dd8f84ee880a1e46eaf712f9d371b6df22191f3e",
                )
                .unwrap(),
            },
        )
        .unwrap();

        let journal = encode_journal(&result).expect("journal encoding failed");
        let expected = [
            result.chain_id.as_slice(),
            result.verifying_contract.as_slice(),
            result.e3_id.as_slice(),
            result.encryption_scheme_id.as_slice(),
            result.committee_public_key_hash.as_slice(),
            result.ciphertext_hash.as_slice(),
            result.ciphertext_commitment.as_slice(),
            result.params_hash.as_slice(),
            result.merkle_root.as_slice(),
        ]
        .into_iter()
        .flat_map(risc0_vec32)
        .collect::<Vec<_>>();

        assert_eq!(journal.len(), 1188);
        assert_eq!(journal, expected);
        assert_eq!(
            hex::encode(Impl::hash_bytes(&journal).as_bytes()),
            "4403934eb9404372d77f23454aeb4bb7f21bbe856c5c51fc3243f5e05cc2c702"
        );
    }

    #[test]
    fn compute_proof_uses_solidity_parameter_encoding() {
        let result = ComputeJournal {
            chain_id: vec![0; 32],
            verifying_contract: vec![0; 32],
            e3_id: vec![0; 32],
            encryption_scheme_id: vec![0; 32],
            committee_public_key_hash: vec![0; 32],
            ciphertext_hash: vec![0; 32],
            ciphertext_commitment: vec![0; 32],
            params_hash: vec![0x22; 32],
            merkle_root: vec![0x33; 32],
        };

        let encoded = encode_compute_proof(&[0x11; 4], &result).unwrap();
        let (seal, params_hash, input_root) =
            <(Bytes, B256, B256)>::abi_decode_params(&encoded).unwrap();

        assert_eq!(seal.as_ref(), &[0x11; 4]);
        assert_eq!(params_hash, B256::repeat_byte(0x22));
        assert_eq!(input_root, B256::repeat_byte(0x33));
    }
}
