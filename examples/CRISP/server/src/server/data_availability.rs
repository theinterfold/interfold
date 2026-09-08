// SPDX-License-Identifier: LGPL-3.0-only

//! Persistent publication jobs for CRISP's large encrypted objects.

use crate::{
    config::Config,
    server::models::{canonical_e3_id, e3_id_to_u256},
};
use alloy::{
    eips::{BlockId, BlockNumberOrTag},
    primitives::{keccak256, Address, Bytes, B256, U256},
    providers::{Provider, ProviderBuilder},
    signers::{local::PrivateKeySigner, SignerSync},
    sol,
    sol_types::SolValue,
};
use e3_bfv_client::client::compute_ct_commitment_with_params;
use e3_data_availability::{
    AvailPublisher, AvailReader, DataAvailabilityPublisher, DataAvailabilityReader, DataReference,
    PendingPublication, ProofStatus,
};
use e3_evm_helpers::contracts::{E3Stage, InterfoldContractFactory, InterfoldRead, InterfoldWrite};
use e3_fhe_params::{build_bfv_params_from_set_arc, encode_bfv_params, BfvParamSet, BfvPreset};
use evm_helpers::{CRISPContract, InputPublished, SimulateError};
use fhe::bfv::BfvParameters;
use serde::{Deserialize, Serialize};
use sled::{transaction::Transactional, Db, Tree};
use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, LazyLock, Mutex as StorageMutex},
    time::Duration,
};
use tokio::{sync::Semaphore, task::JoinSet};
use tracing::warn;

const JOB_POLL_INTERVAL: Duration = Duration::from_secs(30);
// An Avail submission can use 20 seconds to connect, 30 seconds to submit, 300 seconds to
// finalize, and 30 seconds to read its events. Keep the outer bound above those inner bounds.
const JOB_STEP_TIMEOUT: Duration = Duration::from_secs(480);
const JOB_STATUS_REFRESH_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_CONCURRENT_JOB_STEPS: usize = 4;
// Deserialization and the SAFE commitment are real processor work, and intake is a public
// endpoint. Keep this below the job-step bound: a validation holds one processor for the
// complete calculation, while a job step usually waits for a network answer.
const MAX_CONCURRENT_CIPHERTEXT_VALIDATIONS: usize = 2;
const AVAILABILITY_JOB_SCHEMA_VERSION: u32 = 1;
const AVAILABLE_INPUT_REFERENCE_SCHEMA_VERSION: u32 = 1;

/// Bounds the intake ciphertext validations that can run at the same time.
///
/// Process-wide, because the limit protects the processor, and one process can serve more than
/// one round.
static CIPHERTEXT_VALIDATION_SLOTS: LazyLock<Semaphore> =
    LazyLock::new(|| Semaphore::new(MAX_CONCURRENT_CIPHERTEXT_VALIDATIONS));

/// BFV parameter tables and their circuit configuration identifier, by parameter-set index.
///
/// The secure tables are expensive to build and a parameter set has one fixed content, so they
/// are built one time and shared by every later validation.
static BFV_PARAMETERS_BY_PARAM_SET: LazyLock<
    StorageMutex<HashMap<u8, (Arc<BfvParameters>, B256)>>,
> = LazyLock::new(|| StorageMutex::new(HashMap::new()));

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
struct InputRejected(&'static str);

fn reject_input(message: &'static str) -> anyhow::Error {
    anyhow::Error::new(InputRejected(message))
}

fn duration_u64(value: U256, name: &str) -> anyhow::Result<u64> {
    value
        .try_into()
        .map_err(|_| anyhow::anyhow!("{name} does not fit in u64"))
}

fn minimum_input_duration(
    randomness_window: u64,
    sortition_window: u64,
    dkg_window: u64,
    voting_window: u64,
    finalization_window: u64,
) -> anyhow::Result<u64> {
    randomness_window
        .checked_add(sortition_window)
        .and_then(|value| value.checked_add(dkg_window))
        .and_then(|value| value.checked_add(voting_window))
        .and_then(|value| value.checked_add(finalization_window))
        .ok_or_else(|| anyhow::anyhow!("required CRISP input duration overflows u64"))
}

/// Return a stable client message only when the caller's ballot was conclusively rejected.
pub fn input_rejection_message(error: &anyhow::Error) -> Option<&'static str> {
    for cause in error.chain() {
        if let Some(rejection) = cause.downcast_ref::<InputRejected>() {
            return Some(rejection.0);
        }
        if matches!(
            cause.downcast_ref::<SimulateError>(),
            Some(SimulateError::Reverted(_))
        ) {
            return Some("The vote proof or ciphertext was rejected");
        }
    }
    None
}

/// The circuit configuration identifier that Interfold binds to a parameter set at request time.
///
/// `InterfoldLifecycle.validateQuoteLimit` compares the requester's `expectedCryptoConfigId`
/// against `ActiveCryptoConfig.configIdForParamSet(paramSet)`, and `Interfold.request` stores that
/// accepted value in `e3CryptoConfigIds`. This function derives the same identifier from the local
/// parameter tables, so a comparison against the stored value proves that these tables are the
/// request-time parameters.
fn crypto_config_id_for_params(params: &BfvParameters) -> B256 {
    keccak256(
        (
            keccak256(b"fhe.rs:BFV"),
            keccak256(encode_bfv_params(params)),
            keccak256(b"interfold-bfv-v1"),
        )
            .abi_encode(),
    )
}

/// Build the BFV parameter tables for one on-chain parameter set, one time per process.
///
/// The secure tables are large, and every input of one round uses the same tables. The cache
/// keeps intake from rebuilding them for each ballot.
fn bfv_parameters_for_param_set(param_set: u8) -> anyhow::Result<(Arc<BfvParameters>, B256)> {
    if let Some(cached) = BFV_PARAMETERS_BY_PARAM_SET
        .lock()
        .map_err(|_| anyhow::anyhow!("BFV parameter cache lock is poisoned"))?
        .get(&param_set)
    {
        return Ok(cached.clone());
    }
    let preset = BfvPreset::from_on_chain_param_set(param_set)
        .ok_or_else(|| anyhow::anyhow!("unsupported BFV parameter set {param_set}"))?;
    let params = build_bfv_params_from_set_arc(BfvParamSet::from(preset));
    let config_id = crypto_config_id_for_params(&params);
    let entry = (params, config_id);
    // The lock is released while the tables are built, so two callers can miss the cache at the
    // same time. Keep whichever entry arrives first and return that one, or the second insert
    // replaces tables the first caller already holds and every later caller rebuilds them.
    Ok(BFV_PARAMETERS_BY_PARAM_SET
        .lock()
        .map_err(|_| anyhow::anyhow!("BFV parameter cache lock is poisoned"))?
        .entry(param_set)
        .or_insert(entry)
        .clone())
}

/// Recompute the SAFE commitment of `ciphertext` and compare it with `expected`.
///
/// This is the processor-intensive part of intake validation, so the caller must already hold a
/// validation slot. `compute_ct_commitment_with_params` deserializes the bytes with the given
/// parameters and refuses a ciphertext that does not have exactly two components, which keeps the
/// commitment in agreement with the Noir circuit.
fn ciphertext_matches_commitment(
    ciphertext: &[u8],
    expected: B256,
    params: &Arc<BfvParameters>,
) -> bool {
    compute_ct_commitment_with_params(ciphertext, params)
        .is_ok_and(|recomputed| recomputed == expected.0)
}

sol! {
    struct InputEnvelope {
        bytes noirProof;
        address slotAddress;
        bytes32 encryptedVoteCommitment;
        bytes32 encryptedVoteHash;
        uint40 parentIndexPlusOne;
        bytes availabilityProof;
    }

    struct InputCommitmentEnvelope {
        bytes noirProof;
        address slotAddress;
        bytes32 encryptedVoteCommitment;
        bytes32 encryptedVoteHash;
        uint40 parentIndexPlusOne;
        uint64 availabilityAttestationExpiresAt;
        bytes availabilityAttestation;
    }

    enum StoredE3Stage {
        None,
        Requested,
        CommitteeFinalized,
        KeyPublished,
        CiphertextReady,
        Complete,
        Failed
    }

    #[sol(rpc)]
    interface ICrispAvailabilityState {
        function isInputCommitted(
            uint256 e3Id,
            bytes32 encryptedVoteHash,
            bytes32 commitment,
            address slotAddress,
            uint40 parentIndexPlusOne
        ) external view returns (bool);
        function isInputPublished(
            uint256 e3Id,
            bytes32 encryptedVoteHash,
            bytes32 commitment,
            address slotAddress,
            uint40 parentIndexPlusOne
        ) external view returns (bool);
    }

    #[sol(rpc)]
    interface IInterfoldAvailabilityState {
        function getE3Stage(uint256 e3Id) external view returns (StoredE3Stage);
    }
}

fn decode_input_envelope(encoded: &[u8]) -> anyhow::Result<InputEnvelope> {
    Ok(InputEnvelope::abi_decode_params_validate(encoded)?)
}

fn encode_input_commitment_envelope(envelope: &InputCommitmentEnvelope) -> Vec<u8> {
    envelope.abi_encode_params()
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum JobKind {
    Input {
        e3_id: String,
        staged_envelope: Vec<u8>,
        deadline: u64,
        commitment_deadline: u64,
    },
    Output {
        e3_id: String,
        ciphertext_commitment: [u8; 32],
        compute_proof: Vec<u8>,
        deadline: u64,
    },
}

const fn no_deadline() -> u64 {
    u64::MAX
}

impl JobKind {
    fn deadline(&self) -> u64 {
        match self {
            Self::Input { deadline, .. } | Self::Output { deadline, .. } => *deadline,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum JobState {
    Created,
    AwaitingCommitment {
        ethereum_payload: Vec<u8>,
        #[serde(default)]
        attestation_expires_at: u64,
    },
    Committed {
        transaction_hash: String,
    },
    AwaitingProof {
        publication: PendingPublication,
        commitment_transaction_hash: Option<String>,
    },
    Ready {
        ethereum_payload: Vec<u8>,
        commitment_transaction_hash: Option<String>,
        /// The Avail coordinates that produced this candidate proof.
        ///
        /// A candidate proof is not proof that Ethereum accepts it: the bridge API answer is
        /// checked for the expected content hash, not for a valid Merkle path. Keep the
        /// coordinates so a refused candidate can be replaced by a fresh proof for bytes that
        /// Avail already holds. `None` decodes a record written before this field existed. Such
        /// a job keeps its candidate proof and has no automatic replacement path.
        #[serde(default)]
        publication: Option<PendingPublication>,
    },
    /// A publication transaction is on Ethereum but is not yet in finalized state.
    ///
    /// Retiring a job clears its recovery material and can delete the local object, so a job
    /// stops only on a finalized observation. The submitted transaction is recorded so a job
    /// that waits for finality is not sent a second time. The payload and the Avail coordinates
    /// stay durable, so an orphaned transaction can be sent again.
    AwaitingFinality {
        transaction_hash: String,
        ethereum_payload: Vec<u8>,
        commitment_transaction_hash: Option<String>,
        #[serde(default)]
        publication: Option<PendingPublication>,
    },
    Submitted {
        transaction_hash: String,
    },
    Failed {
        message: String,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct AvailabilityJob {
    schema_version: u32,
    id: String,
    content_hash: [u8; 32],
    kind: JobKind,
    state: JobState,
}

#[derive(Clone, Debug, Serialize)]
pub struct AvailabilityJobView {
    pub job_id: String,
    pub status: String,
    pub tx_hash: Option<String>,
    pub encoded_proof: Option<String>,
    pub message: Option<String>,
}

/// The result of one `stage_input` call, and what it did with the funding window.
///
/// The route reserves relay funding before it stages, and must keep that reservation only when
/// this call created durable work that can spend the funds. A repeat of a statement that already
/// has a job spends nothing, so its reservation goes back to the window immediately.
pub struct StagedInput {
    pub view: AvailabilityJobView,
    /// True when this call created durable work that can spend relay funds.
    pub admitted: bool,
}

impl StagedInput {
    fn admitted(view: AvailabilityJobView) -> Self {
        Self {
            view,
            admitted: true,
        }
    }

    fn existing(view: AvailabilityJobView) -> Self {
        Self {
            view,
            admitted: false,
        }
    }
}

/// Durable work item created when Ethereum accepts an input reference.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AvailableInputReference {
    schema_version: u32,
    pub e3_id: String,
    pub content_hash: [u8; 32],
    pub availability_block: u32,
    pub availability_leaf_index: u128,
    pub index: u64,
    pub commitment: [u8; 32],
    pub slot: [u8; 20],
    pub parent_index_plus_one: u64,
}

impl AvailableInputReference {
    pub fn from_event(e3_id: String, event: &InputPublished) -> Self {
        Self {
            schema_version: AVAILABLE_INPUT_REFERENCE_SCHEMA_VERSION,
            e3_id,
            content_hash: event.encryptedVoteHash.0,
            availability_block: event.availabilityBlock,
            availability_leaf_index: event.availabilityLeafIndex,
            index: event.index.to::<u64>(),
            commitment: event.encryptedVoteCommitment.0,
            slot: event.slotAddress.into(),
            parent_index_plus_one: event.parentIndexPlusOne.to::<u64>(),
        }
    }

    fn validate_schema(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.schema_version == AVAILABLE_INPUT_REFERENCE_SCHEMA_VERSION,
            "unsupported available-input reference schema version {}; expected {}",
            self.schema_version,
            AVAILABLE_INPUT_REFERENCE_SCHEMA_VERSION
        );
        Ok(())
    }

    fn key(&self) -> String {
        format!("{}:{}", self.e3_id, self.index)
    }

    pub fn data_reference(&self) -> DataReference {
        DataReference {
            content_hash: self.content_hash,
            block_number: self.availability_block,
            leaf_index: self.availability_leaf_index,
        }
    }
}

impl From<&AvailabilityJob> for AvailabilityJobView {
    fn from(job: &AvailabilityJob) -> Self {
        let (status, tx_hash, encoded_proof, message) = match &job.state {
            JobState::AwaitingCommitment {
                ethereum_payload, ..
            } => (
                "ready_for_commitment",
                None,
                Some(format!("0x{}", hex::encode(ethereum_payload))),
                None,
            ),
            JobState::Created => ("pending_commitment", None, None, None),
            JobState::Committed { transaction_hash } => (
                "pending_availability",
                Some(transaction_hash.clone()),
                None,
                None,
            ),
            JobState::AwaitingProof {
                commitment_transaction_hash,
                ..
            }
            | JobState::Ready {
                commitment_transaction_hash,
                ..
            } => (
                "pending_availability",
                commitment_transaction_hash.clone(),
                None,
                None,
            ),
            // A publication that waits for finality is still pending work for the client: the
            // transaction can be orphaned, and the job then sends it again.
            JobState::AwaitingFinality {
                transaction_hash, ..
            } => (
                "pending_availability",
                Some(transaction_hash.clone()),
                None,
                None,
            ),
            JobState::Submitted { transaction_hash } => (
                "success",
                (transaction_hash != "already-finalized").then(|| transaction_hash.clone()),
                None,
                None,
            ),
            JobState::Failed { message } => ("failed_broadcast", None, None, Some(message.clone())),
        };
        Self {
            job_id: job.id.clone(),
            status: status.to_owned(),
            tx_hash,
            encoded_proof,
            message,
        }
    }
}

enum Backend {
    Mock,
    Avail {
        publisher: Arc<AvailPublisher>,
        reader: Arc<AvailReader>,
    },
}

/// Owns persistent publication state and resumes incomplete jobs after restart.
#[derive(Clone)]
pub struct AvailabilityService {
    jobs: Tree,
    objects: Tree,
    input_retrievals: Tree,
    backend: Arc<Backend>,
    in_progress: Arc<StorageMutex<HashSet<String>>>,
    storage: Arc<StorageMutex<()>>,
    job_slots: Arc<Semaphore>,
    chain_id: u64,
    http_rpc_url: String,
    private_key: String,
    interfold_address: String,
    e3_program_address: String,
    ciphernode_registry_address: String,
    input_duration_seconds: u64,
    proof_lead_seconds: u64,
    max_pending_bytes: u64,
}

struct ActiveJobGuard<'a> {
    jobs: &'a StorageMutex<HashSet<String>>,
    id: &'a str,
}

impl Drop for ActiveJobGuard<'_> {
    fn drop(&mut self) {
        self.jobs
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(self.id);
    }
}

impl AvailabilityService {
    pub fn new(db: &Db, config: &Config) -> anyhow::Result<Self> {
        let mode = config.data_availability_mode();
        let backend = match mode.as_str() {
            "mock" => Backend::Mock,
            "avail" => {
                let rpc_url = config
                    .avail_rpc_url
                    .as_deref()
                    .ok_or_else(|| anyhow::anyhow!("AVAIL_RPC_URL is required"))?;
                Backend::Avail {
                    publisher: Arc::new(AvailPublisher::new(
                        rpc_url,
                        config
                            .avail_app_id
                            .ok_or_else(|| anyhow::anyhow!("AVAIL_APP_ID is required"))?,
                        config
                            .avail_seed
                            .as_deref()
                            .ok_or_else(|| anyhow::anyhow!("AVAIL_SEED is required"))?,
                        config
                            .avail_bridge_api_url
                            .as_deref()
                            .ok_or_else(|| anyhow::anyhow!("AVAIL_BRIDGE_API_URL is required"))?,
                        config.chain_id,
                    )?),
                    reader: Arc::new(AvailReader::new(rpc_url)?),
                }
            }
            other => anyhow::bail!("unsupported DATA_AVAILABILITY_MODE '{other}'"),
        };
        let service = Self {
            jobs: db.open_tree("data-availability-jobs")?,
            objects: db.open_tree("data-availability-objects")?,
            input_retrievals: db.open_tree("data-availability-input-retrievals")?,
            backend: Arc::new(backend),
            in_progress: Arc::new(StorageMutex::new(HashSet::new())),
            storage: Arc::new(StorageMutex::new(())),
            job_slots: Arc::new(Semaphore::new(MAX_CONCURRENT_JOB_STEPS)),
            chain_id: config.chain_id,
            http_rpc_url: config.http_rpc_url.clone(),
            private_key: config.private_key.clone(),
            interfold_address: config.interfold_address.clone(),
            e3_program_address: config.e3_program_address.clone(),
            ciphernode_registry_address: config.ciphernode_registry_address.clone(),
            input_duration_seconds: config.e3_duration,
            proof_lead_seconds: config.avail_proof_lead_seconds.unwrap_or(10_800),
            max_pending_bytes: config.data_availability_max_pending_bytes,
        };
        service.validate_storage()?;
        Ok(service)
    }

    /// Check local timing against the current registry, Interfold, and CRISP contract values.
    pub async fn validate_onchain_configuration(&self) -> anyhow::Result<()> {
        if !matches!(&*self.backend, Backend::Avail { .. }) {
            return Ok(());
        }
        let contract = CRISPContract::new(
            &self.http_rpc_url,
            &self.private_key,
            &self.e3_program_address,
        )
        .await
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        let onchain = duration_u64(
            contract
                .availability_finalization_window()
                .await
                .map_err(|error| anyhow::anyhow!(error.to_string()))?,
            "CRISP finalization window",
        )?;
        anyhow::ensure!(
            onchain == self.proof_lead_seconds,
            "AVAIL_PROOF_LEAD_SECONDS ({}) does not match CRISPProgram.availabilityFinalizationWindow() ({onchain})",
            self.proof_lead_seconds
        );

        let registry: Address = self
            .ciphernode_registry_address
            .parse()
            .map_err(|error| anyhow::anyhow!("invalid ciphernode registry address: {error}"))?;
        let (randomness, sortition) = contract
            .committee_setup_windows(registry)
            .await
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        let interfold =
            InterfoldContractFactory::create_read(&self.http_rpc_url, &self.interfold_address)
                .await
                .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        let timeouts = interfold
            .get_timeout_config()
            .await
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        let voting = contract
            .minimum_voting_duration()
            .await
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        let required = minimum_input_duration(
            duration_u64(randomness, "randomness request timeout")?,
            duration_u64(sortition, "sortition submission window")?,
            duration_u64(timeouts.dkgWindow, "DKG window")?,
            duration_u64(voting, "minimum voting duration")?,
            onchain,
        )?;
        anyhow::ensure!(
            self.input_duration_seconds >= required,
            "E3_DURATION ({}) is shorter than the current on-chain committee, voting, and availability windows ({required})",
            self.input_duration_seconds
        );
        Ok(())
    }

    /// Check that the submitted bytes reproduce the commitment their ballot proof binds.
    ///
    /// The Honk public inputs bind `encryptedVoteCommitment`, the ballot digest, and the slot and
    /// parent context. They do not bind `encryptedVoteHash`. A caller can therefore copy a valid
    /// proof tuple, attach different bytes with their matching hash, and get a different job
    /// identifier, input identifier, and tree leaf without a new ballot proof. Each such
    /// submission makes the service issue an attestation and pay for Avail publication, Ethereum
    /// finalization, storage, and a worker slot for a ciphertext that the Secure Process always
    /// rejects.
    ///
    /// Votes, updates, and masks get the same check. The three operations prove one relation and
    /// use one request format, so a special case for masks would make them different on chain.
    ///
    /// This check is intake only. A job that is already committed keeps its recovery work, because
    /// its pending status still needs DA finalization.
    async fn validate_input_ciphertext(
        &self,
        e3_id: &str,
        ciphertext: &[u8],
        commitment: B256,
    ) -> anyhow::Result<()> {
        let interfold =
            InterfoldContractFactory::create_read(&self.http_rpc_url, &self.interfold_address)
                .await
                .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        let e3_id_value =
            e3_id_to_u256(e3_id).map_err(|_| reject_input("The E3 identifier is invalid"))?;
        let e3 = interfold
            .get_e3(e3_id_value)
            .await
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        let (params, config_id) = bfv_parameters_for_param_set(e3.paramSet)?;
        // Use the local tables only when they are the tables the request accepted. Otherwise a
        // recomputed commitment answers for a different parameter set and rejects honest ballots.
        let request_config_id = interfold
            .get_e3_crypto_config_id(e3_id_value)
            .await
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        anyhow::ensure!(
            request_config_id == config_id,
            "local BFV parameters do not match the request-time configuration for E3 {e3_id}"
        );

        // Bound the processor work at this public endpoint. The calculation also runs on a
        // blocking thread, because it uses milliseconds of processor time and must not hold the
        // asynchronous runtime.
        let _validation_slot = CIPHERTEXT_VALIDATION_SLOTS
            .acquire()
            .await
            .map_err(|_| anyhow::anyhow!("the ciphertext validation limiter is closed"))?;
        let ciphertext = ciphertext.to_vec();
        let matches = tokio::task::spawn_blocking(move || {
            ciphertext_matches_commitment(&ciphertext, commitment, &params)
        })
        .await
        .map_err(|error| anyhow::anyhow!("ciphertext validation did not finish: {error}"))?;
        if !matches {
            return Err(reject_input(
                "The encrypted vote does not match its proved commitment",
            ));
        }
        Ok(())
    }

    /// Derive the durable job identity for one input statement.
    ///
    /// This does the checks that need no chain access: envelope decoding, the object bound, and
    /// the content hash. Both the idempotent replay path and admission use it, so both agree on
    /// what "the same statement" means.
    fn input_identity(
        &self,
        e3_id: &str,
        encoded_envelope: &[u8],
    ) -> anyhow::Result<(String, InputEnvelope, B256, String)> {
        let canonical =
            canonical_e3_id(e3_id).map_err(|_| reject_input("The E3 identifier is invalid"))?;
        let envelope = decode_input_envelope(encoded_envelope)
            .map_err(|_| reject_input("The encoded vote envelope is invalid"))?;
        e3_data_availability::validate_object_bytes(&envelope.availabilityProof)
            .map_err(|_| reject_input("The encrypted vote is too large"))?;
        let actual = keccak256(&envelope.availabilityProof);
        if actual != envelope.encryptedVoteHash {
            return Err(reject_input(
                "The encrypted vote does not match its committed hash",
            ));
        }

        // A proof system can produce more than one valid proof for the same public statement.
        // Keep the durable job keyed by that statement, not by the proof bytes, or retrying with
        // another valid proof can buy the same Avail publication twice.
        let request_identity = (
            envelope.slotAddress,
            envelope.encryptedVoteCommitment,
            envelope.parentIndexPlusOne,
        )
            .abi_encode();
        let id = self.job_id(b"input", &canonical, actual, &request_identity)?;
        Ok((canonical, envelope, actual, id))
    }

    /// Return the view of an existing non-failed job for this statement, if there is one.
    ///
    /// A repeat of a statement that already has durable work is idempotent: it creates no job,
    /// signs no new attestation, and pays for no publication. The route therefore answers it
    /// without taking a funding reservation. Charging a replay would let one caller spend the
    /// window that new votes need, and near the commitment cutoff that is a denial of service.
    /// The caller traffic window still applies, so a replay loop is still bounded.
    pub async fn existing_input_job(
        &self,
        e3_id: &str,
        encoded_envelope: &[u8],
    ) -> anyhow::Result<Option<AvailabilityJobView>> {
        let (_, _, _, id) = self.input_identity(e3_id, encoded_envelope)?;
        if self.load(&id)?.is_none() {
            return Ok(None);
        }
        self.process(&id).await;
        let existing = self.load_required(&id)?;
        if matches!(&existing.state, JobState::Failed { .. }) {
            // A failed job is restarted under the same identifier, which creates a fresh funding
            // obligation. That path must take a reservation.
            return Ok(None);
        }
        Ok(Some((&existing).into()))
    }

    pub async fn stage_input(
        &self,
        e3_id: &str,
        encoded_envelope: Vec<u8>,
    ) -> anyhow::Result<StagedInput> {
        // The numeric parser accepts leading zeros, so two different strings can name the same E3.
        // Canonicalize before the identifier reaches a job ID, a durable record, or a contract
        // call. Otherwise an alias creates a second durable job for one statement.
        let (canonical_e3_id, mut envelope, actual, id) =
            self.input_identity(e3_id, &encoded_envelope)?;
        let e3_id = &canonical_e3_id;
        let object = envelope.availabilityProof.to_vec();

        if self.load(&id)?.is_some() {
            self.process(&id).await;
            let existing = self.load_required(&id)?;
            if !matches!(&existing.state, JobState::Failed { .. }) {
                return Ok(StagedInput::existing((&existing).into()));
            }
        }

        // Reject invalid Noir proofs before the service pays an Avail submission fee.
        let contract = CRISPContract::new(
            &self.http_rpc_url,
            &self.private_key,
            &self.e3_program_address,
        )
        .await
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        contract
            .validate_input_proof(
                e3_id_to_u256(e3_id).map_err(|_| reject_input("The E3 identifier is invalid"))?,
                envelope.noirProof.clone(),
                envelope.slotAddress,
                envelope.encryptedVoteCommitment,
                envelope.encryptedVoteHash,
                envelope.parentIndexPlusOne.to::<u64>(),
            )
            .await?;

        // The proof binds the commitment, not the bytes. Check the bytes against that commitment
        // before this service attests to them or spends funds on their publication.
        self.validate_input_ciphertext(e3_id, &object, envelope.encryptedVoteCommitment)
            .await?;

        let (deadline, commitment_deadline) = if matches!(&*self.backend, Backend::Avail { .. }) {
            let interfold =
                InterfoldContractFactory::create_read(&self.http_rpc_url, &self.interfold_address)
                    .await
                    .map_err(|error| anyhow::anyhow!(error.to_string()))?;
            let e3_id_value =
                e3_id_to_u256(e3_id).map_err(|_| reject_input("The E3 identifier is invalid"))?;
            let e3 = interfold
                .get_e3(e3_id_value)
                .await
                .map_err(|error| anyhow::anyhow!(error.to_string()))?;
            let now = self.chain_timestamp().await?;
            let input_deadline: u64 = e3.inputWindow[1]
                .try_into()
                .map_err(|_| anyhow::anyhow!("input deadline does not fit in u64"))?;
            let deadline: u64 = interfold
                .get_deadlines(e3_id_value)
                .await
                .map_err(|error| anyhow::anyhow!(error.to_string()))?
                .computeDeadline
                .try_into()
                .map_err(|_| anyhow::anyhow!("compute deadline does not fit in u64"))?;
            let commitment_deadline = contract
                .input_commitment_deadline(e3_id_value)
                .await
                .map_err(|error| anyhow::anyhow!(error.to_string()))?;
            if commitment_deadline <= now {
                return Err(reject_input("The vote commitment deadline has passed"));
            }
            anyhow::ensure!(
                input_deadline.saturating_sub(commitment_deadline) >= self.proof_lead_seconds,
                "the CRISP finalization tail is shorter than AVAIL_PROOF_LEAD_SECONDS"
            );
            (deadline, commitment_deadline)
        } else {
            (no_deadline(), no_deadline())
        };

        // The object has its own content-addressed record. Do not duplicate it inside the job or
        // its staged ABI envelope.
        envelope.availabilityProof = Bytes::new();
        let staged_envelope = envelope.abi_encode_params();
        let job = AvailabilityJob {
            schema_version: AVAILABILITY_JOB_SCHEMA_VERSION,
            id: id.clone(),
            content_hash: actual.0,
            kind: JobKind::Input {
                e3_id: e3_id.to_owned(),
                staged_envelope,
                deadline,
                commitment_deadline,
            },
            state: JobState::Created,
        };
        if let Some(existing) = self.admit_input(&job, &object)? {
            // A concurrent request admitted the same statement first. Only one of the two
            // reservations funds durable work, so this one goes back to the window.
            return Ok(StagedInput::existing(existing));
        }
        self.process(&id).await;
        if matches!(&*self.backend, Backend::Mock) {
            // Local mode has no external finality delay. Drive every durable phase so callers
            // keep the synchronous developer experience while production remains asynchronous.
            self.process(&id).await;
            self.process(&id).await;
            self.process(&id).await;
        }
        Ok(StagedInput::admitted((&self.load_required(&id)?).into()))
    }

    pub async fn stage_output(
        &self,
        e3_id: &str,
        ciphertext: Vec<u8>,
        ciphertext_commitment: [u8; 32],
        compute_proof: Vec<u8>,
    ) -> anyhow::Result<AvailabilityJobView> {
        // `/state/add-result` is unauthenticated and the numeric parser accepts leading zeros.
        // Canonicalize the identifier at entry so every alias of one E3 resolves to one job ID,
        // one durable record, and one paid Avail publication.
        let e3_id = &canonical_e3_id(e3_id)?;
        e3_data_availability::validate_object_bytes(&ciphertext)?;
        let hash = keccak256(&ciphertext);
        // The output statement is the E3, exact ciphertext hash, and ciphertext commitment. The
        // RISC Zero seal proves that statement but is not its identity: another valid seal must be
        // an idempotent retry, not another paid Avail publication.
        let id = self.job_id(b"output", e3_id, hash, &ciphertext_commitment)?;
        if let Some(job) = self.load(&id)? {
            return Ok((&job).into());
        }
        let deadline = if matches!(&*self.backend, Backend::Avail { .. }) {
            let interfold =
                InterfoldContractFactory::create_read(&self.http_rpc_url, &self.interfold_address)
                    .await
                    .map_err(|error| anyhow::anyhow!(error.to_string()))?;
            let e3_id_value = e3_id_to_u256(e3_id)?;
            anyhow::ensure!(
                interfold
                    .get_e3_stage(e3_id_value)
                    .await
                    .map_err(|error| anyhow::anyhow!(error.to_string()))?
                    == E3Stage::KeyPublished,
                "the E3 is not accepting an aggregate ciphertext"
            );
            let e3 = interfold
                .get_e3(e3_id_value)
                .await
                .map_err(|error| anyhow::anyhow!(error.to_string()))?;
            let deadlines = interfold
                .get_deadlines(e3_id_value)
                .await
                .map_err(|error| anyhow::anyhow!(error.to_string()))?;
            let deadline: u64 = deadlines
                .computeDeadline
                .try_into()
                .map_err(|_| anyhow::anyhow!("compute deadline does not fit in u64"))?;
            let now = self.chain_timestamp().await?;
            let input_deadline: u64 = e3.inputWindow[1]
                .try_into()
                .map_err(|_| anyhow::anyhow!("input deadline does not fit in u64"))?;
            anyhow::ensure!(
                now >= input_deadline,
                "the input window is still open; the aggregate proof could become stale"
            );
            anyhow::ensure!(
                deadline > now.saturating_add(self.proof_lead_seconds),
                "the compute deadline arrives before VectorX can safely prove this publication"
            );
            deadline
        } else {
            no_deadline()
        };

        // `/state/add-result` is reachable over HTTP. Do not let an arbitrary caller spend the
        // Avail signer balance: first execute the exact CRISP proof check that Interfold will use
        // once the VectorX receipt exists. Invalid output never becomes durable work.
        let contract = CRISPContract::new(
            &self.http_rpc_url,
            &self.private_key,
            &self.e3_program_address,
        )
        .await
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        contract
            .validate_compute_output(
                e3_id_to_u256(e3_id)?,
                hash,
                B256::from(ciphertext_commitment),
                Bytes::copy_from_slice(&compute_proof),
            )
            .await
            .map_err(|error| {
                anyhow::anyhow!("the aggregate ciphertext proof is not acceptable: {error}")
            })?;

        let job = AvailabilityJob {
            schema_version: AVAILABILITY_JOB_SCHEMA_VERSION,
            id: id.clone(),
            content_hash: hash.0,
            kind: JobKind::Output {
                e3_id: e3_id.to_owned(),
                ciphertext_commitment,
                compute_proof,
                deadline,
            },
            state: JobState::Created,
        };
        {
            let _storage = self
                .storage
                .lock()
                .map_err(|_| anyhow::anyhow!("data-availability storage lock is poisoned"))?;
            if let Some(job) = self.load(&id)? {
                return Ok((&job).into());
            }
            self.store_new_job_with_object(&job, &ciphertext)?;
        }
        if matches!(&*self.backend, Backend::Mock) {
            self.process(&id).await;
            self.process(&id).await;
        }
        Ok((&self.load_required(&id)?).into())
    }

    /// Read a job after reconciling wallet-submitted work with Ethereum.
    ///
    /// A browser can close after its input commitment is mined but before the background worker
    /// observes it. On reload, returning the cached `AwaitingCommitment` state would offer the same
    /// transaction again. This bounded read checks the one relevant on-chain fact first. A slow RPC
    /// does not make the status endpoint unavailable; the durable worker still retries normally.
    ///
    /// The refresh takes the same per-job ownership as the worker. Both paths load a copy, await
    /// an Ethereum read, and then save, so without one owner a status refresh can save a state it
    /// loaded before the worker made durable progress, and that stale write can discard saved
    /// Avail coordinates and buy another publication. A request that finds the job busy returns
    /// the persisted view and writes nothing.
    pub async fn refreshed_view(&self, id: &str) -> anyhow::Result<Option<AvailabilityJobView>> {
        let Some(job) = self.load(id)? else {
            return Ok(None);
        };
        if matches!(
            &job.state,
            JobState::Submitted { .. } | JobState::Failed { .. }
        ) {
            return Ok(Some((&job).into()));
        }

        let Some(_active_job) = self.claim_job(id) else {
            return Ok(Some((&job).into()));
        };
        // Load again under ownership: the copy above can already be stale.
        let Some(mut job) = self.load(id)? else {
            return Ok(None);
        };
        if matches!(
            &job.state,
            JobState::Submitted { .. } | JobState::Failed { .. }
        ) {
            return Ok(Some((&job).into()));
        }

        let refresh = async {
            if matches!(&job.state, JobState::AwaitingCommitment { .. }) {
                // A commitment observed at the chain head can still be reorganized out. Advance
                // only on finalized state: `Committed` starts the paid Avail publication, and an
                // orphaned commitment would leave the attestation unrenewable.
                let (finalized_block, _) = self.finalized_block().await?;
                if self.input_is_committed_at(&job, finalized_block).await? {
                    job.state = JobState::Committed {
                        transaction_hash: "wallet-committed".to_owned(),
                    };
                    self.save(&job)?;
                }
            } else if self.publication_is_final(&job).await? {
                job.state = JobState::Submitted {
                    transaction_hash: "already-finalized".to_owned(),
                };
                self.save(&job)?;
            }
            anyhow::Ok(())
        };

        match tokio::time::timeout(JOB_STATUS_REFRESH_TIMEOUT, refresh).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                warn!(job_id = id, %error, "Could not refresh availability job from Ethereum")
            }
            Err(_) => warn!(
                job_id = id,
                "Timed out while refreshing availability job from Ethereum"
            ),
        }

        Ok(Some((&job).into()))
    }

    pub fn object(&self, hash: &str) -> anyhow::Result<Option<Vec<u8>>> {
        let hash = hash.strip_prefix("0x").unwrap_or(hash);
        let key = hex::decode(hash)?;
        Ok(self.objects.get(key)?.map(|value| value.to_vec()))
    }

    fn object_required(&self, content_hash: [u8; 32]) -> anyhow::Result<Vec<u8>> {
        self.objects
            .get(content_hash)?
            .map(|bytes| bytes.to_vec())
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "data-availability object 0x{} is missing",
                    hex::encode(content_hash)
                )
            })
    }

    #[cfg(test)]
    fn store_object(&self, content_hash: [u8; 32], object: &[u8]) -> anyhow::Result<()> {
        anyhow::ensure!(
            keccak256(object).0 == content_hash,
            "data-availability object does not match its content hash"
        );
        if let Some(existing) = self.objects.get(content_hash)? {
            anyhow::ensure!(
                existing.as_ref() == object,
                "stored data-availability object does not match its content hash"
            );
            return Ok(());
        }

        let used = self.objects.iter().try_fold(0u64, |used, entry| {
            let (_, value) = entry?;
            used.checked_add(value.len() as u64)
                .ok_or_else(|| sled::Error::Unsupported("availability byte count overflow".into()))
        })?;
        let required = used
            .checked_add(object.len() as u64)
            .ok_or_else(|| anyhow::anyhow!("data-availability byte count overflows u64"))?;
        anyhow::ensure!(
            required <= self.max_pending_bytes,
            "data-availability pending storage is full; configured limit is {} bytes",
            self.max_pending_bytes
        );

        self.objects.insert(content_hash, object)?;
        self.objects.flush()?;
        Ok(())
    }

    /// Store a new object's bytes and recovery job as one durable admission.
    ///
    /// A job without its object cannot progress, while an object without a job consumes the
    /// bounded pending-storage allowance forever. One sled transaction prevents either partial
    /// state after a process or machine crash.
    fn store_new_job_with_object(
        &self,
        job: &AvailabilityJob,
        object: &[u8],
    ) -> anyhow::Result<()> {
        Self::validate_job_schema(job)?;
        anyhow::ensure!(
            matches!(job.state, JobState::Created),
            "a new data-availability admission must start in the created state"
        );
        anyhow::ensure!(
            keccak256(object).0 == job.content_hash,
            "data-availability object does not match its content hash"
        );

        let existing = self.objects.get(job.content_hash)?;
        if let Some(existing) = &existing {
            anyhow::ensure!(
                existing.as_ref() == object,
                "stored data-availability object does not match its content hash"
            );
        }

        let used = self.objects.iter().try_fold(0u64, |used, entry| {
            let (_, value) = entry?;
            used.checked_add(value.len() as u64)
                .ok_or_else(|| sled::Error::Unsupported("availability byte count overflow".into()))
        })?;
        let additional = if existing.is_some() {
            0
        } else {
            object.len() as u64
        };
        let required = used
            .checked_add(additional)
            .ok_or_else(|| anyhow::anyhow!("data-availability byte count overflows u64"))?;
        anyhow::ensure!(
            required <= self.max_pending_bytes,
            "data-availability pending storage is full; configured limit is {} bytes",
            self.max_pending_bytes
        );

        let encoded_job = serde_json::to_vec(job)?;
        (&self.objects, &self.jobs).transaction(|(objects, jobs)| {
            if let Some(stored) = jobs.get(job.id.as_bytes())? {
                let stored = Self::decode_job(&stored).map_err(|error| {
                    sled::transaction::ConflictableTransactionError::Abort(
                        sled::Error::Unsupported(error.to_string()),
                    )
                })?;
                if stored.content_hash != job.content_hash {
                    return Err(sled::transaction::ConflictableTransactionError::Abort(
                        sled::Error::Unsupported(
                            "data-availability job ID is bound to another content hash".into(),
                        ),
                    ));
                }
                if matches!(&stored.state, JobState::Failed { .. }) {
                    if objects.get(job.content_hash)?.is_none() {
                        objects.insert(job.content_hash.as_slice(), object)?;
                    }
                    jobs.insert(job.id.as_bytes(), encoded_job.as_slice())?;
                    return Ok(());
                }
                if objects.get(job.content_hash)?.is_none() {
                    return Err(sled::transaction::ConflictableTransactionError::Abort(
                        sled::Error::Unsupported(
                            "data-availability job exists without its object".into(),
                        ),
                    ));
                }
                return Ok(());
            }

            if objects.get(job.content_hash)?.is_none() {
                objects.insert(job.content_hash.as_slice(), object)?;
            }
            jobs.insert(job.id.as_bytes(), encoded_job.as_slice())?;
            Ok(())
        })?;
        self.objects.flush()?;
        self.jobs.flush()?;
        Ok(())
    }

    /// Admit one input statement, or return the view of an equal statement already accepted.
    ///
    /// Admission is per statement, not per target slot. CRISP lets any account produce a valid
    /// mask for an eligible slot without that slot owner's signature, so a per-slot reservation
    /// would let one caller hold an attestation, withhold its Ethereum commitment, and stop the
    /// slot owner from getting an attestation for a different statement. Each distinct statement
    /// therefore gets its own durable job, and the bounded object storage, the caller rate limits,
    /// and the proof and deadline checks stay as the only limits on new work.
    ///
    /// Admission does not change retention: an earlier attested job keeps its own job record, and
    /// `save` releases object bytes only when no other non-terminal job uses them.
    fn admit_input(
        &self,
        job: &AvailabilityJob,
        object: &[u8],
    ) -> anyhow::Result<Option<AvailabilityJobView>> {
        // Serialize admission so concurrent requests cannot both pass the capacity check.
        let _storage = self
            .storage
            .lock()
            .map_err(|_| anyhow::anyhow!("data-availability storage lock is poisoned"))?;
        if let Some(existing) = self.load(&job.id)? {
            if !matches!(&existing.state, JobState::Failed { .. }) {
                return Ok(Some((&existing).into()));
            }
        }
        // Persist the bytes and their recovery job atomically before an attestation can be
        // returned. The signature promises that this service received the exact object and can
        // resume after a restart.
        self.store_new_job_with_object(job, object)?;
        Ok(None)
    }

    /// Retrieve bytes named by a receipt that the Ethereum contract already accepted.
    pub async fn retrieve(&self, reference: DataReference) -> anyhow::Result<Vec<u8>> {
        if let Some(bytes) = self
            .objects
            .get(reference.content_hash)?
            .map(|value| value.to_vec())
        {
            return e3_data_availability::verify_retrieved_bytes(reference, bytes);
        }

        match &*self.backend {
            Backend::Mock => anyhow::bail!(
                "local data-availability object 0x{} is not stored",
                hex::encode(reference.content_hash)
            ),
            // The round repository stores a retrieved input. Do not also retain a second cache in
            // the availability tree. Avail remains the source if recovery needs the object again.
            Backend::Avail { reader, .. } => Ok(reader.retrieve(reference).await?),
        }
    }

    pub fn record_input_reference(
        &self,
        reference: &AvailableInputReference,
    ) -> anyhow::Result<()> {
        reference.validate_schema()?;
        self.input_retrievals
            .insert(reference.key(), serde_json::to_vec(reference)?)?;
        self.input_retrievals.flush()?;
        Ok(())
    }

    pub fn pending_input_references(&self) -> anyhow::Result<Vec<AvailableInputReference>> {
        self.input_retrievals
            .iter()
            .map(|entry| {
                let (_, value) = entry?;
                Self::decode_input_reference(&value)
            })
            .collect()
    }

    pub fn complete_input_reference(
        &self,
        reference: &AvailableInputReference,
    ) -> anyhow::Result<()> {
        self.input_retrievals.remove(reference.key())?;
        self.input_retrievals.flush()?;
        Ok(())
    }

    pub async fn run(self: Arc<Self>) -> anyhow::Result<()> {
        loop {
            let ids = self.pending_ids()?;
            let mut tasks = JoinSet::new();
            for id in ids {
                // Do not create one detached task per durable job. A malicious client can stage
                // many valid inputs, and an unbounded task fan-out would turn backlog into a
                // memory and RPC spike. Keep only one bounded batch alive at a time.
                while tasks.len() >= MAX_CONCURRENT_JOB_STEPS {
                    if let Some(result) = tasks.join_next().await {
                        if let Err(error) = result {
                            warn!(%error, "Data-availability job task panicked; continuing with the durable queue");
                        }
                    }
                }
                let service = Arc::clone(&self);
                tasks.spawn(async move {
                    service.process(&id).await;
                });
            }
            while let Some(result) = tasks.join_next().await {
                if let Err(error) = result {
                    warn!(%error, "Data-availability job task panicked; continuing with the durable queue");
                }
            }
            tokio::time::sleep(JOB_POLL_INTERVAL).await;
        }
    }

    /// Take exclusive ownership of one job, or return `None` when another path owns it.
    ///
    /// Every write path takes this guard, because each one loads a copy, awaits an Ethereum or
    /// Avail call, and then saves. Without one owner per job, a copy loaded before the other
    /// path made durable progress can replace that progress and discard recovery material.
    fn claim_job<'a>(&'a self, id: &'a str) -> Option<ActiveJobGuard<'a>> {
        let mut active = self
            .in_progress
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !active.insert(id.to_owned()) {
            return None;
        }
        Some(ActiveJobGuard {
            jobs: &self.in_progress,
            id,
        })
    }

    async fn process(&self, id: &str) {
        let Ok(_permit) = Arc::clone(&self.job_slots).acquire_owned().await else {
            warn!(job_id = id, "Data-availability worker is shutting down");
            return;
        };
        let Some(_active_job) = self.claim_job(id) else {
            return;
        };
        match tokio::time::timeout(JOB_STEP_TIMEOUT, self.process_inner(id)).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => warn!(job_id = id, %error, "Data-availability job will retry"),
            Err(_) => warn!(
                job_id = id,
                "Data-availability job step timed out and will retry"
            ),
        }
    }

    async fn process_inner(&self, id: &str) -> anyhow::Result<()> {
        let mut job = self.load_required(id)?;
        let terminal = matches!(
            &job.state,
            JobState::Submitted { .. } | JobState::Failed { .. }
        );
        if terminal {
            return Ok(());
        }
        if !terminal && self.publication_is_final(&job).await? {
            // Retire only on finalized state. A publication seen at the chain head can be
            // reorganized out, and retirement clears the recovery material and can delete the
            // local object, which removes every automatic path back to a publishable job.
            job.state = JobState::Submitted {
                transaction_hash: "already-finalized".to_owned(),
            };
            self.save(&job)?;
            return Ok(());
        }
        let now = self.chain_timestamp().await?;
        if matches!(&*self.backend, Backend::Avail { .. }) && now > job.kind.deadline() {
            // A load-balanced RPC can expose a new head while serving contract state from an
            // older one. Do not strand a publication that landed at the deadline on that stale
            // read. Once a finalized block after the deadline still lacks it, no later block can
            // accept it and the failure is conclusive.
            if let Some(block) = self
                .finalized_block_past(job.kind.deadline(), false)
                .await?
            {
                if self.ethereum_publication_exists_at(&job, block).await? {
                    job.state = JobState::Submitted {
                        transaction_hash: "already-finalized".to_owned(),
                    };
                } else {
                    job.state = JobState::Failed {
                        message:
                            "the Ethereum publication deadline passed before the availability job completed"
                                .to_owned(),
                    };
                }
                self.save(&job)?;
            }
            return Ok(());
        }

        if let JobKind::Input {
            commitment_deadline,
            ..
        } = &job.kind
        {
            if let JobState::AwaitingCommitment {
                attestation_expires_at,
                ..
            } = &job.state
            {
                if now >= *attestation_expires_at && !self.input_is_committed(&job).await? {
                    // The contract rejects the signature at this exact timestamp. Wait for a
                    // finalized block at or after it before releasing the promised ciphertext.
                    // This preserves a commitment that landed just before the expiry boundary.
                    if let Some(block) = self
                        .finalized_block_past(*attestation_expires_at, true)
                        .await?
                    {
                        if self.input_is_committed_at(&job, block).await? {
                            job.state = JobState::Committed {
                                transaction_hash: "wallet-committed".to_owned(),
                            };
                        } else {
                            job.state = JobState::Failed {
                                message:
                                    "the input availability promise expired before Ethereum accepted its commitment"
                                        .to_owned(),
                            };
                        }
                        self.save(&job)?;
                    }
                    return Ok(());
                }
            }

            let waiting_for_commitment = matches!(
                &job.state,
                JobState::Created | JobState::AwaitingCommitment { .. }
            );
            if waiting_for_commitment
                && now >= *commitment_deadline
                && !self.input_is_committed(&job).await?
            {
                // The cutoff itself is exclusive. A finalized block at or after it contains every
                // commitment that could still have succeeded. Use that historical state rather
                // than a possibly stale latest-state read.
                if let Some(block) = self
                    .finalized_block_past(*commitment_deadline, true)
                    .await?
                {
                    if self.input_is_committed_at(&job, block).await? {
                        job.state = JobState::Committed {
                            transaction_hash: "wallet-committed".to_owned(),
                        };
                    } else {
                        job.state = JobState::Failed {
                            message:
                                "the input proof commitment deadline passed before Ethereum accepted it"
                                    .to_owned(),
                        };
                    }
                    self.save(&job)?;
                }
                return Ok(());
            }
        }

        match job.state.clone() {
            JobState::Created => {
                match &job.kind {
                    JobKind::Input { .. } if self.input_commitment_is_final(&job).await? => {
                        job.state = JobState::Committed {
                            transaction_hash: "already-committed".to_owned(),
                        };
                    }
                    JobKind::Input { .. } if self.chain_id == 1 => {
                        let (ethereum_payload, attestation_expires_at) =
                            self.commitment_payload(&job).await?;
                        job.state = JobState::AwaitingCommitment {
                            ethereum_payload,
                            attestation_expires_at,
                        };
                    }
                    JobKind::Input { .. } => {
                        let receipt = self.submit_input_commitment(&job).await?;
                        job.state = JobState::Committed {
                            transaction_hash: receipt.transaction_hash.to_string(),
                        };
                    }
                    JobKind::Output { .. } => {
                        job.state = self.start_availability(&job, None).await?;
                    }
                }
                self.save(&job)?;
            }
            JobState::AwaitingCommitment { .. } => {
                // Leave this state only on finalized state. `Committed` stops the attestation
                // renewal path and starts the paid Avail publication, so an orphaned commitment
                // would strand the input with no way back to a fresh promise.
                if self.input_commitment_is_final(&job).await? {
                    job.state = JobState::Committed {
                        transaction_hash: "wallet-committed".to_owned(),
                    };
                    self.save(&job)?;
                }
            }
            JobState::Committed { transaction_hash } => {
                if matches!(&job.kind, JobKind::Input { .. })
                    && !self.input_commitment_is_final(&job).await?
                {
                    return Ok(());
                }
                job.state = self
                    .start_availability(&job, Some(transaction_hash))
                    .await?;
                self.save(&job)?;
            }
            JobState::AwaitingProof {
                publication,
                commitment_transaction_hash,
            } => {
                let Backend::Avail { publisher, .. } = &*self.backend else {
                    anyhow::bail!("mock job cannot await a VectorX proof");
                };
                if let ProofStatus::Ready { abi_proof, .. } = publisher.proof(&publication).await? {
                    // Keep the Avail coordinates beside the candidate proof. The bridge answer
                    // is checked for the expected content hash only, so a syntactically valid
                    // answer can carry a Merkle path that Ethereum refuses. Without the
                    // coordinates the job can never request a replacement proof.
                    job.state = JobState::Ready {
                        ethereum_payload: abi_proof,
                        commitment_transaction_hash,
                        publication: Some(publication),
                    };
                    self.save(&job)?;
                }
            }
            JobState::Ready {
                ethereum_payload,
                commitment_transaction_hash,
                publication,
            } => match &job.kind {
                JobKind::Input { .. } => {
                    anyhow::ensure!(
                        self.input_is_committed(&job).await?,
                        "cannot finalize an input whose proof commitment is absent"
                    );
                    let receipt = match self.finalize_input(&job, &ethereum_payload).await {
                        Ok(receipt) => receipt,
                        Err(error) => {
                            self.recover_rejected_proof(
                                &mut job,
                                commitment_transaction_hash,
                                publication,
                            )?;
                            return Err(error);
                        }
                    };
                    job.state = JobState::AwaitingFinality {
                        transaction_hash: receipt.transaction_hash.to_string(),
                        ethereum_payload,
                        commitment_transaction_hash,
                        publication,
                    };
                    self.save(&job)?;
                }
                JobKind::Output {
                    e3_id,
                    ciphertext_commitment,
                    compute_proof,
                    ..
                } => {
                    let contract = InterfoldContractFactory::create_write(
                        &self.http_rpc_url,
                        &self.interfold_address,
                        &self.private_key,
                    )
                    .await
                    .map_err(|error| anyhow::anyhow!(error.to_string()))?;
                    let e3_id = e3_id_to_u256(e3_id)?;
                    let stage = contract
                        .get_e3_stage(e3_id)
                        .await
                        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
                    match stage {
                        E3Stage::KeyPublished => {}
                        E3Stage::CiphertextReady | E3Stage::Complete => {
                            // Another party published this output. Confirm the observation in
                            // finalized state before this job releases its recovery material.
                            if self.publication_is_final(&job).await? {
                                job.state = JobState::Submitted {
                                    transaction_hash: "already-finalized".to_owned(),
                                };
                                self.save(&job)?;
                            }
                            return Ok(());
                        }
                        E3Stage::Failed => {
                            // A failed E3 at the chain head can be reorganized away, and the
                            // failure clears the compute proof. Require finalized state.
                            if self.e3_failure_is_final(&job).await? {
                                job.state = JobState::Failed {
                                    message:
                                        "the E3 failed before its aggregate ciphertext was published"
                                            .to_owned(),
                                };
                                self.save(&job)?;
                            }
                            return Ok(());
                        }
                        E3Stage::None | E3Stage::Requested | E3Stage::CommitteeFinalized => {
                            anyhow::bail!("the E3 is not ready for its aggregate ciphertext");
                        }
                        stage => {
                            anyhow::bail!(
                                    "unsupported E3 stage {stage:?} while publishing an aggregate ciphertext"
                                );
                        }
                    }
                    let receipt = match contract
                        .publish_ciphertext_output(
                            e3_id,
                            B256::from(job.content_hash),
                            B256::from(*ciphertext_commitment),
                            Bytes::copy_from_slice(compute_proof),
                            Bytes::copy_from_slice(&ethereum_payload),
                        )
                        .await
                        .map_err(|error| anyhow::anyhow!(error.to_string()))
                    {
                        Ok(receipt) => receipt,
                        Err(error) => {
                            self.recover_rejected_proof(
                                &mut job,
                                commitment_transaction_hash,
                                publication,
                            )?;
                            return Err(error);
                        }
                    };
                    job.state = JobState::AwaitingFinality {
                        transaction_hash: receipt.transaction_hash.to_string(),
                        ethereum_payload,
                        commitment_transaction_hash,
                        publication,
                    };
                    self.save(&job)?;
                }
            },
            JobState::AwaitingFinality {
                transaction_hash,
                ethereum_payload,
                commitment_transaction_hash,
                publication,
            } => {
                if self.publication_is_final(&job).await? {
                    job.state = JobState::Submitted { transaction_hash };
                    self.save(&job)?;
                    return Ok(());
                }
                // The publication is absent from finalized state. It can still be pending, so
                // send it again only when it is also absent from the chain head. The transaction
                // is idempotent on chain: the contract refuses a second publication of one
                // reference, and that refusal returns this job here on the next step.
                if !self.ethereum_publication_exists(&job).await? {
                    job.state = JobState::Ready {
                        ethereum_payload,
                        commitment_transaction_hash,
                        publication,
                    };
                    self.save(&job)?;
                }
            }
            JobState::Submitted { .. } | JobState::Failed { .. } => unreachable!(),
        }
        Ok(())
    }

    /// Return a job with a refused candidate proof to a state that can request a replacement.
    ///
    /// The Avail bridge answer is checked for the expected content hash, not for a valid Merkle
    /// path, so a `Ready` job can hold a proof that Ethereum refuses. Retrying the same payload
    /// can never succeed, and the job stays `Ready` forever. The saved Avail coordinates name
    /// bytes that Avail already holds, so `AwaitingProof` asks the bridge for a fresh proof and
    /// pays for no second publication. A transport failure takes the same path and costs one
    /// more bridge request, which is why this needs no error classification: a bridge that has
    /// nothing new returns the same proof and the job continues as before. A record written
    /// before the coordinates were kept has nothing to ask the bridge with, so it keeps its
    /// candidate proof and needs operator recovery.
    fn recover_rejected_proof(
        &self,
        job: &mut AvailabilityJob,
        commitment_transaction_hash: Option<String>,
        publication: Option<PendingPublication>,
    ) -> anyhow::Result<()> {
        let Some(publication) = publication else {
            return Ok(());
        };
        warn!(
            job_id = job.id.as_str(),
            "Ethereum refused the availability proof; requesting a replacement"
        );
        job.state = JobState::AwaitingProof {
            publication,
            commitment_transaction_hash,
        };
        self.save(job)
    }

    async fn start_availability(
        &self,
        job: &AvailabilityJob,
        commitment_transaction_hash: Option<String>,
    ) -> anyhow::Result<JobState> {
        let object = self.object_required(job.content_hash)?;
        match &*self.backend {
            Backend::Mock => Ok(JobState::Ready {
                ethereum_payload: object,
                commitment_transaction_hash,
                // The mock backend has no Avail publication to name, so it has no replacement
                // proof to request.
                publication: None,
            }),
            Backend::Avail { publisher, .. } => {
                let publication = publisher.publish(&object).await?;
                anyhow::ensure!(
                    publication.content_hash == job.content_hash,
                    "Avail returned a different content hash"
                );
                Ok(JobState::AwaitingProof {
                    publication,
                    commitment_transaction_hash,
                })
            }
        }
    }

    async fn commitment_payload(&self, job: &AvailabilityJob) -> anyhow::Result<(Vec<u8>, u64)> {
        let JobKind::Input {
            e3_id,
            staged_envelope,
            ..
        } = &job.kind
        else {
            anyhow::bail!("aggregate ciphertext jobs have no input commitment payload");
        };
        let envelope = decode_input_envelope(staged_envelope)?;
        let contract = CRISPContract::new(
            &self.http_rpc_url,
            &self.private_key,
            &self.e3_program_address,
        )
        .await
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        let signer: PrivateKeySigner = self
            .private_key
            .parse()
            .map_err(|error| anyhow::anyhow!("invalid availability signer key: {error}"))?;
        let configured = contract
            .input_availability_signer()
            .await
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        anyhow::ensure!(
            configured == signer.address(),
            "the CRISP inputAvailabilitySigner does not match this service key"
        );
        let ttl = contract
            .input_availability_attestation_ttl()
            .await
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        anyhow::ensure!(ttl > 0, "the input availability promise lifetime is zero");
        let attestation_expires_at = self
            .chain_timestamp()
            .await?
            .checked_add(ttl)
            .ok_or_else(|| anyhow::anyhow!("input availability promise expiry overflows u64"))?;
        let digest = contract
            .input_availability_digest(
                e3_id_to_u256(e3_id)?,
                envelope.encryptedVoteHash,
                envelope.encryptedVoteCommitment,
                envelope.slotAddress,
                envelope.parentIndexPlusOne.to::<u64>(),
                attestation_expires_at,
            )
            .await
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        let attestation = signer
            .sign_hash_sync(&digest)
            .map_err(|error| anyhow::anyhow!("failed to attest input availability: {error}"))?;
        let commitment_envelope = InputCommitmentEnvelope {
            noirProof: envelope.noirProof,
            slotAddress: envelope.slotAddress,
            encryptedVoteCommitment: envelope.encryptedVoteCommitment,
            encryptedVoteHash: envelope.encryptedVoteHash,
            parentIndexPlusOne: envelope.parentIndexPlusOne,
            availabilityAttestationExpiresAt: attestation_expires_at,
            availabilityAttestation: Bytes::copy_from_slice(&attestation.as_bytes()),
        };
        Ok((
            encode_input_commitment_envelope(&commitment_envelope),
            attestation_expires_at,
        ))
    }

    async fn submit_input_commitment(
        &self,
        job: &AvailabilityJob,
    ) -> anyhow::Result<alloy::rpc::types::TransactionReceipt> {
        let JobKind::Input { e3_id, .. } = &job.kind else {
            anyhow::bail!("aggregate ciphertext jobs cannot commit an input");
        };
        let contract = CRISPContract::new(
            &self.http_rpc_url,
            &self.private_key,
            &self.e3_program_address,
        )
        .await
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        let e3_id = e3_id_to_u256(e3_id)?;
        let (payload, _) = self.commitment_payload(job).await?;
        let payload = Bytes::from(payload);
        contract
            .simulate_publish_input(e3_id, payload.clone())
            .await
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        contract
            .publish_input(e3_id, payload)
            .await
            .map_err(|error| anyhow::anyhow!(error.to_string()))
    }

    async fn finalize_input(
        &self,
        job: &AvailabilityJob,
        availability_proof: &[u8],
    ) -> anyhow::Result<alloy::rpc::types::TransactionReceipt> {
        let JobKind::Input {
            e3_id,
            staged_envelope,
            ..
        } = &job.kind
        else {
            anyhow::bail!("aggregate ciphertext jobs cannot finalize an input");
        };
        let envelope = decode_input_envelope(staged_envelope)?;
        let contract = CRISPContract::new(
            &self.http_rpc_url,
            &self.private_key,
            &self.e3_program_address,
        )
        .await
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        let e3_id = e3_id_to_u256(e3_id)?;
        let availability_proof = Bytes::copy_from_slice(availability_proof);
        contract
            .simulate_finalize_input(
                e3_id,
                envelope.slotAddress,
                envelope.encryptedVoteCommitment,
                envelope.encryptedVoteHash,
                envelope.parentIndexPlusOne.to::<u64>(),
                availability_proof.clone(),
            )
            .await
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        contract
            .finalize_input(
                e3_id,
                envelope.slotAddress,
                envelope.encryptedVoteCommitment,
                envelope.encryptedVoteHash,
                envelope.parentIndexPlusOne.to::<u64>(),
                availability_proof,
            )
            .await
            .map_err(|error| anyhow::anyhow!(error.to_string()))
    }

    /// Derive the durable job ID for one statement.
    ///
    /// The identifier is canonicalized here as well as at each entry point. The decimal parser
    /// accepts leading zeros, so an alias of one E3 would otherwise hash to a second job ID and
    /// buy a second paid publication for the same bytes. Canonical decimal identifiers keep the
    /// job IDs they already have.
    fn job_id(
        &self,
        domain: &[u8],
        e3_id: &str,
        content_hash: B256,
        request_identity: &[u8],
    ) -> anyhow::Result<String> {
        let e3_id = canonical_e3_id(e3_id)?;
        let mut identity = Vec::with_capacity(domain.len() + e3_id.len() + 64);
        identity.extend_from_slice(domain);
        identity.extend_from_slice(e3_id.as_bytes());
        identity.extend_from_slice(content_hash.as_slice());
        identity.extend_from_slice(keccak256(request_identity).as_slice());
        Ok(format!("0x{}", hex::encode(keccak256(identity))))
    }

    async fn chain_timestamp(&self) -> anyhow::Result<u64> {
        let block = tokio::time::timeout(Duration::from_secs(15), async {
            let provider = ProviderBuilder::new().connect(&self.http_rpc_url).await?;
            provider.get_block_by_number(BlockNumberOrTag::Latest).await
        })
        .await
        .map_err(|_| anyhow::anyhow!("timed out while reading the Ethereum head"))??
        .ok_or_else(|| anyhow::anyhow!("the Ethereum RPC returned no latest block"))?;
        Ok(block.header.timestamp)
    }

    /// Return a finalized block that proves a deadline has passed.
    ///
    /// Commitment is rejected at its exact cutoff, so `inclusive` accepts a finalized block at
    /// that timestamp. Input and output finalization are valid through their exact deadline, so
    /// those decisions require a strictly later finalized block.
    async fn finalized_block_past(
        &self,
        deadline: u64,
        inclusive: bool,
    ) -> anyhow::Result<Option<u64>> {
        let (block_number, block_timestamp) = self.finalized_block().await?;
        let passed = if inclusive {
            block_timestamp >= deadline
        } else {
            block_timestamp > deadline
        };
        Ok(passed.then_some(block_number))
    }

    async fn finalized_block(&self) -> anyhow::Result<(u64, u64)> {
        let block = tokio::time::timeout(Duration::from_secs(15), async {
            let provider = ProviderBuilder::new().connect(&self.http_rpc_url).await?;
            provider
                .get_block_by_number(BlockNumberOrTag::Finalized)
                .await
        })
        .await
        .map_err(|_| anyhow::anyhow!("timed out while reading the finalized Ethereum head"))??
        .ok_or_else(|| anyhow::anyhow!("the Ethereum RPC returned no finalized block"))?;
        Ok((block.header.number, block.header.timestamp))
    }

    async fn input_is_committed_at(
        &self,
        job: &AvailabilityJob,
        block_number: u64,
    ) -> anyhow::Result<bool> {
        let JobKind::Input {
            e3_id,
            staged_envelope,
            ..
        } = &job.kind
        else {
            return Ok(false);
        };
        let envelope = decode_input_envelope(staged_envelope)?;
        let provider = ProviderBuilder::new().connect(&self.http_rpc_url).await?;
        let contract = ICrispAvailabilityState::new(self.e3_program_address.parse()?, provider);
        Ok(contract
            .isInputCommitted(
                e3_id_to_u256(e3_id)?,
                envelope.encryptedVoteHash,
                envelope.encryptedVoteCommitment,
                envelope.slotAddress,
                envelope.parentIndexPlusOne,
            )
            .block(BlockId::number(block_number))
            .call()
            .await?)
    }

    async fn ethereum_publication_exists_at(
        &self,
        job: &AvailabilityJob,
        block_number: u64,
    ) -> anyhow::Result<bool> {
        let provider = ProviderBuilder::new().connect(&self.http_rpc_url).await?;
        match &job.kind {
            JobKind::Input {
                e3_id,
                staged_envelope,
                ..
            } => {
                let envelope = decode_input_envelope(staged_envelope)?;
                let contract =
                    ICrispAvailabilityState::new(self.e3_program_address.parse()?, provider);
                Ok(contract
                    .isInputPublished(
                        e3_id_to_u256(e3_id)?,
                        envelope.encryptedVoteHash,
                        envelope.encryptedVoteCommitment,
                        envelope.slotAddress,
                        envelope.parentIndexPlusOne,
                    )
                    .block(BlockId::number(block_number))
                    .call()
                    .await?)
            }
            JobKind::Output { e3_id, .. } => {
                let contract =
                    IInterfoldAvailabilityState::new(self.interfold_address.parse()?, provider);
                let stage = contract
                    .getE3Stage(e3_id_to_u256(e3_id)?)
                    .block(BlockId::number(block_number))
                    .call()
                    .await?;
                Ok(matches!(
                    stage,
                    StoredE3Stage::CiphertextReady | StoredE3Stage::Complete
                ))
            }
        }
    }

    async fn input_is_published(&self, job: &AvailabilityJob) -> anyhow::Result<bool> {
        let JobKind::Input {
            e3_id,
            staged_envelope,
            ..
        } = &job.kind
        else {
            return Ok(false);
        };
        let envelope = decode_input_envelope(staged_envelope)?;
        let contract = CRISPContract::new(
            &self.http_rpc_url,
            &self.private_key,
            &self.e3_program_address,
        )
        .await
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        contract
            .is_input_published(
                e3_id_to_u256(e3_id)?,
                envelope.encryptedVoteHash,
                envelope.encryptedVoteCommitment,
                envelope.slotAddress,
                envelope.parentIndexPlusOne.to::<u64>(),
            )
            .await
            .map_err(|error| anyhow::anyhow!(error.to_string()))
    }

    async fn input_is_committed(&self, job: &AvailabilityJob) -> anyhow::Result<bool> {
        let JobKind::Input {
            e3_id,
            staged_envelope,
            ..
        } = &job.kind
        else {
            return Ok(false);
        };
        let envelope = decode_input_envelope(staged_envelope)?;
        let contract = CRISPContract::new(
            &self.http_rpc_url,
            &self.private_key,
            &self.e3_program_address,
        )
        .await
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        contract
            .is_input_committed(
                e3_id_to_u256(e3_id)?,
                envelope.encryptedVoteHash,
                envelope.encryptedVoteCommitment,
                envelope.slotAddress,
                envelope.parentIndexPlusOne.to::<u64>(),
            )
            .await
            .map_err(|error| anyhow::anyhow!(error.to_string()))
    }

    async fn ethereum_publication_exists(&self, job: &AvailabilityJob) -> anyhow::Result<bool> {
        match &job.kind {
            JobKind::Input { .. } => self.input_is_published(job).await,
            JobKind::Output { e3_id, .. } => {
                let contract = InterfoldContractFactory::create_read(
                    &self.http_rpc_url,
                    &self.interfold_address,
                )
                .await
                .map_err(|error| anyhow::anyhow!(error.to_string()))?;
                let stage = contract
                    .get_e3_stage(e3_id_to_u256(e3_id)?)
                    .await
                    .map_err(|error| anyhow::anyhow!(error.to_string()))?;
                Ok(matches!(
                    stage,
                    E3Stage::CiphertextReady | E3Stage::Complete
                ))
            }
        }
    }

    /// Answer whether this job's publication is present in finalized Ethereum state.
    ///
    /// Retiring a job clears its recovery material and can delete the local object, so a
    /// publication seen only at the chain head is not enough: a reorganization would remove the
    /// publication and leave no automatic path back to a publishable job. The mock backend has
    /// no finalized block to read, so it uses the head.
    async fn publication_is_final(&self, job: &AvailabilityJob) -> anyhow::Result<bool> {
        if !matches!(&*self.backend, Backend::Avail { .. }) {
            return self.ethereum_publication_exists(job).await;
        }
        let (finalized_block, _) = self.finalized_block().await?;
        self.ethereum_publication_exists_at(job, finalized_block)
            .await
    }

    /// Answer whether this input's commitment is present in finalized Ethereum state.
    ///
    /// `Committed` stops attestation renewal and starts the paid Avail publication, so an
    /// orphaned commitment would strand the input for the rest of its commitment window.
    async fn input_commitment_is_final(&self, job: &AvailabilityJob) -> anyhow::Result<bool> {
        if !matches!(&*self.backend, Backend::Avail { .. }) {
            return self.input_is_committed(job).await;
        }
        let (finalized_block, _) = self.finalized_block().await?;
        self.input_is_committed_at(job, finalized_block).await
    }

    /// Answer whether this output's E3 has failed in finalized Ethereum state.
    ///
    /// A failure record clears the compute proof, so an orphaned failure would discard the
    /// material needed to publish the aggregate ciphertext.
    async fn e3_failure_is_final(&self, job: &AvailabilityJob) -> anyhow::Result<bool> {
        let JobKind::Output { e3_id, .. } = &job.kind else {
            return Ok(false);
        };
        if !matches!(&*self.backend, Backend::Avail { .. }) {
            return Ok(true);
        }
        let (finalized_block, _) = self.finalized_block().await?;
        let provider = ProviderBuilder::new().connect(&self.http_rpc_url).await?;
        let contract = IInterfoldAvailabilityState::new(self.interfold_address.parse()?, provider);
        let stage = contract
            .getE3Stage(e3_id_to_u256(e3_id)?)
            .block(BlockId::number(finalized_block))
            .call()
            .await?;
        Ok(matches!(stage, StoredE3Stage::Failed))
    }

    fn pending_ids(&self) -> anyhow::Result<Vec<String>> {
        let mut ids = Vec::new();
        for entry in &self.jobs {
            let (_, value) = entry?;
            let job = Self::decode_job(&value)?;
            let terminal = matches!(
                &job.state,
                JobState::Submitted { .. } | JobState::Failed { .. }
            );
            if !terminal {
                ids.push(job.id);
            }
        }
        Ok(ids)
    }

    fn load(&self, id: &str) -> anyhow::Result<Option<AvailabilityJob>> {
        self.jobs
            .get(id.as_bytes())?
            .map(|bytes| Self::decode_job(&bytes))
            .transpose()
    }

    fn load_required(&self, id: &str) -> anyhow::Result<AvailabilityJob> {
        self.load(id)?
            .ok_or_else(|| anyhow::anyhow!("data-availability job {id} does not exist"))
    }

    fn save(&self, job: &AvailabilityJob) -> anyhow::Result<()> {
        // Admission and terminal cleanup must use the same lock. Otherwise, cleanup can decide an
        // object has no live users, a new job can adopt it, and cleanup can then delete bytes that
        // the new job needs.
        let _storage = self
            .storage
            .lock()
            .map_err(|_| anyhow::anyhow!("data-availability storage lock is poisoned"))?;
        let mut stored = job.clone();
        Self::validate_job_schema(&stored)?;
        let terminal = matches!(
            stored.state,
            JobState::Submitted { .. } | JobState::Failed { .. }
        );
        if terminal {
            match &mut stored.kind {
                JobKind::Input {
                    staged_envelope, ..
                } => staged_envelope.clear(),
                JobKind::Output { compute_proof, .. } => compute_proof.clear(),
            }
        }
        self.jobs
            .insert(stored.id.as_bytes(), serde_json::to_vec(&stored)?)?;
        self.jobs.flush()?;

        let release_object = matches!(stored.state, JobState::Failed { .. })
            || (matches!(stored.state, JobState::Submitted { .. })
                && matches!(&*self.backend, Backend::Avail { .. }));
        if release_object && !self.nonterminal_job_uses(stored.content_hash, &stored.id)? {
            self.objects.remove(stored.content_hash)?;
            self.objects.flush()?;
        }
        Ok(())
    }

    fn nonterminal_job_uses(
        &self,
        content_hash: [u8; 32],
        except_id: &str,
    ) -> anyhow::Result<bool> {
        for entry in &self.jobs {
            let (_, value) = entry?;
            let job = Self::decode_job(&value)?;
            if job.id != except_id
                && job.content_hash == content_hash
                && !matches!(
                    job.state,
                    JobState::Submitted { .. } | JobState::Failed { .. }
                )
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn validate_storage(&self) -> anyhow::Result<()> {
        self.pending_ids()?;
        self.pending_input_references()?;
        for entry in &self.jobs {
            let (_, value) = entry?;
            let job = Self::decode_job(&value)?;
            if !matches!(
                job.state,
                JobState::Submitted { .. } | JobState::Failed { .. }
            ) {
                anyhow::ensure!(
                    self.objects.contains_key(job.content_hash)?,
                    "non-terminal data-availability job {} has no stored object",
                    job.id
                );
            }
        }
        if matches!(&*self.backend, Backend::Avail { .. }) {
            for entry in &self.jobs {
                let (_, value) = entry?;
                let job = Self::decode_job(&value)?;
                if matches!(
                    job.state,
                    JobState::Submitted { .. } | JobState::Failed { .. }
                ) && !self.nonterminal_job_uses(job.content_hash, &job.id)?
                {
                    self.objects.remove(job.content_hash)?;
                }
            }
            self.objects.flush()?;
        }
        Ok(())
    }

    fn validate_job_schema(job: &AvailabilityJob) -> anyhow::Result<()> {
        anyhow::ensure!(
            job.schema_version == AVAILABILITY_JOB_SCHEMA_VERSION,
            "unsupported data-availability job schema version {}; expected {}",
            job.schema_version,
            AVAILABILITY_JOB_SCHEMA_VERSION
        );
        Ok(())
    }

    fn decode_job(bytes: &[u8]) -> anyhow::Result<AvailabilityJob> {
        let job: AvailabilityJob = serde_json::from_slice(bytes)
            .map_err(|error| anyhow::anyhow!("cannot decode a data-availability job: {error}"))?;
        Self::validate_job_schema(&job)?;
        Ok(job)
    }

    fn decode_input_reference(bytes: &[u8]) -> anyhow::Result<AvailableInputReference> {
        let reference: AvailableInputReference =
            serde_json::from_slice(bytes).map_err(|error| {
                anyhow::anyhow!("cannot decode an available-input reference: {error}")
            })?;
        reference.validate_schema()?;
        Ok(reference)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_service(max_pending_bytes: u64) -> AvailabilityService {
        let db = sled::Config::new().temporary(true).open().unwrap();
        AvailabilityService {
            jobs: db.open_tree("jobs").unwrap(),
            objects: db.open_tree("objects").unwrap(),
            input_retrievals: db.open_tree("retrievals").unwrap(),
            backend: Arc::new(Backend::Mock),
            in_progress: Arc::new(StorageMutex::new(HashSet::new())),
            storage: Arc::new(StorageMutex::new(())),
            job_slots: Arc::new(Semaphore::new(1)),
            chain_id: 31_337,
            http_rpc_url: String::new(),
            private_key: String::new(),
            interfold_address: String::new(),
            e3_program_address: String::new(),
            ciphernode_registry_address: String::new(),
            input_duration_seconds: 0,
            proof_lead_seconds: 0,
            max_pending_bytes,
        }
    }

    #[test]
    fn active_job_guard_releases_the_job_for_retry() {
        let jobs = StorageMutex::new(HashSet::from(["job".to_owned()]));
        let guard = ActiveJobGuard {
            jobs: &jobs,
            id: "job",
        };

        drop(guard);

        assert!(jobs.lock().unwrap().is_empty());
    }

    const SDK_INPUT_ENVELOPE: &str = concat!(
        "00000000000000000000000000000000000000000000000000000000000000c0",
        "0000000000000000000000001111111111111111111111111111111111111111",
        "2222222222222222222222222222222222222222222222222222222222222222",
        "3333333333333333333333333333333333333333333333333333333333333333",
        "0000000000000000000000000000000000000000000000000000000000000007",
        "0000000000000000000000000000000000000000000000000000000000000100",
        "0000000000000000000000000000000000000000000000000000000000000003",
        "0102030000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000002",
        "aabb000000000000000000000000000000000000000000000000000000000000",
    );

    #[test]
    fn sdk_input_envelope_uses_solidity_parameter_encoding() {
        let encoded = hex::decode(SDK_INPUT_ENVELOPE).unwrap();
        let envelope = decode_input_envelope(&encoded).unwrap();

        assert_eq!(envelope.noirProof.as_ref(), &[1, 2, 3]);
        assert_eq!(
            envelope.slotAddress,
            "0x1111111111111111111111111111111111111111"
                .parse::<alloy::primitives::Address>()
                .unwrap()
        );
        assert_eq!(envelope.encryptedVoteCommitment, B256::repeat_byte(0x22));
        assert_eq!(envelope.encryptedVoteHash, B256::repeat_byte(0x33));
        assert_eq!(envelope.parentIndexPlusOne.to::<u64>(), 7);
        assert_eq!(envelope.availabilityProof.as_ref(), &[0xaa, 0xbb]);

        let commitment_envelope = InputCommitmentEnvelope {
            noirProof: envelope.noirProof,
            slotAddress: envelope.slotAddress,
            encryptedVoteCommitment: envelope.encryptedVoteCommitment,
            encryptedVoteHash: envelope.encryptedVoteHash,
            parentIndexPlusOne: envelope.parentIndexPlusOne,
            availabilityAttestationExpiresAt: 600,
            availabilityAttestation: envelope.availabilityProof,
        };
        let encoded_commitment = encode_input_commitment_envelope(&commitment_envelope);
        let decoded_commitment =
            InputCommitmentEnvelope::abi_decode_params_validate(&encoded_commitment).unwrap();
        assert_eq!(decoded_commitment.availabilityAttestationExpiresAt, 600);
        assert_eq!(
            decoded_commitment.availabilityAttestation.as_ref(),
            &[0xaa, 0xbb]
        );
    }

    #[test]
    fn only_conclusive_input_errors_have_a_client_rejection_message() {
        let malformed = reject_input("The encoded vote envelope is invalid");
        assert_eq!(
            input_rejection_message(&malformed),
            Some("The encoded vote envelope is invalid")
        );

        let reverted = anyhow::Error::new(SimulateError::Reverted("node detail".to_owned()));
        assert_eq!(
            input_rejection_message(&reverted),
            Some("The vote proof or ciphertext was rejected")
        );

        let provider = anyhow::Error::new(SimulateError::Provider("secret RPC detail".to_owned()));
        assert_eq!(input_rejection_message(&provider), None);
    }

    #[test]
    fn input_duration_adds_current_onchain_windows() {
        assert_eq!(
            minimum_input_duration(1_200, 300, 3_600, 3_600, 10_800).unwrap(),
            19_500
        );
        assert!(minimum_input_duration(u64::MAX, 1, 0, 0, 0).is_err());
    }

    #[test]
    fn durable_records_reject_unknown_or_missing_schema_versions() {
        let current_job = AvailabilityJob {
            schema_version: AVAILABILITY_JOB_SCHEMA_VERSION,
            id: "job".to_owned(),
            content_hash: [0x11; 32],
            kind: JobKind::Output {
                e3_id: "e3".to_owned(),
                ciphertext_commitment: [0x22; 32],
                compute_proof: vec![4, 5, 6],
                deadline: 7,
            },
            state: JobState::Created,
        };
        let encoded = serde_json::to_vec(&current_job).unwrap();
        assert!(AvailabilityService::decode_job(&encoded).is_ok());

        let mut unknown_job = current_job.clone();
        unknown_job.schema_version += 1;
        let error = AvailabilityService::decode_job(&serde_json::to_vec(&unknown_job).unwrap())
            .unwrap_err();
        assert!(error
            .to_string()
            .contains("unsupported data-availability job schema version"));

        let mut missing_version = serde_json::to_value(&current_job).unwrap();
        missing_version
            .as_object_mut()
            .unwrap()
            .remove("schema_version");
        let error = AvailabilityService::decode_job(&serde_json::to_vec(&missing_version).unwrap())
            .unwrap_err();
        assert!(error.to_string().contains("schema_version"));

        let reference = AvailableInputReference {
            schema_version: AVAILABLE_INPUT_REFERENCE_SCHEMA_VERSION + 1,
            e3_id: "e3".to_owned(),
            content_hash: [0x33; 32],
            availability_block: 1,
            availability_leaf_index: 2,
            index: 3,
            commitment: [0x44; 32],
            slot: [0x55; 20],
            parent_index_plus_one: 4,
        };
        let error =
            AvailabilityService::decode_input_reference(&serde_json::to_vec(&reference).unwrap())
                .unwrap_err();
        assert!(error
            .to_string()
            .contains("unsupported available-input reference schema version"));
    }

    #[test]
    fn legacy_uncommitted_job_without_expiry_fails_closed() {
        let job = AvailabilityJob {
            schema_version: AVAILABILITY_JOB_SCHEMA_VERSION,
            id: "legacy-input".to_owned(),
            content_hash: [0x11; 32],
            kind: JobKind::Input {
                e3_id: "1".to_owned(),
                staged_envelope: vec![0x22],
                deadline: 1_000,
                commitment_deadline: 900,
            },
            state: JobState::AwaitingCommitment {
                ethereum_payload: vec![0x33],
                attestation_expires_at: 600,
            },
        };
        let mut encoded = serde_json::to_value(&job).unwrap();
        encoded["state"]
            .as_object_mut()
            .unwrap()
            .remove("attestation_expires_at");

        let decoded =
            AvailabilityService::decode_job(&serde_json::to_vec(&encoded).unwrap()).unwrap();
        let JobState::AwaitingCommitment {
            attestation_expires_at,
            ..
        } = decoded.state
        else {
            panic!("expected an uncommitted input job");
        };
        assert_eq!(attestation_expires_at, 0);
    }

    #[test]
    fn pending_object_storage_is_bounded_and_content_addressed() {
        let service = test_service(4);
        let first = b"abc";
        let first_hash = keccak256(first).0;
        service.store_object(first_hash, first).unwrap();
        service.store_object(first_hash, first).unwrap();

        assert!(service.store_object([0; 32], b"x").is_err());
        assert!(service.store_object(keccak256(b"de").0, b"de").is_err());
        assert_eq!(service.object_required(first_hash).unwrap(), first);
    }

    #[test]
    fn new_job_and_object_are_admitted_together() {
        let service = test_service(10);
        let object = b"ciphertext";
        let content_hash = keccak256(object).0;
        let job = AvailabilityJob {
            schema_version: AVAILABILITY_JOB_SCHEMA_VERSION,
            id: "new-output".to_owned(),
            content_hash,
            kind: JobKind::Output {
                e3_id: "1".to_owned(),
                ciphertext_commitment: [0x22; 32],
                compute_proof: vec![0x33],
                deadline: 7,
            },
            state: JobState::Created,
        };

        service.store_new_job_with_object(&job, object).unwrap();
        assert_eq!(service.object_required(content_hash).unwrap(), object);
        assert_eq!(
            service.load_required(&job.id).unwrap().content_hash,
            content_hash
        );

        let oversized = b"x";
        let oversized_job = AvailabilityJob {
            id: "over-capacity".to_owned(),
            content_hash: keccak256(oversized).0,
            ..job
        };
        assert!(service
            .store_new_job_with_object(&oversized_job, oversized)
            .is_err());
        assert!(service.load(&oversized_job.id).unwrap().is_none());
        assert!(service.object_required(oversized_job.content_hash).is_err());
    }

    #[test]
    fn terminal_cleanup_keeps_an_object_used_by_another_job() {
        let service = test_service(1024);
        let object = b"shared-ciphertext";
        let content_hash = keccak256(object).0;
        let mut first = AvailabilityJob {
            schema_version: AVAILABILITY_JOB_SCHEMA_VERSION,
            id: "first-output".to_owned(),
            content_hash,
            kind: JobKind::Output {
                e3_id: "1".to_owned(),
                ciphertext_commitment: [0x11; 32],
                compute_proof: vec![0x22],
                deadline: 7,
            },
            state: JobState::Created,
        };
        let second = AvailabilityJob {
            id: "second-output".to_owned(),
            kind: JobKind::Output {
                e3_id: "2".to_owned(),
                ciphertext_commitment: [0x33; 32],
                compute_proof: vec![0x44],
                deadline: 8,
            },
            ..first.clone()
        };

        service.store_new_job_with_object(&first, object).unwrap();
        service.store_new_job_with_object(&second, object).unwrap();
        first.state = JobState::Failed {
            message: "deadline passed".to_owned(),
        };
        service.save(&first).unwrap();

        assert_eq!(service.object_required(content_hash).unwrap(), object);
        assert!(service.validate_storage().is_ok());
    }

    #[test]
    fn failed_job_releases_bytes_and_large_payloads() {
        let service = test_service(1024);
        let object = b"ciphertext";
        let content_hash = keccak256(object).0;
        service.store_object(content_hash, object).unwrap();
        let mut job = AvailabilityJob {
            schema_version: AVAILABILITY_JOB_SCHEMA_VERSION,
            id: "failed-output".to_owned(),
            content_hash,
            kind: JobKind::Output {
                e3_id: "1".to_owned(),
                ciphertext_commitment: [0x22; 32],
                compute_proof: vec![0x33; 128],
                deadline: 7,
            },
            state: JobState::Created,
        };
        service.save(&job).unwrap();
        job.state = JobState::Failed {
            message: "deadline passed".to_owned(),
        };
        service.save(&job).unwrap();

        assert!(service.object_required(content_hash).is_err());
        let stored = service.load_required(&job.id).unwrap();
        let JobKind::Output { compute_proof, .. } = stored.kind else {
            panic!("expected an output job");
        };
        assert!(compute_proof.is_empty());
    }

    #[test]
    fn failed_input_job_can_be_staged_again() {
        let service = test_service(1024);
        let object = b"ciphertext";
        let content_hash = keccak256(object).0;
        let mut job = AvailabilityJob {
            schema_version: AVAILABILITY_JOB_SCHEMA_VERSION,
            id: "retry-input".to_owned(),
            content_hash,
            kind: JobKind::Input {
                e3_id: "1".to_owned(),
                staged_envelope: vec![0x11],
                deadline: 1_000,
                commitment_deadline: 900,
            },
            state: JobState::Created,
        };

        service.store_new_job_with_object(&job, object).unwrap();
        job.state = JobState::Failed {
            message: "availability promise expired".to_owned(),
        };
        service.save(&job).unwrap();
        assert!(service.object_required(content_hash).is_err());

        let replacement = AvailabilityJob {
            kind: JobKind::Input {
                e3_id: "1".to_owned(),
                staged_envelope: vec![0x22],
                deadline: 1_000,
                commitment_deadline: 900,
            },
            state: JobState::Created,
            ..job
        };
        service
            .store_new_job_with_object(&replacement, object)
            .unwrap();

        assert_eq!(service.object_required(content_hash).unwrap(), object);
        let stored = service.load_required(&replacement.id).unwrap();
        assert!(matches!(stored.state, JobState::Created));
    }

    fn staged_envelope_for_slot(slot: Address, commitment: B256, object: &[u8]) -> Vec<u8> {
        let mut envelope =
            decode_input_envelope(&hex::decode(SDK_INPUT_ENVELOPE).unwrap()).unwrap();
        envelope.slotAddress = slot;
        envelope.encryptedVoteCommitment = commitment;
        envelope.encryptedVoteHash = keccak256(object);
        envelope.availabilityProof = Bytes::new();
        envelope.abi_encode_params()
    }

    fn input_job(id: &str, slot: Address, commitment: u8, object: &[u8]) -> AvailabilityJob {
        AvailabilityJob {
            schema_version: AVAILABILITY_JOB_SCHEMA_VERSION,
            id: id.to_owned(),
            content_hash: keccak256(object).0,
            kind: JobKind::Input {
                e3_id: "1".to_owned(),
                staged_envelope: staged_envelope_for_slot(
                    slot,
                    B256::repeat_byte(commitment),
                    object,
                ),
                deadline: 1_000,
                commitment_deadline: 900,
            },
            state: JobState::Created,
        }
    }

    /// A mask needs no signature from the slot owner, so an uncommitted job for a slot must not
    /// stop a different statement for the same slot.
    #[test]
    fn a_second_statement_for_one_slot_is_admitted_and_keeps_the_first() {
        let service = test_service(1024);
        let slot = Address::repeat_byte(0x77);

        let mask_object = b"attacker-mask-ciphertext";
        let mask = input_job("mask-input", slot, 0x11, mask_object);
        assert!(service.admit_input(&mask, mask_object).unwrap().is_none());

        // The attacker holds the attestation and never sends its Ethereum commitment.
        let mut attested = service.load_required(&mask.id).unwrap();
        attested.state = JobState::AwaitingCommitment {
            ethereum_payload: vec![0x01],
            attestation_expires_at: 600,
        };
        service.save(&attested).unwrap();

        let vote_object = b"slot-owner-ciphertext";
        let vote = input_job("owner-input", slot, 0x22, vote_object);
        assert!(service.admit_input(&vote, vote_object).unwrap().is_none());

        // Admission of the second statement keeps the earlier attestation valid and keeps its
        // bytes retrievable.
        assert!(matches!(
            service.load_required(&mask.id).unwrap().state,
            JobState::AwaitingCommitment { .. }
        ));
        assert_eq!(
            service.object_required(mask.content_hash).unwrap(),
            mask_object
        );
        assert_eq!(
            service.object_required(vote.content_hash).unwrap(),
            vote_object
        );

        // The same statement stays one job.
        let repeat = service.admit_input(&vote, vote_object).unwrap();
        assert_eq!(repeat.unwrap().job_id, vote.id);
        assert_eq!(service.jobs.len(), 2);
        assert!(service.validate_storage().is_ok());
    }

    /// Per-statement admission must not remove the bounded pending-object limit.
    #[test]
    fn admission_still_respects_the_pending_byte_limit() {
        let service = test_service(8);
        let slot = Address::repeat_byte(0x77);

        let first_object = b"12345678";
        let first = input_job("first-input", slot, 0x11, first_object);
        assert!(service.admit_input(&first, first_object).unwrap().is_none());

        let second_object = b"9";
        let second = input_job("second-input", slot, 0x22, second_object);
        assert!(service.admit_input(&second, second_object).is_err());
        assert!(service.load(&second.id).unwrap().is_none());
    }

    /// A noncanonical E3 identifier must not buy a second publication for the same statement.
    #[test]
    fn noncanonical_e3_identifiers_resolve_to_one_job() {
        let service = test_service(1024);
        let ciphertext = b"aggregate-ciphertext";
        let hash = keccak256(ciphertext);
        let commitment = [0x22u8; 32];

        let canonical = service.job_id(b"output", "42", hash, &commitment).unwrap();
        for alias in ["042", "0000042", "0000000000000000000000000042"] {
            assert_eq!(
                service.job_id(b"output", alias, hash, &commitment).unwrap(),
                canonical
            );
        }
        assert!(service
            .job_id(b"output", "not-an-id", hash, &commitment)
            .is_err());
        assert_ne!(
            service.job_id(b"output", "43", hash, &commitment).unwrap(),
            canonical
        );

        let job = AvailabilityJob {
            schema_version: AVAILABILITY_JOB_SCHEMA_VERSION,
            id: canonical.clone(),
            content_hash: hash.0,
            kind: JobKind::Output {
                e3_id: "42".to_owned(),
                ciphertext_commitment: commitment,
                compute_proof: vec![0x33],
                deadline: 7,
            },
            state: JobState::Created,
        };
        service.store_new_job_with_object(&job, ciphertext).unwrap();

        // An alias of the same E3 now finds the stored job, so its call is an idempotent retry
        // instead of a second paid Avail publication.
        let alias_id = service
            .job_id(b"output", "0042", hash, &commitment)
            .unwrap();
        assert_eq!(service.load(&alias_id).unwrap().unwrap().id, canonical);
        assert_eq!(service.jobs.len(), 1);
    }

    /// One encrypted ballot with the SAFE commitment that its ballot proof binds.
    ///
    /// `message` selects the operation: a vote or an update carries ballot coefficients, and a
    /// mask carries zero. Every operation produces the same request shape, so the tests use one
    /// builder for all three.
    fn encrypted_ballot(params: &Arc<BfvParameters>, message: &[u64]) -> (Vec<u8>, B256) {
        use fhe::bfv::{Encoding, Plaintext, PublicKey, SecretKey};
        use fhe_traits::{FheEncoder, FheEncrypter, Serialize as _};

        let mut rng = rand::rng();
        let secret_key = SecretKey::random(params, &mut rng);
        let public_key = PublicKey::new(&secret_key, &mut rng);
        let plaintext = Plaintext::try_encode(message, Encoding::poly(), params).unwrap();
        let ciphertext = public_key.try_encrypt(&plaintext, &mut rng).unwrap();
        let bytes = ciphertext.to_bytes();
        let commitment = compute_ct_commitment_with_params(&bytes, params).unwrap();
        (bytes, B256::from(commitment))
    }

    fn insecure_test_params() -> Arc<BfvParameters> {
        bfv_parameters_for_param_set(0).unwrap().0
    }

    /// The proof binds the commitment, not the bytes, so intake must compare the two.
    #[test]
    fn intake_accepts_proved_bytes_and_refuses_substituted_bytes() {
        let params = insecure_test_params();
        let (bytes, commitment) = encrypted_ballot(&params, &[1_u64]);

        assert!(ciphertext_matches_commitment(&bytes, commitment, &params));

        // The attack this check stops: a copied proof tuple keeps its commitment while the bytes
        // and their Keccak hash change. The hash check passes and this check must not.
        let (other_bytes, other_commitment) = encrypted_ballot(&params, &[1_u64]);
        assert_ne!(other_commitment, commitment);
        assert!(!ciphertext_matches_commitment(
            &other_bytes,
            commitment,
            &params
        ));

        // Bytes that do not deserialize are unusable, not merely mismatched.
        assert!(!ciphertext_matches_commitment(
            b"not-a-ciphertext",
            commitment,
            &params
        ));
        let mut truncated = bytes.clone();
        truncated.truncate(bytes.len() / 2);
        assert!(!ciphertext_matches_commitment(
            &truncated, commitment, &params
        ));
    }

    /// The SAFE commitment covers `c[0]` and `c[1]` only.
    ///
    /// A padded ciphertext would otherwise share one commitment with its two-component prefix,
    /// and threshold decryption would reject it after the service paid to publish it. The
    /// underlying two-component restriction must therefore stay in effect at intake.
    #[test]
    fn intake_preserves_the_two_component_restriction() {
        use fhe::bfv::Ciphertext;
        use fhe_traits::{DeserializeParametrized, Serialize as _};

        let params = insecure_test_params();
        let (bytes, commitment) = encrypted_ballot(&params, &[1_u64]);
        let ciphertext = Ciphertext::from_bytes(&bytes, &params).unwrap();

        let padded = Ciphertext::new(
            vec![
                ciphertext[0].clone(),
                ciphertext[1].clone(),
                ciphertext[1].clone(),
            ],
            &params,
        )
        .unwrap();
        assert_eq!(padded.len(), 3);

        let padded_bytes = padded.to_bytes();
        assert_ne!(padded_bytes, bytes);
        assert!(!ciphertext_matches_commitment(
            &padded_bytes,
            commitment,
            &params
        ));
    }

    /// Votes, updates, and masks use one validation path.
    ///
    /// The three operations prove one relation and publish one shape. A special case for masks
    /// would make them different on chain, which is what masks exist to prevent.
    #[test]
    fn votes_updates_and_masks_get_identical_validation() {
        let params = insecure_test_params();
        let vote = encrypted_ballot(&params, &[1_u64]);
        let update = encrypted_ballot(&params, &[1_u64, 1_u64]);
        let mask = encrypted_ballot(&params, &[0_u64]);

        for (bytes, commitment) in [&vote, &update, &mask] {
            assert!(ciphertext_matches_commitment(bytes, *commitment, &params));
        }

        // Every operation refuses substituted bytes on the same terms.
        assert!(!ciphertext_matches_commitment(&vote.0, update.1, &params));
        assert!(!ciphertext_matches_commitment(&update.0, mask.1, &params));
        assert!(!ciphertext_matches_commitment(&mask.0, vote.1, &params));
    }

    /// Intake validates with the parameters the request accepted, not with a local default.
    ///
    /// `Interfold.request` stores the configuration identifier that
    /// `ActiveCryptoConfig.configIdForParamSet` produced for the requested parameter set. Intake
    /// derives the same identifier from its own tables and compares. A mismatch means the local
    /// tables are not the request-time parameters, so their recomputed commitment would refuse
    /// honest ballots.
    #[test]
    fn local_parameters_reproduce_the_onchain_crypto_config_id() {
        let (insecure, insecure_config_id) = bfv_parameters_for_param_set(0).unwrap();
        assert_eq!(
            insecure_config_id,
            "0x04f3677e73b0f5066d6caf5cbd92e3fb2e38338edaf5cfc971ab28f7b684da78"
                .parse::<B256>()
                .unwrap(),
            "insecure-512 must reproduce ActiveCryptoConfig.INSECURE_CONFIG_ID"
        );

        let (_, secure_config_id) = bfv_parameters_for_param_set(1).unwrap();
        assert_eq!(
            secure_config_id,
            "0xd9c86e581f8291ffb5b63595600e8d096ed30b16e2e0a6634a76c22b1f58fb4e"
                .parse::<B256>()
                .unwrap(),
            "secure-8192 must reproduce ActiveCryptoConfig.SECURE_CONFIG_ID"
        );
        assert_ne!(insecure_config_id, secure_config_id);

        assert!(bfv_parameters_for_param_set(2).is_err());

        // The cache returns the same tables, so intake does not rebuild them for every ballot.
        assert!(Arc::ptr_eq(
            &insecure,
            &bfv_parameters_for_param_set(0).unwrap().0
        ));
    }

    /// Deserialization plus the commitment is real processor work at a public endpoint.
    #[test]
    fn intake_ciphertext_validation_is_bounded() {
        assert_eq!(
            CIPHERTEXT_VALIDATION_SLOTS.available_permits(),
            MAX_CONCURRENT_CIPHERTEXT_VALIDATIONS
        );

        let mut held = Vec::new();
        for _ in 0..MAX_CONCURRENT_CIPHERTEXT_VALIDATIONS {
            held.push(CIPHERTEXT_VALIDATION_SLOTS.try_acquire().unwrap());
        }
        assert!(
            CIPHERTEXT_VALIDATION_SLOTS.try_acquire().is_err(),
            "an unbounded validation endpoint is a denial-of-service surface"
        );

        drop(held);
        assert_eq!(
            CIPHERTEXT_VALIDATION_SLOTS.available_permits(),
            MAX_CONCURRENT_CIPHERTEXT_VALIDATIONS
        );
    }

    /// Build a wire envelope that still carries its ciphertext, as a client sends it.
    ///
    /// `staged_envelope_for_slot` builds the durable form, which has the ciphertext removed.
    /// Intake needs the form that still contains the bytes.
    fn staged_envelope_with_object(slot: Address, commitment: B256, object: &[u8]) -> Vec<u8> {
        let mut envelope =
            decode_input_envelope(&hex::decode(SDK_INPUT_ENVELOPE).unwrap()).unwrap();
        envelope.slotAddress = slot;
        envelope.encryptedVoteCommitment = commitment;
        envelope.encryptedVoteHash = keccak256(object);
        envelope.availabilityProof = Bytes::copy_from_slice(object);
        envelope.abi_encode_params()
    }

    /// Store a job and then move it to `state`.
    ///
    /// `store_new_job_with_object` admits only a new job in the created state, so a test that
    /// needs a later state stores the admission and then saves the transition.
    fn store_job_in_state(
        service: &AvailabilityService,
        job: &AvailabilityJob,
        object: &[u8],
        state: JobState,
    ) -> AvailabilityJob {
        let mut created = job.clone();
        created.state = JobState::Created;
        service.store_new_job_with_object(&created, object).unwrap();
        let mut moved = created;
        moved.state = state;
        service.save(&moved).unwrap();
        moved
    }

    fn output_job(id: &str, state: JobState, object: &[u8]) -> AvailabilityJob {
        AvailabilityJob {
            schema_version: AVAILABILITY_JOB_SCHEMA_VERSION,
            id: id.to_owned(),
            content_hash: keccak256(object).0,
            kind: JobKind::Output {
                e3_id: "1".to_owned(),
                ciphertext_commitment: [0x22; 32],
                compute_proof: vec![0x33; 8],
                deadline: 1_000,
            },
            state,
        }
    }

    fn test_publication(content_hash: [u8; 32]) -> PendingPublication {
        PendingPublication {
            content_hash,
            block_hash: "0xblock".to_owned(),
            block_number: 42,
            extrinsic_index: 7,
        }
    }

    /// ZEN2-11: a candidate proof must keep the coordinates that can replace it.
    ///
    /// The bridge answer is checked for the expected content hash, not for a valid Merkle path,
    /// so a `Ready` job can hold a proof Ethereum refuses. Discarding the Avail coordinates
    /// leaves no way to request a replacement, and the job retries one payload forever.
    #[test]
    fn a_ready_job_keeps_the_avail_coordinates_of_its_candidate_proof() {
        let service = test_service(1024);
        let object = b"ciphertext";
        let publication = test_publication(keccak256(object).0);
        let state = JobState::Ready {
            ethereum_payload: vec![0xaa; 4],
            commitment_transaction_hash: Some("0xcommit".to_owned()),
            publication: Some(publication.clone()),
        };
        let job = output_job("candidate-proof", state.clone(), object);
        store_job_in_state(&service, &job, object, state);

        let JobState::Ready {
            publication: stored,
            ..
        } = service.load_required(&job.id).unwrap().state
        else {
            panic!("expected a job with a candidate proof");
        };
        assert_eq!(stored, Some(publication));
    }

    /// ZEN2-11: a refused candidate returns to the state that asks for a replacement proof.
    ///
    /// The Avail bytes are already published, so the replacement costs one bridge request and no
    /// second publication.
    #[test]
    fn a_refused_candidate_proof_returns_to_awaiting_proof() {
        let service = test_service(1024);
        let object = b"ciphertext";
        let publication = test_publication(keccak256(object).0);
        let state = JobState::Ready {
            ethereum_payload: vec![0xaa; 4],
            commitment_transaction_hash: Some("0xcommit".to_owned()),
            publication: Some(publication.clone()),
        };
        let job = output_job("refused-proof", state.clone(), object);
        let mut job = store_job_in_state(&service, &job, object, state);

        service
            .recover_rejected_proof(
                &mut job,
                Some("0xcommit".to_owned()),
                Some(publication.clone()),
            )
            .unwrap();

        let stored = service.load_required(&job.id).unwrap();
        let JobState::AwaitingProof {
            publication: recovered,
            commitment_transaction_hash,
        } = stored.state
        else {
            panic!("a refused candidate must be able to request a replacement");
        };
        assert_eq!(recovered, publication);
        assert_eq!(commitment_transaction_hash, Some("0xcommit".to_owned()));
        // The bytes stay available, so the replacement pays for no second publication.
        assert_eq!(
            service.object_required(stored.content_hash).unwrap(),
            object
        );
    }

    /// ZEN2-11: a record written before the coordinates were kept must still decode.
    ///
    /// Such a job has nothing to ask the bridge with. It keeps its candidate proof and needs
    /// operator recovery rather than failing to load.
    #[test]
    fn a_legacy_ready_job_without_coordinates_decodes_and_is_not_recovered() {
        let service = test_service(1024);
        let object = b"ciphertext";
        let job = output_job(
            "legacy-ready",
            JobState::Ready {
                ethereum_payload: vec![0xaa; 4],
                commitment_transaction_hash: None,
                publication: Some(test_publication(keccak256(object).0)),
            },
            object,
        );
        let mut encoded = serde_json::to_value(&job).unwrap();
        encoded["state"]
            .as_object_mut()
            .unwrap()
            .remove("publication");

        let decoded =
            AvailabilityService::decode_job(&serde_json::to_vec(&encoded).unwrap()).unwrap();
        let JobState::Ready {
            publication,
            ethereum_payload,
            ..
        } = decoded.state.clone()
        else {
            panic!("expected a job with a candidate proof");
        };
        assert_eq!(publication, None);
        assert_eq!(ethereum_payload, vec![0xaa; 4]);

        // With no coordinates there is no replacement to request, so the state is unchanged.
        let mut legacy = decoded;
        store_job_in_state(&service, &legacy, object, legacy.state.clone());
        service
            .recover_rejected_proof(&mut legacy, None, None)
            .unwrap();
        assert!(matches!(legacy.state, JobState::Ready { .. }));
    }

    /// ZEN2-24: a submitted publication waits for finality before the job retires.
    ///
    /// Retirement clears the recovery material and can delete the local object. A transaction
    /// seen only at the chain head can be orphaned, and the job would then have no way back.
    #[test]
    fn a_publication_awaiting_finality_keeps_its_recovery_material() {
        let service = test_service(1024);
        let object = b"ciphertext";
        let publication = test_publication(keccak256(object).0);
        let state = JobState::AwaitingFinality {
            transaction_hash: "0xpublish".to_owned(),
            ethereum_payload: vec![0xaa; 4],
            commitment_transaction_hash: None,
            publication: Some(publication.clone()),
        };
        let job = output_job("awaiting-finality", state.clone(), object);
        let job = store_job_in_state(&service, &job, object, state);

        let stored = service.load_required(&job.id).unwrap();
        let JobState::AwaitingFinality {
            ethereum_payload,
            publication: stored_publication,
            ..
        } = stored.state.clone()
        else {
            panic!("expected a job that waits for finality");
        };
        // Everything a resend needs survives: the payload, the coordinates, and the bytes.
        assert_eq!(ethereum_payload, vec![0xaa; 4]);
        assert_eq!(stored_publication, Some(publication));
        assert_eq!(service.object_required(job.content_hash).unwrap(), object);
        let JobKind::Output { compute_proof, .. } = &stored.kind else {
            panic!("expected an output job");
        };
        assert!(
            !compute_proof.is_empty(),
            "a nonfinal publication must not clear the compute proof"
        );

        // The worker still schedules it, and startup validation still accepts it.
        assert!(service.pending_ids().unwrap().contains(&job.id));
        assert!(service.validate_storage().is_ok());

        // The view keeps the client waiting rather than reporting success.
        let view: AvailabilityJobView = (&stored).into();
        assert_eq!(view.status, "pending_availability");
        assert_eq!(view.tx_hash, Some("0xpublish".to_owned()));
    }

    /// ZEN2-24: only a finalized observation retires a job and releases its material.
    #[test]
    fn only_a_finalized_publication_retires_a_job() {
        let service = test_service(1024);
        let object = b"ciphertext";
        let state = JobState::AwaitingFinality {
            transaction_hash: "0xpublish".to_owned(),
            ethereum_payload: vec![0xaa; 4],
            commitment_transaction_hash: None,
            publication: Some(test_publication(keccak256(object).0)),
        };
        let job = output_job("finalized-publication", state.clone(), object);
        let mut job = store_job_in_state(&service, &job, object, state);
        assert!(service.pending_ids().unwrap().contains(&job.id));

        job.state = JobState::Submitted {
            transaction_hash: "0xpublish".to_owned(),
        };
        service.save(&job).unwrap();

        assert!(!service.pending_ids().unwrap().contains(&job.id));
        let stored = service.load_required(&job.id).unwrap();
        let JobKind::Output { compute_proof, .. } = stored.kind else {
            panic!("expected an output job");
        };
        assert!(compute_proof.is_empty());
    }

    /// ZEN2-22: the status refresh takes the same per-job ownership as the worker.
    ///
    /// Both paths load a copy, await an Ethereum read, and then save. Without one owner, a stale
    /// copy can replace newer durable progress and discard saved Avail coordinates.
    #[tokio::test]
    async fn a_status_refresh_does_not_write_while_the_worker_owns_the_job() {
        let service = test_service(1024);
        let object = b"ciphertext";
        let publication = test_publication(keccak256(object).0);
        let state = JobState::AwaitingProof {
            publication: publication.clone(),
            commitment_transaction_hash: None,
        };
        let job = output_job("contended-job", state.clone(), object);
        let job = store_job_in_state(&service, &job, object, state);

        // The worker owns the job while it awaits Avail.
        let owned = service.claim_job(&job.id).expect("the job is free");
        assert!(
            service.claim_job(&job.id).is_none(),
            "one job must have one owner"
        );

        // The refresh finds the job busy, so it reports the persisted view and writes nothing.
        let view = service
            .refreshed_view(&job.id)
            .await
            .unwrap()
            .expect("the job exists");
        assert_eq!(view.job_id, job.id);
        let JobState::AwaitingProof {
            publication: stored,
            ..
        } = service.load_required(&job.id).unwrap().state
        else {
            panic!("a busy job must keep its durable state");
        };
        assert_eq!(stored, publication);

        drop(owned);
        assert!(
            service.claim_job(&job.id).is_some(),
            "ownership must be released for the next step"
        );
    }

    /// ZEN2-23: a repeat of an existing statement must not consume funding quota.
    ///
    /// `existing_input_job` answers a replay without creating work, so the route can serve it
    /// before it touches the global window.
    #[tokio::test]
    async fn replaying_an_existing_statement_is_idempotent_without_new_work() {
        let service = test_service(4096);
        let slot = Address::repeat_byte(0x77);
        let object = b"voter-ciphertext";
        let envelope = staged_envelope_with_object(slot, B256::repeat_byte(0x11), object);

        // No job yet: the caller is a potential new admission and must reserve quota.
        assert!(service
            .existing_input_job("1", &envelope)
            .await
            .unwrap()
            .is_none());

        let (_, _, _, id) = service.input_identity("1", &envelope).unwrap();
        let job = AvailabilityJob {
            schema_version: AVAILABILITY_JOB_SCHEMA_VERSION,
            id: id.clone(),
            content_hash: keccak256(object).0,
            kind: JobKind::Input {
                e3_id: "1".to_owned(),
                staged_envelope: staged_envelope_for_slot(slot, B256::repeat_byte(0x11), object),
                deadline: no_deadline(),
                commitment_deadline: no_deadline(),
            },
            state: JobState::Created,
        };
        store_job_in_state(
            &service,
            &job,
            object,
            JobState::Submitted {
                transaction_hash: "0xdone".to_owned(),
            },
        );

        // The same statement now resolves to the stored job, with no new durable work.
        let replay = service
            .existing_input_job("1", &envelope)
            .await
            .unwrap()
            .expect("the statement already has a job");
        assert_eq!(replay.job_id, id);
        assert_eq!(replay.status, "success");
        assert_eq!(service.jobs.len(), 1);

        // A noncanonical alias of the same E3 is the same statement.
        let alias = service
            .existing_input_job("001", &envelope)
            .await
            .unwrap()
            .expect("an alias names the same statement");
        assert_eq!(alias.job_id, id);
        assert_eq!(service.jobs.len(), 1);
    }

    /// ZEN2-23: a failed job restarted under one identifier creates a fresh funding obligation,
    /// so it must not take the free replay path.
    #[tokio::test]
    async fn a_failed_job_is_not_a_free_replay() {
        let service = test_service(4096);
        let slot = Address::repeat_byte(0x77);
        let object = b"voter-ciphertext";
        let envelope = staged_envelope_with_object(slot, B256::repeat_byte(0x11), object);
        let (_, _, _, id) = service.input_identity("1", &envelope).unwrap();

        let mut job = AvailabilityJob {
            schema_version: AVAILABILITY_JOB_SCHEMA_VERSION,
            id: id.clone(),
            content_hash: keccak256(object).0,
            kind: JobKind::Input {
                e3_id: "1".to_owned(),
                staged_envelope: staged_envelope_for_slot(slot, B256::repeat_byte(0x11), object),
                deadline: no_deadline(),
                commitment_deadline: no_deadline(),
            },
            state: JobState::Created,
        };
        service.store_new_job_with_object(&job, object).unwrap();
        job.state = JobState::Failed {
            message: "availability promise expired".to_owned(),
        };
        service.save(&job).unwrap();

        assert!(
            service
                .existing_input_job("1", &envelope)
                .await
                .unwrap()
                .is_none(),
            "restarting a failed job must reserve funding capacity"
        );
    }

    /// ZEN2-23: an invalid envelope is refused before it reaches the free replay path.
    #[tokio::test]
    async fn the_replay_check_still_validates_the_envelope() {
        let service = test_service(4096);

        let error = service
            .existing_input_job("1", b"not-an-envelope")
            .await
            .unwrap_err();
        assert_eq!(
            input_rejection_message(&error),
            Some("The encoded vote envelope is invalid")
        );

        // Bytes that do not reproduce their committed hash are refused as well.
        let slot = Address::repeat_byte(0x77);
        let mut envelope =
            decode_input_envelope(&staged_envelope_with_object(slot, B256::ZERO, b"real")).unwrap();
        envelope.encryptedVoteHash = B256::repeat_byte(0x99);
        let error = service
            .existing_input_job("1", &envelope.abi_encode_params())
            .await
            .unwrap_err();
        assert_eq!(
            input_rejection_message(&error),
            Some("The encrypted vote does not match its committed hash")
        );

        let error = service
            .existing_input_job(
                "not-an-e3",
                &staged_envelope_with_object(slot, B256::ZERO, b"real"),
            )
            .await
            .unwrap_err();
        assert_eq!(
            input_rejection_message(&error),
            Some("The E3 identifier is invalid")
        );
    }
}
