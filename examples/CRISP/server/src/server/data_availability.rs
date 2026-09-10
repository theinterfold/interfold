// SPDX-License-Identifier: LGPL-3.0-only

//! Persistent publication jobs for CRISP's large encrypted objects.

use crate::{config::Config, server::models::e3_id_to_u256};
use alloy::{
    eips::{BlockId, BlockNumberOrTag},
    primitives::{keccak256, Address, Bytes, B256, U256},
    providers::{Provider, ProviderBuilder},
    signers::{local::PrivateKeySigner, SignerSync},
    sol,
    sol_types::SolValue,
};
use e3_data_availability::{
    AvailPublisher, AvailReader, DataAvailabilityPublisher, DataAvailabilityReader, DataReference,
    PendingPublication, ProofStatus,
};
use e3_evm_helpers::contracts::{E3Stage, InterfoldContractFactory, InterfoldRead, InterfoldWrite};
use evm_helpers::{CRISPContract, InputPublished, SimulateError};
use serde::{Deserialize, Serialize};
use sled::{transaction::Transactional, Db, Tree};
use std::{
    collections::HashSet,
    sync::{Arc, Mutex as StorageMutex},
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
const AVAILABILITY_JOB_SCHEMA_VERSION: u32 = 1;
const AVAILABLE_INPUT_REFERENCE_SCHEMA_VERSION: u32 = 1;

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

    pub async fn stage_input(
        &self,
        e3_id: &str,
        encoded_envelope: Vec<u8>,
    ) -> anyhow::Result<AvailabilityJobView> {
        let mut envelope = decode_input_envelope(&encoded_envelope)
            .map_err(|_| reject_input("The encoded vote envelope is invalid"))?;
        e3_data_availability::validate_object_bytes(&envelope.availabilityProof)
            .map_err(|_| reject_input("The encrypted vote is too large"))?;
        let actual = keccak256(&envelope.availabilityProof);
        if actual != envelope.encryptedVoteHash {
            return Err(reject_input(
                "The encrypted vote does not match its committed hash",
            ));
        }
        let object = envelope.availabilityProof.to_vec();

        // A proof system can produce more than one valid proof for the same public statement.
        // Keep the durable job keyed by that statement, not by the proof bytes, or retrying with
        // another valid proof can buy the same Avail publication twice.
        let request_identity = (
            envelope.slotAddress,
            envelope.encryptedVoteCommitment,
            envelope.parentIndexPlusOne,
        )
            .abi_encode();
        let id = self.job_id(b"input", e3_id, actual, &request_identity);
        if self.load(&id)?.is_some() {
            self.process(&id).await;
            let existing = self.load_required(&id)?;
            if !matches!(&existing.state, JobState::Failed { .. }) {
                return Ok((&existing).into());
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
        {
            // Serialize admission so concurrent requests cannot both pass the slot and capacity
            // checks. A slot can have one uncommitted promise at a time. Once that promise lands
            // on Ethereum, a later re-vote can be staged normally.
            let _storage = self
                .storage
                .lock()
                .map_err(|_| anyhow::anyhow!("data-availability storage lock is poisoned"))?;
            if let Some(existing) = self.load(&id)? {
                if !matches!(&existing.state, JobState::Failed { .. }) {
                    return Ok((&existing).into());
                }
            }
            if self
                .uncommitted_input_for_slot(e3_id, envelope.slotAddress, &id)?
                .is_some()
            {
                return Err(reject_input(
                    "A vote for this slot is already waiting for commitment",
                ));
            }
            // Persist the bytes and their recovery job atomically before an attestation can be
            // returned. The signature promises that this service received the exact object and
            // can resume after a restart.
            self.store_new_job_with_object(&job, &object)?;
        }
        self.process(&id).await;
        if matches!(&*self.backend, Backend::Mock) {
            // Local mode has no external finality delay. Drive every durable phase so callers
            // keep the synchronous developer experience while production remains asynchronous.
            self.process(&id).await;
            self.process(&id).await;
            self.process(&id).await;
        }
        Ok((&self.load_required(&id)?).into())
    }

    pub async fn stage_output(
        &self,
        e3_id: &str,
        ciphertext: Vec<u8>,
        ciphertext_commitment: [u8; 32],
        compute_proof: Vec<u8>,
    ) -> anyhow::Result<AvailabilityJobView> {
        e3_data_availability::validate_object_bytes(&ciphertext)?;
        let hash = keccak256(&ciphertext);
        // The output statement is the E3, exact ciphertext hash, and ciphertext commitment. The
        // RISC Zero seal proves that statement but is not its identity: another valid seal must be
        // an idempotent retry, not another paid Avail publication.
        let id = self.job_id(b"output", e3_id, hash, &ciphertext_commitment);
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
    pub async fn refreshed_view(&self, id: &str) -> anyhow::Result<Option<AvailabilityJobView>> {
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
                if self.input_is_committed(&job).await? {
                    job.state = JobState::Committed {
                        transaction_hash: "wallet-committed".to_owned(),
                    };
                    self.save(&job)?;
                }
            } else if self.ethereum_publication_exists(&job).await? {
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

    fn uncommitted_input_for_slot(
        &self,
        e3_id: &str,
        slot: Address,
        except_id: &str,
    ) -> anyhow::Result<Option<String>> {
        for entry in &self.jobs {
            let (_, value) = entry?;
            let job = Self::decode_job(&value)?;
            if job.id == except_id
                || !matches!(
                    job.state,
                    JobState::Created | JobState::AwaitingCommitment { .. }
                )
            {
                continue;
            }
            let JobKind::Input {
                e3_id: existing_e3,
                staged_envelope,
                ..
            } = &job.kind
            else {
                continue;
            };
            if existing_e3 == e3_id && decode_input_envelope(staged_envelope)?.slotAddress == slot {
                return Ok(Some(job.id));
            }
        }
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

    async fn process(&self, id: &str) {
        let Ok(_permit) = Arc::clone(&self.job_slots).acquire_owned().await else {
            warn!(job_id = id, "Data-availability worker is shutting down");
            return;
        };
        let _active_job = {
            let mut active = self
                .in_progress
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if !active.insert(id.to_owned()) {
                return;
            }
            ActiveJobGuard {
                jobs: &self.in_progress,
                id,
            }
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
        if !terminal && self.ethereum_publication_exists(&job).await? {
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
                    JobKind::Input { .. } if self.input_is_committed(&job).await? => {
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
                if self.input_is_committed(&job).await? {
                    job.state = JobState::Committed {
                        transaction_hash: "wallet-committed".to_owned(),
                    };
                    self.save(&job)?;
                }
            }
            JobState::Committed { transaction_hash } => {
                if matches!(&job.kind, JobKind::Input { .. })
                    && matches!(&*self.backend, Backend::Avail { .. })
                {
                    let (finalized_block, _) = self.finalized_block().await?;
                    if !self.input_is_committed_at(&job, finalized_block).await? {
                        return Ok(());
                    }
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
                    job.state = JobState::Ready {
                        ethereum_payload: abi_proof,
                        commitment_transaction_hash,
                    };
                    self.save(&job)?;
                }
            }
            JobState::Ready {
                ethereum_payload, ..
            } => match &job.kind {
                JobKind::Input { .. } => {
                    anyhow::ensure!(
                        self.input_is_committed(&job).await?,
                        "cannot finalize an input whose proof commitment is absent"
                    );
                    let receipt = self.finalize_input(&job, &ethereum_payload).await?;
                    job.state = JobState::Submitted {
                        transaction_hash: receipt.transaction_hash.to_string(),
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
                            job.state = JobState::Submitted {
                                transaction_hash: "already-finalized".to_owned(),
                            };
                            self.save(&job)?;
                            return Ok(());
                        }
                        E3Stage::Failed => {
                            job.state = JobState::Failed {
                                message:
                                    "the E3 failed before its aggregate ciphertext was published"
                                        .to_owned(),
                            };
                            self.save(&job)?;
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
                    let receipt = contract
                        .publish_ciphertext_output(
                            e3_id,
                            B256::from(job.content_hash),
                            B256::from(*ciphertext_commitment),
                            Bytes::copy_from_slice(compute_proof),
                            Bytes::copy_from_slice(&ethereum_payload),
                        )
                        .await
                        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
                    job.state = JobState::Submitted {
                        transaction_hash: receipt.transaction_hash.to_string(),
                    };
                    self.save(&job)?;
                }
            },
            JobState::Submitted { .. } | JobState::Failed { .. } => unreachable!(),
        }
        Ok(())
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

    fn job_id(
        &self,
        domain: &[u8],
        e3_id: &str,
        content_hash: B256,
        request_identity: &[u8],
    ) -> String {
        let mut identity = Vec::with_capacity(domain.len() + e3_id.len() + 64);
        identity.extend_from_slice(domain);
        identity.extend_from_slice(e3_id.as_bytes());
        identity.extend_from_slice(content_hash.as_slice());
        identity.extend_from_slice(keccak256(request_identity).as_slice());
        format!("0x{}", hex::encode(keccak256(identity)))
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
}
