// SPDX-License-Identifier: LGPL-3.0-only

//! Persistent publication jobs for CRISP's large encrypted objects.

use crate::{
    config::Config,
    server::{
        models::{canonical_e3_id, e3_id_to_u256},
        rate_limit::GlobalReservation,
        rpc,
    },
};
use alloy::{
    eips::{BlockId, BlockNumberOrTag},
    primitives::{keccak256, Address, Bytes, B256, U256},
    providers::{DynProvider, Provider},
    rpc::types::TransactionReceipt,
    signers::{local::PrivateKeySigner, SignerSync},
    sol,
    sol_types::SolValue,
};
use e3_bfv_client::client::compute_ct_commitment_with_params;
use e3_data_availability::{
    AvailPublisher, AvailReader, DataAvailabilityPublisher, DataAvailabilityReader, DataReference,
    PendingPublication, ProofStatus,
};
use e3_evm_helpers::contracts::{
    InterfoldContractFactory, InterfoldRead, InterfoldReadContract, InterfoldWrite,
};
use e3_fhe_params::{build_bfv_params_from_set_arc, encode_bfv_params, BfvParamSet, BfvPreset};
use evm_helpers::{is_insufficient_funds, CRISPContract, InputPublished, SimulateError};
use fhe::bfv::BfvParameters;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sled::{transaction::Transactional, Db, Tree};
use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, LazyLock, Mutex, MutexGuard, PoisonError},
    time::Duration,
};
use tokio::{sync::Semaphore, task::JoinSet};
use tracing::{info, warn};

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
// How long a relay record outlives the commitment cutoff of its round. The margin covers a local
// clock that runs ahead of the chain.
const RELAY_RECORD_RETENTION_SECONDS: u64 = 3_600;
/// The key of the relay ledger start time in the relayed-inputs tree. Every relay record key
/// starts with a decimal E3 identifier, so no round or slot prefix matches this key.
const RELAY_LEDGER_EPOCH_KEY: &[u8] = b"ledger-epoch";
/// How long a relayed job keeps the relay after a node refuses its send for lack of funds while
/// other transactions of the relay key are pending. Such a refusal normally clears within a few
/// blocks. A longer one, for example behind a stuck transaction, moves the job to the wallet path.
/// Clients wait ten minutes for the choice of sender, so the grace period ends inside that wait.
const RELAY_FUNDING_GRACE_SECONDS: u64 = 300;
/// The deadline of a job on the mock backend, which has none.
const NO_DEADLINE: u64 = u64::MAX;

/// Process-wide, because the limit protects the processor, and one process can serve more than
/// one round.
static CIPHERTEXT_VALIDATION_SLOTS: LazyLock<Semaphore> =
    LazyLock::new(|| Semaphore::new(MAX_CONCURRENT_CIPHERTEXT_VALIDATIONS));

type BfvTables = (Arc<BfvParameters>, B256);

/// BFV parameter tables and their circuit configuration identifier, by parameter-set index. The
/// secure tables are expensive to build and a parameter set has one fixed content.
static BFV_PARAMETERS_BY_PARAM_SET: LazyLock<Mutex<HashMap<u8, BfvTables>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Lock `mutex` and ignore poisoning. Every mutex here guards either `()` or a map whose single
/// operations cannot leave it inconsistent, and the durable state lives on disk.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Flatten an `eyre` report from a contract client into an `anyhow` error with the same text.
fn from_eyre(error: eyre::Report) -> anyhow::Error {
    anyhow::anyhow!(error.to_string())
}

fn required<T>(value: Option<T>, name: &str) -> anyhow::Result<T> {
    value.ok_or_else(|| anyhow::anyhow!("{name} is required"))
}

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
struct InputRejected(&'static str);

fn reject_input(message: &'static str) -> anyhow::Error {
    anyhow::Error::new(InputRejected(message))
}

/// A node refused a `publishInput` of the relay because the relay key cannot pay for it.
#[derive(Debug, thiserror::Error)]
#[error("the relay key cannot pay for the input commitment: {message}")]
struct RelayUnfunded {
    message: String,
    /// Other transactions of the relay key were pending. A node also refuses a transaction when
    /// the worst-case costs of all pending transactions of the key exceed its balance, and that
    /// refusal can clear when they are mined.
    other_transactions_pending: bool,
}

fn duration_u64(value: U256, name: &str) -> anyhow::Result<u64> {
    value
        .try_into()
        .map_err(|_| anyhow::anyhow!("{name} does not fit in u64"))
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

/// The circuit configuration identifier that Interfold binds to a parameter set at request time
/// (`ActiveCryptoConfig.configIdForParamSet`). Deriving it from the local tables proves that they
/// are the request-time parameters when it equals the stored `e3CryptoConfigIds` value.
fn crypto_config_id_for_params(params: &BfvParameters) -> B256 {
    keccak256(
        (
            keccak256(b"fhe.rs:BFV"),
            keccak256(encode_bfv_params(params)),
            keccak256(b"interfold-bfv-v5"),
        )
            .abi_encode(),
    )
}

/// The BFV tables for one on-chain parameter set, built once per process.
fn bfv_parameters_for_param_set(param_set: u8) -> anyhow::Result<BfvTables> {
    if let Some(cached) = lock(&BFV_PARAMETERS_BY_PARAM_SET).get(&param_set) {
        return Ok(cached.clone());
    }
    let preset = BfvPreset::from_on_chain_param_set(param_set)
        .ok_or_else(|| anyhow::anyhow!("unsupported BFV parameter set {param_set}"))?;
    let params = build_bfv_params_from_set_arc(BfvParamSet::from(preset));
    let entry = (params.clone(), crypto_config_id_for_params(&params));
    // The lock is released while the tables are built, so two callers can miss the cache at the
    // same time. Keep the first entry and return it, or a later insert replaces tables that the
    // first caller already holds.
    Ok(lock(&BFV_PARAMETERS_BY_PARAM_SET)
        .entry(param_set)
        .or_insert(entry)
        .clone())
}

/// Recompute the SAFE commitment of `ciphertext` and compare it with `expected`. This is the
/// processor-intensive part of intake, so the caller must hold a validation slot.
/// `compute_ct_commitment_with_params` refuses a ciphertext without exactly two components, which
/// keeps the commitment in agreement with the Noir circuit.
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

    #[derive(Debug, PartialEq)]
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

impl InputEnvelope {
    /// The parent index as the contract clients take it. A `uint40` always fits.
    fn parent_index(&self) -> u64 {
        self.parentIndexPlusOne.to::<u64>()
    }
}

/// What the worker does with a provisional input commitment on one pass.
#[derive(Debug, Clone, PartialEq, Eq)]
enum CommitmentStep {
    /// Finalized on Ethereum: record it and start the paid publication.
    Promote(String),
    /// The service relayed it and the chain head no longer shows it: it was reorganized out
    /// and not re-included, and nothing else will resend it.
    Recommit,
    /// Still pending at the head, or wallet-submitted and absent: keep waiting.
    Wait,
}

/// Decides the next step for a job in `AwaitingCommitment` from two Ethereum reads. A receipt is a
/// head observation, so a relayed commitment stays provisional until it is final. Only the relay
/// resubmits an orphaned commitment, also after its attestation expired: a wallet-submitted one
/// belongs to the voter.
fn commitment_step(
    relayed_transaction_hash: Option<&str>,
    is_final: bool,
    at_head: bool,
) -> CommitmentStep {
    if is_final {
        return CommitmentStep::Promote(
            relayed_transaction_hash
                .unwrap_or("wallet-committed")
                .to_owned(),
        );
    }
    match (relayed_transaction_hash, at_head) {
        (Some(_), false) => CommitmentStep::Recommit,
        _ => CommitmentStep::Wait,
    }
}

/// Whether `tree` holds at least `limit` keys that start with `prefix`. Reads at most `limit` keys.
fn holds_at_least(tree: &Tree, prefix: &str, limit: u32) -> sled::Result<bool> {
    let limit = limit as usize;
    let mut held = 0;
    for key in tree.scan_prefix(prefix).keys().take(limit) {
        key?;
        held += 1;
    }
    Ok(held == limit)
}

/// The current wall-clock time in Unix seconds.
fn wall_clock_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

/// Return the time from which the relay ledger in `tree` holds every relay of this service, and
/// record `now` as that time when the tree holds none.
///
/// The ledger cannot hold the relays of a round whose input window opened before this time, such
/// as the relays of an older server version or the records of a lost database. So `reserve_relay`
/// does not relay for such a round. Only the first start records the time, so a restart keeps it.
/// An unreadable time stops the start, because a new one would admit the rounds that opened
/// before it.
fn open_relay_ledger(tree: &Tree, now: u64) -> anyhow::Result<u64> {
    if let Some(stored) = tree.get(RELAY_LEDGER_EPOCH_KEY)? {
        let epoch = <[u8; 8]>::try_from(stored.as_ref())
            .map_err(|_| anyhow::anyhow!("the relay ledger start time is unreadable"))?;
        return Ok(u64::from_be_bytes(epoch));
    }
    tree.insert(RELAY_LEDGER_EPOCH_KEY, &now.to_be_bytes()[..])?;
    tree.flush()?;
    Ok(now)
}

/// Decode a persisted JSON record and refuse a schema version other than `expected`.
fn decode_versioned<T: DeserializeOwned>(
    bytes: &[u8],
    noun: &str,
    expected: u32,
    version: impl Fn(&T) -> u32,
) -> anyhow::Result<T> {
    let value: T = serde_json::from_slice(bytes)
        .map_err(|error| anyhow::anyhow!("cannot decode the {noun}: {error}"))?;
    anyhow::ensure!(
        version(&value) == expected,
        "unsupported {noun} schema version {}; expected {expected}",
        version(&value)
    );
    Ok(value)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum JobKind {
    Input {
        e3_id: String,
        staged_envelope: Vec<u8>,
        deadline: u64,
        commitment_deadline: u64,
        /// The voter asked that its own wallet send the commitment. The job then never takes the
        /// relay path. Records without this field load as `false`.
        #[serde(default)]
        send_from_wallet: bool,
    },
    Output {
        e3_id: String,
        ciphertext_commitment: [u8; 32],
        compute_proof: Vec<u8>,
        deadline: u64,
    },
}

impl JobKind {
    fn deadline(&self) -> u64 {
        match self {
            Self::Input { deadline, .. } | Self::Output { deadline, .. } => *deadline,
        }
    }

    /// Whether the voter asked that its own wallet send the commitment of this input.
    fn sends_from_wallet(&self) -> bool {
        matches!(
            self,
            Self::Input {
                send_from_wallet: true,
                ..
            }
        )
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
        /// The commitment transaction this service relayed, when it relayed one. A receipt is a
        /// head observation: the transaction can be reorganized out and never re-included, and
        /// `Committed` has no way back. The job therefore stays provisional here, the finality
        /// gate is the only exit, and an orphaned relay is resubmitted with a fresh attestation.
        /// `None` for a wallet-submitted job and for a record written before this field existed.
        #[serde(default)]
        relayed_transaction_hash: Option<String>,
    },
    Committed {
        transaction_hash: String,
    },
    AwaitingProof {
        publication: PendingPublication,
        commitment_transaction_hash: Option<String>,
        /// The candidate proof this job held before it asked for a replacement. A failed
        /// publication does not establish that the candidate is invalid (a transport error reaches
        /// the same path), so a job whose replacement never arrives retries this proof. `None` for
        /// a job that never held a candidate and for a record written before this field existed.
        #[serde(default)]
        last_candidate: Option<Vec<u8>>,
    },
    Ready {
        ethereum_payload: Vec<u8>,
        commitment_transaction_hash: Option<String>,
        /// The Avail coordinates that produced this candidate proof. The bridge answer is checked
        /// for the expected content hash, not for a valid Merkle path, so Ethereum can refuse the
        /// proof. The coordinates let a refused candidate be replaced by a fresh proof for bytes
        /// that Avail already holds. `None` decodes a record written before this field existed;
        /// such a job keeps its candidate proof and has no automatic replacement path.
        #[serde(default)]
        publication: Option<PendingPublication>,
    },
    /// A publication transaction is on Ethereum but is not yet in finalized state.
    ///
    /// Retiring a job clears its recovery material and can delete the local object, so a job
    /// stops only on a finalized observation. The payload and the Avail coordinates stay durable,
    /// so an orphaned transaction can be sent again.
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

impl JobState {
    fn is_terminal(&self) -> bool {
        matches!(self, Self::Submitted { .. } | Self::Failed { .. })
    }

    fn is_failed(&self) -> bool {
        matches!(self, Self::Failed { .. })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct AvailabilityJob {
    schema_version: u32,
    id: String,
    content_hash: [u8; 32],
    kind: JobKind,
    state: JobState,
}

impl AvailabilityJob {
    fn new(id: String, content_hash: [u8; 32], kind: JobKind) -> Self {
        Self {
            schema_version: AVAILABILITY_JOB_SCHEMA_VERSION,
            id,
            content_hash,
            kind,
            state: JobState::Created,
        }
    }

    fn decode(bytes: &[u8]) -> anyhow::Result<Self> {
        decode_versioned(
            bytes,
            "data-availability job",
            AVAILABILITY_JOB_SCHEMA_VERSION,
            |job: &Self| job.schema_version,
        )
    }

    /// The E3 and the decoded staged envelope of an input job.
    fn input(&self) -> anyhow::Result<(U256, InputEnvelope)> {
        let JobKind::Input {
            e3_id,
            staged_envelope,
            ..
        } = &self.kind
        else {
            anyhow::bail!("data-availability job {} is not an input job", self.id);
        };
        Ok((
            e3_id_to_u256(e3_id)?,
            InputEnvelope::abi_decode_params_validate(staged_envelope)?,
        ))
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct AvailabilityJobView {
    pub job_id: String,
    pub status: String,
    pub tx_hash: Option<String>,
    pub encoded_proof: Option<String>,
    pub message: Option<String>,
}

/// The result of one `stage_input` call.
pub struct StagedInput {
    pub view: AvailabilityJobView,
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
    pub fn from_event(e3_id: String, event: &InputPublished) -> anyhow::Result<Self> {
        Ok(Self {
            schema_version: AVAILABLE_INPUT_REFERENCE_SCHEMA_VERSION,
            e3_id,
            content_hash: event.encryptedVoteHash.0,
            availability_block: event.availabilityBlock,
            availability_leaf_index: event.availabilityLeafIndex,
            index: u64::try_from(event.index).map_err(|_| {
                anyhow::anyhow!("the input index {} does not fit in u64", event.index)
            })?,
            commitment: event.encryptedVoteCommitment.0,
            slot: event.slotAddress.into(),
            parent_index_plus_one: event.parentIndexPlusOne.to::<u64>(),
        })
    }

    fn decode(bytes: &[u8]) -> anyhow::Result<Self> {
        decode_versioned(
            bytes,
            "available-input reference",
            AVAILABLE_INPUT_REFERENCE_SCHEMA_VERSION,
            |reference: &Self| reference.schema_version,
        )
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

/// A stored transaction hash as a client may show it, or `None` for a placeholder. The service
/// stores `already-committed`, `wallet-committed`, or `already-finalized` where it did not send
/// the transaction and does not know its hash, and a client must not link those as transactions.
fn reported_transaction(hash: &str) -> Option<String> {
    (!matches!(
        hash,
        "already-committed" | "wallet-committed" | "already-finalized"
    ))
    .then(|| hash.to_owned())
}

impl From<&AvailabilityJob> for AvailabilityJobView {
    fn from(job: &AvailabilityJob) -> Self {
        let proof = |payload: &[u8]| Some(format!("0x{}", hex::encode(payload)));
        let (status, tx_hash, encoded_proof, message) = match &job.state {
            JobState::Created => ("pending_commitment", None, None, None),
            // A relayed commitment is the service's own transaction. Report it as pending so a
            // client does not sign a second commitment with its wallet; the payload is still
            // exposed for a client that wants the direct path after a relay failure.
            JobState::AwaitingCommitment {
                ethereum_payload,
                relayed_transaction_hash: Some(hash),
                ..
            } => (
                "pending_availability",
                reported_transaction(hash),
                proof(ethereum_payload),
                None,
            ),
            JobState::AwaitingCommitment {
                ethereum_payload, ..
            } => ("ready_for_commitment", None, proof(ethereum_payload), None),
            JobState::Committed { transaction_hash } => (
                "pending_availability",
                reported_transaction(transaction_hash),
                None,
                None,
            ),
            JobState::AwaitingProof {
                commitment_transaction_hash: hash,
                ..
            }
            | JobState::Ready {
                commitment_transaction_hash: hash,
                ..
            } => (
                "pending_availability",
                hash.as_deref().and_then(reported_transaction),
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
                reported_transaction(transaction_hash),
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

/// Limits on the input commitments that this service sends and pays for.
///
/// The limits never refuse an input. Past a limit, this service still stores and signs the input,
/// and the voter's wallet sends the commitment. A mask needs no signature from the slot owner, and
/// `publishInput` needs this service's signature, so a refusal would let any account stop a slot
/// owner from voting.
#[derive(Clone, Copy)]
struct RelayPolicy {
    /// False when nothing may be relayed: on Ethereum mainnet without `MAINNET_RELAY`, or with a
    /// limit of zero. This also stops jobs that were chosen for the relay earlier.
    enabled: bool,
    /// Relayed commitments for one slot in one round.
    max_per_slot: u32,
    /// Relayed commitments in one round, across all slots. `None` sets no round limit.
    max_per_round: Option<u32>,
    /// The server key balance, in wei, below which the service stops relaying.
    min_balance: Option<U256>,
}

impl RelayPolicy {
    fn new(
        chain_id: u64,
        mainnet_relay: bool,
        max_per_slot: u32,
        max_per_round: Option<u32>,
        min_balance: Option<U256>,
    ) -> Self {
        Self {
            enabled: (chain_id != 1 || mainnet_relay)
                && max_per_slot > 0
                && max_per_round != Some(0),
            max_per_slot,
            max_per_round,
            min_balance,
        }
    }
}

/// Owns persistent publication state and resumes incomplete jobs after restart.
#[derive(Clone)]
pub struct AvailabilityService {
    jobs: Tree,
    objects: Tree,
    input_retrievals: Tree,
    backend: Arc<Backend>,
    in_progress: Arc<Mutex<HashSet<String>>>,
    storage: Arc<Mutex<()>>,
    job_slots: Arc<Semaphore>,
    /// One record for each input whose commitment this service chose to relay, keyed by round,
    /// slot, and job. The relay limits count these records, so the limits hold across a restart.
    /// The tree also holds the ledger start time, at `RELAY_LEDGER_EPOCH_KEY`.
    relayed_inputs: Tree,
    /// The time from which `relayed_inputs` holds every relay of this service
    /// (`open_relay_ledger`).
    relay_ledger_epoch: u64,
    /// The round records of the indexer (the default tree). `reserve_relay` reads the input
    /// window of a round from them.
    round_records: Tree,
    /// Serializes relay decisions, so concurrent job steps cannot pass one limit together.
    relay_decisions: Arc<Mutex<()>>,
    /// The chain time of the first funds refusal of each relayed job in its grace period
    /// (`relay_funding_grace_ended`). A restart clears it, which only starts the grace again.
    relay_funding_refusals: Arc<Mutex<HashMap<String, u64>>>,
    relay: RelayPolicy,
    http_rpc_url: String,
    private_key: String,
    interfold_address: Address,
    e3_program_address: Address,
    input_duration_seconds: u64,
    proof_lead_seconds: u64,
    max_pending_bytes: u64,
}

struct ActiveJobGuard<'a> {
    jobs: &'a Mutex<HashSet<String>>,
    id: &'a str,
}

impl Drop for ActiveJobGuard<'_> {
    fn drop(&mut self) {
        lock(self.jobs).remove(self.id);
    }
}

impl AvailabilityService {
    pub fn new(db: &Db, config: &Config) -> anyhow::Result<Self> {
        let backend = match config.data_availability_mode().as_str() {
            "mock" => Backend::Mock,
            "avail" => {
                let rpc_url = required(config.avail_rpc_url.as_deref(), "AVAIL_RPC_URL")?;
                Backend::Avail {
                    publisher: Arc::new(AvailPublisher::new(
                        rpc_url,
                        required(config.avail_app_id, "AVAIL_APP_ID")?,
                        required(config.avail_seed.as_deref(), "AVAIL_SEED")?,
                        required(
                            config.avail_bridge_api_url.as_deref(),
                            "AVAIL_BRIDGE_API_URL",
                        )?,
                        config.chain_id,
                    )?),
                    reader: Arc::new(AvailReader::new(rpc_url)?),
                }
            }
            other => anyhow::bail!("unsupported DATA_AVAILABILITY_MODE '{other}'"),
        };
        let relayed_inputs = db.open_tree("data-availability-relayed-inputs")?;
        let service =
            Self {
                jobs: db.open_tree("data-availability-jobs")?,
                objects: db.open_tree("data-availability-objects")?,
                input_retrievals: db.open_tree("data-availability-input-retrievals")?,
                backend: Arc::new(backend),
                in_progress: Arc::default(),
                storage: Arc::default(),
                job_slots: Arc::new(Semaphore::new(MAX_CONCURRENT_JOB_STEPS)),
                relay_ledger_epoch: open_relay_ledger(&relayed_inputs, wall_clock_seconds())?,
                relayed_inputs,
                round_records: (**db).clone(),
                relay_decisions: Arc::default(),
                relay_funding_refusals: Arc::default(),
                relay: RelayPolicy::new(
                    config.chain_id,
                    config.mainnet_relay,
                    config.relay_max_inputs_per_slot,
                    config.relay_max_inputs_per_round,
                    config.relay_min_balance()?,
                ),
                http_rpc_url: config.http_rpc_url.clone(),
                private_key: config.private_key.clone(),
                interfold_address: config.interfold_address.parse().map_err(|error| {
                    anyhow::anyhow!("the Interfold address is invalid: {error}")
                })?,
                e3_program_address: config.e3_program_address.parse().map_err(|error| {
                    anyhow::anyhow!("the E3 program address is invalid: {error}")
                })?,
                input_duration_seconds: config.e3_duration,
                proof_lead_seconds: config.avail_proof_lead(),
                max_pending_bytes: config.data_availability_max_pending_bytes,
            };
        service.validate_storage()?;
        Ok(service)
    }

    fn is_avail(&self) -> bool {
        matches!(&*self.backend, Backend::Avail { .. })
    }

    /// The block that advances or retires a job: finalized on Avail, because a head observation
    /// can be reorganized away. The mock backend has no finality delay and reads the head.
    fn settled(&self) -> BlockId {
        if self.is_avail() {
            BlockId::finalized()
        } else {
            BlockId::latest()
        }
    }

    fn signer(&self) -> anyhow::Result<PrivateKeySigner> {
        self.private_key
            .parse()
            .map_err(|error| anyhow::anyhow!("invalid signer key: {error}"))
    }

    /// A read provider on the shared, timeout-bounded HTTP client.
    fn provider(&self) -> anyhow::Result<DynProvider> {
        rpc::http_provider(&self.http_rpc_url).map_err(from_eyre)
    }

    async fn crisp(&self) -> anyhow::Result<CRISPContract> {
        CRISPContract::new(
            &self.http_rpc_url,
            &self.private_key,
            &self.e3_program_address.to_string(),
        )
        .await
        .map_err(from_eyre)
    }

    async fn interfold_read(&self) -> anyhow::Result<InterfoldReadContract> {
        InterfoldContractFactory::create_read(
            &self.http_rpc_url,
            &self.interfold_address.to_string(),
        )
        .await
        .map_err(from_eyre)
    }

    /// Check the post-key input duration against the current CRISP contract values.
    pub async fn validate_onchain_configuration(&self) -> anyhow::Result<()> {
        if !self.is_avail() {
            return Ok(());
        }
        let contract = self.crisp().await?;
        let onchain = duration_u64(
            contract
                .availability_finalization_window()
                .await
                .map_err(from_eyre)?,
            "CRISP finalization window",
        )?;
        anyhow::ensure!(
            onchain == self.proof_lead_seconds,
            "AVAIL_PROOF_LEAD_SECONDS ({}) does not match CRISPProgram.availabilityFinalizationWindow() ({onchain})",
            self.proof_lead_seconds
        );
        let voting = duration_u64(
            contract
                .minimum_voting_duration()
                .await
                .map_err(from_eyre)?,
            "minimum voting duration",
        )?;
        let required = voting
            .checked_add(onchain)
            .ok_or_else(|| anyhow::anyhow!("required CRISP input duration overflows u64"))?;
        anyhow::ensure!(
            self.input_duration_seconds >= required,
            "E3_DURATION ({}) is shorter than the current on-chain voting and availability windows ({required})",
            self.input_duration_seconds
        );
        Ok(())
    }

    /// Check that the submitted bytes reproduce the commitment their ballot proof binds.
    ///
    /// The Honk public inputs bind `encryptedVoteCommitment` but not `encryptedVoteHash`. A caller
    /// could otherwise copy a valid proof tuple, attach different bytes with their matching hash,
    /// and make the service attest and pay for a ciphertext that the Secure Process rejects.
    /// Votes, updates, and masks get the same check. The check is for intake only: a committed job
    /// keeps its recovery work.
    async fn validate_input_ciphertext(
        &self,
        e3_id: U256,
        ciphertext: Bytes,
        commitment: B256,
    ) -> anyhow::Result<()> {
        let interfold = self.interfold_read().await?;
        let e3 = interfold.get_e3(e3_id).await.map_err(from_eyre)?;
        let (params, config_id) = bfv_parameters_for_param_set(e3.paramSet)?;
        // Use the local tables only when they are the tables the request accepted. Otherwise a
        // recomputed commitment answers for a different parameter set and rejects honest ballots.
        let request_config_id = interfold
            .get_e3_crypto_config_id(e3_id)
            .await
            .map_err(from_eyre)?;
        anyhow::ensure!(
            request_config_id == config_id,
            "local BFV parameters do not match the request-time configuration for E3 {e3_id}"
        );

        // Bound the processor work at this public endpoint, and run it on a blocking thread so it
        // does not hold the asynchronous runtime.
        let _validation_slot = CIPHERTEXT_VALIDATION_SLOTS
            .acquire()
            .await
            .map_err(|_| anyhow::anyhow!("the ciphertext validation limiter is closed"))?;
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

    /// Derive the durable job identity for one input statement, with the checks that need no
    /// chain access. The replay path and admission both use it, so both agree on what "the same
    /// statement" means.
    fn input_identity(
        &self,
        e3_id: &str,
        encoded_envelope: &[u8],
    ) -> anyhow::Result<(String, InputEnvelope, B256, String)> {
        let canonical =
            canonical_e3_id(e3_id).map_err(|_| reject_input("The E3 identifier is invalid"))?;
        let envelope = InputEnvelope::abi_decode_params_validate(encoded_envelope)
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
        // Key the job by that statement, not by the proof bytes, or retrying with another valid
        // proof can buy the same Avail publication twice.
        let request_identity = (
            envelope.slotAddress,
            envelope.encryptedVoteCommitment,
            envelope.parentIndexPlusOne,
        )
            .abi_encode();
        let id = self.job_id(b"input", &canonical, actual, &request_identity)?;
        Ok((canonical, envelope, actual, id))
    }

    /// Run one step of the job `id` and return its view. `None` when there is no job, or when it
    /// failed: a failed job restarts under the same identifier, which creates a fresh funding
    /// obligation and must take a reservation.
    async fn replay(&self, id: &str) -> anyhow::Result<Option<AvailabilityJobView>> {
        if self.load(id)?.is_none() {
            return Ok(None);
        }
        self.process(id).await;
        let existing = self.load_required(id)?;
        Ok((!existing.state.is_failed()).then(|| (&existing).into()))
    }

    /// Return the view of an existing non-failed job for this statement, if there is one.
    ///
    /// A repeat of a statement that already has durable work is idempotent: it creates no job,
    /// signs no new attestation, and pays for no publication. The route therefore answers it
    /// without a funding reservation. Charging a replay would let one caller spend the window that
    /// new votes need. The caller traffic window still bounds a replay loop.
    pub async fn existing_input_job(
        &self,
        e3_id: &str,
        encoded_envelope: &[u8],
    ) -> anyhow::Result<Option<AvailabilityJobView>> {
        let (_, _, _, id) = self.input_identity(e3_id, encoded_envelope)?;
        self.replay(&id).await
    }

    /// Stage one input statement for publication.
    ///
    /// `reservation` is the caller's slot of the relay funding window. It is committed inside
    /// `admit_input` and released on every path that admits nothing.
    ///
    /// `send_from_wallet` records the voter's request that its own wallet send the commitment. It
    /// is not part of the job identity: a statement that already has a job keeps the choice that
    /// the job was created with. Only a failed job, staged again under the same identifier, takes
    /// the choice of the new request.
    pub async fn stage_input(
        &self,
        e3_id: &str,
        encoded_envelope: Vec<u8>,
        send_from_wallet: bool,
        reservation: Option<GlobalReservation<'_>>,
    ) -> anyhow::Result<StagedInput> {
        // The numeric parser accepts leading zeros, so `input_identity` canonicalizes the E3
        // identifier before it reaches a job ID, a durable record, or a contract call.
        let (e3_id, mut envelope, actual, id) = self.input_identity(e3_id, &encoded_envelope)?;
        if let Some(view) = self.replay(&id).await? {
            return Ok(StagedInput { view });
        }

        let e3_id_value =
            e3_id_to_u256(&e3_id).map_err(|_| reject_input("The E3 identifier is invalid"))?;
        // An input that Ethereum already committed needs its publication, for example after this
        // service lost its database. Its input ID binds the content hash that `input_identity`
        // checked, so these are the committed bytes. The contract refuses the new-input checks for
        // a committed input, and `verify` refuses the round until the input is published.
        let committed = self
            .input_fact(e3_id_value, &envelope, BlockId::latest(), false)
            .await?;
        // The object has its own content-addressed record. Keep it out of the job and out of its
        // staged ABI envelope.
        let object = std::mem::take(&mut envelope.availabilityProof);
        let contract = self.crisp().await?;
        if !committed {
            // Reject invalid Noir proofs before the service pays an Avail submission fee.
            contract
                .validate_input_proof(
                    e3_id_value,
                    envelope.noirProof.clone(),
                    envelope.slotAddress,
                    envelope.encryptedVoteCommitment,
                    envelope.encryptedVoteHash,
                    envelope.parent_index(),
                )
                .await?;
            // The proof binds the commitment, not the bytes. Check the bytes against that
            // commitment before this service attests to them or spends funds on their publication.
            self.validate_input_ciphertext(
                e3_id_value,
                object.clone(),
                envelope.encryptedVoteCommitment,
            )
            .await?;
        }

        // Mock mode stores the real cutoff too: the relay record of the input keeps it for pruning.
        let commitment_deadline = contract
            .input_commitment_deadline(e3_id_value)
            .await
            .map_err(from_eyre)?;
        let deadline = if self.is_avail() {
            let (input_deadline, deadline, now) = self.e3_deadlines(e3_id_value).await?;
            if !committed && commitment_deadline <= now {
                return Err(reject_input("The vote commitment deadline has passed"));
            }
            // `finalizeInput` refuses a receipt after the compute deadline, so a committed input
            // cannot be recovered after it. Its job could only fail, and a failed job does not
            // answer a repeat of its statement, so each repeat would hold a funding reservation.
            if committed && now > deadline {
                return Err(reject_input("The vote finalization deadline has passed"));
            }
            anyhow::ensure!(
                input_deadline.saturating_sub(commitment_deadline) >= self.proof_lead_seconds,
                "the CRISP finalization tail is shorter than AVAIL_PROOF_LEAD_SECONDS"
            );
            deadline
        } else {
            NO_DEADLINE
        };

        let job = AvailabilityJob::new(
            id.clone(),
            actual.0,
            JobKind::Input {
                e3_id,
                staged_envelope: envelope.abi_encode_params(),
                deadline,
                commitment_deadline,
                send_from_wallet,
            },
        );
        if let Some(view) = self.admit_input(&job, &object, reservation)? {
            // A concurrent request admitted the same statement first, and this reservation went
            // back to the window.
            return Ok(StagedInput { view });
        }
        // The reservation is committed and the job is durable. Cancelling this future leaves both
        // in place for the background worker. Local mode has no external finality delay, so it
        // drives every durable phase here.
        for _ in 0..if self.is_avail() { 1 } else { 4 } {
            self.process(&id).await;
        }
        Ok(StagedInput {
            view: (&self.load_required(&id)?).into(),
        })
    }

    /// The input deadline, the compute deadline, and the chain time of one E3.
    async fn e3_deadlines(&self, e3_id: U256) -> anyhow::Result<(u64, u64, u64)> {
        let interfold = self.interfold_read().await?;
        let e3 = interfold.get_e3(e3_id).await.map_err(from_eyre)?;
        let deadlines = interfold.get_deadlines(e3_id).await.map_err(from_eyre)?;
        Ok((
            duration_u64(e3.inputWindow[1], "input deadline")?,
            duration_u64(deadlines.computeDeadline, "compute deadline")?,
            self.chain_timestamp().await?,
        ))
    }

    pub async fn stage_output(
        &self,
        e3_id: &str,
        ciphertext: Vec<u8>,
        ciphertext_commitment: [u8; 32],
        compute_proof: Vec<u8>,
    ) -> anyhow::Result<AvailabilityJobView> {
        // `/state/add-result` is unauthenticated and the numeric parser accepts leading zeros.
        // Canonicalize the identifier at entry so every alias of one E3 resolves to one job.
        let e3_id = canonical_e3_id(e3_id)?;
        e3_data_availability::validate_object_bytes(&ciphertext)?;
        let hash = keccak256(&ciphertext);
        // The output statement is the E3, exact ciphertext hash, and ciphertext commitment. The
        // OpenVM seal proves that statement but is not its identity: another valid seal must be
        // an idempotent retry, not another paid Avail publication.
        let id = self.job_id(b"output", &e3_id, hash, &ciphertext_commitment)?;
        if let Some(job) = self.load(&id)? {
            return Ok((&job).into());
        }
        let e3_id_value = e3_id_to_u256(&e3_id)?;
        let deadline = if self.is_avail() {
            anyhow::ensure!(
                self.e3_stage(e3_id_value, BlockId::latest()).await? == StoredE3Stage::KeyPublished,
                "the E3 is not accepting an aggregate ciphertext"
            );
            let (input_deadline, deadline, now) = self.e3_deadlines(e3_id_value).await?;
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
            NO_DEADLINE
        };

        // The endpoint is reachable over HTTP. Do not let an arbitrary caller spend the Avail
        // signer balance: first execute the exact CRISP proof check that Interfold will use once
        // the VectorX receipt exists. Invalid output never becomes durable work.
        self.crisp()
            .await?
            .validate_compute_output(
                e3_id_value,
                hash,
                B256::from(ciphertext_commitment),
                Bytes::copy_from_slice(&compute_proof),
            )
            .await
            .map_err(|error| {
                anyhow::anyhow!("the aggregate ciphertext proof is not acceptable: {error}")
            })?;

        let job = AvailabilityJob::new(
            id.clone(),
            hash.0,
            JobKind::Output {
                e3_id,
                ciphertext_commitment,
                compute_proof,
                deadline,
            },
        );
        {
            let _storage = lock(&self.storage);
            if let Some(job) = self.load(&id)? {
                return Ok((&job).into());
            }
            self.store_new_job_with_object(&job, &ciphertext)?;
        }
        if !self.is_avail() {
            self.process(&id).await;
            self.process(&id).await;
        }
        Ok((&self.load_required(&id)?).into())
    }

    /// Read a job after reconciling wallet-submitted work with Ethereum.
    ///
    /// A browser can close after its input commitment is mined but before the background worker
    /// observes it, and returning the cached `AwaitingCommitment` state would offer the same
    /// transaction again. This bounded read checks the one relevant on-chain fact first. A slow RPC
    /// does not make the status endpoint unavailable; the durable worker still retries.
    ///
    /// The refresh takes the same per-job ownership as the worker. Both paths load a copy, await
    /// an Ethereum read, and then save, so without one owner a status refresh can save a state it
    /// loaded before the worker made durable progress, discard saved Avail coordinates, and buy
    /// another publication. A request that finds the job busy returns the persisted view and
    /// writes nothing.
    pub async fn refreshed_view(&self, id: &str) -> anyhow::Result<Option<AvailabilityJobView>> {
        let Some(job) = self.load(id)? else {
            return Ok(None);
        };
        // Answer a `Created` job from storage without the job claim. The refresh never advances
        // this state, and a claim held by a poll makes the worker skip the job for a whole pass.
        if matches!(job.state, JobState::Created) || job.state.is_terminal() {
            return Ok(Some((&job).into()));
        }
        let Some(_active_job) = self.claim_job(id) else {
            return Ok(Some((&job).into()));
        };
        // Load again under ownership: the copy above can already be stale.
        let Some(mut job) = self.load(id)? else {
            return Ok(None);
        };
        if job.state.is_terminal() {
            return Ok(Some((&job).into()));
        }

        let refresh = async {
            // Advance only on finalized state: `Committed` starts the paid Avail publication, and
            // an orphaned commitment would leave the attestation unrenewable.
            if matches!(job.state, JobState::AwaitingCommitment { .. }) {
                if self.input_committed(&job, BlockId::finalized()).await? {
                    let state = JobState::Committed {
                        transaction_hash: "wallet-committed".to_owned(),
                    };
                    self.advance(&mut job, state)?;
                }
            } else if self.publication_exists(&job, self.settled()).await? {
                let state = JobState::Submitted {
                    transaction_hash: "already-finalized".to_owned(),
                };
                self.advance(&mut job, state)?;
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
        let key = hex::decode(hash.strip_prefix("0x").unwrap_or(hash))?;
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

    /// Store a new object's bytes and recovery job as one durable admission.
    ///
    /// A job without its object cannot progress, while an object without a job consumes the
    /// bounded pending-storage allowance forever. One sled transaction prevents either partial
    /// state after a crash.
    fn store_new_job_with_object(
        &self,
        job: &AvailabilityJob,
        object: &[u8],
    ) -> anyhow::Result<()> {
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
        let mut required = if existing.is_some() {
            0
        } else {
            object.len() as u64
        };
        for entry in self.objects.iter() {
            required = required.saturating_add(entry?.1.len() as u64);
        }
        anyhow::ensure!(
            required <= self.max_pending_bytes,
            "data-availability pending storage is full; configured limit is {} bytes",
            self.max_pending_bytes
        );

        let encoded_job = serde_json::to_vec(job)?;
        let abort = |message: &str| {
            sled::transaction::ConflictableTransactionError::Abort(sled::Error::Unsupported(
                message.to_owned(),
            ))
        };
        (&self.objects, &self.jobs).transaction(|(objects, jobs)| {
            // A failed job is replaced; any other stored job keeps its record.
            let write_job = match jobs.get(job.id.as_bytes())? {
                None => true,
                Some(stored) => {
                    let stored = AvailabilityJob::decode(&stored)
                        .map_err(|error| abort(&error.to_string()))?;
                    if stored.content_hash != job.content_hash {
                        return Err(abort(
                            "data-availability job ID is bound to another content hash",
                        ));
                    }
                    stored.state.is_failed()
                }
            };
            let object_stored = objects.get(job.content_hash)?.is_some();
            if write_job {
                if !object_stored {
                    objects.insert(job.content_hash.as_slice(), object)?;
                }
                jobs.insert(job.id.as_bytes(), encoded_job.as_slice())?;
            } else if !object_stored {
                return Err(abort("data-availability job exists without its object"));
            }
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
    /// slot owner from getting an attestation for a different statement. The bounded object
    /// storage, the caller rate limits, and the proof and deadline checks are the only limits on
    /// new work. Admission does not change retention: `save` releases object bytes only when no
    /// other non-terminal job uses them.
    ///
    /// The reservation is committed in the same synchronous step, under the storage lock, that
    /// writes the durable job, with no await between them. A cancelled request (the client closes
    /// the connection during a later await) therefore cannot release quota for work that stays
    /// retrievable and can still spend relay funds. A repeat statement or a storage refusal drops
    /// the reservation, which returns the slot.
    fn admit_input(
        &self,
        job: &AvailabilityJob,
        object: &[u8],
        reservation: Option<GlobalReservation<'_>>,
    ) -> anyhow::Result<Option<AvailabilityJobView>> {
        // Serialize admission so concurrent requests cannot both pass the capacity check.
        let _storage = lock(&self.storage);
        if let Some(existing) = self.load(&job.id)? {
            if !existing.state.is_failed() {
                return Ok(Some((&existing).into()));
            }
        }
        // Persist the bytes and their recovery job atomically before an attestation can be
        // returned. The signature promises that this service received the exact object and can
        // resume after a restart.
        match self.store_new_job_with_object(job, object) {
            Ok(()) => {
                if let Some(reservation) = reservation {
                    reservation.commit();
                }
                Ok(None)
            }
            Err(error) => {
                if let Some(reservation) = reservation {
                    self.settle_uncertain_admission(job, reservation);
                }
                Err(error)
            }
        }
    }

    /// Decide a reservation whose admission reported an error.
    ///
    /// The store transaction may have applied before a later step (the flush) failed, so the call
    /// result does not say whether the job exists. Judge by the record: a live record is admitted
    /// work, so its slot stays taken. A missing record, or one still `Failed` (the earlier job
    /// this call was replacing), means the write did not apply and the slot goes back. A read
    /// error keeps the slot: counting work that was not admitted costs one slot for one window,
    /// while releasing quota for admitted work is the bug.
    fn settle_uncertain_admission(
        &self,
        job: &AvailabilityJob,
        reservation: GlobalReservation<'_>,
    ) {
        let admitted = match self.load(&job.id) {
            Ok(stored) => stored.is_some_and(|stored| !stored.state.is_failed()),
            Err(error) => {
                warn!(job_id = job.id.as_str(), %error, "Could not read a job after a failed admission; keeping its reservation");
                true
            }
        };
        if admitted {
            reservation.commit();
        }
    }

    /// Retrieve bytes named by a receipt that the Ethereum contract already accepted.
    pub async fn retrieve(&self, reference: DataReference) -> anyhow::Result<Vec<u8>> {
        if let Some(bytes) = self.objects.get(reference.content_hash)? {
            return e3_data_availability::verify_retrieved_bytes(reference, bytes.to_vec());
        }

        match &*self.backend {
            Backend::Mock => anyhow::bail!(
                "local data-availability object 0x{} is not stored",
                hex::encode(reference.content_hash)
            ),
            // The round repository stores a retrieved input, so the availability tree keeps no
            // second cache. Avail remains the source if recovery needs the object again.
            Backend::Avail { reader, .. } => Ok(reader.retrieve(reference).await?),
        }
    }

    pub fn record_input_reference(
        &self,
        reference: &AvailableInputReference,
    ) -> anyhow::Result<()> {
        self.input_retrievals
            .insert(reference.key(), serde_json::to_vec(reference)?)?;
        self.input_retrievals.flush()?;
        Ok(())
    }

    pub fn pending_input_references(&self) -> anyhow::Result<Vec<AvailableInputReference>> {
        self.input_retrievals
            .iter()
            .map(|entry| AvailableInputReference::decode(&entry?.1))
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

    /// The worker loop. A storage error or a failed job step never ends it.
    pub async fn run(self: Arc<Self>) -> anyhow::Result<()> {
        loop {
            if let Err(error) = self.prune_relay_records(wall_clock_seconds()) {
                warn!(%error, "Could not prune relay records; will retry");
            }
            // Keep one bounded batch alive. An unbounded fan-out turns a backlog that any client
            // can stage into a memory and RPC spike, and queues the request-path steps of new
            // inputs behind every pending job on the FIFO `job_slots` semaphore.
            let mut tasks = JoinSet::new();
            for id in self.pending_ids() {
                while tasks.len() >= MAX_CONCURRENT_JOB_STEPS {
                    tasks.join_next().await;
                }
                let service = Arc::clone(&self);
                tasks.spawn(async move { service.process(&id).await });
            }
            while tasks.join_next().await.is_some() {}
            tokio::time::sleep(JOB_POLL_INTERVAL).await;
        }
    }

    /// Take exclusive ownership of one job, or return `None` when another path owns it.
    ///
    /// Every write path takes this guard, because each one loads a copy, awaits an Ethereum or
    /// Avail call, and then saves. Without one owner per job, a copy loaded before the other path
    /// made durable progress can replace that progress and discard recovery material.
    fn claim_job<'a>(&'a self, id: &'a str) -> Option<ActiveJobGuard<'a>> {
        lock(&self.in_progress)
            .insert(id.to_owned())
            .then(|| ActiveJobGuard {
                jobs: &self.in_progress,
                id,
            })
    }

    /// Run one step of a job in its own task. A caller that stops waiting, such as a request whose
    /// client closed the connection, then cannot cancel a paid step partway through.
    async fn process(&self, id: &str) {
        let service = self.clone();
        let id = id.to_owned();
        if let Err(error) = tokio::spawn(async move { service.process_step(&id).await }).await {
            warn!(%error, "Data-availability job step panicked; the worker retries the job");
        }
    }

    async fn process_step(&self, id: &str) {
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

    fn advance(&self, job: &mut AvailabilityJob, state: JobState) -> anyhow::Result<()> {
        job.state = state;
        self.save(job)
    }

    /// Settle a job whose `deadline` has passed, once a finalized block shows that no later block
    /// can change the answer. `published` selects the fact that the job needed: its publication
    /// on Ethereum, or else its input commitment. A job that holds the fact takes its success
    /// state, any other job fails with `failure`. Nothing changes until a finalized block is
    /// past the deadline.
    ///
    /// A load-balanced RPC can expose a new head while it serves contract state from an older one,
    /// so the fact is read at the finalized block rather than at the head. Commitment is rejected
    /// at its exact cutoff, so `inclusive` accepts a finalized block at that timestamp. Input and
    /// output finalization are valid through their exact deadline, so those decisions require a
    /// strictly later finalized block.
    async fn conclude_past(
        &self,
        job: &mut AvailabilityJob,
        deadline: u64,
        inclusive: bool,
        published: bool,
        failure: &str,
    ) -> anyhow::Result<()> {
        let block = self
            .provider()?
            .get_block_by_number(BlockNumberOrTag::Finalized)
            .await?
            .ok_or_else(|| anyhow::anyhow!("the Ethereum RPC returned no finalized block"))?;
        let passed = if inclusive {
            block.header.timestamp >= deadline
        } else {
            block.header.timestamp > deadline
        };
        if !passed {
            return Ok(());
        }
        let at = BlockId::number(block.header.number);
        let state = if published {
            if self.publication_exists(job, at).await? {
                JobState::Submitted {
                    transaction_hash: "already-finalized".to_owned(),
                }
            } else {
                JobState::Failed {
                    message: failure.to_owned(),
                }
            }
        } else if self.input_committed(job, at).await? {
            JobState::Committed {
                transaction_hash: "wallet-committed".to_owned(),
            }
        } else {
            JobState::Failed {
                message: failure.to_owned(),
            }
        };
        self.advance(job, state)
    }

    async fn process_inner(&self, id: &str) -> anyhow::Result<()> {
        let mut job = self.load_required(id)?;
        if job.state.is_terminal() {
            return Ok(());
        }
        // Retire only on finalized state. A publication seen at the chain head can be reorganized
        // out, and retirement clears the recovery material and can delete the local object, which
        // removes every automatic path back to a publishable job.
        if self.publication_exists(&job, self.settled()).await? {
            let state = JobState::Submitted {
                transaction_hash: "already-finalized".to_owned(),
            };
            return self.advance(&mut job, state);
        }
        let now = self.chain_timestamp().await?;
        // Deadline order: the publication deadline (Avail only), then the attestation expiry of a
        // wallet commitment, then the commitment cutoff.
        let deadline = job.kind.deadline();
        if self.is_avail() && now > deadline {
            return self
                .conclude_past(
                    &mut job,
                    deadline,
                    false,
                    true,
                    "the Ethereum publication deadline passed before the availability job completed",
                )
                .await;
        }

        if let JobKind::Input {
            commitment_deadline,
            ..
        } = &job.kind
        {
            let commitment_deadline = *commitment_deadline;
            // Only a wallet commitment fails when its attestation expires. The relay sends a lost
            // commitment again with a fresh attestation until the cutoff (`commitment_step`). The
            // contract rejects the signature at the exact expiry timestamp, so wait for a
            // finalized block at or after it before releasing the promised ciphertext. This
            // preserves a commitment that landed just before the boundary.
            if let JobState::AwaitingCommitment {
                attestation_expires_at,
                relayed_transaction_hash: None,
                ..
            } = &job.state
            {
                let expires_at = *attestation_expires_at;
                if now >= expires_at && !self.input_committed(&job, BlockId::latest()).await? {
                    return self
                        .conclude_past(
                            &mut job,
                            expires_at,
                            true,
                            false,
                            "the input availability promise expired before Ethereum accepted its commitment",
                        )
                        .await;
                }
            }

            if matches!(
                job.state,
                JobState::Created | JobState::AwaitingCommitment { .. }
            ) && now >= commitment_deadline
                && !self.input_committed(&job, BlockId::latest()).await?
            {
                return self
                    .conclude_past(
                        &mut job,
                        commitment_deadline,
                        true,
                        false,
                        "the input proof commitment deadline passed before Ethereum accepted it",
                    )
                    .await;
            }
        }

        match job.state.clone() {
            JobState::Created => {
                let state = match &job.kind {
                    JobKind::Output { .. } => self.start_availability(&job, None).await?,
                    JobKind::Input { .. } if self.input_committed(&job, self.settled()).await? => {
                        JobState::Committed {
                            transaction_hash: "already-committed".to_owned(),
                        }
                    }
                    JobKind::Input { .. }
                        if self.input_committed(&job, BlockId::latest()).await? =>
                    {
                        // A relay step that was interrupted after its send left this commitment
                        // at the chain head. Wait for finality as a relayed job does, instead of
                        // signing and sending the same commitment again.
                        let (ethereum_payload, attestation_expires_at) =
                            self.commitment_payload(&job).await?;
                        JobState::AwaitingCommitment {
                            ethereum_payload,
                            attestation_expires_at,
                            relayed_transaction_hash: Some("already-committed".to_owned()),
                        }
                    }
                    // A receipt is a head observation, not finality. The job stays provisional
                    // and the `AwaitingCommitment` arm promotes it on finalized state.
                    JobKind::Input { .. } if self.relays(&job).await? => {
                        self.relay_input_commitment(&job, now).await?
                    }
                    // The voter asked to send from its own wallet, the relay is off, the relay key
                    // is below its balance floor or its balance cannot be read, a relay limit is
                    // reached, or the round opened before the relay ledger started.
                    JobKind::Input { .. } => self.wallet_commitment(&job).await?,
                };
                self.advance(&mut job, state)?;
            }
            JobState::AwaitingCommitment {
                relayed_transaction_hash,
                ..
            } => {
                // Leave this state only on finalized state. `Committed` stops the attestation
                // renewal path and starts the paid Avail publication, so an orphaned commitment
                // would strand the input with no way back to a fresh promise.
                let is_final = self.input_committed(&job, self.settled()).await?;
                let at_head = is_final || self.input_committed(&job, BlockId::latest()).await?;
                let state =
                    match commitment_step(relayed_transaction_hash.as_deref(), is_final, at_head) {
                        CommitmentStep::Promote(transaction_hash) => {
                            JobState::Committed { transaction_hash }
                        }
                        // A reorganization removed the relayed transaction. Send it again only while
                        // the relay may spend and the voter did not ask to send from its own wallet.
                        // Otherwise the voter's wallet must send it, so that turning the relay off
                        // stops every relay send.
                        CommitmentStep::Recommit => {
                            if !job.kind.sends_from_wallet() && self.relay_may_send().await {
                                self.relay_input_commitment(&job, now).await?
                            } else {
                                self.wallet_commitment(&job).await?
                            }
                        }
                        CommitmentStep::Wait => return Ok(()),
                    };
                self.advance(&mut job, state)?;
            }
            JobState::Committed { transaction_hash } => {
                if matches!(job.kind, JobKind::Input { .. })
                    && !self.input_committed(&job, self.settled()).await?
                {
                    return Ok(());
                }
                // Another transaction can have published the input, for example from the job of
                // a database that this service lost. That publication retires this job when it is
                // final, so wait while the chain head holds it: the Avail publication is paid.
                if self.publication_exists(&job, BlockId::latest()).await? {
                    return Ok(());
                }
                let state = self
                    .start_availability(&job, Some(transaction_hash))
                    .await?;
                self.advance(&mut job, state)?;
            }
            JobState::AwaitingProof {
                publication,
                commitment_transaction_hash,
                last_candidate,
            } => {
                let Backend::Avail { publisher, .. } = &*self.backend else {
                    anyhow::bail!("mock job cannot await a VectorX proof");
                };
                // A refresh that fails must not strand a job that already holds a usable
                // candidate. On `Pending` or a transport error, fall back to the candidate this
                // job had before it asked. The publication is unchanged, so the fallback costs no
                // second publication.
                let refreshed = match publisher.proof(&publication).await {
                    Ok(ProofStatus::Ready { abi_proof, .. }) => Some(abi_proof),
                    Ok(ProofStatus::Pending) => None,
                    Err(error) => {
                        warn!(
                            job_id = job.id.as_str(),
                            %error,
                            "The availability bridge did not answer; will retry"
                        );
                        None
                    }
                };
                if let Some(ethereum_payload) =
                    Self::publishable_payload(refreshed, last_candidate, job.id.as_str())
                {
                    // Keep the Avail coordinates beside the candidate proof, or the job can never
                    // request a replacement for a Merkle path that Ethereum refuses.
                    let state = JobState::Ready {
                        ethereum_payload,
                        commitment_transaction_hash,
                        publication: Some(publication),
                    };
                    self.advance(&mut job, state)?;
                }
            }
            JobState::Ready {
                ethereum_payload,
                commitment_transaction_hash,
                publication,
            } => {
                let receipt = match &job.kind {
                    JobKind::Input { .. } => {
                        anyhow::ensure!(
                            self.input_committed(&job, BlockId::latest()).await?,
                            "cannot finalize an input whose proof commitment is absent"
                        );
                        self.finalize_input(&job, &ethereum_payload).await
                    }
                    JobKind::Output {
                        e3_id,
                        ciphertext_commitment,
                        compute_proof,
                        ..
                    } => {
                        let e3_id = e3_id_to_u256(e3_id)?;
                        match self.e3_stage(e3_id, BlockId::latest()).await? {
                            StoredE3Stage::KeyPublished => {}
                            StoredE3Stage::CiphertextReady | StoredE3Stage::Complete => {
                                // Another party published this output. Confirm the observation in
                                // finalized state before this job releases its recovery material.
                                if self.publication_exists(&job, self.settled()).await? {
                                    let state = JobState::Submitted {
                                        transaction_hash: "already-finalized".to_owned(),
                                    };
                                    self.advance(&mut job, state)?;
                                }
                                return Ok(());
                            }
                            StoredE3Stage::Failed => {
                                // A failure at the chain head can be reorganized away, and the
                                // failure clears the compute proof. Require finalized state.
                                if self.e3_stage(e3_id, self.settled()).await?
                                    == StoredE3Stage::Failed
                                {
                                    let state = JobState::Failed {
                                        message: "the E3 failed before its aggregate ciphertext was published".to_owned(),
                                    };
                                    self.advance(&mut job, state)?;
                                }
                                return Ok(());
                            }
                            _ => anyhow::bail!("the E3 is not ready for its aggregate ciphertext"),
                        }
                        InterfoldContractFactory::create_write(
                            &self.http_rpc_url,
                            &self.interfold_address.to_string(),
                            &self.private_key,
                        )
                        .await
                        .map_err(from_eyre)?
                        .publish_ciphertext_output(
                            e3_id,
                            B256::from(job.content_hash),
                            B256::from(*ciphertext_commitment),
                            Bytes::copy_from_slice(compute_proof),
                            Bytes::copy_from_slice(&ethereum_payload),
                        )
                        .await
                        .map_err(from_eyre)
                    }
                };
                let receipt = match receipt {
                    Ok(receipt) => receipt,
                    Err(error) => {
                        self.recover_rejected_proof(
                            &mut job,
                            commitment_transaction_hash,
                            publication,
                            Some(ethereum_payload),
                        )?;
                        return Err(error);
                    }
                };
                let state = JobState::AwaitingFinality {
                    transaction_hash: receipt.transaction_hash.to_string(),
                    ethereum_payload,
                    commitment_transaction_hash,
                    publication,
                };
                self.advance(&mut job, state)?;
            }
            JobState::AwaitingFinality {
                transaction_hash,
                ethereum_payload,
                commitment_transaction_hash,
                publication,
            } => {
                if self.publication_exists(&job, self.settled()).await? {
                    return self.advance(&mut job, JobState::Submitted { transaction_hash });
                }
                // The publication is absent from finalized state. It can still be pending, so
                // send it again only when it is also absent from the chain head. The transaction
                // is idempotent on chain: the contract refuses a second publication of one
                // reference, and that refusal returns this job here on the next step.
                if !self.publication_exists(&job, BlockId::latest()).await? {
                    let state = JobState::Ready {
                        ethereum_payload,
                        commitment_transaction_hash,
                        publication,
                    };
                    self.advance(&mut job, state)?;
                }
            }
            JobState::Submitted { .. } | JobState::Failed { .. } => {}
        }
        Ok(())
    }

    /// Choose the payload to publish from a bridge answer and the job's last candidate. A
    /// replacement wins. Without one, because the bridge answered `Pending` or did not answer,
    /// the previous candidate is still publishable: the Avail coordinates and the deadline are
    /// unchanged. `None` leaves the job in `AwaitingProof`, which the durable queue retries.
    fn publishable_payload(
        refreshed: Option<Vec<u8>>,
        last_candidate: Option<Vec<u8>>,
        job_id: &str,
    ) -> Option<Vec<u8>> {
        refreshed.or_else(|| {
            if last_candidate.is_some() {
                warn!(
                    job_id,
                    "No replacement proof is available; retrying the last candidate"
                );
            }
            last_candidate
        })
    }

    /// Return a job with a refused candidate proof to a state that can request a replacement.
    ///
    /// A `Ready` job can hold a proof that Ethereum refuses, and retrying the same payload can
    /// never succeed. The saved Avail coordinates name bytes that Avail already holds, so
    /// `AwaitingProof` asks the bridge for a fresh proof and pays for no second publication.
    ///
    /// A refused proof and a temporary RPC error arrive as the same error, so the candidate is
    /// kept rather than discarded: if no replacement arrives, the job retries the candidate it
    /// had. Discarding it would turn one transport failure into a missed deadline whenever the
    /// bridge is also unavailable. A record written before the coordinates were kept has nothing
    /// to ask the bridge with and needs operator recovery.
    fn recover_rejected_proof(
        &self,
        job: &mut AvailabilityJob,
        commitment_transaction_hash: Option<String>,
        publication: Option<PendingPublication>,
        last_candidate: Option<Vec<u8>>,
    ) -> anyhow::Result<()> {
        let Some(publication) = publication else {
            return Ok(());
        };
        warn!(
            job_id = job.id.as_str(),
            "Ethereum did not accept the availability proof; requesting a replacement and \
             keeping the current candidate"
        );
        self.advance(
            job,
            JobState::AwaitingProof {
                publication,
                commitment_transaction_hash,
                last_candidate,
            },
        )
    }

    async fn start_availability(
        &self,
        job: &AvailabilityJob,
        commitment_transaction_hash: Option<String>,
    ) -> anyhow::Result<JobState> {
        let object = self.object_required(job.content_hash)?;
        match &*self.backend {
            // The mock backend has no Avail publication to name, so it has no replacement proof
            // to request.
            Backend::Mock => Ok(JobState::Ready {
                ethereum_payload: object,
                commitment_transaction_hash,
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
                    last_candidate: None,
                })
            }
        }
    }

    async fn commitment_payload(&self, job: &AvailabilityJob) -> anyhow::Result<(Vec<u8>, u64)> {
        let (e3_id, envelope) = job.input()?;
        let contract = self.crisp().await?;
        let signer = self.signer()?;
        let configured = contract
            .input_availability_signer()
            .await
            .map_err(from_eyre)?;
        anyhow::ensure!(
            configured == signer.address(),
            "the CRISP inputAvailabilitySigner does not match this service key"
        );
        let ttl = contract
            .input_availability_attestation_ttl()
            .await
            .map_err(from_eyre)?;
        anyhow::ensure!(ttl > 0, "the input availability promise lifetime is zero");
        let attestation_expires_at = self
            .chain_timestamp()
            .await?
            .checked_add(ttl)
            .ok_or_else(|| anyhow::anyhow!("input availability promise expiry overflows u64"))?;
        let digest = contract
            .input_availability_digest(
                e3_id,
                envelope.encryptedVoteHash,
                envelope.encryptedVoteCommitment,
                envelope.slotAddress,
                envelope.parent_index(),
                attestation_expires_at,
            )
            .await
            .map_err(from_eyre)?;
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
            commitment_envelope.abi_encode_params(),
            attestation_expires_at,
        ))
    }

    /// Decide whether this service relays the commitment of a `Created` input job. The service
    /// never relays a job whose voter asked to send from its own wallet. This check comes first,
    /// so such a job reads no relay balance and writes no relay record.
    async fn relays(&self, job: &AvailabilityJob) -> anyhow::Result<bool> {
        if job.kind.sends_from_wallet() {
            return Ok(false);
        }
        Ok(self.relay_may_send().await && self.reserve_relay(job)?)
    }

    /// Whether the relay may send a commitment now: the relay is on, and the server key holds at
    /// least `RELAY_MIN_BALANCE_ETH`. A balance that cannot be read counts as too low, so a failed
    /// read neither spends nor stops the job: the job takes the wallet path.
    async fn relay_may_send(&self) -> bool {
        if !self.relay.enabled {
            return false;
        }
        match self.relay_has_funds().await {
            Ok(funded) => funded,
            Err(error) => {
                warn!(%error, "Could not read the relay balance; voters' wallets send new commitments");
                false
            }
        }
    }

    /// Whether the server key holds at least `RELAY_MIN_BALANCE_ETH`. The same key pays for
    /// `finalizeInput`, so the floor keeps relays from spending the funds that finalization needs.
    /// Every balance meets a zero floor, so a zero floor reads no balance.
    async fn relay_has_funds(&self) -> anyhow::Result<bool> {
        let Some(floor) = self.relay.min_balance.filter(|floor| !floor.is_zero()) else {
            return Ok(true);
        };
        let balance = self
            .provider()?
            .get_balance(self.signer()?.address())
            .await?;
        if balance < floor {
            warn!("The relay key is below RELAY_MIN_BALANCE_ETH; voters' wallets send new commitments");
            return Ok(false);
        }
        Ok(true)
    }

    /// Sign a fresh commitment payload for the voter's wallet to send.
    async fn wallet_commitment(&self, job: &AvailabilityJob) -> anyhow::Result<JobState> {
        let (ethereum_payload, attestation_expires_at) = self.commitment_payload(job).await?;
        Ok(JobState::AwaitingCommitment {
            ethereum_payload,
            attestation_expires_at,
            relayed_transaction_hash: None,
        })
    }

    /// Decide whether this service relays the commitment of an input job, and record a relay.
    ///
    /// While the relay may send, a relay decision holds for the life of the job: a failed send
    /// that the worker retries, and a relayed transaction that a reorganization removes, keep the
    /// place of the job. A send that the relay key cannot pay for moves the job to the wallet path
    /// (`relay_input_commitment`), and its record stays and counts against the limits. Apart from
    /// the voter's request to send from its own wallet (`relays`), the decision reads only the
    /// round, the slot, and the earlier relays, so votes, updates, and masks get the same answer.
    /// The record is durable before the relay transaction is sent, and it holds the commitment
    /// cutoff of the round, after which `prune_relay_records` removes it.
    ///
    /// A round whose input window opened before the ledger started (`open_relay_ledger`) is not
    /// relayed, because the limits cannot count the relays that the ledger does not hold.
    fn reserve_relay(&self, job: &AvailabilityJob) -> anyhow::Result<bool> {
        if !self.relay.enabled {
            return Ok(false);
        }
        let JobKind::Input {
            e3_id,
            commitment_deadline,
            ..
        } = &job.kind
        else {
            anyhow::bail!("aggregate ciphertext jobs have no input commitment to relay");
        };
        let (_, envelope) = job.input()?;
        // The E3 identifier is canonical decimal, so the separator makes each round prefix match
        // only its own round: round 1 does not count the records of round 12.
        let round = format!("{e3_id}/");
        let slot = format!("{round}{}/", hex::encode(envelope.slotAddress));
        let key = format!("{slot}{}", job.id);
        // Read before the lock: the input window of a round never changes, and the read decodes
        // the complete round record.
        let ledger_holds_round = self.ledger_holds_round(e3_id);

        let _decisions = lock(&self.relay_decisions);
        if self.relayed_inputs.contains_key(&key)? {
            return Ok(true);
        }
        if !ledger_holds_round {
            info!(
                e3_id = e3_id.as_str(),
                "The round opened before the relay ledger started; voters' wallets send its commitments"
            );
            return Ok(false);
        }
        if holds_at_least(&self.relayed_inputs, &slot, self.relay.max_per_slot)? {
            info!(
                job_id = job.id.as_str(),
                "The slot reached its relay limit for this round; the voter's wallet sends the commitment"
            );
            return Ok(false);
        }
        if let Some(max_per_round) = self.relay.max_per_round {
            if holds_at_least(&self.relayed_inputs, &round, max_per_round)? {
                warn!(
                    job_id = job.id.as_str(),
                    e3_id = e3_id.as_str(),
                    "The round reached its relay limit; voters' wallets send new commitments"
                );
                return Ok(false);
            }
        }
        self.relayed_inputs
            .insert(key.as_bytes(), &commitment_deadline.to_be_bytes()[..])?;
        self.relayed_inputs.flush()?;
        Ok(true)
    }

    /// Whether the relay ledger holds every relay of a round: the input window of the round
    /// opened after the ledger started. A round whose window start this service cannot read
    /// counts as opened before.
    fn ledger_holds_round(&self, e3_id: &str) -> bool {
        match self.input_window_start(e3_id) {
            Ok(Some(start)) => start > self.relay_ledger_epoch,
            Ok(None) => false,
            Err(error) => {
                warn!(%error, e3_id, "Could not read the input window of a round");
                false
            }
        }
    }

    /// The start of the input window of a round, from the round record that the indexer stores
    /// when the committee key is published (`E3Repository`). `None` when there is no record yet.
    fn input_window_start(&self, e3_id: &str) -> anyhow::Result<Option<u64>> {
        /// The one field of the indexer's round record that this service reads.
        #[derive(Deserialize)]
        struct IndexedRound {
            input_window: [u64; 2],
        }
        let Some(record) = self.round_records.get(format!("_e3:{e3_id}"))? else {
            return Ok(None);
        };
        let round: IndexedRound = serde_json::from_slice(&record)?;
        Ok(Some(round.input_window[0]))
    }

    /// Remove the relay records of rounds whose commitment cutoff passed before `now`, with a
    /// margin, and return how many went. No relay decision can use them after the cutoff: intake
    /// refuses new proofs, and a `Created` job fails at the cutoff check before it reaches one.
    /// A record without a readable cutoff stays, and so does the ledger start time.
    fn prune_relay_records(&self, now: u64) -> anyhow::Result<usize> {
        let _decisions = lock(&self.relay_decisions);
        let mut removed = 0;
        for entry in &self.relayed_inputs {
            let (key, value) = entry?;
            if key.as_ref() == RELAY_LEDGER_EPOCH_KEY {
                continue;
            }
            let Ok(cutoff) = <[u8; 8]>::try_from(value.as_ref()) else {
                continue;
            };
            if u64::from_be_bytes(cutoff).saturating_add(RELAY_RECORD_RETENTION_SECONDS) < now {
                self.relayed_inputs.remove(key)?;
                removed += 1;
            }
        }
        if removed > 0 {
            self.relayed_inputs.flush()?;
        }
        Ok(removed)
    }

    /// Relay one input commitment and return the provisional state that records it.
    ///
    /// If the relay key cannot pay for the transaction, the job takes the wallet path with the same
    /// signed payload, and the voter's wallet sends the commitment before the cutoff. A retry with
    /// the same key would fail until the cutoff and lose the vote. A refusal while other
    /// transactions of the key are pending can clear when they are mined, so the job keeps the
    /// relay for a grace period first (`relay_funding_grace_ended`).
    async fn relay_input_commitment(
        &self,
        job: &AvailabilityJob,
        now: u64,
    ) -> anyhow::Result<JobState> {
        let (ethereum_payload, attestation_expires_at) = self.commitment_payload(job).await?;
        let relayed_transaction_hash = match self
            .submit_input_commitment_payload(job, ethereum_payload.clone())
            .await
        {
            Ok(receipt) => Some(receipt.transaction_hash.to_string()),
            Err(error) => {
                let Some(unfunded) = error.downcast_ref::<RelayUnfunded>() else {
                    return Err(error);
                };
                if unfunded.other_transactions_pending && !self.relay_funding_grace_ended(job, now)
                {
                    return Err(error);
                }
                warn!(
                    job_id = job.id.as_str(),
                    %error,
                    "The relay key cannot pay; the voter's wallet sends the commitment"
                );
                None
            }
        };
        lock(&self.relay_funding_refusals).remove(&job.id);
        Ok(JobState::AwaitingCommitment {
            ethereum_payload,
            attestation_expires_at,
            relayed_transaction_hash,
        })
    }

    /// Whether a relayed job has waited long enough for a funds refusal to clear, while other
    /// transactions of the relay key are pending.
    ///
    /// The first refusal of the job starts its grace period. The period ends after
    /// `RELAY_FUNDING_GRACE_SECONDS`, and also as soon as the commitment cutoff is closer than
    /// that, so that the voter's wallet can still send the commitment. A refusal that is older than
    /// two grace periods belongs to a job that was not processed since then, and it starts again.
    fn relay_funding_grace_ended(&self, job: &AvailabilityJob, now: u64) -> bool {
        let JobKind::Input {
            commitment_deadline,
            ..
        } = &job.kind
        else {
            return true;
        };
        if now.saturating_add(RELAY_FUNDING_GRACE_SECONDS) >= *commitment_deadline {
            return true;
        }
        let mut refusals = lock(&self.relay_funding_refusals);
        refusals
            .retain(|_, started| now.saturating_sub(*started) < 2 * RELAY_FUNDING_GRACE_SECONDS);
        let started = *refusals.entry(job.id.clone()).or_insert(now);
        now.saturating_sub(started) >= RELAY_FUNDING_GRACE_SECONDS
    }

    /// Send `publishInput` for a relayed input after a dry run. A refusal for lack of funds comes
    /// back as `RelayUnfunded`, which records whether other transactions of the relay key were
    /// pending.
    async fn submit_input_commitment_payload(
        &self,
        job: &AvailabilityJob,
        payload: Vec<u8>,
    ) -> anyhow::Result<TransactionReceipt> {
        let (e3_id, _) = job.input()?;
        let contract = self.crisp().await?;
        let payload = Bytes::from(payload);
        contract
            .simulate_publish_input(e3_id, payload.clone())
            .await?;
        match contract.publish_input(e3_id, payload).await {
            Ok(receipt) => Ok(receipt),
            Err(error) if is_insufficient_funds(&error) => Err(anyhow::Error::new(RelayUnfunded {
                message: error.to_string(),
                other_transactions_pending: self.relay_key_has_pending_transactions().await?,
            })),
            Err(error) => Err(from_eyre(error)),
        }
    }

    /// Whether the relay key has transactions that the chain has not mined: its pending
    /// transaction count is higher than its mined one.
    async fn relay_key_has_pending_transactions(&self) -> anyhow::Result<bool> {
        let address = self.signer()?.address();
        let provider = self.provider()?;
        let pending = provider.get_transaction_count(address).pending().await?;
        let mined = provider.get_transaction_count(address).latest().await?;
        Ok(pending > mined)
    }

    async fn finalize_input(
        &self,
        job: &AvailabilityJob,
        availability_proof: &[u8],
    ) -> anyhow::Result<TransactionReceipt> {
        let (e3_id, envelope) = job.input()?;
        let contract = self.crisp().await?;
        let availability_proof = Bytes::copy_from_slice(availability_proof);
        contract
            .simulate_finalize_input(
                e3_id,
                envelope.slotAddress,
                envelope.encryptedVoteCommitment,
                envelope.encryptedVoteHash,
                envelope.parent_index(),
                availability_proof.clone(),
            )
            .await?;
        contract
            .finalize_input(
                e3_id,
                envelope.slotAddress,
                envelope.encryptedVoteCommitment,
                envelope.encryptedVoteHash,
                envelope.parent_index(),
                availability_proof,
            )
            .await
            .map_err(from_eyre)
    }

    /// Derive the durable job ID for one statement.
    ///
    /// The identifier is canonicalized here as well as at each entry point. The decimal parser
    /// accepts leading zeros, so an alias of one E3 would otherwise hash to a second job ID and
    /// buy a second paid publication for the same bytes.
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
        rpc::latest_timestamp(&self.provider()?)
            .await
            .map_err(from_eyre)
    }

    /// One of the two facts that `CRISPProgram` keeps about an input statement, read at `at`:
    /// whether its commitment is on chain, or else whether it is published.
    async fn input_fact(
        &self,
        e3_id: U256,
        envelope: &InputEnvelope,
        at: BlockId,
        published: bool,
    ) -> anyhow::Result<bool> {
        let contract = ICrispAvailabilityState::new(self.e3_program_address, self.provider()?);
        let (hash, commitment, slot, parent) = (
            envelope.encryptedVoteHash,
            envelope.encryptedVoteCommitment,
            envelope.slotAddress,
            envelope.parentIndexPlusOne,
        );
        Ok(if published {
            contract
                .isInputPublished(e3_id, hash, commitment, slot, parent)
                .block(at)
                .call()
                .await?
        } else {
            contract
                .isInputCommitted(e3_id, hash, commitment, slot, parent)
                .block(at)
                .call()
                .await?
        })
    }

    async fn input_committed(&self, job: &AvailabilityJob, at: BlockId) -> anyhow::Result<bool> {
        let (e3_id, envelope) = job.input()?;
        self.input_fact(e3_id, &envelope, at, false).await
    }

    async fn e3_stage(&self, e3_id: U256, at: BlockId) -> anyhow::Result<StoredE3Stage> {
        Ok(
            IInterfoldAvailabilityState::new(self.interfold_address, self.provider()?)
                .getE3Stage(e3_id)
                .block(at)
                .call()
                .await?,
        )
    }

    /// Whether the publication of the job is on Ethereum at `at`: the input is published, or the
    /// E3 holds the aggregate ciphertext. Reading at `self.settled()` answers whether it is
    /// final. Retiring a job clears its recovery material and can delete the local object, so a
    /// publication seen only at the head is not enough: a reorganization would remove it and
    /// leave no automatic path back to a publishable job.
    async fn publication_exists(&self, job: &AvailabilityJob, at: BlockId) -> anyhow::Result<bool> {
        match &job.kind {
            JobKind::Input { .. } => {
                let (e3_id, envelope) = job.input()?;
                self.input_fact(e3_id, &envelope, at, true).await
            }
            JobKind::Output { e3_id, .. } => Ok(matches!(
                self.e3_stage(e3_id_to_u256(e3_id)?, at).await?,
                StoredE3Stage::CiphertextReady | StoredE3Stage::Complete
            )),
        }
    }

    /// Every stored job, in key order. A record that cannot be decoded is an `Err` item.
    fn all_jobs(&self) -> impl Iterator<Item = anyhow::Result<AvailabilityJob>> + '_ {
        self.jobs
            .iter()
            .map(|entry| AvailabilityJob::decode(&entry?.1))
    }

    /// The jobs that the worker still has to drive. An unreadable record is skipped with a
    /// warning, so one bad record cannot stop the queue; `validate_storage` refuses it at startup.
    fn pending_ids(&self) -> Vec<String> {
        self.all_jobs()
            .filter_map(|job| match job {
                Ok(job) => (!job.state.is_terminal()).then_some(job.id),
                Err(error) => {
                    warn!(%error, "Skipping an unreadable data-availability job record");
                    None
                }
            })
            .collect()
    }

    fn load(&self, id: &str) -> anyhow::Result<Option<AvailabilityJob>> {
        self.jobs
            .get(id.as_bytes())?
            .map(|bytes| AvailabilityJob::decode(&bytes))
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
        let _storage = lock(&self.storage);
        let mut stored = job.clone();
        if stored.state.is_terminal() {
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

        let release_object = stored.state.is_failed()
            || (matches!(stored.state, JobState::Submitted { .. }) && self.is_avail());
        // The terminal state is durable, so a failed cleanup must not fail the save. A leaked
        // object is released at the next start (`validate_storage`).
        if release_object {
            if let Err(error) = self.release_object(&stored) {
                warn!(job_id = stored.id.as_str(), %error, "Could not release the object of a finished job");
            }
        }
        Ok(())
    }

    /// Delete the object of a finished job unless another non-terminal job uses it. The caller
    /// holds the storage lock.
    fn release_object(&self, job: &AvailabilityJob) -> anyhow::Result<()> {
        for other in self.all_jobs() {
            let other = other?;
            if other.id != job.id
                && other.content_hash == job.content_hash
                && !other.state.is_terminal()
            {
                return Ok(());
            }
        }
        self.objects.remove(job.content_hash)?;
        self.objects.flush()?;
        Ok(())
    }

    fn validate_storage(&self) -> anyhow::Result<()> {
        self.pending_input_references()?;
        let jobs = self.all_jobs().collect::<anyhow::Result<Vec<_>>>()?;
        let live: HashSet<[u8; 32]> = jobs
            .iter()
            .filter(|job| !job.state.is_terminal())
            .map(|job| job.content_hash)
            .collect();
        for job in jobs.iter().filter(|job| !job.state.is_terminal()) {
            anyhow::ensure!(
                self.objects.contains_key(job.content_hash)?,
                "non-terminal data-availability job {} has no stored object",
                job.id
            );
        }
        if self.is_avail() {
            for job in jobs
                .iter()
                .filter(|job| job.state.is_terminal() && !live.contains(&job.content_hash))
            {
                self.objects.remove(job.content_hash)?;
            }
            self.objects.flush()?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::rate_limit::RateLimiter;
    use alloy::providers::ProviderBuilder;

    const SLOT: Address = Address::repeat_byte(0x77);

    fn temporary_db() -> Db {
        sled::Config::new().temporary(true).open().unwrap()
    }

    fn default_relay() -> RelayPolicy {
        RelayPolicy::new(31_337, false, 3, None, None)
    }

    fn test_service(max_pending_bytes: u64) -> AvailabilityService {
        test_service_on(&temporary_db(), max_pending_bytes, default_relay())
    }

    /// A service over `db`. A second service over the same `db` shares only the durable state of
    /// the first, as after a restart.
    fn test_service_on(db: &Db, max_pending_bytes: u64, relay: RelayPolicy) -> AvailabilityService {
        test_service_started_at(db, max_pending_bytes, relay, wall_clock_seconds())
    }

    /// A service over `db` that starts at the wall-clock time `now`.
    fn test_service_started_at(
        db: &Db,
        max_pending_bytes: u64,
        relay: RelayPolicy,
        now: u64,
    ) -> AvailabilityService {
        let relayed_inputs = db.open_tree("relayed-inputs").unwrap();
        AvailabilityService {
            jobs: db.open_tree("jobs").unwrap(),
            objects: db.open_tree("objects").unwrap(),
            input_retrievals: db.open_tree("retrievals").unwrap(),
            backend: Arc::new(Backend::Mock),
            in_progress: Arc::default(),
            storage: Arc::default(),
            job_slots: Arc::new(Semaphore::new(1)),
            relay_ledger_epoch: open_relay_ledger(&relayed_inputs, now).unwrap(),
            relayed_inputs,
            round_records: (**db).clone(),
            relay_decisions: Arc::default(),
            relay_funding_refusals: Arc::default(),
            relay,
            http_rpc_url: String::new(),
            private_key: String::new(),
            interfold_address: Address::ZERO,
            e3_program_address: Address::ZERO,
            input_duration_seconds: 0,
            proof_lead_seconds: 0,
            max_pending_bytes,
        }
    }

    /// Store the round record of `e3_id` the way the indexer does when the committee key is
    /// published, with an input window that opens at `input_window_start`.
    async fn index_round(db: &Db, e3_id: &str, input_window_start: u64) {
        use crate::server::database::SledDB;
        use e3_evm_helpers::contracts::CommitteeSize;
        use e3_sdk::indexer::{models::E3, E3Repository, SharedStore};

        let store = SharedStore::new(Arc::new(tokio::sync::RwLock::new(
            SledDB::from_db(db.clone()).unwrap(),
        )));
        let round = E3 {
            chain_id: 31_337,
            ciphertext_inputs: Vec::new(),
            ciphertext_output: Vec::new(),
            ciphertext_output_reference: None,
            ciphertext_commitment: Vec::new(),
            committee_public_key: vec![0x01],
            committee_public_key_hash: vec![0x02; 32],
            e3_params: Vec::new(),
            custom_params: Vec::new(),
            interfold_address: Address::repeat_byte(0x01).to_string(),
            encryption_scheme_id: vec![0x03; 32],
            crypto_config_id: vec![0x04; 32],
            id: e3_id.to_owned(),
            plaintext_output: Vec::new(),
            request_block: 0,
            seed: [0x05; 32],
            input_window: [input_window_start, input_window_start + 3_600],
            committee_size: CommitteeSize::Minimum,
            requester: Address::repeat_byte(0x02).to_string(),
        };
        assert!(E3Repository::new(store, e3_id)
            .set_e3_if_absent(round)
            .await
            .unwrap());
    }

    /// A service under `relay` over a database whose round 1 opened after the relay ledger
    /// started, so that only the policy decides.
    async fn relay_service(relay: RelayPolicy) -> (Db, AvailabilityService) {
        let db = temporary_db();
        let service = test_service_on(&db, 1024, relay);
        index_round(&db, "1", service.relay_ledger_epoch + 1).await;
        (db, service)
    }

    /// How many relay records the ledger of `service` holds.
    fn relay_record_count(service: &AvailabilityService) -> usize {
        service
            .relayed_inputs
            .iter()
            .keys()
            .filter(|key| key.as_ref().unwrap().as_ref() != RELAY_LEDGER_EPOCH_KEY)
            .count()
    }

    /// An endpoint that takes connections and never answers. Nothing connected while `accept`
    /// reports `WouldBlock`.
    fn never_answering_rpc() -> (std::net::TcpListener, String) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        (listener, url)
    }

    fn assert_nothing_connected(listener: &std::net::TcpListener, message: &str) {
        assert_eq!(
            listener.accept().err().map(|error| error.kind()),
            Some(std::io::ErrorKind::WouldBlock),
            "{message}"
        );
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

    /// A wire envelope for `object`. A client sends the object inside it (`keep_object`); the
    /// durable job keeps it out.
    fn envelope(slot: Address, commitment: B256, object: &[u8], keep_object: bool) -> Vec<u8> {
        let mut envelope =
            InputEnvelope::abi_decode_params_validate(&hex::decode(SDK_INPUT_ENVELOPE).unwrap())
                .unwrap();
        envelope.slotAddress = slot;
        envelope.encryptedVoteCommitment = commitment;
        envelope.encryptedVoteHash = keccak256(object);
        envelope.availabilityProof = if keep_object {
            Bytes::copy_from_slice(object)
        } else {
            Bytes::new()
        };
        envelope.abi_encode_params()
    }

    fn input_job(id: &str, slot: Address, commitment: u8, object: &[u8]) -> AvailabilityJob {
        AvailabilityJob::new(
            id.to_owned(),
            keccak256(object).0,
            JobKind::Input {
                e3_id: "1".to_owned(),
                staged_envelope: envelope(slot, B256::repeat_byte(commitment), object, false),
                deadline: 1_000,
                commitment_deadline: 900,
                send_from_wallet: false,
            },
        )
    }

    /// The fields of an input job that tests change: the round, the two deadlines, and the
    /// voter's sender choice.
    fn input_fields(job: &mut AvailabilityJob) -> (&mut String, &mut u64, &mut u64, &mut bool) {
        let JobKind::Input {
            e3_id,
            deadline,
            commitment_deadline,
            send_from_wallet,
            ..
        } = &mut job.kind
        else {
            panic!("not an input job");
        };
        (e3_id, deadline, commitment_deadline, send_from_wallet)
    }

    /// An input job without deadlines for `slot`.
    fn open_input_job(id: &str, object: &[u8]) -> AvailabilityJob {
        let mut job = input_job(id, SLOT, 0x11, object);
        let (_, deadline, commitment_deadline, _) = input_fields(&mut job);
        (*deadline, *commitment_deadline) = (NO_DEADLINE, NO_DEADLINE);
        job
    }

    /// An input job for `slot` in the round `e3_id`, with a commitment cutoff of 900.
    fn round_input_job(id: &str, e3_id: &str, slot: Address) -> AvailabilityJob {
        let mut job = input_job(id, slot, 0x11, id.as_bytes());
        *input_fields(&mut job).0 = e3_id.to_owned();
        job
    }

    fn output_job(id: &str, state: JobState, object: &[u8]) -> AvailabilityJob {
        let mut job = AvailabilityJob::new(
            id.to_owned(),
            keccak256(object).0,
            JobKind::Output {
                e3_id: "1".to_owned(),
                ciphertext_commitment: [0x22; 32],
                compute_proof: vec![0x33; 8],
                deadline: 1_000,
            },
        );
        job.state = state;
        job
    }

    fn test_publication(content_hash: [u8; 32]) -> PendingPublication {
        PendingPublication {
            content_hash,
            block_hash: "0xblock".to_owned(),
            block_number: 42,
            extrinsic_index: 7,
        }
    }

    fn ready(publication: Option<PendingPublication>) -> JobState {
        JobState::Ready {
            ethereum_payload: vec![0xaa; 4],
            commitment_transaction_hash: Some("0xcommit".to_owned()),
            publication,
        }
    }

    fn awaiting_commitment(relayed_transaction_hash: Option<&str>) -> JobState {
        JobState::AwaitingCommitment {
            ethereum_payload: vec![0x33],
            attestation_expires_at: 600,
            relayed_transaction_hash: relayed_transaction_hash.map(str::to_owned),
        }
    }

    fn failed(message: &str) -> JobState {
        JobState::Failed {
            message: message.to_owned(),
        }
    }

    /// Store a job and then move it to `state`. `store_new_job_with_object` admits only a new
    /// job in the created state, so a test that needs a later state saves the transition.
    fn store_job_in_state(
        service: &AvailabilityService,
        job: &AvailabilityJob,
        object: &[u8],
        state: JobState,
    ) -> AvailabilityJob {
        let mut job = job.clone();
        job.state = JobState::Created;
        service.store_new_job_with_object(&job, object).unwrap();
        job.state = state;
        service.save(&job).unwrap();
        job
    }

    fn pending_state(service: &AvailabilityService, job: &AvailabilityJob) -> JobState {
        service.load_required(&job.id).unwrap().state
    }

    #[test]
    fn a_relayed_commitment_is_provisional_and_a_wallet_commitment_is_never_resent() {
        use CommitmentStep::*;
        let relayed = Some("0xrelayed");
        for (hash, is_final, at_head, expected) in [
            // A receipt in hand, the transaction still at the head and not yet final: wait.
            (relayed, false, true, Wait),
            // Reorganized out and not re-included: the relay sends it again.
            (relayed, false, false, Recommit),
            // Final: promote, and keep the relayed hash as the record.
            (relayed, true, true, Promote("0xrelayed".to_owned())),
            // The voter's own transaction is absent from the head: the voter owns it.
            (None, false, false, Wait),
            (None, false, true, Wait),
            (None, true, true, Promote("wallet-committed".to_owned())),
        ] {
            assert_eq!(
                commitment_step(hash, is_final, at_head),
                expected,
                "{hash:?} final={is_final} head={at_head}"
            );
        }
    }

    /// A relayed job is reported as pending so the client does not sign a second commitment, and a
    /// placeholder is never reported as a transaction hash.
    #[test]
    fn the_view_reports_only_real_transactions_and_keeps_a_relayed_client_waiting() {
        let committed = |hash: &str| JobState::Committed {
            transaction_hash: hash.to_owned(),
        };
        let mut job = input_job("view", SLOT, 0x11, b"object");
        for (state, status, tx_hash) in [
            (
                awaiting_commitment(Some("0xrelayed")),
                "pending_availability",
                Some("0xrelayed"),
            ),
            (awaiting_commitment(None), "ready_for_commitment", None),
            (
                awaiting_commitment(Some("already-committed")),
                "pending_availability",
                None,
            ),
            (committed("wallet-committed"), "pending_availability", None),
        ] {
            job.state = state;
            let view = AvailabilityJobView::from(&job);
            assert_eq!(
                (view.status.as_str(), view.tx_hash.as_deref()),
                (status, tx_hash)
            );
        }
    }

    #[test]
    fn sdk_input_envelope_uses_solidity_parameter_encoding() {
        let encoded = hex::decode(SDK_INPUT_ENVELOPE).unwrap();
        let envelope = InputEnvelope::abi_decode_params_validate(&encoded).unwrap();

        assert_eq!(envelope.noirProof.as_ref(), &[1, 2, 3]);
        assert_eq!(envelope.slotAddress, Address::repeat_byte(0x11));
        assert_eq!(envelope.encryptedVoteCommitment, B256::repeat_byte(0x22));
        assert_eq!(envelope.encryptedVoteHash, B256::repeat_byte(0x33));
        assert_eq!(envelope.parent_index(), 7);
        assert_eq!(envelope.availabilityProof.as_ref(), &[0xaa, 0xbb]);
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
    fn durable_records_reject_unknown_or_missing_schema_versions() {
        let job = output_job("job", JobState::Created, b"object");
        assert!(AvailabilityJob::decode(&serde_json::to_vec(&job).unwrap()).is_ok());

        let mut unknown_job = job.clone();
        unknown_job.schema_version += 1;
        let error =
            AvailabilityJob::decode(&serde_json::to_vec(&unknown_job).unwrap()).unwrap_err();
        assert!(error
            .to_string()
            .contains("unsupported data-availability job schema version"));

        let mut missing_version = serde_json::to_value(&job).unwrap();
        missing_version
            .as_object_mut()
            .unwrap()
            .remove("schema_version");
        let error =
            AvailabilityJob::decode(&serde_json::to_vec(&missing_version).unwrap()).unwrap_err();
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
            AvailableInputReference::decode(&serde_json::to_vec(&reference).unwrap()).unwrap_err();
        assert!(error
            .to_string()
            .contains("unsupported available-input reference schema version"));
    }

    #[test]
    fn legacy_uncommitted_job_without_expiry_fails_closed() {
        let mut job = input_job("legacy-input", SLOT, 0x11, b"object");
        job.state = awaiting_commitment(None);
        let mut encoded = serde_json::to_value(&job).unwrap();
        let state = encoded["state"].as_object_mut().unwrap();
        state.remove("attestation_expires_at");
        state.remove("relayed_transaction_hash");
        encoded["kind"]
            .as_object_mut()
            .unwrap()
            .remove("send_from_wallet");

        let decoded = AvailabilityJob::decode(&serde_json::to_vec(&encoded).unwrap()).unwrap();
        let JobState::AwaitingCommitment {
            attestation_expires_at,
            relayed_transaction_hash,
            ..
        } = decoded.state
        else {
            panic!("expected an uncommitted input job");
        };
        assert_eq!(attestation_expires_at, 0);
        // A record written before the relay became provisional is a wallet-path record.
        assert_eq!(relayed_transaction_hash, None);
        // A record without the sender choice leaves the relay decision to the service.
        assert!(!decoded.kind.sends_from_wallet());
    }

    #[test]
    fn pending_object_storage_is_bounded_and_admitted_with_its_job() {
        let service = test_service(10);
        let object = b"ciphertext";
        let job = output_job("new-output", JobState::Created, object);

        service.store_new_job_with_object(&job, object).unwrap();
        assert_eq!(service.object_required(job.content_hash).unwrap(), object);
        assert_eq!(service.load_required(&job.id).unwrap().id, job.id);

        // The same bytes under another job cost nothing more, although the storage is full.
        let sharing = AvailabilityJob {
            id: "sharing-output".to_owned(),
            ..job.clone()
        };
        service.store_new_job_with_object(&sharing, object).unwrap();

        // A refused admission leaves neither a job nor an object.
        let over = output_job("over-capacity", JobState::Created, b"x");
        assert!(service.store_new_job_with_object(&over, b"x").is_err());
        assert!(service.load(&over.id).unwrap().is_none());
        assert!(service.object_required(over.content_hash).is_err());
        // Bytes must reproduce the content hash.
        assert!(service.store_new_job_with_object(&over, b"y").is_err());
    }

    #[test]
    fn terminal_cleanup_keeps_an_object_used_by_another_job() {
        let service = test_service(1024);
        let object = b"shared-ciphertext";
        let mut first = output_job("first-output", JobState::Created, object);
        let second = AvailabilityJob {
            id: "second-output".to_owned(),
            ..first.clone()
        };

        service.store_new_job_with_object(&first, object).unwrap();
        service.store_new_job_with_object(&second, object).unwrap();
        first.state = failed("deadline passed");
        service.save(&first).unwrap();

        assert_eq!(service.object_required(first.content_hash).unwrap(), object);
        assert!(service.validate_storage().is_ok());
    }

    #[test]
    fn failed_job_releases_bytes_and_large_payloads() {
        let service = test_service(1024);
        let object = b"ciphertext";
        let mut job = output_job("failed-output", JobState::Created, object);
        service.store_new_job_with_object(&job, object).unwrap();
        job.state = failed("deadline passed");
        service.save(&job).unwrap();

        assert!(service.object_required(job.content_hash).is_err());
        let JobKind::Output { compute_proof, .. } = service.load_required(&job.id).unwrap().kind
        else {
            panic!("expected an output job");
        };
        assert!(compute_proof.is_empty());
    }

    #[test]
    fn failed_input_job_can_be_staged_again() {
        let service = test_service(1024);
        let object = b"ciphertext";
        let mut job = input_job("retry-input", SLOT, 0x11, object);

        service.store_new_job_with_object(&job, object).unwrap();
        job.state = failed("availability promise expired");
        service.save(&job).unwrap();
        assert!(service.object_required(job.content_hash).is_err());

        let replacement = AvailabilityJob {
            state: JobState::Created,
            ..job
        };
        service
            .store_new_job_with_object(&replacement, object)
            .unwrap();

        assert_eq!(
            service.object_required(replacement.content_hash).unwrap(),
            object
        );
        assert!(matches!(
            pending_state(&service, &replacement),
            JobState::Created
        ));
    }

    /// A slot gets a bounded number of relayed commitments in one round. Past the limit the
    /// voter's wallet sends the commitment, so masks from any account can use up the relay
    /// allowance of a slot but cannot stop its owner from voting.
    #[tokio::test]
    async fn a_slot_is_relayed_up_to_its_limit_and_then_uses_the_wallet() {
        let (db, service) = relay_service(default_relay()).await;
        let jobs: Vec<_> = (0..4)
            .map(|n| round_input_job(&format!("slot-input-{n}"), "1", SLOT))
            .collect();

        for job in &jobs[..3] {
            assert!(service.reserve_relay(job).unwrap());
        }
        assert!(!service.reserve_relay(&jobs[3]).unwrap());

        // A relayed job keeps its place, so the worker can send a failed relay again.
        assert!(service.reserve_relay(&jobs[0]).unwrap());
        // Another slot has its own limit.
        let other_slot = round_input_job("other-slot-input", "1", Address::repeat_byte(0x88));
        assert!(service.reserve_relay(&other_slot).unwrap());

        // The records are durable: after a restart the slot is still at its limit.
        let restarted = test_service_on(&db, 1024, default_relay());
        assert!(!restarted.reserve_relay(&jobs[3]).unwrap());
        assert!(restarted.reserve_relay(&jobs[1]).unwrap());

        // A limit of zero turns the relay off, also for a job that was chosen for it earlier.
        let off = test_service_on(&db, 1024, RelayPolicy::new(31_337, false, 0, None, None));
        assert!(!off.reserve_relay(&jobs[0]).unwrap());
    }

    /// A round gets a bounded number of relayed commitments across all of its slots.
    #[tokio::test]
    async fn a_round_is_relayed_up_to_its_limit_and_then_uses_the_wallet() {
        let (db, service) = relay_service(RelayPolicy::new(31_337, false, 3, Some(2), None)).await;
        index_round(&db, "12", service.relay_ledger_epoch + 1).await;
        let relays = |id: &str, e3_id: &str, slot: u8| {
            service
                .reserve_relay(&round_input_job(id, e3_id, Address::repeat_byte(slot)))
                .unwrap()
        };

        assert!(relays("a", "12", 0x01));
        assert!(relays("b", "12", 0x02));
        assert!(!relays("c", "12", 0x03));

        // Round 1 has its own count, although its identifier is a prefix of round 12.
        assert!(relays("d", "1", 0x01));
    }

    /// Mainnet relays only when the operator turns the relay on. Other chains relay without it.
    #[tokio::test]
    async fn mainnet_relays_only_when_enabled() {
        for (policy, relayed) in [
            (RelayPolicy::new(1, false, 3, Some(100), None), false),
            (RelayPolicy::new(1, true, 3, Some(100), None), true),
            (RelayPolicy::new(11_155_111, false, 3, None, None), true),
        ] {
            let (_db, service) = relay_service(policy).await;
            let job = round_input_job("mainnet-input", "1", SLOT);
            assert_eq!(service.reserve_relay(&job).unwrap(), relayed);
        }
    }

    /// A balance that cannot be read counts as too low. The job takes the wallet path instead of
    /// stopping, and it uses none of the relay allowance. A zero floor reads no balance, so the
    /// same failure does not stop a relay without a floor.
    #[tokio::test]
    async fn an_unreadable_relay_balance_takes_the_wallet_path_unless_the_floor_is_zero() {
        // A port with no listener, so the balance read fails at once.
        let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let rpc = format!("http://{}", closed.local_addr().unwrap());
        drop(closed);
        let service = |floor: u64| {
            let rpc = rpc.clone();
            async move {
                let (_db, mut service) = relay_service(RelayPolicy::new(
                    11_155_111,
                    false,
                    3,
                    None,
                    Some(U256::from(floor)),
                ))
                .await;
                service.http_rpc_url = rpc;
                service.private_key =
                    "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80".to_owned();
                service
            }
        };
        let job = round_input_job("unreadable-balance", "1", SLOT);

        let floored = service(1).await;
        assert!(!floored.relays(&job).await.unwrap());
        assert_eq!(relay_record_count(&floored), 0);

        assert!(service(0).await.relays(&job).await.unwrap());
    }

    /// A node refuses a `publishInput` that the relay key cannot pay for. The refusal records
    /// whether other transactions of the key were pending, because only such a refusal can clear
    /// by itself and keeps the relay for a grace period.
    #[tokio::test]
    async fn a_funds_refusal_records_whether_other_transactions_are_pending() {
        use alloy::providers::ext::AnvilApi;

        // This node mines no blocks, so a sent transaction stays pending.
        let anvil = alloy::node_bindings::Anvil::new()
            .arg("--no-mining")
            .try_spawn()
            .unwrap();
        let mut service = test_service(1024);
        service.http_rpc_url = anvil.endpoint();
        // A call to an address without code succeeds, so the test needs no deployed contract.
        service.e3_program_address = Address::repeat_byte(0x42);
        let job = round_input_job("unfunded-relay", "1", SLOT);
        let unfunded = |error: anyhow::Error| match error.downcast::<RelayUnfunded>() {
            Ok(unfunded) => unfunded,
            Err(error) => panic!("not a funds refusal: {error:#}"),
        };

        // A key that never held funds and has nothing pending.
        service.private_key =
            "0x1111111111111111111111111111111111111111111111111111111111111111".to_owned();
        let error = service
            .submit_input_commitment_payload(&job, vec![1])
            .await
            .unwrap_err();
        assert!(!unfunded(error).other_transactions_pending);

        // A key that sends one transaction, which stays pending, and then loses its funds.
        let key = anvil.keys()[1].to_bytes();
        let signer = PrivateKeySigner::from_slice(&key).unwrap();
        let address = signer.address();
        let provider = ProviderBuilder::new()
            .wallet(signer)
            .connect(&anvil.endpoint())
            .await
            .unwrap();
        let _pending_transaction = provider
            .send_transaction(
                alloy::rpc::types::TransactionRequest::default()
                    .to(Address::repeat_byte(0x43))
                    .value(U256::from(1)),
            )
            .await
            .unwrap();
        provider
            .anvil_set_balance(address, U256::from(1))
            .await
            .unwrap();
        service.private_key = format!("0x{}", hex::encode(key));
        let error = service
            .submit_input_commitment_payload(&job, vec![1])
            .await
            .unwrap_err();
        assert!(unfunded(error).other_transactions_pending);
    }

    /// A funds refusal while other transactions of the relay key are pending keeps the relay only
    /// for a grace period, and the wallet path always comes before the commitment cutoff.
    #[test]
    fn a_funds_refusal_keeps_the_relay_only_for_a_grace_period() {
        let service = test_service(1024);
        // `input_job` sets a commitment cutoff of 900.
        let job = round_input_job("refused-relay", "1", SLOT);
        assert!(!service.relay_funding_grace_ended(&job, 100));
        assert!(!service.relay_funding_grace_ended(&job, 100 + RELAY_FUNDING_GRACE_SECONDS - 1));
        assert!(service.relay_funding_grace_ended(&job, 100 + RELAY_FUNDING_GRACE_SECONDS));

        // Close to the cutoff, the first refusal already moves the job to the wallet path.
        let late = round_input_job("late-refused-relay", "1", Address::repeat_byte(0x78));
        assert!(service.relay_funding_grace_ended(&late, 900 - RELAY_FUNDING_GRACE_SECONDS));
    }

    /// A voter that asks to send from its own wallet gets the wallet path, also when the relay is
    /// on and no relay limit is reached. The job uses none of the relay allowance.
    #[tokio::test]
    async fn a_voter_that_asks_for_its_wallet_is_not_relayed() {
        let (_db, service) = relay_service(default_relay()).await;
        let mut job = round_input_job("wallet-choice", "1", SLOT);

        *input_fields(&mut job).3 = true;
        assert!(!service.relays(&job).await.unwrap());
        assert_eq!(relay_record_count(&service), 0);

        // The same job without the request is relayed, so the check above is the voter's choice.
        *input_fields(&mut job).3 = false;
        assert!(service.relays(&job).await.unwrap());
        assert_eq!(relay_record_count(&service), 1);
    }

    /// A round whose input window opened before the relay ledger started can have relays that
    /// the ledger does not hold, here one sent by a server version without the ledger. The
    /// service does not relay for that round, also after a restart, so it cannot pass the limits
    /// with relays it cannot count. A round that opens after the ledger started is relayed.
    #[tokio::test]
    async fn a_round_open_before_the_relay_ledger_started_is_not_relayed() {
        let db = temporary_db();
        let policy = RelayPolicy::new(31_337, false, 1, None, None);
        let started = wall_clock_seconds();
        // The database of a server version without the ledger: round 1 is open, and it holds a
        // relayed job of the slot, but no relay record and no ledger start time.
        index_round(&db, "1", started - 600).await;
        let mut legacy = round_input_job("legacy-relayed", "1", SLOT);
        legacy.state = awaiting_commitment(Some("0xrelayed"));
        db.open_tree("jobs")
            .unwrap()
            .insert(legacy.id.as_bytes(), serde_json::to_vec(&legacy).unwrap())
            .unwrap();

        let service = test_service_started_at(&db, 1024, policy, started);
        assert_eq!(service.relay_ledger_epoch, started);
        index_round(&db, "2", started + 60).await;
        let vote = round_input_job("vote", "1", SLOT);
        assert!(!service.reserve_relay(&vote).unwrap());
        assert!(service
            .reserve_relay(&round_input_job("later-round-vote", "2", SLOT))
            .unwrap());

        // A restart after round 2 opened keeps the ledger start time, so round 2 stays relayed
        // and round 1 stays on the wallet path.
        let restarted = test_service_started_at(&db, 1024, policy, started + 3_600);
        assert_eq!(restarted.relay_ledger_epoch, started);
        assert!(!restarted.reserve_relay(&vote).unwrap());
        assert!(restarted
            .reserve_relay(&round_input_job(
                "later-round-other-slot",
                "2",
                Address::repeat_byte(0x88)
            ))
            .unwrap());
    }

    /// A mask needs no signature from the slot owner, so an uncommitted job for a slot must not
    /// stop a different statement for the same slot.
    #[test]
    fn a_second_statement_for_one_slot_is_admitted_and_keeps_the_first() {
        let service = test_service(1024);

        let mask_object = b"attacker-mask-ciphertext";
        let mask = input_job("mask-input", SLOT, 0x11, mask_object);
        assert!(service
            .admit_input(&mask, mask_object, None)
            .unwrap()
            .is_none());

        // The attacker holds the attestation and never sends its Ethereum commitment.
        store_job_in_state(&service, &mask, mask_object, awaiting_commitment(None));

        let vote_object = b"slot-owner-ciphertext";
        let vote = input_job("owner-input", SLOT, 0x22, vote_object);
        assert!(service
            .admit_input(&vote, vote_object, None)
            .unwrap()
            .is_none());

        // Admission of the second statement keeps the earlier attestation valid and keeps its
        // bytes retrievable.
        assert!(matches!(
            pending_state(&service, &mask),
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
        let repeat = service.admit_input(&vote, vote_object, None).unwrap();
        assert_eq!(repeat.unwrap().job_id, vote.id);
        assert_eq!(service.jobs.len(), 2);
        assert!(service.validate_storage().is_ok());
    }

    /// The relay reservation is committed in the same synchronous step that writes the durable
    /// job, so a request cancelled after admission cannot release quota for work that the
    /// background worker still holds. The slot stays taken until its window expires.
    #[test]
    fn admission_commits_the_reservation_before_any_await() {
        let service = test_service(1024);
        let limiter = RateLimiter::with_limits(8, 1);
        let object = b"admitted-ciphertext";
        let job = input_job("admitted", SLOT, 0x11, object);

        let reservation = limiter.try_reserve_global().unwrap();
        assert!(service
            .admit_input(&job, object, Some(reservation))
            .unwrap()
            .is_none());
        assert!(service.load(&job.id).unwrap().is_some());
        assert!(limiter.try_reserve_global().is_err());
    }

    #[test]
    fn a_repeat_statement_returns_its_reservation() {
        let service = test_service(1024);
        let limiter = RateLimiter::with_limits(8, 2);
        let object = b"repeated-ciphertext";
        let job = input_job("repeated", SLOT, 0x11, object);

        let first = limiter.try_reserve_global().unwrap();
        assert!(service
            .admit_input(&job, object, Some(first))
            .unwrap()
            .is_none());
        // The second request admits nothing durable, so its slot goes back and one slot of the
        // two stays taken for the admitted job.
        let second = limiter.try_reserve_global().unwrap();
        assert!(service
            .admit_input(&job, object, Some(second))
            .unwrap()
            .is_some());
        let _probe = limiter.try_reserve_global().unwrap();
        assert!(limiter.try_reserve_global().is_err());
    }

    /// Storage refuses a second object past the pending byte limit: nothing durable is written,
    /// so the slot goes back.
    #[test]
    fn a_refused_admission_returns_its_reservation() {
        let service = test_service(8);
        let limiter = RateLimiter::with_limits(8, 1);
        let first_object = b"12345678";
        let first = input_job("first-input", SLOT, 0x11, first_object);
        assert!(service
            .admit_input(&first, first_object, None)
            .unwrap()
            .is_none());

        let second_object = b"9";
        let second = input_job("second-input", SLOT, 0x22, second_object);
        let reservation = limiter.try_reserve_global().unwrap();
        assert!(service
            .admit_input(&second, second_object, Some(reservation))
            .is_err());
        assert!(service.load(&second.id).unwrap().is_none());
        assert!(limiter.try_reserve_global().is_ok());
    }

    /// `store_new_job_with_object` can report an error after its transaction applied, as a failed
    /// flush does. The decision is judged by the record, not by the call result.
    #[test]
    fn a_store_error_with_a_live_record_keeps_the_reservation() {
        let service = test_service(1024);
        let object = b"flushed-ciphertext";
        let job = input_job("flushed", SLOT, 0x11, object);
        service.store_new_job_with_object(&job, object).unwrap();

        let limiter = RateLimiter::with_limits(8, 1);
        service.settle_uncertain_admission(&job, limiter.try_reserve_global().unwrap());
        assert!(limiter.try_reserve_global().is_err());

        // With no live record (the earlier job is `Failed`, so the replacement did not apply),
        // the same path returns the slot.
        let mut failed_job = service.load_required(&job.id).unwrap();
        failed_job.state = failed("test");
        service.save(&failed_job).unwrap();
        let limiter = RateLimiter::with_limits(8, 1);
        service.settle_uncertain_admission(&job, limiter.try_reserve_global().unwrap());
        assert!(limiter.try_reserve_global().is_ok());
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
            id: canonical.clone(),
            ..output_job("unused", JobState::Created, ciphertext)
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

    /// One encrypted ballot with the SAFE commitment that its ballot proof binds. A vote or an
    /// update carries ballot coefficients and a mask carries zero.
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
        let truncated = &bytes[..bytes.len() / 2];
        assert!(!ciphertext_matches_commitment(
            truncated, commitment, &params
        ));
    }

    /// The SAFE commitment covers `c[0]` and `c[1]` only. A padded ciphertext would otherwise
    /// share one commitment with its two-component prefix, and threshold decryption would reject
    /// it after the service paid to publish it.
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

    /// Intake validates with the parameters the request accepted, not with a local default.
    /// `Interfold.request` stores the configuration identifier that
    /// `ActiveCryptoConfig.configIdForParamSet` produced, and a mismatch with the local tables
    /// would make the recomputed commitment refuse honest ballots.
    #[test]
    fn local_parameters_reproduce_the_onchain_crypto_config_id() {
        let (insecure, insecure_config_id) = bfv_parameters_for_param_set(0).unwrap();
        assert_eq!(
            insecure_config_id,
            "0x7d3f52af7ad13baa9f34ce2426e980907ffeb86b4b374308e6c590d5d43f9e41"
                .parse::<B256>()
                .unwrap(),
            "insecure-512 must reproduce ActiveCryptoConfig.INSECURE_CONFIG_ID"
        );

        let (_, secure_config_id) = bfv_parameters_for_param_set(2).unwrap();
        assert_eq!(
            secure_config_id,
            "0xa174862efd4487031d423ca96516807775ade0191c714e513aab93d0cc289baa"
                .parse::<B256>()
                .unwrap(),
            "secure-8192 must reproduce ActiveCryptoConfig.SECURE_CONFIG_ID"
        );

        assert!(bfv_parameters_for_param_set(1).is_err());
        assert!(bfv_parameters_for_param_set(3).is_err());

        // The cache returns the same tables, so intake does not rebuild them for every ballot.
        assert!(Arc::ptr_eq(
            &insecure,
            &bfv_parameters_for_param_set(0).unwrap().0
        ));
    }

    sol! {
        /// `tests/fixtures/mock_crisp_availability.sol`, built with solc 0.8.30 and
        /// `solc --optimize --bin mock_crisp_availability.sol` in that directory.
        #[sol(rpc, bytecode = "60c0604052336080526001600160401b03600255348015601d575f5ffd5b50604051610a1d380380610a1d833981016040819052603a916041565b60a0526057565b5f602082840312156050575f5ffd5b5051919050565b60805160a05161099e61007f5f395f81816101d1015261036501525f61013b015261099e5ff3fe608060405234801561000f575f5ffd5b5060043610610132575f3560e01c8063912d7b55116100b4578063d016b08d11610079578063d016b08d14610341578063d1245f6214610354578063e5d6ab8f14610387578063efa4f94d1461039f578063f02631ae146103a8578063f7111336146103ca575f5ffd5b8063912d7b55146102a457806392312386146102b75780639b6b9664146102ea578063b604ecfe146102f6578063ca6b137c1461032e575f5ffd5b806362c6aabf116100fa57806362c6aabf1461023f578063795e008b1461026057806383be451a146102755780638d4d2b0c1461028a5780638fa990e31461029b575f5ffd5b8063118b9871146101365780631900f4831461017a578063203487ce146101cc578063406ed35c146101f357806356e0932f14610213575b5f5ffd5b61015d7f000000000000000000000000000000000000000000000000000000000000000081565b6040516001600160a01b0390911681526020015b60405180910390f35b6101be610188366004610527565b6040805167ffffffffffffffff831660208201525f91016040516020818303038152906040528051906020012090509392505050565b604051908152602001610171565b6101be7f000000000000000000000000000000000000000000000000000000000000000081565b610206610201366004610569565b6103d3565b60405161017191906105d6565b61022f61022136600461072a565b5f5460ff1695945050505050565b6040519015158152602001610171565b61022f61024d36600461072a565b50505f54610100900460ff169392505050565b6101be61026e366004610569565b5060015490565b6102886102833660046107bb565b6103e0565b005b5f5461022f90610100900460ff1681565b6101be60015481565b6102886102b2366004610569565b600255565b6102cf6102c5366004610569565b506002545f918290565b60408051938452602084019290925290820152606001610171565b5f5461022f9060ff1681565b610288610304366004610846565b5f805461ffff191693151561ff001916939093176101009215159290920291909117909155600155565b61022f61033c366004610880565b61040a565b61028861034f3660046108fc565b610467565b6101be610362366004610569565b507f000000000000000000000000000000000000000000000000000000000000000090565b6101be61039536600461072a565b5f95945050505050565b6101be60025481565b6103b161025881565b60405167ffffffffffffffff9091168152602001610171565b6101be60035481565b6103db61048b565b919050565b5f805461ff00191661010017815560038054916103fc83610944565b919050555050505050505050565b5f805460ff16156104595760405162461bcd60e51b8152602060048201526015602482015274125b9c1d5d105b1c9958591e541d589b1a5cda1959605a1b604482015260640160405180910390fd5b506001979650505050505050565b5f805460ff19166001178155600380549161048183610944565b9190505550505050565b604051806101e001604052805f81526020015f60ff1681526020015f81526020016104b4610509565b81525f602082018190526040820181905260608083018290526080830181905260a0830182905260c0830182905260e08301829052610100830182905261012083015261014082018190526101609091015290565b60405180604001604052806002906020820280368337509192915050565b5f5f5f60608486031215610539575f5ffd5b8335925060208401359150604084013567ffffffffffffffff8116811461055e575f5ffd5b809150509250925092565b5f60208284031215610579575f5ffd5b5035919050565b805f5b60028110156105a2578151845260209384019390910190600101610583565b50505050565b5f81518084528060208401602086015e5f602082860101526020601f19601f83011685010191505092915050565b60208152815160208201525f60208301516105f6604084018260ff169052565b506040830151606083015260608301516106136080840182610580565b50608083015160c083015260a08301516001600160a01b03811660e08401525060c083015160ff81166101008401525060e083015161020061012084015261065f6102208401826105a8565b905061010084015161067d6101408501826001600160a01b03169052565b506101208401516001600160a01b038116610160850152506101408401516101808401526101608401516101a0840152610180840151601f19848303016101c08501526106ca82826105a8565b9150506101a08401516106e96101e08501826001600160a01b03169052565b506101c08401516102008401528091505092915050565b80356001600160a01b03811681146103db575f5ffd5b803564ffffffffff811681146103db575f5ffd5b5f5f5f5f5f60a0868803121561073e575f5ffd5b85359450602086013593506040860135925061075c60608701610700565b915061076a60808701610716565b90509295509295909350565b5f5f83601f840112610786575f5ffd5b50813567ffffffffffffffff81111561079d575f5ffd5b6020830191508360208285010111156107b4575f5ffd5b9250929050565b5f5f5f5f5f5f5f60c0888a0312156107d1575f5ffd5b873596506107e160208901610700565b955060408801359450606088013593506107fd60808901610716565b925060a088013567ffffffffffffffff811115610818575f5ffd5b6108248a828b01610776565b989b979a50959850939692959293505050565b803580151581146103db575f5ffd5b5f5f5f60608486031215610858575f5ffd5b61086184610837565b925061086f60208501610837565b929592945050506040919091013590565b5f5f5f5f5f5f5f60c0888a031215610896575f5ffd5b87359650602088013567ffffffffffffffff8111156108b3575f5ffd5b6108bf8a828b01610776565b90975095506108d2905060408901610700565b935060608801359250608088013591506108ee60a08901610716565b905092959891949750929550565b5f5f5f6040848603121561090e575f5ffd5b83359250602084013567ffffffffffffffff81111561092b575f5ffd5b61093786828701610776565b9497909650939450505050565b5f6001820161096157634e487b7160e01b5f52601160045260245ffd5b506001019056fea2646970667358221220464980b5df8b58d9b34237308d1e4526d586d921fcb141ccb40ec7184be9c2da64736f6c634300081e0033")]
        contract MockCrispAvailability {
            constructor(bytes32 configId);
            function set(bool isCommitted, bool isPublished, uint256 deadline) external;
            function setComputeDeadline(uint256 deadline) external;
            function committed() external view returns (bool);
            function sends() external view returns (uint256);
        }
    }

    /// A node with the `Interfold` and `CRISPProgram` state of one input, and a service over `db`
    /// that sends from a funded key. Each chain gets a new key: the process keeps one nonce sequence
    /// for each account.
    async fn chain_service(
        db: &Db,
    ) -> (
        AvailabilityService,
        MockCrispAvailability::MockCrispAvailabilityInstance<impl Provider>,
        alloy::node_bindings::AnvilInstance,
    ) {
        use alloy::providers::ext::AnvilApi;

        // One slot for each epoch puts the finalized block two blocks behind the head.
        let anvil = alloy::node_bindings::Anvil::new()
            .args(["--slots-in-an-epoch", "1"])
            .try_spawn()
            .unwrap();
        let signer = PrivateKeySigner::random();
        let provider = ProviderBuilder::new()
            .wallet(signer.clone())
            .connect(&anvil.endpoint())
            .await
            .unwrap();
        provider
            .anvil_set_balance(signer.address(), U256::from(10).pow(U256::from(18)))
            .await
            .unwrap();
        let (_, config_id) = bfv_parameters_for_param_set(0).unwrap();
        let mock = MockCrispAvailability::deploy(provider, config_id)
            .await
            .unwrap();
        let mut service = test_service_on(db, 1 << 20, default_relay());
        service.http_rpc_url = anvil.endpoint();
        service.private_key = format!("0x{}", hex::encode(signer.to_bytes()));
        service.interfold_address = *mock.address();
        service.e3_program_address = *mock.address();
        (service, mock, anvil)
    }

    /// Set the state of the input and its commitment cutoff, and finalize them.
    async fn set_input(
        mock: &MockCrispAvailability::MockCrispAvailabilityInstance<impl Provider>,
        committed: bool,
        published: bool,
        cutoff: u64,
    ) {
        use alloy::providers::ext::AnvilApi;

        mock.set(committed, published, U256::from(cutoff))
            .send()
            .await
            .unwrap()
            .watch()
            .await
            .unwrap();
        mock.provider().anvil_mine(Some(2), None).await.unwrap();
    }

    /// An Avail backend that submits to `rpc`. Nothing answers at its bridge and reader endpoints.
    fn avail_backend(rpc: &str) -> Arc<Backend> {
        Arc::new(Backend::Avail {
            publisher: Arc::new(
                AvailPublisher::new(rpc, 1, "//Alice", "http://127.0.0.1:1", 1).unwrap(),
            ),
            reader: Arc::new(AvailReader::new("http://127.0.0.1:1").unwrap()),
        })
    }

    /// A browser stages a committed input again after the service lost its database, and after the
    /// commitment cutoff. The contract refuses the new-input checks for a committed input, so the
    /// service must recover the input from its chain state. Otherwise `verify` refuses the round
    /// until the compute deadline.
    #[tokio::test]
    async fn a_committed_input_is_recovered_after_the_database_is_lost() {
        let (mut service, mock, _anvil) = chain_service(&temporary_db()).await;
        // The test ends before the service calls Avail.
        service.backend = avail_backend("http://127.0.0.1:1");
        set_input(&mock, true, false, 0).await;
        let envelope = envelope(SLOT, B256::repeat_byte(0x11), b"committed-ciphertext", true);

        let staged = service
            .stage_input("1", envelope, false, None)
            .await
            .unwrap();

        // The worker found the finalized commitment, and publishes the input next.
        let job = service.load_required(&staged.view.job_id).unwrap();
        assert!(matches!(job.state, JobState::Committed { .. }), "{job:?}");
    }

    /// `finalizeInput` refuses a receipt after the compute deadline, so a committed input cannot be
    /// recovered after it. Intake refuses such an input and returns the funding reservation: its
    /// job could only fail, and a failed job does not answer a repeat of its statement.
    #[tokio::test]
    async fn a_committed_input_is_refused_after_the_compute_deadline() {
        let (mut service, mock, _anvil) = chain_service(&temporary_db()).await;
        service.backend = avail_backend("http://127.0.0.1:1");
        mock.setComputeDeadline(U256::from(1))
            .send()
            .await
            .unwrap()
            .watch()
            .await
            .unwrap();
        set_input(&mock, true, false, 0).await;
        let limiter = RateLimiter::with_limits(8, 1);
        let envelope = envelope(SLOT, B256::repeat_byte(0x11), b"late-ciphertext", true);

        let error = service
            .stage_input(
                "1",
                envelope,
                false,
                Some(limiter.try_reserve_global().unwrap()),
            )
            .await
            .err()
            .expect("intake admitted an input that can no longer be finalized");

        assert!(input_rejection_message(&error).is_some(), "{error:#}");
        assert!(limiter.try_reserve_global().is_ok());
    }

    /// Another transaction can publish an input that this service still has to publish, for
    /// example the job of a database that the service lost. While that publication is at the chain
    /// head and not final, the worker waits for it and does not pay for a second Avail
    /// publication.
    #[tokio::test]
    async fn a_publication_at_the_chain_head_is_not_paid_for_again() {
        use alloy::providers::ext::AnvilApi;

        let (mut service, mock, _anvil) = chain_service(&temporary_db()).await;
        // Takes the connection of an Avail submission and never answers it.
        let (avail, avail_url) = never_answering_rpc();
        service.backend = avail_backend(&avail_url);
        set_input(&mock, true, false, u64::MAX).await;
        // Finalized state holds the commitment, and only the chain head holds the publication.
        mock.set(true, true, U256::from(u64::MAX))
            .send()
            .await
            .unwrap()
            .watch()
            .await
            .unwrap();
        let object = b"published-ciphertext";
        let committed = JobState::Committed {
            transaction_hash: "already-committed".to_owned(),
        };
        let job = store_job_in_state(
            &service,
            &open_input_job("published-input", object),
            object,
            committed,
        );

        service.process(&job.id).await;

        assert_nothing_connected(&avail, "the worker submitted a published input to Avail");
        let state = pending_state(&service, &job);
        assert!(matches!(state, JobState::Committed { .. }), "{state:?}");

        mock.provider().anvil_mine(Some(2), None).await.unwrap();
        service.process(&job.id).await;

        let state = pending_state(&service, &job);
        assert!(matches!(state, JobState::Submitted { .. }), "{state:?}");
    }

    /// A local round stores its real commitment cutoff, so the worker prunes the relay record of a
    /// relayed input after that cutoff and its retention margin, as in an Avail round. The ledger
    /// start time stays, so a restart does not move it.
    #[tokio::test]
    async fn a_local_relay_record_is_pruned_after_the_commitment_cutoff() {
        let db = temporary_db();
        let (service, mock, _anvil) = chain_service(&db).await;
        index_round(&db, "1", service.relay_ledger_epoch + 1).await;
        let cutoff = service.chain_timestamp().await.unwrap() + 3_600;
        set_input(&mock, false, false, cutoff).await;
        let (object, commitment) = encrypted_ballot(&insecure_test_params(), &[1]);
        let envelope = envelope(SLOT, commitment, &object, true);

        service
            .stage_input("1", envelope, false, None)
            .await
            .unwrap();

        let past_margin = cutoff + RELAY_RECORD_RETENTION_SECONDS;
        assert_eq!(service.prune_relay_records(past_margin).unwrap(), 0);
        assert_eq!(service.prune_relay_records(past_margin + 1).unwrap(), 1);
        assert_eq!(relay_record_count(&service), 0);
        assert_eq!(
            open_relay_ledger(&service.relayed_inputs, past_margin).unwrap(),
            service.relay_ledger_epoch
        );
    }

    /// A reorganization removes a relayed commitment after its attestation expired, while the
    /// commitment window is still open. The relay sends the input again with a fresh attestation,
    /// so the expired attestation must not fail the job.
    #[tokio::test]
    async fn an_orphaned_relayed_commitment_is_sent_again_after_its_attestation_expired() {
        let (service, mock, _anvil) = chain_service(&temporary_db()).await;
        set_input(&mock, false, false, u64::MAX).await;
        let object = b"orphaned-ciphertext";
        let orphaned = JobState::AwaitingCommitment {
            ethereum_payload: vec![1],
            attestation_expires_at: 1,
            relayed_transaction_hash: Some("0xorphaned".to_owned()),
        };
        let job = store_job_in_state(
            &service,
            &open_input_job("orphaned-relay", object),
            object,
            orphaned,
        );

        service.process(&job.id).await;

        let state = pending_state(&service, &job);
        let JobState::AwaitingCommitment {
            attestation_expires_at,
            relayed_transaction_hash: Some(hash),
            ..
        } = &state
        else {
            panic!("the relay did not send the orphaned commitment again: {state:?}");
        };
        assert_ne!(hash, "0xorphaned");
        assert!(*attestation_expires_at > 1);
        assert!(mock.committed().call().await.unwrap());
    }

    /// A restart between an Ethereum send and the save of its result must not pay for that send
    /// again. Each case stops the worker at one point, and a restarted service over the same
    /// database drives the job to the end: it ends in the same state, and Ethereum takes each paid
    /// transaction once.
    #[tokio::test]
    async fn a_restart_around_an_ethereum_send_pays_for_it_once() {
        let object = b"restarted-ciphertext";
        let job = open_input_job("restarted-input", object);
        let relayed = JobState::AwaitingCommitment {
            ethereum_payload: vec![1],
            attestation_expires_at: u64::MAX,
            relayed_transaction_hash: Some("0xrelayed".to_owned()),
        };
        let finalizing = JobState::Ready {
            ethereum_payload: object.to_vec(),
            commitment_transaction_hash: None,
            publication: None,
        };
        // Where the worker stopped, what Ethereum holds, and the paid sends that are still owed.
        let cases = [
            ("before the relay send", JobState::Created, false, false, 2),
            ("after the relay send", JobState::Created, true, false, 1),
            ("after the relay result was saved", relayed, true, false, 1),
            ("after the finalization", finalizing, true, true, 0),
        ];
        for (point, state, committed, published, owed) in cases {
            let db = temporary_db();
            let (service, mock, _anvil) = chain_service(&db).await;
            index_round(&db, "1", service.relay_ledger_epoch + 1).await;
            set_input(&mock, committed, published, u64::MAX).await;
            store_job_in_state(&service, &job, object, state);
            let restarted = AvailabilityService {
                in_progress: Arc::default(),
                relay_funding_refusals: Arc::default(),
                ..service
            };

            for _ in 0..6 {
                restarted.process(&job.id).await;
            }

            let state = pending_state(&restarted, &job);
            assert!(
                matches!(state, JobState::Submitted { .. }),
                "{point}: {state:?}"
            );
            assert_eq!(
                mock.sends().call().await.unwrap(),
                U256::from(owed),
                "{point}"
            );
        }
    }

    /// A refused candidate returns to the state that asks for a replacement proof. The Avail bytes
    /// are already published, so the replacement costs one bridge request and no second
    /// publication. A temporary RPC error reaches the same path as a refused proof, so the
    /// candidate survives: a job whose replacement never arrives retries the proof it had.
    #[test]
    fn a_refused_candidate_proof_returns_to_awaiting_proof() {
        let service = test_service(1024);
        let object = b"ciphertext";
        let publication = test_publication(keccak256(object).0);
        let state = ready(Some(publication.clone()));
        let job = output_job("refused-proof", state.clone(), object);
        let mut job = store_job_in_state(&service, &job, object, state);

        service
            .recover_rejected_proof(
                &mut job,
                Some("0xcommit".to_owned()),
                Some(publication.clone()),
                Some(vec![0xaa; 4]),
            )
            .unwrap();

        let stored = service.load_required(&job.id).unwrap();
        let JobState::AwaitingProof {
            publication: recovered,
            commitment_transaction_hash,
            last_candidate,
        } = stored.state
        else {
            panic!("a refused candidate must be able to request a replacement");
        };
        assert_eq!(recovered, publication);
        assert_eq!(commitment_transaction_hash, Some("0xcommit".to_owned()));
        assert_eq!(last_candidate, Some(vec![0xaa; 4]));
        // The bytes stay available, so the replacement pays for no second publication.
        assert_eq!(
            service.object_required(stored.content_hash).unwrap(),
            object
        );
    }

    /// A replacement proof supersedes the candidate it replaces. Without one, the job falls back
    /// to the candidate it had, and a job with neither stays in `AwaitingProof`.
    #[test]
    fn a_replacement_proof_supersedes_the_last_candidate() {
        let candidate = vec![0xaa; 4];
        let replacement = vec![0xbb; 8];
        for (refreshed, last_candidate, expected) in [
            (
                Some(replacement.clone()),
                Some(candidate.clone()),
                Some(replacement.clone()),
            ),
            (None, Some(candidate.clone()), Some(candidate)),
            (None, None, None),
        ] {
            assert_eq!(
                AvailabilityService::publishable_payload(refreshed, last_candidate, "job"),
                expected
            );
        }
    }

    /// A record written before the coordinates were kept must still decode. Such a job has nothing
    /// to ask the bridge with, so it keeps its candidate proof instead of failing to load.
    #[test]
    fn a_legacy_ready_job_without_coordinates_decodes_and_is_not_recovered() {
        let service = test_service(1024);
        let object = b"ciphertext";
        let job = output_job(
            "legacy-ready",
            ready(Some(test_publication(keccak256(object).0))),
            object,
        );
        let mut encoded = serde_json::to_value(&job).unwrap();
        encoded["state"]
            .as_object_mut()
            .unwrap()
            .remove("publication");

        let mut legacy = AvailabilityJob::decode(&serde_json::to_vec(&encoded).unwrap()).unwrap();
        let JobState::Ready {
            publication,
            ethereum_payload,
            ..
        } = legacy.state.clone()
        else {
            panic!("expected a job with a candidate proof");
        };
        assert_eq!(publication, None);
        assert_eq!(ethereum_payload, vec![0xaa; 4]);

        // With no coordinates there is no replacement to request, so the state is unchanged.
        service
            .recover_rejected_proof(&mut legacy, None, None, Some(vec![0xaa; 4]))
            .unwrap();
        assert!(matches!(legacy.state, JobState::Ready { .. }));
    }

    /// A submitted publication waits for finality before the job retires. Retirement clears the
    /// recovery material and can delete the local object, and a transaction seen only at the chain
    /// head can be orphaned.
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
        let job = output_job("awaiting-finality", state.clone(), object);
        let mut job = store_job_in_state(&service, &job, object, state);

        // Everything a resend needs survives: the object and the compute proof. The worker still
        // schedules the job, startup validation accepts it, and the client keeps waiting.
        assert_eq!(service.object_required(job.content_hash).unwrap(), object);
        let JobKind::Output { compute_proof, .. } = service.load_required(&job.id).unwrap().kind
        else {
            panic!("expected an output job");
        };
        assert!(!compute_proof.is_empty());
        assert!(service.pending_ids().contains(&job.id));
        assert!(service.validate_storage().is_ok());
        let view = AvailabilityJobView::from(&job);
        assert_eq!(view.status, "pending_availability");
        assert_eq!(view.tx_hash, Some("0xpublish".to_owned()));

        job.state = JobState::Submitted {
            transaction_hash: "0xpublish".to_owned(),
        };
        service.save(&job).unwrap();

        assert!(!service.pending_ids().contains(&job.id));
        let JobKind::Output { compute_proof, .. } = service.load_required(&job.id).unwrap().kind
        else {
            panic!("expected an output job");
        };
        assert!(compute_proof.is_empty());
    }

    /// The status refresh takes the same per-job ownership as the worker. Both paths load a copy,
    /// await an Ethereum read, and then save. Without one owner, a stale copy can replace newer
    /// durable progress and discard saved Avail coordinates.
    #[tokio::test]
    async fn a_status_refresh_does_not_write_while_the_worker_owns_the_job() {
        let service = test_service(1024);
        let object = b"ciphertext";
        let publication = test_publication(keccak256(object).0);
        let state = JobState::AwaitingProof {
            publication: publication.clone(),
            commitment_transaction_hash: None,
            last_candidate: None,
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
        } = pending_state(&service, &job)
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

    /// A client polls the status of a `Created` job for the relay decision. The read must not call
    /// Ethereum under the job claim: a claim held by a poll makes the worker skip the job for a
    /// whole pass, and a `Created` job has nothing on Ethereum to reconcile.
    #[tokio::test]
    async fn a_status_read_of_a_created_job_leaves_it_to_the_worker() {
        let (rpc, rpc_url) = never_answering_rpc();
        let mut service = test_service(1024);
        service.http_rpc_url = rpc_url;
        service.private_key =
            "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80".to_owned();
        service.e3_program_address = Address::repeat_byte(0x55);
        let object = b"queued-ciphertext";
        let job = input_job("queued-input", SLOT, 0x11, object);
        service.store_new_job_with_object(&job, object).unwrap();

        let view = service
            .refreshed_view(&job.id)
            .await
            .unwrap()
            .expect("the job exists");

        assert_eq!(view.status, "pending_commitment");
        assert_nothing_connected(
            &rpc,
            "a status read of a created job must not call Ethereum",
        );
    }

    /// An undecodable record in the jobs tree must not stop the worker: it skips the record and
    /// keeps driving the others, while the clock runs through several passes.
    #[tokio::test(start_paused = true)]
    async fn an_unreadable_job_record_does_not_stop_the_worker() {
        let service = test_service(1024);
        let object = b"queued-ciphertext";
        let job = input_job("queued-input", SLOT, 0x11, object);
        service.store_new_job_with_object(&job, object).unwrap();
        service.jobs.insert("corrupt", &b"{not json"[..]).unwrap();

        assert_eq!(service.pending_ids(), vec![job.id.clone()]);

        let worker = tokio::time::timeout(Duration::from_secs(120), Arc::new(service).run()).await;
        assert!(
            worker.is_err(),
            "the worker stopped on an unreadable record: {worker:?}"
        );
    }

    /// A repeat of an existing statement must not consume funding quota: `existing_input_job`
    /// answers a replay without creating work, so the route can serve it before it touches the
    /// global window.
    #[tokio::test]
    async fn replaying_an_existing_statement_is_idempotent_without_new_work() {
        let service = test_service(4096);
        let object = b"voter-ciphertext";
        let envelope = envelope(SLOT, B256::repeat_byte(0x11), object, true);

        // No job yet: the caller is a potential new admission and must reserve quota.
        assert!(service
            .existing_input_job("1", &envelope)
            .await
            .unwrap()
            .is_none());

        let (_, _, _, id) = service.input_identity("1", &envelope).unwrap();
        let job = AvailabilityJob {
            id: id.clone(),
            ..open_input_job("unused", object)
        };
        let done = JobState::Submitted {
            transaction_hash: "0xdone".to_owned(),
        };
        store_job_in_state(&service, &job, object, done);

        // The same statement now resolves to the stored job, with no new durable work, and so
        // does a noncanonical alias of the same E3.
        for e3_id in ["1", "001"] {
            let replay = service
                .existing_input_job(e3_id, &envelope)
                .await
                .unwrap()
                .expect("the statement already has a job");
            assert_eq!(replay.job_id, id);
            assert_eq!(replay.status, "success");
            assert_eq!(service.jobs.len(), 1);
        }
    }

    /// A failed job restarted under one identifier creates a fresh funding obligation, so it must
    /// not take the free replay path.
    #[tokio::test]
    async fn a_failed_job_is_not_a_free_replay() {
        let service = test_service(4096);
        let object = b"voter-ciphertext";
        let envelope = envelope(SLOT, B256::repeat_byte(0x11), object, true);
        let (_, _, _, id) = service.input_identity("1", &envelope).unwrap();
        let job = AvailabilityJob {
            id,
            ..open_input_job("unused", object)
        };
        store_job_in_state(
            &service,
            &job,
            object,
            failed("availability promise expired"),
        );

        assert!(
            service
                .existing_input_job("1", &envelope)
                .await
                .unwrap()
                .is_none(),
            "restarting a failed job must reserve funding capacity"
        );
    }

    /// An invalid envelope is refused before it reaches the free replay path.
    #[tokio::test]
    async fn the_replay_check_still_validates_the_envelope() {
        let service = test_service(4096);
        let rejection = |error: anyhow::Error| input_rejection_message(&error);

        let error = service
            .existing_input_job("1", b"not-an-envelope")
            .await
            .unwrap_err();
        assert_eq!(
            rejection(error),
            Some("The encoded vote envelope is invalid")
        );

        // Bytes that do not reproduce their committed hash are refused as well.
        let mut mismatched =
            InputEnvelope::abi_decode_params_validate(&envelope(SLOT, B256::ZERO, b"real", true))
                .unwrap();
        mismatched.encryptedVoteHash = B256::repeat_byte(0x99);
        let error = service
            .existing_input_job("1", &mismatched.abi_encode_params())
            .await
            .unwrap_err();
        assert_eq!(
            rejection(error),
            Some("The encrypted vote does not match its committed hash")
        );

        let error = service
            .existing_input_job("not-an-e3", &envelope(SLOT, B256::ZERO, b"real", true))
            .await
            .unwrap_err();
        assert_eq!(rejection(error), Some("The E3 identifier is invalid"));
    }
}
