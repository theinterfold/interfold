// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::server::models::{
    CustomParams, ExclusionReason, InputSelectionResponse, InputSelectionStatus, TokenHolder,
};

use super::{
    database::{generate_emoji, CIPHERTEXT_KEY_PREFIX, INPUT_GENERATION_KEY_PREFIX},
    models::{CurrentRound, E3Crisp, E3StateLite, WebResultRequest},
};
use alloy::primitives::{keccak256, Address};
use e3_compute_provider::policy::InputRecord;
use e3_sdk::indexer::{models::E3 as InterfoldE3, DataStore, E3Repository, SharedStore};
use e3_user_program::policy::chain_head_per_slot;
use eyre::Result;
use fhe::bfv::BfvParameters;
use log::info;
use num_bigint::BigUint;
use std::collections::HashMap;
use std::sync::{Arc, LazyLock, Mutex};

/// The key prefix of a round record. The round ID follows it.
pub const CRISP_KEY_PREFIX: &str = "_e3:crisp:";

/// How many rounds the input cache holds. Voters poll the rounds that are open, which are few.
const INPUT_CACHE_ROUNDS: usize = 8;

#[derive(Debug, Default, serde::Deserialize, serde::Serialize)]
struct RoundIndex {
    ids: Vec<String>,
}

pub struct CurrentRoundRepository<S: DataStore> {
    store: SharedStore<S>,
}

impl<S: DataStore> CurrentRoundRepository<S> {
    pub fn new(store: SharedStore<S>) -> Self {
        Self { store }
    }

    pub async fn set_current_round(&mut self, value: CurrentRound) -> Result<()> {
        let key = self.current_round_key();
        self.store
            .insert(&key, &value)
            .await
            .map_err(|_| eyre::eyre!("Could not set current_round for '{key}'"))?;
        Ok(())
    }

    pub async fn record_round(&mut self, e3_id: impl ToString) -> Result<()> {
        let e3_id = e3_id.to_string();
        let key = self.round_index_key();
        self.store
            .modify(&key, |index: Option<RoundIndex>| {
                let mut index = index.unwrap_or_default();
                if !index.ids.contains(&e3_id) {
                    index.ids.push(e3_id.clone());
                }
                Some(index)
            })
            .await
            .map_err(|_| eyre::eyre!("Could not record round in '{key}'"))?;
        Ok(())
    }

    pub async fn get_round_ids(&self) -> Result<Vec<String>> {
        let key = self.round_index_key();
        let index = self
            .store
            .get::<RoundIndex>(&key)
            .await
            .map_err(|_| eyre::eyre!("Could not get round index at '{key}'"))?
            .unwrap_or_default();
        Ok(index.ids)
    }

    pub async fn get_current_round(&self) -> Result<Option<CurrentRound>> {
        let key = self.current_round_key();
        let round = self
            .store
            .get::<CurrentRound>(&key)
            .await
            .map_err(|_| eyre::eyre!("Could get e3 at '{key}'"))?;

        Ok(round)
    }

    /// Get the current (most recent) round for a specific requester
    ///
    /// # Arguments
    /// * `requester` - The requester address to find the current round for
    ///
    /// # Returns
    /// * The CurrentRound object for the most recent round by this requester, or None if not found
    pub async fn get_current_round_for_requester(
        &self,
        requester: String,
    ) -> Result<Option<CurrentRound>> {
        for round_id in self.get_round_ids().await?.into_iter().rev() {
            let crisp_repo = CrispE3Repository::new(self.store.clone(), &round_id);

            if crisp_repo.is_requested_by(&requester).await? {
                return Ok(Some(CurrentRound { id: round_id }));
            }
        }

        Ok(None)
    }

    fn current_round_key(&self) -> String {
        "_e3:current_round".to_string()
    }

    fn round_index_key(&self) -> String {
        "_e3:round_index".to_string()
    }
}

/// A round's inputs, read in one shot so the four vectors describe the same moment.
///
/// Every vector is in on-chain index order and has one entry per ciphertext.
pub struct InputSnapshot {
    /// The published ciphertexts, each paired with its on-chain index.
    pub ciphertexts: Vec<(Vec<u8>, u64)>,
    /// The commitment `CRISPProgram` stored for each input.
    pub commitments: Vec<[u8; 32]>,
    /// The slot each input was published to.
    pub slots: Vec<[u8; 20]>,
    /// The entry each input names as the one it extends, plus one; zero for none.
    pub parents: Vec<u64>,
    /// Whether each input's bytes reproduce its commitment, decided when it was indexed.
    pub usable: Vec<bool>,
}

impl InputSnapshot {
    /// The position of the head of one slot, given the positions of that slot's entries in
    /// tree-index order.
    ///
    /// The Secure Process's own rule decides (`chain_head_per_slot`): an entry becomes the head
    /// only when its published bytes reproduce its commitment and it names the head before it, so
    /// an entry nobody can open never becomes the head and never blocks the slot. The usability
    /// decision made at indexing stands in for the commitment check. The rule compares a parent
    /// only with the head of the entry's own slot, so the entries of other slots cannot move this
    /// head and are left out.
    fn slot_head(&self, entries: &[usize]) -> Option<usize> {
        let commitment = [0u8; 32];
        // The layout `CRISPProgram` publishes: the slot, then the parent plus one as a uint40.
        let metadata: Vec<[u8; 25]> = entries
            .iter()
            .map(|&position| {
                let mut bytes = [0u8; 25];
                bytes[..20].copy_from_slice(&self.slots[position]);
                bytes[20..].copy_from_slice(&self.parents[position].to_be_bytes()[3..]);
                bytes
            })
            .collect();
        let inputs: Vec<InputRecord> = entries
            .iter()
            .zip(&metadata)
            .map(|(&position, metadata)| InputRecord {
                index: self.ciphertexts[position].1 as usize,
                ciphertext_hash: [0; 32],
                commitment: Some(&commitment),
                metadata,
                recomputed: self.usable[position].then_some(commitment),
            })
            .collect();
        chain_head_per_slot(&inputs)
            .first()
            .and_then(|&index| self.position_of(index as u64))
    }

    /// The position of the entry with tree index `index`. The entries are sorted by tree index.
    fn position_of(&self, index: u64) -> Option<usize> {
        self.ciphertexts
            .binary_search_by_key(&index, |(_, entry)| *entry)
            .ok()
    }

    /// Where the input `(slot, commitment, parent_index_plus_one)` with bytes of hash
    /// `content_hash` stands in the selection of its slot. `entries` holds the positions of the
    /// slot's entries in tree-index order, and `hashes` the content hash of each entry, in the
    /// order of the snapshot.
    ///
    /// The verdict for an entry is final only when every lower tree index is indexed here: tree
    /// indexes are dense, and a missing entry can still take the slot or be the parent of the entry.
    fn selection(
        &self,
        hashes: &[[u8; 32]],
        entries: &[usize],
        slot: [u8; 20],
        commitment: [u8; 32],
        parent_index_plus_one: u64,
        content_hash: [u8; 32],
    ) -> InputSelectionResponse {
        let head_index = self
            .slot_head(entries)
            .map(|position| self.ciphertexts[position].1);
        let input = entries.iter().copied().find(|&position| {
            self.commitments[position] == commitment
                && self.parents[position] == parent_index_plus_one
                && hashes[position] == content_hash
        });
        let Some(position) = input else {
            return InputSelectionResponse {
                status: InputSelectionStatus::NotIndexed,
                index: None,
                head_index,
                reason: None,
            };
        };
        let index = self.ciphertexts[position].1;
        // A head at its turn stays selected when a later entry extends it.
        let was_head = |position: usize| {
            let turn = entries.partition_point(|&entry| entry <= position);
            self.slot_head(&entries[..turn]) == Some(position)
        };
        let (status, reason) = if position as u64 != index {
            (InputSelectionStatus::SelectionPending, None)
        } else if was_head(position) {
            (InputSelectionStatus::Selected, None)
        } else if !self.usable[position] {
            (
                InputSelectionStatus::Excluded,
                Some(ExclusionReason::Unusable),
            )
        } else {
            // A usable entry is dropped when the head moved on before its turn. The head moves
            // only to an entry that names it, so an earlier sibling took the parent exactly when
            // the parent was the head of this slot: the slot starts with no head, and a parent
            // in the slot was the head when it became one at its turn.
            let sibling_took_parent = match parent_index_plus_one.checked_sub(1) {
                None => true,
                Some(parent) => self
                    .position_of(parent)
                    .is_some_and(|parent| self.slots[parent] == slot && was_head(parent)),
            };
            let reason = if sibling_took_parent {
                ExclusionReason::EarlierSibling
            } else {
                ExclusionReason::StaleParent
            };
            (InputSelectionStatus::Excluded, Some(reason))
        };
        InputSelectionResponse {
            status,
            index: Some(index),
            head_index,
            reason,
        }
    }
}

/// A round's inputs as the slot head and the selection read them, with the entries of each slot.
struct IndexedInputs {
    records: InputSnapshot,
    /// The content hash of each entry, in the order of `records`.
    hashes: Vec<[u8; 32]>,
    /// The positions of each slot's entries, in tree-index order.
    by_slot: HashMap<[u8; 20], Vec<usize>>,
}

impl IndexedInputs {
    fn new(records: InputSnapshot, hashes: Vec<[u8; 32]>) -> Self {
        let mut by_slot: HashMap<[u8; 20], Vec<usize>> = HashMap::new();
        for (position, slot) in records.slots.iter().enumerate() {
            by_slot.entry(*slot).or_default().push(position);
        }
        Self {
            records,
            hashes,
            by_slot,
        }
    }

    /// The positions of the entries of `slot`, in tree-index order.
    fn entries_of(&self, slot: [u8; 20]) -> &[usize] {
        self.by_slot.get(&slot).map_or(&[], Vec::as_slice)
    }
}

/// How far the inputs of a round have changed, for the input cache. It is kept under
/// `INPUT_GENERATION_KEY_PREFIX`.
///
/// `epoch` is random and chosen with the first change, so two stores never share a generation.
/// `started` and `finished` count the changes that began and the changes that completed. A change
/// in progress, or one that failed after it began, leaves them unequal.
#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
struct InputGeneration {
    epoch: String,
    started: u64,
    finished: u64,
}

/// One round's inputs that this process read, with the settled input generation they were read
/// under.
struct CachedInputs {
    e3_id: String,
    generation: InputGeneration,
    inputs: Arc<IndexedInputs>,
}

/// The rounds whose inputs this process read, the newest last.
static INPUT_CACHE: LazyLock<Mutex<Vec<CachedInputs>>> = LazyLock::new(|| Mutex::new(Vec::new()));

/// The inputs of round `e3_id` that this process read at `generation`.
fn cached_inputs(e3_id: &str, generation: &InputGeneration) -> Option<Arc<IndexedInputs>> {
    let cache = INPUT_CACHE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    cache
        .iter()
        .find(|cached| cached.e3_id == e3_id && cached.generation == *generation)
        .map(|cached| Arc::clone(&cached.inputs))
}

/// Keep the inputs of round `e3_id` read at `generation`, in place of an older read of the round.
fn cache_inputs(e3_id: &str, generation: InputGeneration, inputs: Arc<IndexedInputs>) {
    let mut cache = INPUT_CACHE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    cache.retain(|cached| cached.e3_id != e3_id);
    if cache.len() == INPUT_CACHE_ROUNDS {
        cache.remove(0);
    }
    cache.push(CachedInputs {
        e3_id: e3_id.to_owned(),
        generation,
        inputs,
    });
}

pub struct CrispE3Repository<S: DataStore> {
    store: SharedStore<S>,
    e3_id: String,
}

impl<S: DataStore> CrispE3Repository<S> {
    pub fn new(store: SharedStore<S>, e3_id: impl ToString) -> Self {
        Self {
            store,
            e3_id: e3_id.to_string(),
        }
    }

    #[cfg(test)]
    async fn set_crisp(&mut self, value: E3Crisp) -> Result<()> {
        // The record is written whole and without a generation, so reads skip the input cache.
        let generation_key = self.input_generation_key();
        self.store
            .modify(&generation_key, |_: Option<InputGeneration>| None)
            .await
            .map_err(|_| {
                eyre::eyre!("Could not clear the input generation at '{generation_key}'")
            })?;
        let key = self.crisp_key();
        self.store
            .insert(&key, &value)
            .await
            .map_err(|_| eyre::eyre!("Could not store crisp at '{key}'"))?;
        Ok(())
    }

    /// The round's CRISP record, or `None` when there is no such round.
    ///
    /// The distinction between "absent" and "broken" only exists here: every caller below that
    /// flattens it into an error loses it, and a handler that cannot tell the two apart has to
    /// answer 500 to a client that asked for a round that was simply never requested.
    pub async fn try_get_crisp(&self) -> Result<Option<E3Crisp>> {
        let key = self.crisp_key();
        self.store
            .get::<E3Crisp>(&key)
            .await
            .map_err(|e| eyre::eyre!("Could get crisp at '{key}' due to error: {e}"))
    }

    /// Whether this server has a record of the round at all.
    ///
    /// The CRISP record is written when `E3Requested` is indexed; the indexer's `_e3:` record only
    /// lands after a public-key byte event passes commitment verification. A round can
    /// therefore have the first record and not the second during DKG or after on-chain
    /// `KeyPublished`. Without this check, "verified key bytes are pending" reads as "no such
    /// round".
    pub async fn has_crisp_record(&self) -> Result<bool> {
        Ok(self.try_get_crisp().await?.is_some())
    }

    /// Whether the request-time CRISP record belongs to `requester`.
    pub async fn is_requested_by(&self, requester: &str) -> Result<bool> {
        Ok(self
            .try_get_crisp()
            .await?
            .is_some_and(|round| round.requester.eq_ignore_ascii_case(requester)))
    }

    /// Whether the generic indexer stored a verified committee public key for this round.
    pub async fn has_indexed_public_key(&self) -> Result<bool> {
        Ok(self.try_get_e3().await?.is_some())
    }

    pub async fn get_crisp(&self) -> Result<E3Crisp> {
        let key = self.crisp_key();
        let e3_crisp = self
            .try_get_crisp()
            .await?
            .ok_or(eyre::eyre!("No data found at {key}"))?;
        Ok(e3_crisp)
    }

    /// The round's inputs for the slot head and the selection, or `None` when there is no round
    /// record.
    ///
    /// Served from this process's cache while the round's input generation is settled, with as many
    /// changes finished as started, and is the one they were read under. A round whose generation
    /// is not settled, or that has none because no input reached it since the upgrade, is read from
    /// the store every time.
    async fn indexed_inputs(&self) -> Result<Option<Arc<IndexedInputs>>> {
        // Read before the record. Every change counted as finished here wrote the record first, so
        // the record read below holds it. A change that starts later raises `started` for good, so
        // this generation is never settled again and a read cached under it is never served.
        let generation_key = self.input_generation_key();
        let generation: Option<InputGeneration> =
            self.store.get(&generation_key).await.map_err(|e| {
                eyre::eyre!("Could not read the input generation at '{generation_key}': {e}")
            })?;
        let settled = generation.filter(|generation| generation.started == generation.finished);
        if let Some(cached) = settled
            .as_ref()
            .and_then(|generation| cached_inputs(&self.e3_id, generation))
        {
            return Ok(Some(cached));
        }
        let Some(round) = self.try_get_crisp().await? else {
            return Ok(None);
        };
        let (records, hashes) = Self::records_of(round)?;
        let inputs = Arc::new(IndexedInputs::new(records, hashes));
        if let Some(generation) = settled {
            cache_inputs(&self.e3_id, generation, Arc::clone(&inputs));
        }
        Ok(Some(inputs))
    }

    /// Apply `change` to the inputs of the round record, and count it in the input generation.
    ///
    /// Every change to the input fields goes through here. It is counted as started before the
    /// record changes and as finished after, so no read caches the round while the change is in
    /// progress. A change that fails after it started leaves the round unsettled, and its inputs
    /// are then read from the store until `settle_input_generation` runs at the next start.
    async fn modify_inputs(&mut self, mut change: impl FnMut(&mut E3Crisp) + Send) -> Result<()> {
        let generation_key = self.input_generation_key();
        self.store
            .modify(&generation_key, |generation: Option<InputGeneration>| {
                let mut generation = generation.unwrap_or_else(|| InputGeneration {
                    epoch: format!("{:032x}", rand::random::<u128>()),
                    started: 0,
                    finished: 0,
                });
                generation.started += 1;
                Some(generation)
            })
            .await
            .map_err(|e| {
                eyre::eyre!("Could not start a change of the inputs at '{generation_key}': {e}")
            })?;
        let key = self.crisp_key();
        self.store
            .modify(&key, |round: Option<E3Crisp>| {
                round.map(|mut round| {
                    change(&mut round);
                    round
                })
            })
            .await
            .map_err(|e| eyre::eyre!("Could not update the inputs at '{key}': {e}"))?;
        self.store
            .modify(&generation_key, |generation: Option<InputGeneration>| {
                generation.map(|mut generation| {
                    generation.finished += 1;
                    generation
                })
            })
            .await
            .map_err(|e| {
                eyre::eyre!("Could not finish a change of the inputs at '{generation_key}': {e}")
            })?;
        Ok(())
    }

    /// Count every change of the inputs that started before this start as finished.
    ///
    /// Call it at startup, before the indexer runs, when no change is in progress. The round record
    /// then holds what each earlier change wrote, so the generation can settle and the cache can
    /// serve the round again.
    pub async fn settle_input_generation(&mut self) -> Result<()> {
        let generation_key = self.input_generation_key();
        self.store
            .modify(&generation_key, |generation: Option<InputGeneration>| {
                generation.map(|mut generation| {
                    generation.finished = generation.started;
                    generation
                })
            })
            .await
            .map_err(|e| {
                eyre::eyre!("Could not settle the input generation at '{generation_key}': {e}")
            })?;
        Ok(())
    }

    /// Start a requested round once. Duplicate committee events do not reset its deadline state.
    pub async fn try_start_round(&mut self) -> Result<bool> {
        let key = self.crisp_key();
        let mut started = false;
        let now = chrono::Utc::now().timestamp() as u64;
        self.store
            .modify(&key, |current: Option<E3Crisp>| {
                current.map(|mut round| {
                    if round.status == "Requested" {
                        round.start_time = now;
                        round.status = "Active".to_owned();
                        started = true;
                    }
                    round
                })
            })
            .await
            .map_err(|error| eyre::eyre!("Could not start CRISP round at '{key}': {error}"))?;
        Ok(started)
    }

    pub async fn insert_ciphertext_input(
        &mut self,
        vote: Vec<u8>,
        index: u64,
        commitment: [u8; 32],
        slot: [u8; 20],
        parent_index_plus_one: u64,
        params: &BfvParameters,
    ) -> Result<()> {
        let key = self.crisp_key();
        // The bytes first, under their content hash, which the round record names in the same
        // update as the other fields of the input. A ballot that replaces another at this index
        // after a reorganization can then never be read with the fields of the other ballot.
        let hash = keccak256(&vote).0;
        self.store_ciphertext(index, hash, &vote).await?;

        // Decided here, once, rather than on every read. An entry's bytes never change, so neither
        // does the answer. `Err` means the bytes do not deserialize, which is itself unusable.
        let usable = e3_bfv_client::client::compute_ct_commitment(
            vote,
            params.degree(),
            params.plaintext(),
            params.moduli().to_vec(),
        )
        .is_ok_and(|recomputed| recomputed == commitment);

        self.modify_inputs(|e| {
            match e
                .input_ciphertext_hashes
                .iter_mut()
                .find(|(i, _)| *i == index)
            {
                Some(existing) => existing.1 = hash,
                None => e.input_ciphertext_hashes.push((index, hash)),
            }
            if let Some(existing) = e.input_commitments.iter_mut().find(|(i, _)| *i == index) {
                existing.1 = commitment;
            } else {
                e.input_commitments.push((index, commitment));
            }
            if let Some(existing) = e.input_slots.iter_mut().find(|(i, _)| *i == index) {
                existing.1 = slot;
            } else {
                e.input_slots.push((index, slot));
            }
            if let Some(existing) = e.input_parents.iter_mut().find(|(i, _)| *i == index) {
                existing.1 = parent_index_plus_one;
            } else {
                e.input_parents.push((index, parent_index_plus_one));
            }
            if let Some(existing) = e.input_usable.iter_mut().find(|(i, _)| *i == index) {
                existing.1 = usable;
            } else {
                e.input_usable.push((index, usable));
            }
        })
        .await
        .map_err(|e| eyre::eyre!("Could not append ciphertext_input for '{key}': {e}"))?;

        Ok(())
    }

    /// Move the ciphertexts that an older release kept inside the round record to their own keys.
    ///
    /// The inline copies go only after `sync` succeeds. sled does not sync the file of a large
    /// value, so without the sync a crash could lose the only copy of a ballot. The sync covers the
    /// log and the files of large values that exist when it runs. sled can later write the page of
    /// a moved ballot again into a new file that the sync does not cover, as it can for every large
    /// value that the server stores. An entry without a commitment was indexed before the
    /// commitments existed. It stays, so that reads still refuse the round (`input_records`).
    pub async fn move_inline_ciphertexts(
        &mut self,
        sync: impl FnOnce() -> Result<()>,
    ) -> Result<()> {
        let Some(round) = self.try_get_crisp().await? else {
            return Ok(());
        };
        let mut moved = Vec::new();
        for (bytes, index) in &round.ciphertext_inputs {
            if round.input_commitments.iter().any(|(i, _)| i == index) {
                let hash = keccak256(bytes).0;
                self.store_ciphertext(*index, hash, bytes).await?;
                moved.push((*index, hash));
            }
        }
        if moved.is_empty() {
            return Ok(());
        }
        sync()?;
        let key = self.crisp_key();
        let is_moved = |index: &u64| moved.iter().any(|(i, _)| i == index);
        self.modify_inputs(|round| {
            round
                .ciphertext_inputs
                .retain(|(_, index)| !is_moved(index));
            round
                .input_ciphertext_hashes
                .retain(|(index, _)| !is_moved(index));
            round.input_ciphertext_hashes.extend(moved.iter().copied());
        })
        .await
        .map_err(|e| eyre::eyre!("Could not clear the inline ciphertexts at '{key}': {e}"))?;
        Ok(())
    }

    pub async fn initialize_round(
        &mut self,
        custom_params: CustomParams,
        e3_program: Address,
        requester: String,
        voting_end_time: u64,
        end_time: u64,
        snapshot_block: u64,
    ) -> Result<()> {
        let key = self.crisp_key();
        let initial = E3Crisp {
            input_commitments: Vec::new(),
            input_slots: Vec::new(),
            input_parents: Vec::new(),
            input_ciphertext_hashes: Vec::new(),
            input_usable: Vec::new(),
            start_time: 0u64,
            voting_end_time,
            status: "Requested".to_string(),
            tally: vec![],
            emojis: generate_emoji(),
            token_holder_hashes: vec![],
            eligible_addresses: vec![],
            token_address: custom_params.token_address,
            balance_threshold: custom_params.balance_threshold,
            ciphertext_inputs: vec![],
            requester,
            num_options: custom_params.num_options,
            credit_mode: custom_params.credit_mode,
            credits: custom_params.credits,
            census_mode: custom_params.census_mode,
            end_time,
            snapshot_block,
            discovery_pending: false,
            e3_program: e3_program.to_string(),
        };

        self.store
            .modify(&key, move |current: Option<E3Crisp>| {
                current.or_else(|| Some(initial.clone()))
            })
            .await
            .map_err(|_| eyre::eyre!("Could not initialize round at '{key}'"))?;
        Ok(())
    }

    fn get_e3_repo(&self) -> E3Repository<S> {
        E3Repository::new(self.store.clone(), &self.e3_id)
    }

    pub async fn get_e3(&self) -> Result<InterfoldE3> {
        let e3 = self.get_e3_repo().get_e3().await?;
        Ok(e3)
    }

    /// The indexer's E3 record, or `None` when the round has none yet.
    ///
    /// Read straight from the store rather than through `E3Repository::get_e3`, which folds the
    /// missing case into an error string. The key mirrors `E3Repository::e3_key` — the same
    /// convention `crisp_key` already follows one level down.
    async fn try_get_e3(&self) -> Result<Option<InterfoldE3>> {
        let key = format!("_e3:{}", self.e3_id);
        self.store
            .get::<InterfoldE3>(&key)
            .await
            .map_err(|e| eyre::eyre!("Could get e3 at '{key}' due to error: {e}"))
    }

    /// How many slots hold at least one available, locally indexed entry.
    ///
    /// The closest thing to a participation count the server can give. A mask is
    /// indistinguishable from a vote by design, so per-slot activity — not "who voted" — is what
    /// is countable, and a slot with ten entries still counts once.
    pub async fn get_vote_count(&self) -> Result<u64> {
        let e3_crisp = self.get_crisp().await?;
        Ok(count_active_slots(&e3_crisp.input_slots))
    }

    /// The round's current status.
    ///
    /// Read by the deadline handler so a retry pass can tell a round it already moved on from. The
    /// handler runs more than once, and computation is one-shot.
    pub async fn get_status(&self) -> Result<String> {
        let e3_crisp = self.get_crisp().await?;
        Ok(e3_crisp.status)
    }

    /// Marks a round expired only while it is still waiting for computation.
    ///
    /// Deadline callbacks can overlap. A blind status write can move a round from
    /// `PublishingCiphertext` back to `Expired`, which permits a second compute request.
    pub async fn try_mark_expired(&mut self) -> Result<bool> {
        let key = self.crisp_key();
        let mut marked = false;
        self.store
            .modify(&key, |e3_obj: Option<E3Crisp>| {
                e3_obj.map(|mut e| {
                    if e.status == "Active" || e.status == "Expired" {
                        e.status = "Expired".to_owned();
                        marked = true;
                    }
                    e
                })
            })
            .await
            .map_err(|_| eyre::eyre!("Could not expire round at '{key}'"))?;
        Ok(marked)
    }

    /// Moves the round to "Computing", but only if nothing has claimed it yet.
    ///
    /// Returns whether this caller made the transition. One store operation, because `modify` is a
    /// read-modify-write under a single write lock: reading the status and writing it back as two
    /// separate awaits leaves a window where two deadline passes both observe "Expired" and both
    /// submit `run_compute` concurrently. Restart recovery can submit again because the remote
    /// response might have been lost; Interfold is the durable idempotency boundary and accepts
    /// only the first valid ciphertext output.
    pub async fn try_claim_computing(&mut self) -> Result<bool> {
        let key = self.crisp_key();
        let mut claimed = false;

        self.store
            .modify(&key, |e3_obj: Option<E3Crisp>| {
                e3_obj.map(|mut e| {
                    if e.status == "Expired" {
                        e.status = "Computing".to_string();
                        claimed = true;
                    }
                    e
                })
            })
            .await
            .map_err(|_| eyre::eyre!("Could not claim computation for '{key}'"))?;

        Ok(claimed)
    }

    /// Record that the program server accepted the claimed computation.
    pub async fn mark_compute_submitted(&mut self) -> Result<bool> {
        let key = self.crisp_key();
        let mut submitted = false;

        self.store
            .modify(&key, |e3_obj: Option<E3Crisp>| {
                e3_obj.map(|mut e| {
                    if e.status == "Computing" {
                        e.status = "PublishingCiphertext".to_string();
                        submitted = true;
                    }
                    e
                })
            })
            .await
            .map_err(|_| eyre::eyre!("Could not record compute submission at '{key}'"))?;

        Ok(submitted)
    }

    /// Release a compute claim when the program server refused the request.
    ///
    /// Only `Computing` can move back. A callback or output event may already have advanced the
    /// round while the request handler was returning an error. Reverting a later state would start
    /// a second computation for an output already in progress.
    pub async fn release_compute_claim(&mut self) -> Result<bool> {
        let key = self.crisp_key();
        let mut released = false;

        self.store
            .modify(&key, |e3_obj: Option<E3Crisp>| {
                e3_obj.map(|mut e| {
                    if e.status == "Computing" {
                        e.status = "Expired".to_owned();
                        released = true;
                    }
                    e
                })
            })
            .await
            .map_err(|_| eyre::eyre!("Could not release computation for '{key}'"))?;

        Ok(released)
    }

    pub async fn update_status(&mut self, value: &str) -> Result<()> {
        let key = self.crisp_key();

        self.store
            .modify(&key, |e3_obj: Option<E3Crisp>| {
                e3_obj.map(|mut e| {
                    e.status = value.to_string();
                    e
                })
            })
            .await
            .map_err(|_| eyre::eyre!("Could not update status for '{key}'"))?;
        Ok(())
    }

    pub async fn set_votes(&mut self, votes: Vec<BigUint>) -> Result<()> {
        info!(
            "set_votes: [{}]",
            votes
                .iter()
                .enumerate()
                .map(|(i, v)| format!("option_{}: {}", i, v))
                .collect::<Vec<_>>()
                .join(", ")
        );

        let key = self.crisp_key();
        self.store
            .modify(&key, |e3_obj: Option<E3Crisp>| {
                e3_obj.map(|mut e| {
                    e.tally = votes.iter().map(|v| v.to_string()).collect();
                    e
                })
            })
            .await
            .map_err(|_| eyre::eyre!("Could not set votes for '{key}'"))?;
        Ok(())
    }

    pub async fn get_ciphertext_output(&self) -> Result<Vec<u8>> {
        let e3 = self.get_e3().await?;
        Ok(e3.ciphertext_output)
    }

    pub async fn get_committee_public_key(&self) -> Result<Vec<u8>> {
        let e3 = self.get_e3().await?;
        Ok(e3.committee_public_key)
    }

    /// The round's result, or `None` when the round is not in the store. See
    /// [`Self::try_get_e3_state_lite`] for why both records have to be present.
    pub async fn try_get_web_result_request(&self) -> Result<Option<WebResultRequest>> {
        let (Some(e3), Some(e3_crisp)) = (self.try_get_e3().await?, self.try_get_crisp().await?)
        else {
            return Ok(None);
        };
        Ok(Some(WebResultRequest {
            round_id: e3.id,
            tally: e3_crisp.tally,
            option_1_emoji: e3_crisp.emojis[0].clone(),
            option_2_emoji: e3_crisp.emojis[1].clone(),
            end_time: e3.input_window[1],
            total_votes: self.get_vote_count().await?,
            requester: e3_crisp.requester,
        }))
    }

    pub async fn get_e3_state_lite(&self) -> Result<E3StateLite> {
        self.try_get_e3_state_lite()
            .await?
            .ok_or_else(|| eyre::eyre!("No state stored for round {}", self.e3_id))
    }

    /// The round's public state, or `None` when the round is not in the store.
    ///
    /// Both records are needed and they are written at different points in a round's life: the
    /// `_e3:` record lands when the committee is published, the `_e3:crisp:` record when the
    /// request is indexed. A round mid-flight legitimately has one and not the other, and that is
    /// "not ready", not a failure.
    pub async fn try_get_e3_state_lite(&self) -> Result<Option<E3StateLite>> {
        let (Some(e3), Some(e3_crisp)) = (self.try_get_e3().await?, self.try_get_crisp().await?)
        else {
            return Ok(None);
        };
        let snapshot_block = snapshot_block(e3.request_block, e3_crisp.snapshot_block);
        let voting_end_time = if e3_crisp.voting_end_time == 0 {
            e3.input_window[1]
        } else {
            e3_crisp.voting_end_time
        };
        Ok(Some(E3StateLite {
            emojis: e3_crisp.emojis,
            id: self.e3_id.clone(),
            status: e3_crisp.status,
            chain_id: e3.chain_id,
            start_time: e3.input_window[0],
            end_time: voting_end_time,
            vote_count: count_active_slots(&e3_crisp.input_slots),
            start_block: e3.request_block,
            snapshot_block,
            interfold_address: e3.interfold_address,
            committee_public_key: e3.committee_public_key,
            token_address: e3_crisp.token_address,
            balance_threshold: e3_crisp.balance_threshold,
            requester: e3_crisp.requester,
            num_options: e3_crisp.num_options,
            credit_mode: e3_crisp.credit_mode,
            credits: e3_crisp.credits,
            census_mode: e3_crisp.census_mode,
        }))
    }

    /// Get the input deadline for the current round
    pub async fn get_input_deadline(&self) -> Result<u64> {
        let e3_crisp = self.get_crisp().await?;
        Ok(e3_crisp.end_time)
    }

    /// Everything the compute request needs about a round's inputs, in on-chain index order.
    ///
    /// The per-input fields come from one read of the round record. Four getters would be separate
    /// `await`s, and an `InputPublished` event can land between them, so a request assembled from
    /// several reads can pair a ciphertext with another input's commitment or leave the vectors
    /// different lengths. The Secure Process would then derive a root `CRISPProgram` rejects, and
    /// nothing would say why. The bytes are read afterwards under the content hash that the record
    /// names, so they always belong to the fields read with them.
    pub async fn get_input_snapshot(&self) -> Result<InputSnapshot> {
        let (mut snapshot, hashes) = self.input_records().await?;
        for ((bytes, index), hash) in snapshot.ciphertexts.iter_mut().zip(hashes) {
            *bytes = self.get_ciphertext(*index, hash).await?;
        }
        Ok(snapshot)
    }

    /// The round's per-input records in on-chain index order, from one read, with empty bytes, and
    /// the content hash of each input in the same order.
    ///
    /// Event handlers run concurrently, so arrival order is not chain order, and a leaf's position
    /// in the input tree is its position in these vectors. Sorting here is what keeps the root the
    /// Secure Process derives equal to the one the contract accumulated.
    async fn input_records(&self) -> Result<(InputSnapshot, Vec<[u8; 32]>)> {
        Self::records_of(self.get_crisp().await?)
    }

    /// `input_records` over a round record that the caller has read.
    fn records_of(e3_crisp: E3Crisp) -> Result<(InputSnapshot, Vec<[u8; 32]>)> {
        // An input indexed before the event carried these fields keeps its ciphertext in the round
        // record (`move_inline_ciphertexts`). Computing over the round would fall back to the
        // pre-binding leaf layout and derive a root `CRISPProgram` rejects, with nothing to explain
        // why. Such a round has to be re-indexed, not computed.
        let expected = e3_crisp.input_commitments.len();
        let inline = e3_crisp.ciphertext_inputs.len();
        Self::require_indexed(expected + inline, expected, "commitments")?;
        Self::require_indexed(expected, e3_crisp.input_slots.len(), "slots")?;
        Self::require_indexed(expected, e3_crisp.input_parents.len(), "parents")?;
        Self::require_indexed(expected, e3_crisp.input_usable.len(), "usability flags")?;
        let hashes = e3_crisp.input_ciphertext_hashes.len();
        Self::require_indexed(expected, hashes, "ciphertext hashes")?;

        let mut commitments = e3_crisp.input_commitments;
        commitments.sort_by_key(|(index, _)| *index);
        let mut slots = e3_crisp.input_slots;
        slots.sort_by_key(|(index, _)| *index);
        let mut parents = e3_crisp.input_parents;
        parents.sort_by_key(|(index, _)| *index);
        let mut usable = e3_crisp.input_usable;
        usable.sort_by_key(|(index, _)| *index);
        let mut hashes = e3_crisp.input_ciphertext_hashes;
        hashes.sort_by_key(|(index, _)| *index);

        let snapshot = InputSnapshot {
            ciphertexts: commitments
                .iter()
                .map(|(index, _)| (Vec::new(), *index))
                .collect(),
            commitments: commitments.into_iter().map(|(_, value)| value).collect(),
            slots: slots.into_iter().map(|(_, value)| value).collect(),
            parents: parents.into_iter().map(|(_, value)| value).collect(),
            usable: usable.into_iter().map(|(_, value)| value).collect(),
        };
        Ok((snapshot, hashes.into_iter().map(|(_, hash)| hash).collect()))
    }

    /// Refuses a round whose per-input records do not line up with its ciphertexts.
    fn require_indexed(expected: usize, found: usize, field: &str) -> Result<()> {
        if expected != found {
            return Err(eyre::eyre!(
                "round has {expected} inputs but {found} {field}; it is partially indexed or \
                 predates the binding, and must be re-indexed"
            ));
        }
        Ok(())
    }

    /// Store an input's bytes as hex, about half the size of a JSON byte array.
    async fn store_ciphertext(&mut self, index: u64, hash: [u8; 32], bytes: &[u8]) -> Result<()> {
        let key = self.ciphertext_key(index, hash);
        self.store
            .insert(&key, &hex::encode(bytes))
            .await
            .map_err(|e| eyre::eyre!("Could not store the ciphertext at '{key}': {e}"))
    }

    async fn get_ciphertext(&self, index: u64, hash: [u8; 32]) -> Result<Vec<u8>> {
        let key = self.ciphertext_key(index, hash);
        let bytes: String = self
            .store
            .get(&key)
            .await
            .map_err(|e| eyre::eyre!("Could not read the ciphertext at '{key}': {e}"))?
            .ok_or_else(|| eyre::eyre!("the round lists input {index} but '{key}' is empty"))?;
        Ok(hex::decode(bytes)?)
    }

    /// The end of a slot's chain of usable entries: the entry a new input must name as its parent.
    ///
    /// Resolved by the Secure Process's own rule (`InputSnapshot::slot_head`), so a client that
    /// builds on this answer produces an input the tally will take.
    ///
    /// Reads the usability decision rather than recomputing it. Recomputing costs a BFV commitment
    /// per candidate — about 5ms each, comparable to deserializing a thousand-input round — and
    /// every voter calls this before every ballot. The decision is made once, when the input is
    /// indexed, and the round's inputs are read once per input generation (`indexed_inputs`).
    ///
    /// `None` when the slot holds nothing usable, which is what a first vote sees.
    pub async fn get_slot_head(&self, slot: [u8; 20]) -> Result<Option<(Vec<u8>, u64)>> {
        let inputs = self
            .indexed_inputs()
            .await?
            .ok_or_else(|| eyre::eyre!("No data found at {}", self.crisp_key()))?;
        let head = inputs.records.slot_head(inputs.entries_of(slot));

        // Only the head's bytes: a slot's chain can hold many entries.
        match head {
            Some(position) => {
                let index = inputs.records.ciphertexts[position].1;
                let bytes = self.get_ciphertext(index, inputs.hashes[position]).await?;
                Ok(Some((bytes, index)))
            }
            None => Ok(None),
        }
    }

    /// Where one submitted input stands in the selection of its slot, and the current slot head.
    ///
    /// The input is the round entry with this slot, commitment, parent, and content hash, the
    /// keccak256 of its bytes that the round record names. Only the entries of that slot are
    /// replayed. `None` when this server has no record of the round.
    pub async fn get_input_selection(
        &self,
        slot: [u8; 20],
        commitment: [u8; 32],
        parent_index_plus_one: u64,
        content_hash: [u8; 32],
    ) -> Result<Option<InputSelectionResponse>> {
        let Some(inputs) = self.indexed_inputs().await? else {
            return Ok(None);
        };
        Ok(Some(inputs.records.selection(
            &inputs.hashes,
            inputs.entries_of(slot),
            slot,
            commitment,
            parent_index_plus_one,
            content_hash,
        )))
    }

    #[allow(dead_code)]
    pub async fn set_ciphertext_output(&mut self, data: Vec<u8>) -> Result<()> {
        self.get_e3_repo().set_ciphertext_output(data).await?;
        Ok(())
    }

    /// Whether the slot holds any committed entry that this server has the bytes for.
    ///
    /// Deliberately not "has this address voted" — the server cannot know that. Anyone can mask
    /// any eligible slot, and a mask is indistinguishable from a vote, so activity is the only
    /// per-slot fact there is.
    ///
    /// Takes parsed slot bytes so address validation stays with the route, where a malformed
    /// address is client error rather than a storage failure.
    pub async fn slot_has_activity(&self, slot: [u8; 20]) -> Result<bool> {
        let e3_crisp = self.get_crisp().await?;
        Ok(e3_crisp.input_slots.iter().any(|(_, s)| *s == slot))
    }

    #[allow(dead_code)]
    pub async fn is_finished(&self) -> Result<bool> {
        let e3 = self.get_crisp().await?;
        Ok(e3.status == "Finished")
    }

    pub async fn set_token_holder_hashes(&mut self, hashes: Vec<String>) -> Result<()> {
        let key = self.crisp_key();

        self.store
            .modify(&key, |e3_obj: Option<E3Crisp>| {
                e3_obj.map(|mut e| {
                    e.token_holder_hashes = hashes.clone();
                    e
                })
            })
            .await
            .map_err(|_| eyre::eyre!("Could not set token_holder_hashes for '{key}'"))?;

        Ok(())
    }

    /// `None` when the round is not in the store; an empty vec when it is but has no census yet.
    pub async fn try_get_token_holder_hashes(&self) -> Result<Option<Vec<String>>> {
        Ok(self
            .try_get_crisp()
            .await?
            .map(|e3_crisp| e3_crisp.token_holder_hashes))
    }

    pub async fn set_eligible_addresses(&mut self, holders: Vec<TokenHolder>) -> Result<()> {
        let key = self.crisp_key();

        self.store
            .modify(&key, |e3_obj: Option<E3Crisp>| {
                e3_obj.map(|mut e| {
                    e.eligible_addresses = holders.clone();
                    e
                })
            })
            .await
            .map_err(|_| eyre::eyre!("Could not set eligible_addresses for '{key}'"))?;
        Ok(())
    }

    /// `None` when the round is not in the store; an empty vec when it is but has no census yet.
    /// Record whether holder discovery is still owed for this round.
    pub async fn set_discovery_pending(&mut self, pending: bool) -> Result<()> {
        let key = self.crisp_key();
        self.store
            .modify(&key, move |current: Option<E3Crisp>| {
                current.map(|mut e| {
                    e.discovery_pending = pending;
                    e
                })
            })
            .await
            .map_err(|_| eyre::eyre!("Could not set discovery_pending for '{key}'"))?;
        Ok(())
    }

    pub async fn try_get_eligible_addresses(&self) -> Result<Option<Vec<TokenHolder>>> {
        Ok(self
            .try_get_crisp()
            .await?
            .map(|e3_crisp| e3_crisp.eligible_addresses))
    }

    fn crisp_key(&self) -> String {
        format!("{CRISP_KEY_PREFIX}{}", self.e3_id)
    }

    fn input_generation_key(&self) -> String {
        format!("{INPUT_GENERATION_KEY_PREFIX}{}", self.e3_id)
    }

    /// The index has a fixed width, so a round's ciphertexts sort in index order. sled then adds
    /// each new ballot to the last page and does not write the full pages of earlier ballots again.
    /// The content hash keeps a ballot that replaces another at the same index apart from it.
    fn ciphertext_key(&self, index: u64, hash: [u8; 32]) -> String {
        let hash = hex::encode(hash);
        format!("{CIPHERTEXT_KEY_PREFIX}{}:{index:020}:{hash}", self.e3_id)
    }
}

/// The block the census was built at.
///
/// Rounds stored before the snapshot block was persisted fall back to the block before
/// the request, which is what the indexer used to build their census.
///
/// `stored_snapshot_block` is the value persisted on the round, 0 when it is missing.
fn snapshot_block(request_block: u64, stored_snapshot_block: u64) -> u64 {
    if stored_snapshot_block == 0 {
        request_block.saturating_sub(1)
    } else {
        stored_snapshot_block
    }
}

/// How many distinct slots appear in the indexed inputs.
///
/// Counts slots rather than entries: a slot's chain can hold a vote plus any number of masks and
/// updates, and it still represents one participant at most.
fn count_active_slots(input_slots: &[(u64, [u8; 20])]) -> u64 {
    let mut slots: Vec<[u8; 20]> = input_slots.iter().map(|(_, slot)| *slot).collect();
    slots.sort_unstable();
    slots.dedup();
    slots.len() as u64
}

/// Parse a `0x`-prefixed or bare hex address into the slot bytes the indexer stores.
pub fn parse_slot_address(address: &str) -> Result<[u8; 20]> {
    let bytes = hex::decode(address.strip_prefix("0x").unwrap_or(address))
        .map_err(|e| eyre::eyre!("'{address}' is not a hex address: {e}"))?;
    <[u8; 20]>::try_from(bytes).map_err(|_| eyre::eyre!("'{address}' is not 20 bytes of address"))
}

#[cfg(test)]
mod tests {
    use super::{
        count_active_slots, parse_slot_address, snapshot_block, CrispE3Repository,
        CurrentRoundRepository, InputGeneration,
    };
    use crate::server::database::INPUT_GENERATION_KEY_PREFIX;
    use crate::server::models::{
        CensusMode, CreditMode, CustomParams, E3Crisp, ExclusionReason, InputSelectionResponse,
        InputSelectionStatus,
    };
    use alloy::primitives::{keccak256, Address};
    use async_trait::async_trait;
    use e3_fhe_params::{build_bfv_params_from_set_arc, BfvParamSet, BfvPreset};
    use e3_sdk::indexer::{DataStore, InMemoryStore, SharedStore};
    use serde::{de::DeserializeOwned, Serialize};
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };
    use tokio::sync::RwLock;

    fn test_store() -> SharedStore<InMemoryStore> {
        SharedStore::new(Arc::new(RwLock::new(InMemoryStore::new())))
    }

    /// A store whose `modify` fails while `failing` is set, as a failed disk write does.
    struct FailingModify {
        store: InMemoryStore,
        failing: Arc<AtomicBool>,
    }

    #[async_trait]
    impl DataStore for FailingModify {
        type Error = eyre::Error;

        async fn insert<T: Serialize + Send + Sync>(
            &mut self,
            key: &str,
            value: &T,
        ) -> Result<(), Self::Error> {
            self.store.insert(key, value).await
        }

        async fn get<T: DeserializeOwned + Send + Sync>(
            &self,
            key: &str,
        ) -> Result<Option<T>, Self::Error> {
            self.store.get(key).await
        }

        async fn modify<T, F>(&mut self, key: &str, f: F) -> Result<Option<T>, Self::Error>
        where
            T: Serialize + DeserializeOwned + Send + Sync,
            F: FnMut(Option<T>) -> Option<T> + Send,
        {
            if self.failing.load(Ordering::SeqCst) {
                return Err(eyre::eyre!("the write failed"));
            }
            self.store.modify(key, f).await
        }
    }

    /// A store that, while `failing` is set, refuses the write that counts a change of the inputs
    /// as finished. The change and its start are written, as when the disk fails between them.
    struct FailingFinish {
        store: InMemoryStore,
        failing: Arc<AtomicBool>,
    }

    #[async_trait]
    impl DataStore for FailingFinish {
        type Error = eyre::Error;

        async fn insert<T: Serialize + Send + Sync>(
            &mut self,
            key: &str,
            value: &T,
        ) -> Result<(), Self::Error> {
            self.store.insert(key, value).await
        }

        async fn get<T: DeserializeOwned + Send + Sync>(
            &self,
            key: &str,
        ) -> Result<Option<T>, Self::Error> {
            self.store.get(key).await
        }

        async fn modify<T, F>(&mut self, key: &str, f: F) -> Result<Option<T>, Self::Error>
        where
            T: Serialize + DeserializeOwned + Send + Sync,
            F: FnMut(Option<T>) -> Option<T> + Send,
        {
            if self.failing.load(Ordering::SeqCst) && key.starts_with(INPUT_GENERATION_KEY_PREFIX) {
                let current: Option<InputGeneration> = self.store.get(key).await?;
                if current.is_some_and(|generation| generation.started > generation.finished) {
                    return Err(eyre::eyre!("the write failed"));
                }
            }
            self.store.modify(key, f).await
        }
    }

    fn crisp_round(requester: &str, status: &str) -> E3Crisp {
        E3Crisp {
            emojis: ["one".to_string(), "two".to_string()],
            start_time: 0,
            voting_end_time: 100,
            end_time: 100,
            status: status.to_string(),
            tally: vec![],
            token_holder_hashes: vec![],
            eligible_addresses: vec![],
            token_address: "0x0000000000000000000000000000000000000001".to_string(),
            balance_threshold: "1".to_string(),
            ciphertext_inputs: vec![],
            input_commitments: vec![],
            input_slots: vec![],
            input_usable: vec![],
            input_parents: vec![],
            input_ciphertext_hashes: vec![],
            requester: requester.to_string(),
            num_options: "2".to_string(),
            credit_mode: CreditMode::Constant,
            credits: Some("1".to_string()),
            snapshot_block: 1,
            census_mode: CensusMode::Token,
            discovery_pending: false,
            e3_program: String::new(),
        }
    }

    /// A round record of an older release, with its ballots inline and input 0 committed.
    fn inline_round(ciphertext_inputs: Vec<(Vec<u8>, u64)>) -> E3Crisp {
        let mut record = crisp_round("requester", "Active");
        record.ciphertext_inputs = ciphertext_inputs;
        record.input_commitments = vec![(0, [1; 32])];
        record.input_slots = vec![(0, [7; 20])];
        record.input_parents = vec![(0, 0)];
        record.input_usable = vec![(0, true)];
        record
    }

    #[test]
    fn counts_each_slot_once_no_matter_how_long_its_chain_is() {
        let slot_a = [1u8; 20];
        let slot_b = [2u8; 20];
        let inputs = vec![(0, slot_a), (1, slot_b), (2, slot_a), (3, slot_a)];

        assert_eq!(count_active_slots(&inputs), 2);
        assert_eq!(count_active_slots(&[]), 0);
    }

    #[test]
    fn parses_an_address_with_or_without_prefix() {
        let expected = [0x11u8; 20];
        let bare = "11".repeat(20);

        assert_eq!(parse_slot_address(&bare).unwrap(), expected);
        assert_eq!(parse_slot_address(&format!("0x{bare}")).unwrap(), expected);
        assert!(parse_slot_address("0x1234").is_err());
        assert!(parse_slot_address("not-hex").is_err());
    }

    #[test]
    fn returns_the_stored_snapshot_block() {
        assert_eq!(snapshot_block(100, 99), 99);
    }

    #[test]
    fn falls_back_to_the_block_before_the_request() {
        assert_eq!(snapshot_block(100, 0), 99);
    }

    #[test]
    fn does_not_underflow_on_the_genesis_block() {
        assert_eq!(snapshot_block(0, 0), 0);
    }

    #[tokio::test]
    async fn requested_round_is_visible_before_the_public_key_is_indexed() {
        let store = test_store();
        let requester = "0x1111111111111111111111111111111111111111";
        let mut round = CrispE3Repository::new(store.clone(), "8");
        round
            .set_crisp(crisp_round(requester, "Requested"))
            .await
            .unwrap();

        let mut current = CurrentRoundRepository::new(store);
        current.record_round("8").await.unwrap();

        let found = current
            .get_current_round_for_requester(requester.to_uppercase())
            .await
            .unwrap()
            .expect("the request-time CRISP record should be sufficient");
        assert_eq!(found.id, "8");
    }

    #[tokio::test]
    async fn compute_claim_release_never_regresses_an_accepted_submission() {
        let store = test_store();
        let mut round = CrispE3Repository::new(store, "9");
        round
            .set_crisp(crisp_round("requester", "Requested"))
            .await
            .unwrap();

        assert!(round.try_start_round().await.unwrap());
        assert!(!round.try_start_round().await.unwrap());
        assert!(round.try_mark_expired().await.unwrap());
        assert!(round.try_claim_computing().await.unwrap());
        assert!(!round.try_claim_computing().await.unwrap());
        assert!(round.release_compute_claim().await.unwrap());
        assert_eq!(round.get_status().await.unwrap(), "Expired");
        assert!(round.try_claim_computing().await.unwrap());
        assert!(round.mark_compute_submitted().await.unwrap());
        assert_eq!(round.get_status().await.unwrap(), "PublishingCiphertext");
        assert!(!round.release_compute_claim().await.unwrap());
        assert_eq!(round.get_status().await.unwrap(), "PublishingCiphertext");
    }

    #[tokio::test]
    async fn requested_event_replay_does_not_reset_round_status() {
        let store = test_store();
        let mut round = CrispE3Repository::new(store, "10");
        let params = || CustomParams {
            token_address: "0x0000000000000000000000000000000000000001".to_string(),
            balance_threshold: "1".to_string(),
            num_options: "2".to_string(),
            credit_mode: CreditMode::Constant,
            credits: Some("1".to_string()),
            census_mode: CensusMode::Token,
            voting_power_divisor: "0".to_string(),
        };

        round
            .initialize_round(
                params(),
                Address::ZERO,
                "requester".to_string(),
                100,
                100,
                1,
            )
            .await
            .unwrap();
        round.update_status("Finished").await.unwrap();
        round
            .initialize_round(
                params(),
                Address::ZERO,
                "requester".to_string(),
                200,
                200,
                2,
            )
            .await
            .unwrap();

        assert_eq!(round.get_status().await.unwrap(), "Finished");
        assert_eq!(round.get_input_deadline().await.unwrap(), 100);
    }

    /// An input indexed before the input commitments existed keeps its ballot in the round record
    /// after the move, and reads still refuse the round: computing it would derive a root that
    /// `CRISPProgram` rejects.
    #[tokio::test]
    async fn a_round_with_an_input_indexed_before_commitments_stays_refused() {
        let record = inline_round(vec![(vec![1; 3], 0), (vec![2; 3], 1)]);
        let mut round = CrispE3Repository::new(test_store(), "12");
        round.set_crisp(record).await.unwrap();

        round.move_inline_ciphertexts(|| Ok(())).await.unwrap();

        assert!(round.get_input_snapshot().await.is_err());
    }

    /// The inline copy of a ballot stays until the sync of the moved copy succeeds. A crash before
    /// the sync could otherwise lose the only copy of the ballot.
    #[tokio::test]
    async fn a_failed_sync_keeps_the_inline_ballot() {
        let mut round = CrispE3Repository::new(test_store(), "14");
        round
            .set_crisp(inline_round(vec![(vec![1; 3], 0)]))
            .await
            .unwrap();

        let failed_sync = || Err(eyre::eyre!("the sync failed"));
        assert!(round.move_inline_ciphertexts(failed_sync).await.is_err());
        let inline = round.get_crisp().await.unwrap().ciphertext_inputs;
        assert_eq!(inline, vec![(vec![1; 3], 0)]);

        round.move_inline_ciphertexts(|| Ok(())).await.unwrap();
        let snapshot = round.get_input_snapshot().await.unwrap();
        assert_eq!(snapshot.ciphertexts, vec![(vec![1; 3], 0)]);
    }

    /// A ballot that replaces another at the same index, as after a reorganization, reads with its
    /// own fields. When the round record keeps the old fields, because its update failed, the old
    /// ballot reads with them.
    #[tokio::test]
    async fn a_replaced_input_reads_the_new_ballot() {
        let failing = Arc::new(AtomicBool::new(false));
        let store = FailingModify {
            store: InMemoryStore::new(),
            failing: Arc::clone(&failing),
        };
        let store = SharedStore::new(Arc::new(RwLock::new(store)));
        let mut round = CrispE3Repository::new(store, "13");
        round
            .set_crisp(crisp_round("requester", "Active"))
            .await
            .unwrap();
        let bfv = build_bfv_params_from_set_arc(BfvParamSet::from(BfvPreset::InsecureThreshold512));
        round
            .insert_ciphertext_input(vec![1; 3], 0, [1; 32], [7; 20], 0, &bfv)
            .await
            .unwrap();

        failing.store(true, Ordering::SeqCst);
        let replaced = round
            .insert_ciphertext_input(vec![2; 3], 0, [2; 32], [7; 20], 0, &bfv)
            .await;
        assert!(replaced.is_err());
        let snapshot = round.get_input_snapshot().await.unwrap();
        assert_eq!(snapshot.ciphertexts, vec![(vec![1; 3], 0)]);
        assert_eq!(snapshot.commitments, vec![[1; 32]]);

        failing.store(false, Ordering::SeqCst);
        round
            .insert_ciphertext_input(vec![2; 3], 0, [2; 32], [7; 20], 0, &bfv)
            .await
            .unwrap();
        let snapshot = round.get_input_snapshot().await.unwrap();
        assert_eq!(snapshot.ciphertexts, vec![(vec![2; 3], 0)]);
        assert_eq!(snapshot.commitments, vec![[2; 32]]);
    }

    /// One indexed input of a round, with the fields the indexer stores for it.
    #[derive(Clone, Copy)]
    struct Entry {
        index: u64,
        slot: [u8; 20],
        parent_index_plus_one: u64,
        usable: bool,
        /// The published bytes, which the round record names by their keccak256. The first byte
        /// also makes the commitment of the entry.
        bytes: &'static [u8],
    }

    impl Entry {
        fn commitment(&self) -> [u8; 32] {
            [self.bytes[0]; 32]
        }
    }

    const SLOT: [u8; 20] = [0x77; 20];

    /// Store round 3 with `entries` as its indexed inputs.
    async fn round_with(entries: &[Entry]) -> CrispE3Repository<InMemoryStore> {
        let mut record = crisp_round("requester", "Active");
        for entry in entries {
            record
                .input_ciphertext_hashes
                .push((entry.index, keccak256(entry.bytes).0));
            record
                .input_commitments
                .push((entry.index, entry.commitment()));
            record.input_slots.push((entry.index, entry.slot));
            record
                .input_parents
                .push((entry.index, entry.parent_index_plus_one));
            record.input_usable.push((entry.index, entry.usable));
        }
        let mut round = CrispE3Repository::new(test_store(), "3");
        round.set_crisp(record).await.unwrap();
        round
    }

    /// The selection answer for the input that `entry` describes.
    async fn selection_of(
        round: &CrispE3Repository<InMemoryStore>,
        entry: Entry,
    ) -> InputSelectionResponse {
        round
            .get_input_selection(
                entry.slot,
                entry.commitment(),
                entry.parent_index_plus_one,
                keccak256(entry.bytes).0,
            )
            .await
            .unwrap()
            .expect("the round is recorded")
    }

    fn answer(
        status: InputSelectionStatus,
        index: Option<u64>,
        head_index: Option<u64>,
        reason: Option<ExclusionReason>,
    ) -> InputSelectionResponse {
        InputSelectionResponse {
            status,
            index,
            head_index,
            reason,
        }
    }

    /// A mask and the voter's ballot both name the head. The mask is committed first and takes
    /// the slot, so the ballot is excluded and the answer names the mask as the head to build on.
    /// A retry that names the mask is selected. An entry that names the excluded ballot names a
    /// parent that was never the head.
    #[tokio::test]
    async fn a_sibling_after_a_mask_is_excluded_and_its_retry_is_selected() {
        let head = Entry {
            index: 0,
            slot: SLOT,
            parent_index_plus_one: 0,
            usable: true,
            bytes: b"\x01head",
        };
        let mask = Entry {
            index: 1,
            parent_index_plus_one: 1,
            bytes: b"\x02mask",
            ..head
        };
        let ballot = Entry {
            index: 2,
            parent_index_plus_one: 1,
            bytes: b"\x03ballot",
            ..head
        };
        let round = round_with(&[head, mask, ballot]).await;
        assert_eq!(
            selection_of(&round, ballot).await,
            answer(
                InputSelectionStatus::Excluded,
                Some(2),
                Some(1),
                Some(ExclusionReason::EarlierSibling)
            )
        );

        let retry = Entry {
            index: 3,
            parent_index_plus_one: 2,
            bytes: b"\x04retry",
            ..head
        };
        let on_the_ballot = Entry {
            index: 4,
            parent_index_plus_one: 3,
            bytes: b"\x05on-ballot",
            ..head
        };
        let round = round_with(&[head, mask, ballot, retry, on_the_ballot]).await;
        assert_eq!(
            selection_of(&round, retry).await,
            answer(InputSelectionStatus::Selected, Some(3), Some(3), None)
        );
        assert_eq!(
            selection_of(&round, on_the_ballot).await,
            answer(
                InputSelectionStatus::Excluded,
                Some(4),
                Some(3),
                Some(ExclusionReason::StaleParent)
            )
        );
    }

    /// A later entry that extends a selected ballot, a mask or a re-vote, moves the head but
    /// does not undo the selection of the ballot.
    #[tokio::test]
    async fn a_selected_ballot_stays_selected_after_a_later_entry_extends_it() {
        let ballot = Entry {
            index: 0,
            slot: SLOT,
            parent_index_plus_one: 0,
            usable: true,
            bytes: b"\x01ballot",
        };
        let descendant = Entry {
            index: 1,
            parent_index_plus_one: 1,
            bytes: b"\x02descendant",
            ..ballot
        };
        let round = round_with(&[ballot, descendant]).await;

        assert_eq!(
            selection_of(&round, ballot).await,
            answer(InputSelectionStatus::Selected, Some(0), Some(1), None)
        );
    }

    /// An entry with a lower tree index is not indexed here yet. It can still take the slot or
    /// be the parent of the ballot, so the verdict waits for it.
    #[tokio::test]
    async fn an_entry_after_a_missing_tree_index_is_pending() {
        let other_slot = Entry {
            index: 0,
            slot: [0x88; 20],
            parent_index_plus_one: 0,
            usable: true,
            bytes: b"\x01other",
        };
        let ballot = Entry {
            index: 2,
            slot: SLOT,
            bytes: b"\x02ballot",
            ..other_slot
        };
        let round = round_with(&[other_slot, ballot]).await;

        assert_eq!(
            selection_of(&round, ballot).await,
            answer(
                InputSelectionStatus::SelectionPending,
                Some(2),
                Some(2),
                None
            )
        );
    }

    /// An input is matched by its bytes too. The same slot, commitment, and parent with other
    /// bytes is another input, which this server has not indexed.
    #[tokio::test]
    async fn an_input_with_other_bytes_is_not_indexed() {
        let ballot = Entry {
            index: 0,
            slot: SLOT,
            parent_index_plus_one: 0,
            usable: true,
            bytes: b"\x01ballot",
        };
        let round = round_with(&[ballot]).await;
        let other_bytes = Entry {
            bytes: b"\x01other bytes",
            ..ballot
        };

        assert_eq!(
            selection_of(&round, other_bytes).await,
            answer(InputSelectionStatus::NotIndexed, None, Some(0), None)
        );
    }

    /// An entry whose bytes do not reproduce its commitment never becomes the head.
    #[tokio::test]
    async fn an_unusable_entry_is_excluded_as_unusable() {
        let ballot = Entry {
            index: 0,
            slot: SLOT,
            parent_index_plus_one: 0,
            usable: false,
            bytes: b"\x01ballot",
        };
        let round = round_with(&[ballot]).await;

        assert_eq!(
            selection_of(&round, ballot).await,
            answer(
                InputSelectionStatus::Excluded,
                Some(0),
                None,
                Some(ExclusionReason::Unusable)
            )
        );
    }

    /// A read of the round's inputs is kept for its input generation. An input indexed after the
    /// read changes the generation, so the next read sees the input.
    #[tokio::test]
    async fn a_selection_sees_an_input_indexed_after_an_earlier_read() {
        let mut round = CrispE3Repository::new(test_store(), "14");
        round
            .set_crisp(crisp_round("requester", "Active"))
            .await
            .unwrap();
        let bfv = build_bfv_params_from_set_arc(BfvParamSet::from(BfvPreset::InsecureThreshold512));
        // An input to another slot, so the round has a generation when it is first read.
        round
            .insert_ciphertext_input(vec![9; 3], 0, [9; 32], [0x88; 20], 0, &bfv)
            .await
            .unwrap();
        let ballot = vec![1; 3];
        let hash = keccak256(&ballot).0;
        let before = round
            .get_input_selection(SLOT, [1; 32], 0, hash)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(before.status, InputSelectionStatus::NotIndexed);

        round
            .insert_ciphertext_input(ballot, 1, [1; 32], SLOT, 0, &bfv)
            .await
            .unwrap();
        // The bytes are not a ciphertext, so the entry is indexed as unusable.
        assert_eq!(
            round
                .get_input_selection(SLOT, [1; 32], 0, hash)
                .await
                .unwrap()
                .unwrap(),
            answer(
                InputSelectionStatus::Excluded,
                Some(1),
                None,
                Some(ExclusionReason::Unusable)
            )
        );
    }

    /// A change that fails after its record write leaves the generation unsettled, so reads go to
    /// the store and see the change. The next start settles the generation, and reads still see it.
    #[tokio::test]
    async fn a_change_that_fails_to_finish_is_read_from_the_store() {
        let failing = Arc::new(AtomicBool::new(false));
        let store = FailingFinish {
            store: InMemoryStore::new(),
            failing: Arc::clone(&failing),
        };
        let mut round =
            CrispE3Repository::new(SharedStore::new(Arc::new(RwLock::new(store))), "15");
        round
            .set_crisp(crisp_round("requester", "Active"))
            .await
            .unwrap();
        let bfv = build_bfv_params_from_set_arc(BfvParamSet::from(BfvPreset::InsecureThreshold512));
        round
            .insert_ciphertext_input(vec![9; 3], 0, [9; 32], [0x88; 20], 0, &bfv)
            .await
            .unwrap();
        let ballot = vec![1; 3];
        let hash = keccak256(&ballot).0;
        let before = round
            .get_input_selection(SLOT, [1; 32], 0, hash)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(before.status, InputSelectionStatus::NotIndexed);

        failing.store(true, Ordering::SeqCst);
        assert!(round
            .insert_ciphertext_input(ballot, 1, [1; 32], SLOT, 0, &bfv)
            .await
            .is_err());
        failing.store(false, Ordering::SeqCst);
        let indexed = answer(
            InputSelectionStatus::Excluded,
            Some(1),
            None,
            Some(ExclusionReason::Unusable),
        );
        assert_eq!(
            round
                .get_input_selection(SLOT, [1; 32], 0, hash)
                .await
                .unwrap()
                .unwrap(),
            indexed
        );

        round.settle_input_generation().await.unwrap();
        assert_eq!(
            round
                .get_input_selection(SLOT, [1; 32], 0, hash)
                .await
                .unwrap()
                .unwrap(),
            indexed
        );
    }
}
