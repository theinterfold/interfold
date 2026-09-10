// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::server::models::{CustomParams, TokenHolder};

use super::{
    database::generate_emoji,
    models::{CurrentRound, E3Crisp, E3StateLite, WebResultRequest},
};
use e3_sdk::indexer::{models::E3 as InterfoldE3, DataStore, E3Repository, SharedStore};
use eyre::Result;
use fhe::bfv::BfvParameters;
use log::info;
use num_bigint::BigUint;

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
    async fn try_get_crisp(&self) -> Result<Option<E3Crisp>> {
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

    async fn get_crisp(&self) -> Result<E3Crisp> {
        let key = self.crisp_key();
        let e3_crisp = self
            .try_get_crisp()
            .await?
            .ok_or(eyre::eyre!("No data found at {key}"))?;
        Ok(e3_crisp)
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

        // Decided here, once, rather than on every read. An entry's bytes never change, so neither
        // does the answer. `Err` means the bytes do not deserialize, which is itself unusable.
        let usable = e3_bfv_client::client::compute_ct_commitment(
            vote.clone(),
            params.degree(),
            params.plaintext(),
            params.moduli().to_vec(),
        )
        .is_ok_and(|recomputed| recomputed == commitment);

        self.store
            .modify(&key, |e3_obj: Option<E3Crisp>| {
                e3_obj.map(|mut e| {
                    // We check if we already have a vote at this index (re-vote case)
                    // If we do, we update the vote
                    // If we don't, we append the vote
                    if let Some(existing) =
                        e.ciphertext_inputs.iter_mut().find(|(_, i)| *i == index)
                    {
                        existing.0 = vote.clone();
                    } else {
                        e.ciphertext_inputs.push((vote.clone(), index));
                    }
                    if let Some(existing) =
                        e.input_commitments.iter_mut().find(|(i, _)| *i == index)
                    {
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
                    e
                })
            })
            .await
            .map_err(|_| eyre::eyre!("Could not append ciphertext_input for '{key}'"))?;

        Ok(())
    }

    pub async fn initialize_round(
        &mut self,
        custom_params: CustomParams,
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

    pub async fn get_num_options(&self) -> Result<usize> {
        let e3_crisp = self.get_crisp().await?;
        Ok(e3_crisp.num_options.parse::<usize>()?)
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

    /// Returns the inputs in on-chain index order.
    ///
    /// Event handlers run concurrently, so arrival order is not chain order, and a leaf's position
    /// in the input tree is its position in this vector. Sorting here is what keeps the root the
    /// Secure Process derives equal to the one the contract accumulated.
    #[allow(dead_code)]
    pub async fn get_ciphertext_inputs(&self) -> Result<Vec<(Vec<u8>, u64)>> {
        let e3_crisp = self.get_crisp().await?;
        let mut inputs = e3_crisp.ciphertext_inputs;
        inputs.sort_by_key(|(_, index)| *index);
        Ok(inputs)
    }

    /// Everything the compute request needs about a round's inputs, from one read.
    ///
    /// One read rather than four getters. Each is a separate `await`, and an `InputPublished` event
    /// can land between them, so a request assembled from several reads can pair a ciphertext with
    /// another input's commitment or leave the vectors different lengths. The Secure Process would
    /// then derive a root `CRISPProgram` rejects, and nothing would say why.
    pub async fn get_input_snapshot(&self) -> Result<InputSnapshot> {
        let e3_crisp = self.get_crisp().await?;

        let mut ciphertexts = e3_crisp.ciphertext_inputs;
        ciphertexts.sort_by_key(|(_, index)| *index);

        // A round recorded before the event carried these fields loads with them empty, because
        // they default. Computing over it would fall back to the pre-binding leaf layout and derive
        // a root `CRISPProgram` rejects, with nothing to explain why. Such a round has to be
        // re-indexed, not computed.
        let expected = ciphertexts.len();
        Self::require_indexed(expected, e3_crisp.input_commitments.len(), "commitments")?;
        Self::require_indexed(expected, e3_crisp.input_slots.len(), "slots")?;
        Self::require_indexed(expected, e3_crisp.input_parents.len(), "parents")?;
        Self::require_indexed(expected, e3_crisp.input_usable.len(), "usability flags")?;

        let mut commitments = e3_crisp.input_commitments;
        commitments.sort_by_key(|(index, _)| *index);
        let mut slots = e3_crisp.input_slots;
        slots.sort_by_key(|(index, _)| *index);
        let mut parents = e3_crisp.input_parents;
        parents.sort_by_key(|(index, _)| *index);
        let mut usable = e3_crisp.input_usable;
        usable.sort_by_key(|(index, _)| *index);

        Ok(InputSnapshot {
            ciphertexts,
            commitments: commitments.into_iter().map(|(_, value)| value).collect(),
            slots: slots.into_iter().map(|(_, value)| value).collect(),
            parents: parents.into_iter().map(|(_, value)| value).collect(),
            usable: usable.into_iter().map(|(_, value)| value).collect(),
        })
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

    /// The end of a slot's chain of usable entries: the entry a new input must name as its parent.
    ///
    /// Resolved the same way the Secure Process resolves it, so a client that builds on this answer
    /// produces an input the tally will take. An entry is only ever the head when its published
    /// bytes reproduce its commitment and it names the head before it, so an entry nobody can open
    /// never becomes one and never blocks the slot.
    ///
    /// Reads the usability decision rather than recomputing it. Recomputing costs a BFV commitment
    /// per candidate — about 5ms each, comparable to deserializing a thousand-input round — and
    /// every voter calls this before every ballot. The decision is made once, when the input is
    /// indexed.
    ///
    /// `None` when the slot holds nothing usable, which is what a first vote sees.
    pub async fn get_slot_head(&self, slot: [u8; 20]) -> Result<Option<(Vec<u8>, u64)>> {
        let snapshot = self.get_input_snapshot().await?;
        let mut head: Option<u64> = None;
        let mut selected: Option<usize> = None;

        for (position, (_, index)) in snapshot.ciphertexts.iter().enumerate() {
            if snapshot.slots[position] != slot || !snapshot.usable[position] {
                continue;
            }

            if snapshot.parents[position].checked_sub(1) != head {
                continue;
            }

            head = Some(*index);
            // The position, not the bytes. Cloning a ciphertext for every candidate would copy the
            // whole chain to return its last entry.
            selected = Some(position);
        }

        Ok(selected.map(|position| {
            let (bytes, index) = &snapshot.ciphertexts[position];
            (bytes.clone(), *index)
        }))
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
    pub async fn try_get_eligible_addresses(&self) -> Result<Option<Vec<TokenHolder>>> {
        Ok(self
            .try_get_crisp()
            .await?
            .map(|e3_crisp| e3_crisp.eligible_addresses))
    }

    fn crisp_key(&self) -> String {
        let e3_id = &self.e3_id;
        format!("_e3:crisp:{e3_id}")
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
        CurrentRoundRepository,
    };
    use crate::server::models::{CensusMode, CreditMode, CustomParams, E3Crisp};
    use e3_sdk::indexer::{InMemoryStore, SharedStore};
    use std::sync::Arc;
    use tokio::sync::RwLock;

    fn test_store() -> SharedStore<InMemoryStore> {
        SharedStore::new(Arc::new(RwLock::new(InMemoryStore::new())))
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
            requester: requester.to_string(),
            num_options: "2".to_string(),
            credit_mode: CreditMode::Constant,
            credits: Some("1".to_string()),
            snapshot_block: 1,
            census_mode: CensusMode::Token,
        }
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
            .initialize_round(params(), "requester".to_string(), 100, 100, 1)
            .await
            .unwrap();
        round.update_status("Finished").await.unwrap();
        round
            .initialize_round(params(), "requester".to_string(), 200, 200, 2)
            .await
            .unwrap();

        assert_eq!(round.get_status().await.unwrap(), "Finished");
        assert_eq!(round.get_input_deadline().await.unwrap(), 100);
    }
}
