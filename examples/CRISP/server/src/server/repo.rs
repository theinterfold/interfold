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
use log::info;
use num_bigint::BigUint;

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
        // Get the current round count to iterate through all rounds
        let round_count = self.get_current_round_id().await?;

        // Iterate backwards from the most recent round to find the latest one for this requester
        for round_id in (0..=round_count).rev() {
            let crisp_repo = CrispE3Repository::new(self.store.clone(), round_id);

            match crisp_repo.get_e3_state_lite().await {
                Ok(state) => {
                    if state.requester == requester {
                        return Ok(Some(CurrentRound { id: round_id }));
                    }
                }
                Err(e) => {
                    info!("Error retrieving state for round {}: {:?}", round_id, e);
                    continue;
                }
            }
        }

        Ok(None)
    }

    pub async fn get_current_round_id(&self) -> Result<u64> {
        let round = self
            .get_current_round()
            .await?
            .ok_or(eyre::eyre!("No current round has been saved"))?;

        Ok(round.id)
    }

    fn current_round_key(&self) -> String {
        "_e3:current_round".to_string()
    }
}

pub struct CrispE3Repository<S: DataStore> {
    store: SharedStore<S>,
    e3_id: u64,
}

impl<S: DataStore> CrispE3Repository<S> {
    pub fn new(store: SharedStore<S>, e3_id: u64) -> Self {
        Self { store, e3_id }
    }

    async fn set_crisp(&mut self, value: E3Crisp) -> Result<()> {
        let key = self.crisp_key();
        self.store
            .insert(&key, &value)
            .await
            .map_err(|_| eyre::eyre!("Could not store crisp at '{key}'"))?;
        Ok(())
    }

    async fn get_crisp(&self) -> Result<E3Crisp> {
        let key = self.crisp_key();
        let e3_crisp = self
            .store
            .get::<E3Crisp>(&key)
            .await
            .map_err(|e| eyre::eyre!("Could get crisp at '{key}' due to error: {e}"))?
            .ok_or(eyre::eyre!("No data found at {key}"))?;
        Ok(e3_crisp)
    }

    pub async fn start_round(&mut self) -> Result<()> {
        let mut e3_crisp = self.get_crisp().await?;
        e3_crisp.start_time = chrono::Utc::now().timestamp() as u64;
        e3_crisp.status = "Active".to_string();
        self.set_crisp(e3_crisp).await
    }

    pub async fn insert_ciphertext_input(&mut self, vote: Vec<u8>, index: u64) -> Result<()> {
        let key = self.crisp_key();

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
                    e
                })
            })
            .await
            .map_err(|_| eyre::eyre!("Could not append ciphertext_input for '{key}'"))?;

        Ok(())
    }

    pub async fn get_ciphertext_input(&self, index: u64) -> Result<Option<Vec<u8>>> {
        let e3_crisp = self.get_crisp().await?;
        for (vote, i) in e3_crisp.ciphertext_inputs {
            if i == index {
                return Ok(Some(vote));
            }
        }

        Ok(None)
    }

    pub async fn initialize_round(
        &mut self,
        custom_params: CustomParams,
        requester: String,
        end_time: u64,
    ) -> Result<()> {
        self.set_crisp(E3Crisp {
            has_voted: vec![],
            start_time: 0u64,
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
            end_time,
        })
        .await
    }

    fn get_e3_repo(&self) -> E3Repository<S> {
        E3Repository::new(self.store.clone(), self.e3_id)
    }

    pub async fn get_e3(&self) -> Result<InterfoldE3> {
        let e3 = self.get_e3_repo().get_e3().await?;
        Ok(e3)
    }

    pub async fn get_num_options(&self) -> Result<usize> {
        let e3_crisp = self.get_crisp().await?;
        Ok(e3_crisp.num_options.parse::<usize>()?)
    }

    pub async fn get_vote_count(&self) -> Result<u64> {
        let e3_crisp = self.get_crisp().await?;
        Ok(u64::try_from(e3_crisp.has_voted.len())?)
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

    pub async fn get_web_result_request(&self) -> Result<WebResultRequest> {
        let e3 = self.get_e3().await?;
        let e3_crisp = self.get_crisp().await?;
        Ok(WebResultRequest {
            round_id: e3.id,
            tally: e3_crisp.tally,
            option_1_emoji: e3_crisp.emojis[0].clone(),
            option_2_emoji: e3_crisp.emojis[1].clone(),
            end_time: e3.input_window[1],
            total_votes: self.get_vote_count().await?,
            requester: e3_crisp.requester,
        })
    }

    pub async fn get_e3_state_lite(&self) -> Result<E3StateLite> {
        let e3 = self.get_e3().await?;
        let e3_crisp = self.get_crisp().await?;
        Ok(E3StateLite {
            emojis: e3_crisp.emojis,
            id: self.e3_id,
            status: e3_crisp.status,
            chain_id: e3.chain_id,
            start_time: e3.input_window[0],
            end_time: e3.input_window[1],
            vote_count: u64::try_from(e3_crisp.has_voted.len())?,
            start_block: e3.request_block,
            interfold_address: e3.interfold_address,
            committee_public_key: e3.committee_public_key,
            token_address: e3_crisp.token_address,
            balance_threshold: e3_crisp.balance_threshold,
            requester: e3_crisp.requester,
            num_options: e3_crisp.num_options,
            credit_mode: e3_crisp.credit_mode,
            credits: e3_crisp.credits,
        })
    }

    /// Get the input deadline for the current round
    pub async fn get_input_deadline(&self) -> Result<u64> {
        let e3_crisp = self.get_crisp().await?;
        Ok(e3_crisp.end_time)
    }

    pub async fn get_ciphertext_inputs(&self) -> Result<Vec<(Vec<u8>, u64)>> {
        let e3_crisp = self.get_crisp().await?;
        Ok(e3_crisp.ciphertext_inputs)
    }

    #[allow(dead_code)]
    pub async fn set_ciphertext_output(&mut self, data: Vec<u8>) -> Result<()> {
        self.get_e3_repo().set_ciphertext_output(data).await?;
        Ok(())
    }

    pub async fn has_voted(&self, address: String) -> Result<bool> {
        let e3_crisp = self.get_crisp().await?;
        Ok(e3_crisp.has_voted.contains(&address))
    }

    pub async fn insert_voter_address(&mut self, address: String) -> Result<()> {
        let key = self.crisp_key();
        self.store
            .modify(&key, |e3_obj: Option<E3Crisp>| {
                e3_obj.map(|mut e| {
                    e.has_voted.push(address.clone());
                    e
                })
            })
            .await
            .map_err(|_| eyre::eyre!("Could not insert address on '{key}'"))?;
        Ok(())
    }

    #[allow(dead_code)]
    pub async fn remove_voter_address(&mut self, address: &str) -> Result<()> {
        let key = self.crisp_key();
        self.store
            .modify(&key, |e3_obj: Option<E3Crisp>| {
                e3_obj.map(|mut e| {
                    e.has_voted.retain(|item| item != address);
                    e
                })
            })
            .await
            .map_err(|_| eyre::eyre!("Could not remove address {address}"))?;
        Ok(())
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

    pub async fn get_token_holder_hashes(&self) -> Result<Vec<String>> {
        let e3_crisp = self.get_crisp().await?;
        Ok(e3_crisp.token_holder_hashes)
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

    pub async fn get_eligible_addresses(&self) -> Result<Vec<TokenHolder>> {
        let e3_crisp = self.get_crisp().await?;
        Ok(e3_crisp.eligible_addresses)
    }

    fn crisp_key(&self) -> String {
        let e3_id = self.e3_id;
        format!("_e3:crisp:{e3_id}")
    }
}
