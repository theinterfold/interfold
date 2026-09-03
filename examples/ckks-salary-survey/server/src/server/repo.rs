// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Round repository over the shared sled store. Every mutation is a
//! read-modify-write on the round record keyed `_survey:<e3_id>`;
//! ciphertexts are stored separately (`_survey_ct:<e3_id>:<index>`) so the
//! round document stays small.

use e3_sdk::indexer::{DataStore, SharedStore};
use eyre::{eyre, Result};

use super::database::SledDB;
use super::models::{Round, RoundStatus, Submission};

pub const ROUND_PREFIX: &str = "_survey:";
const CT_PREFIX: &str = "_survey_ct:";

pub struct RoundRepository<S: DataStore = SledDB> {
    store: SharedStore<S>,
    e3_id: String,
}

impl<S: DataStore> RoundRepository<S> {
    pub fn new(store: SharedStore<S>, e3_id: impl ToString) -> Self {
        Self {
            store,
            e3_id: e3_id.to_string(),
        }
    }

    fn key(&self) -> String {
        format!("{ROUND_PREFIX}{}", self.e3_id)
    }

    fn ct_key(&self, index: u64) -> String {
        format!("{CT_PREFIX}{}:{index:06}", self.e3_id)
    }

    pub async fn get(&self) -> Result<Option<Round>> {
        self.store
            .get::<Round>(&self.key())
            .await
            .map_err(|e| eyre!("reading round {}: {e}", self.e3_id))
    }

    pub async fn require(&self) -> Result<Round> {
        self.get()
            .await?
            .ok_or_else(|| eyre!("round {} not found", self.e3_id))
    }

    pub async fn set(&mut self, round: &Round) -> Result<()> {
        self.store
            .insert(&self.key(), round)
            .await
            .map_err(|e| eyre!("storing round {}: {e}", self.e3_id))
    }

    /// Atomic read-modify-write of the round record.
    pub async fn update<F>(&mut self, mut f: F) -> Result<Round>
    where
        F: FnMut(&mut Round) + Send,
    {
        let key = self.key();
        self.store
            .modify(&key, |round: Option<Round>| {
                round.map(|mut r| {
                    f(&mut r);
                    r
                })
            })
            .await
            .map_err(|e| eyre!("updating round {}: {e}", self.e3_id))?
            .ok_or_else(|| eyre!("round {} not found", self.e3_id))
    }

    pub async fn set_status(&mut self, status: RoundStatus) -> Result<Round> {
        self.update(|r| r.status = status).await
    }

    /// Append a submission (idempotent on `u_commitment`) and store its
    /// ciphertext bytes. Returns the stored submission index.
    pub async fn add_submission(
        &mut self,
        submission: Submission,
        ciphertext: &[u8],
    ) -> Result<u64> {
        let u = submission.u_commitment.clone();
        let mut index = submission.index;
        let round = self
            .update(|r| {
                if let Some(existing) = r
                    .submissions
                    .iter_mut()
                    .find(|s| s.u_commitment.eq_ignore_ascii_case(&u))
                {
                    // Confirmation of an optimistically stored relay, or a
                    // relay receipt landing after the indexer's event:
                    // merge whichever fields the other side lacks.
                    existing.verified = existing.verified || submission.verified;
                    if existing.tx_hash.is_empty() {
                        existing.tx_hash = submission.tx_hash.clone();
                    }
                    if existing.block_number == 0 {
                        existing.block_number = submission.block_number;
                    }
                    if existing.gas_used.is_none() {
                        existing.gas_used = submission.gas_used;
                    }
                    if existing.ciphertext_bytes == 0 {
                        existing.ciphertext_bytes = submission.ciphertext_bytes;
                    }
                    index = existing.index;
                } else {
                    let mut s = submission.clone();
                    s.index = r.submissions.len() as u64;
                    index = s.index;
                    r.submissions.push(s);
                }
            })
            .await?;
        debug_assert!(index < round.submissions.len() as u64);
        if !ciphertext.is_empty() {
            self.store
                .insert(&self.ct_key(index), &hex::encode(ciphertext))
                .await
                .map_err(|e| eyre!("storing ciphertext {index} for {}: {e}", self.e3_id))?;
        }
        Ok(index)
    }

    /// All stored ciphertexts in submission order (only those with bytes —
    /// submissions relayed by another client have no local ciphertext).
    pub async fn ciphertexts(&self) -> Result<Vec<(u64, Vec<u8>)>> {
        let round = self.require().await?;
        let mut out = Vec::new();
        for s in &round.submissions {
            if let Some(hex_str) = self
                .store
                .get::<String>(&self.ct_key(s.index))
                .await
                .map_err(|e| eyre!("reading ciphertext {}: {e}", s.index))?
            {
                out.push((s.index, hex::decode(hex_str)?));
            }
        }
        Ok(out)
    }
}

/// All round ids known to the store (the `_survey:` prefix scan runs on
/// the sled handle directly; `SharedStore` does not expose iteration).
pub fn list_round_ids(db: &SledDB) -> Vec<String> {
    let mut ids: Vec<String> = db
        .keys_with_prefix(ROUND_PREFIX)
        .into_iter()
        .filter_map(|k| k.strip_prefix(ROUND_PREFIX).map(str::to_string))
        .collect();
    ids.sort_by_key(|id| id.parse::<u64>().unwrap_or(u64::MAX));
    ids
}
