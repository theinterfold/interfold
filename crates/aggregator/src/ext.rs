// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use std::sync::Arc;

use crate::actors::DecryptionshareCreatedBuffer;
use crate::actors::KeyshareCreatedFilterBuffer;
use crate::domain::committee::{
    committee_addresses_from_nodes, committee_addresses_in_party_order,
};
use crate::{
    PublicKeyAggregator, PublicKeyAggregatorParams, PublicKeyAggregatorState,
    PublicKeyRepositoryFactory, ThresholdPlaintextAggregator, ThresholdPlaintextAggregatorParams,
    ThresholdPlaintextAggregatorState, TrBfvPlaintextRepositoryFactory,
};
use actix::{Actor, Addr, Recipient};
use alloy::primitives::Address;
use anyhow::{anyhow, ensure, Result};
use async_trait::async_trait;
use e3_data::{AutoPersist, Persistable, RepositoriesFactory};
use e3_events::{prelude::*, CiphernodeSelected, CiphertextOutputPublished, E3id};
use e3_events::{BusHandle, EType, InterfoldEvent, InterfoldEventData};
use e3_fhe::ext::FHE_KEY;
use e3_fhe::Fhe;
use e3_fhe_params::BfvPreset;
use e3_keyshare::ThresholdKeyshareRepositoryFactory;
use e3_request::{E3Context, E3ContextSnapshot, E3Extension, TypedKey, META_KEY};
use e3_sortition::Sortition;
use e3_zk_helpers::CiphernodesCommitteeSize;
use std::collections::{BTreeSet, HashMap};

/// Full finalized committee (`PublicKeyAggregated.committee_addresses`, length `N`)
/// for `committee_hash_*` binding in downstream ZK requests.
pub const COMMITTEE_ADDRESSES_KEY: TypedKey<Vec<Address>> = TypedKey::new("committee_addresses");

/// Honest subset of the committee (`PublicKeyAggregated.honest_committee_addresses`, length `H`)
/// for decryption-share collection gating.
pub const HONEST_COMMITTEE_ADDRESSES_KEY: TypedKey<Vec<Address>> =
    TypedKey::new("honest_committee_addresses");
const ACTIVE_AGGREGATOR_KEY: TypedKey<bool> = TypedKey::new("active_aggregator");
const PENDING_CIPHERTEXT_OUTPUT_KEY: TypedKey<CiphertextOutputPublished> =
    TypedKey::new("pending_ciphertext_output");
const HONEST_PARTY_IDS_KEY: TypedKey<BTreeSet<u64>> = TypedKey::new("honest_party_ids");

pub struct PublicKeyAggregatorExtension {
    bus: BusHandle,
}

impl PublicKeyAggregatorExtension {
    pub fn create(bus: &BusHandle) -> Box<Self> {
        Box::new(Self { bus: bus.clone() })
    }
}

const ERROR_PUBKEY_FHE_MISSING:&str = "Could not create PublicKeyAggregator because the fhe instance it depends on was not set on the context.";
const ERROR_PUBKEY_META_MISSING:&str = "Could not create PublicKeyAggregator because the meta instance it depends on was not set on the context.";

#[async_trait]
impl E3Extension for PublicKeyAggregatorExtension {
    fn on_event(&self, ctx: &mut E3Context, evt: &InterfoldEvent) {
        // Create the public-key aggregation pipeline only for finalized committee members.
        let InterfoldEventData::CiphernodeSelected(data) = evt.get_data() else {
            return;
        };

        if ctx.get_event_recipient("publickey").is_some() {
            return;
        }

        let Some(fhe) = ctx.get_dependency(FHE_KEY) else {
            self.bus.err(
                EType::PublickeyAggregation,
                anyhow!(ERROR_PUBKEY_FHE_MISSING),
            );
            return;
        };
        let CiphernodeSelected {
            e3_id,
            threshold_n,
            threshold_m,
            seed,
            params_preset,
            ..
        } = data.clone();
        let repo = ctx.repositories().publickey(&e3_id);
        let sync_state = repo.send(Some(PublicKeyAggregatorState::init(
            threshold_n,
            threshold_m,
            seed,
        )));

        let committee_size = match CiphernodesCommitteeSize::from_threshold(
            threshold_m,
            threshold_n,
        ) {
            Ok(c) => c,
            Err(e) => {
                self.bus.err(
                    EType::PublickeyAggregation,
                    anyhow!("Unknown committee size for E3 {e3_id} (threshold_m={threshold_m}, threshold_n={threshold_n}): {e}"),
                );
                return;
            }
        };
        let value = create_publickey_aggregator(
            fhe.clone(),
            self.bus.clone(),
            e3_id,
            sync_state,
            params_preset,
            committee_size,
        );

        ctx.set_event_recipient("publickey", Some(value));
    }

    async fn hydrate(&self, ctx: &mut E3Context, snapshot: &E3ContextSnapshot) -> Result<()> {
        // No ID on the snapshot -> bail
        if !snapshot.contains("publickey") {
            return Ok(());
        };

        let repo = ctx.repositories().publickey(&ctx.e3_id);
        let sync_state = repo.load().await?;

        // No Snapshot returned from the store -> bail
        if !sync_state.has() {
            return Ok(());
        };

        // Get deps
        let Some(fhe) = ctx.get_dependency(FHE_KEY) else {
            self.bus.err(
                EType::PublickeyAggregation,
                anyhow!(ERROR_PUBKEY_FHE_MISSING),
            );

            return Ok(());
        };
        let Some(meta) = ctx.get_dependency(META_KEY) else {
            self.bus.err(
                EType::PublickeyAggregation,
                anyhow!(ERROR_PUBKEY_META_MISSING),
            );

            return Ok(());
        };
        let committee_size =
            CiphernodesCommitteeSize::from_threshold(meta.threshold_m, meta.threshold_n).map_err(
                |e| {
                    anyhow!(
                        "Unknown committee size (threshold_m={}, threshold_n={}): {e}",
                        meta.threshold_m,
                        meta.threshold_n
                    )
                },
            )?;
        let value = create_publickey_aggregator(
            fhe.clone(),
            self.bus.clone(),
            ctx.e3_id.clone(),
            sync_state,
            meta.params_preset,
            committee_size,
        );

        // send to context
        ctx.set_event_recipient("publickey", Some(value));

        Ok(())
    }
}

fn create_publickey_aggregator(
    fhe: Arc<Fhe>,
    bus: BusHandle,
    e3_id: E3id,
    sync_state: Persistable<PublicKeyAggregatorState>,
    params_preset: BfvPreset,
    committee_size: CiphernodesCommitteeSize,
) -> Recipient<InterfoldEvent> {
    KeyshareCreatedFilterBuffer::new(
        PublicKeyAggregator::new(
            PublicKeyAggregatorParams {
                fhe,
                bus,
                e3_id,
                params_preset,
                committee_size,
            },
            sync_state,
        )
        .start(),
    )
    .start()
    .into()
}

pub struct ThresholdPlaintextAggregatorExtension {
    bus: BusHandle,
    sortition: Addr<Sortition>,
}

impl ThresholdPlaintextAggregatorExtension {
    pub fn create(bus: &BusHandle, sortition: &Addr<Sortition>) -> Box<Self> {
        Box::new(Self {
            bus: bus.clone(),
            sortition: sortition.clone(),
        })
    }

    fn try_start_plaintext(&self, ctx: &mut E3Context, data: &CiphertextOutputPublished) -> bool {
        if ctx.get_event_recipient("threshold_keyshare").is_none() {
            tracing::warn!(
                e3_id = %data.e3_id,
                "Deferring ThresholdPlaintextAggregator creation: threshold_keyshare recipient is not ready"
            );
            return false;
        }

        if ctx.get_event_recipient("plaintext").is_some() {
            return true;
        }

        let Some(meta) = ctx.get_dependency(META_KEY) else {
            self.bus.err(
                EType::PlaintextAggregation,
                anyhow!(ERROR_TRBFV_PLAINTEXT_META_MISSING),
            );
            return false;
        };

        let e3_id = data.e3_id.clone();
        let committee_addresses = match load_committee_addresses(ctx) {
            Ok(addrs) => addrs,
            Err(e) => {
                tracing::warn!(
                    e3_id = %e3_id,
                    "Deferring ThresholdPlaintextAggregator creation: {e}"
                );
                return false;
            }
        };
        let honest_committee_addresses = match load_honest_committee_addresses(ctx) {
            Ok(addrs) => addrs,
            Err(e) => {
                tracing::warn!(
                    e3_id = %e3_id,
                    "Deferring ThresholdPlaintextAggregator creation: {e}"
                );
                return false;
            }
        };
        let initial_is_aggregator = load_is_active_aggregator(ctx);

        let repo = ctx.repositories().trbfv_plaintext(&e3_id);
        let sync_state = repo.send(Some(ThresholdPlaintextAggregatorState::init(
            meta.threshold_m as u64,
            meta.threshold_n as u64,
            meta.seed,
            data.ciphertext_output.clone(),
            meta.params.clone(),
        )));

        ctx.set_event_recipient(
            "plaintext",
            Some(create_decryptionshare_buffer(
                ThresholdPlaintextAggregator::new(
                    ThresholdPlaintextAggregatorParams {
                        bus: self.bus.clone(),
                        sortition: self.sortition.clone(),
                        e3_id: e3_id.clone(),
                        params_preset: meta.params_preset,
                        committee_size: match CiphernodesCommitteeSize::from_threshold(
                            meta.threshold_m,
                            meta.threshold_n,
                        ) {
                            Ok(c) => c,
                            Err(e) => {
                                self.bus.err(
                                    EType::PlaintextAggregation,
                                    anyhow!("Unknown committee size for E3 {e3_id} (threshold_m={}, threshold_n={}): {e}", meta.threshold_m, meta.threshold_n),
                                );
                                return false;
                            }
                        },
                        proof_aggregation_enabled: meta.proof_aggregation_enabled,
                        committee_addresses,
                        honest_committee_addresses,
                    },
                    sync_state,
                )
                .start(),
                initial_is_aggregator,
            )),
        );

        true
    }
}

const ERROR_TRBFV_PLAINTEXT_META_MISSING:&str = "Could not create ThresholdPlaintextAggregator because the meta instance it depends on was not set on the context.";
const ERROR_TRBFV_PLAINTEXT_COMMITTEE_MISSING: &str =
    "Could not create ThresholdPlaintextAggregator because committee addresses were not set (expected PublicKeyAggregated or CommitteePublished before CiphertextOutputPublished).";
const ERROR_TRBFV_PLAINTEXT_HONEST_COMMITTEE_MISSING: &str =
    "Could not create ThresholdPlaintextAggregator because honest committee addresses were not set (expected non-empty PublicKeyAggregated.honest_committee_addresses or recovered public-key state).";

fn load_committee_addresses(ctx: &E3Context) -> Result<Vec<Address>> {
    if let Some(addrs) = ctx.get_dependency(COMMITTEE_ADDRESSES_KEY) {
        return Ok(addrs.clone());
    }
    Err(anyhow!(ERROR_TRBFV_PLAINTEXT_COMMITTEE_MISSING))
}

fn load_honest_committee_addresses(ctx: &E3Context) -> Result<Vec<Address>> {
    if let Some(addrs) = ctx.get_dependency(HONEST_COMMITTEE_ADDRESSES_KEY) {
        if addrs.is_empty() {
            return Err(anyhow!(ERROR_TRBFV_PLAINTEXT_HONEST_COMMITTEE_MISSING));
        }
        return Ok(addrs.clone());
    }
    Err(anyhow!(ERROR_TRBFV_PLAINTEXT_HONEST_COMMITTEE_MISSING))
}

fn addresses_for_sorted_party_ids(party_nodes: &HashMap<u64, String>) -> Result<Vec<Address>> {
    let mut party_ids: Vec<u64> = party_nodes.keys().copied().collect();
    party_ids.sort_unstable();
    committee_addresses_in_party_order(&party_ids, party_nodes)
}

fn publickey_state_committee_addresses(
    state: &PublicKeyAggregatorState,
) -> Result<Option<Vec<Address>>> {
    match state {
        PublicKeyAggregatorState::Complete {
            committee_addresses,
            ..
        } if !committee_addresses.is_empty() => Ok(Some(committee_addresses.clone())),
        PublicKeyAggregatorState::GeneratingC5Proof { party_nodes, .. }
            if !party_nodes.is_empty() =>
        {
            Ok(Some(addresses_for_sorted_party_ids(party_nodes)?))
        }
        _ => Ok(None),
    }
}

fn publickey_state_honest_committee_addresses(
    state: &PublicKeyAggregatorState,
) -> Result<Option<Vec<Address>>> {
    match state {
        PublicKeyAggregatorState::Complete {
            honest_committee_addresses,
            ..
        } if !honest_committee_addresses.is_empty() => Ok(Some(honest_committee_addresses.clone())),
        PublicKeyAggregatorState::GeneratingC5Proof {
            party_nodes,
            honest_party_ids,
            ..
        } if !honest_party_ids.is_empty() => {
            let party_ids: Vec<u64> = honest_party_ids.iter().copied().collect();
            Ok(Some(committee_addresses_in_party_order(
                &party_ids,
                party_nodes,
            )?))
        }
        _ => Ok(None),
    }
}

fn honest_addresses_from_party_ids(
    committee_addresses: &[Address],
    honest_party_ids: &BTreeSet<u64>,
) -> Result<Vec<Address>> {
    ensure!(
        !honest_party_ids.is_empty(),
        "cannot recover honest committee from an empty honest party set"
    );

    honest_party_ids
        .iter()
        .map(|party_id| {
            let index = usize::try_from(*party_id)
                .map_err(|_| anyhow!("party_id {party_id} does not fit in usize"))?;
            committee_addresses.get(index).copied().ok_or_else(|| {
                anyhow!(
                    "honest party_id {party_id} is out of bounds for committee of {} nodes",
                    committee_addresses.len()
                )
            })
        })
        .collect()
}

fn committee_addresses_from_node_strings(nodes: &[String]) -> Result<Vec<Address>> {
    nodes
        .iter()
        .map(|node| {
            node.parse::<Address>()
                .map_err(|e| anyhow!("invalid committee node address {node}: {e}"))
        })
        .collect()
}

fn remember_committee_dependencies_from_publickey_state(
    ctx: &mut E3Context,
    state: &PublicKeyAggregatorState,
) -> Result<()> {
    if let Some(addrs) = publickey_state_committee_addresses(state)? {
        ctx.set_dependency(COMMITTEE_ADDRESSES_KEY, addrs);
    }
    if let Some(addrs) = publickey_state_honest_committee_addresses(state)? {
        ctx.set_dependency(HONEST_COMMITTEE_ADDRESSES_KEY, addrs);
    }
    Ok(())
}

async fn recover_committee_dependencies_from_publickey_state(
    ctx: &mut E3Context,
    e3_id: &E3id,
) -> Result<()> {
    let repo = ctx.repositories().publickey(e3_id);
    if let Some(state) = repo.read().await? {
        remember_committee_dependencies_from_publickey_state(ctx, &state)?;
    }
    Ok(())
}

async fn recover_honest_committee_dependencies_from_keyshare_state(
    ctx: &mut E3Context,
    e3_id: &E3id,
) -> Result<()> {
    let repo = ctx.repositories().threshold_keyshare(e3_id);
    let Some(state) = repo.read().await? else {
        return Ok(());
    };
    let Some(honest_party_ids) = state.honest_parties.clone() else {
        return Ok(());
    };

    ctx.set_dependency(HONEST_PARTY_IDS_KEY, honest_party_ids);
    remember_honest_committee_from_cached_party_ids(ctx, e3_id)?;
    Ok(())
}

fn remember_honest_committee_from_cached_party_ids(
    ctx: &mut E3Context,
    e3_id: &E3id,
) -> Result<()> {
    if ctx.get_dependency(HONEST_COMMITTEE_ADDRESSES_KEY).is_some() {
        return Ok(());
    }

    let Some(committee_addresses) = ctx.get_dependency(COMMITTEE_ADDRESSES_KEY).cloned() else {
        return Ok(());
    };
    let Some(honest_party_ids) = ctx.get_dependency(HONEST_PARTY_IDS_KEY).cloned() else {
        return Ok(());
    };

    let honest_committee_addresses =
        honest_addresses_from_party_ids(&committee_addresses, &honest_party_ids)?;
    tracing::info!(
        e3_id = %e3_id,
        honest_party_ids = ?honest_party_ids,
        honest_committee_len = honest_committee_addresses.len(),
        "Recovered honest committee addresses from persisted threshold keyshare state"
    );
    ctx.set_dependency(HONEST_COMMITTEE_ADDRESSES_KEY, honest_committee_addresses);
    Ok(())
}

fn remember_committee_published(ctx: &mut E3Context, e3_id: &E3id, nodes: &[String]) -> Result<()> {
    let addrs = committee_addresses_from_node_strings(nodes)?;
    let addrs_len = addrs.len();
    ctx.set_dependency(COMMITTEE_ADDRESSES_KEY, addrs.clone());

    // In committees where every on-chain member is also part of the honest circuit set,
    // CommitteePublished is sufficient to recover the honest roster. For N > H we keep
    // the honest dependency from PublicKeyAggregated / public-key state.
    if let Some(meta) = ctx.get_dependency(META_KEY) {
        let committee =
            CiphernodesCommitteeSize::from_threshold(meta.threshold_m, meta.threshold_n)
                .map(|size| size.values());
        if committee.is_ok_and(|committee| committee.h == addrs_len) {
            ctx.set_dependency(HONEST_COMMITTEE_ADDRESSES_KEY, addrs);
        }
    }

    remember_honest_committee_from_cached_party_ids(ctx, e3_id)?;
    Ok(())
}

fn load_is_active_aggregator(ctx: &E3Context) -> bool {
    ctx.get_dependency(ACTIVE_AGGREGATOR_KEY)
        .copied()
        .unwrap_or(false)
}

fn create_decryptionshare_buffer(
    dest: Addr<ThresholdPlaintextAggregator>,
    initial_is_aggregator: bool,
) -> Recipient<InterfoldEvent> {
    DecryptionshareCreatedBuffer::new_with_aggregator_state(dest, initial_is_aggregator)
        .start()
        .into()
}

#[async_trait]
impl E3Extension for ThresholdPlaintextAggregatorExtension {
    fn on_event(&self, ctx: &mut E3Context, evt: &InterfoldEvent) {
        if let InterfoldEventData::AggregatorChanged(data) = evt.get_data() {
            ctx.set_dependency(ACTIVE_AGGREGATOR_KEY, data.is_aggregator);
            if let Some(ciphertext) = ctx.get_dependency(PENDING_CIPHERTEXT_OUTPUT_KEY).cloned() {
                self.try_start_plaintext(ctx, &ciphertext);
            }
            return;
        }

        if matches!(evt.get_data(), InterfoldEventData::CiphernodeSelected(_)) {
            if let Some(ciphertext) = ctx.get_dependency(PENDING_CIPHERTEXT_OUTPUT_KEY).cloned() {
                self.try_start_plaintext(ctx, &ciphertext);
            }
            return;
        }

        if let InterfoldEventData::PublicKeyAggregated(data) = evt.get_data() {
            let addrs = if !data.committee_addresses.is_empty() {
                Ok(data.committee_addresses.clone())
            } else {
                committee_addresses_from_nodes(&data.nodes)
            };
            match addrs {
                Ok(addrs) => {
                    ctx.set_dependency(COMMITTEE_ADDRESSES_KEY, addrs);
                    if data.honest_committee_addresses.is_empty() {
                        self.bus.err(
                            EType::PlaintextAggregation,
                            anyhow!(ERROR_TRBFV_PLAINTEXT_HONEST_COMMITTEE_MISSING),
                        );
                        return;
                    }
                    ctx.set_dependency(
                        HONEST_COMMITTEE_ADDRESSES_KEY,
                        data.honest_committee_addresses.clone(),
                    );
                    if let Some(ciphertext) =
                        ctx.get_dependency(PENDING_CIPHERTEXT_OUTPUT_KEY).cloned()
                    {
                        self.try_start_plaintext(ctx, &ciphertext);
                    }
                }
                Err(e) => {
                    self.bus.err(EType::PlaintextAggregation, e);
                }
            }
            return;
        }

        if let InterfoldEventData::CommitteePublished(data) = evt.get_data() {
            if let Err(e) = remember_committee_published(ctx, &data.e3_id, &data.nodes) {
                self.bus.err(EType::PlaintextAggregation, e);
            }
            if let Some(ciphertext) = ctx.get_dependency(PENDING_CIPHERTEXT_OUTPUT_KEY).cloned() {
                self.try_start_plaintext(ctx, &ciphertext);
            }
            return;
        }

        // Save plaintext aggregator for finalized committee members.
        let InterfoldEventData::CiphertextOutputPublished(data) = evt.get_data() else {
            return;
        };
        ctx.set_dependency(PENDING_CIPHERTEXT_OUTPUT_KEY, data.clone());
        self.try_start_plaintext(ctx, data);
    }

    async fn hydrate(&self, ctx: &mut E3Context, snapshot: &E3ContextSnapshot) -> Result<()> {
        let e3_id = ctx.e3_id.clone();
        recover_committee_dependencies_from_publickey_state(ctx, &e3_id).await?;
        recover_honest_committee_dependencies_from_keyshare_state(ctx, &e3_id).await?;

        // No ID on the snapshot -> bail
        if !snapshot.contains("plaintext") {
            return Ok(());
        }

        let repo = ctx.repositories().trbfv_plaintext(&snapshot.e3_id);
        let sync_state = repo.load().await?;

        // No Snapshot returned from the store -> bail
        if !sync_state.has() {
            return Ok(());
        };

        let Some(meta) = ctx.get_dependency(META_KEY) else {
            self.bus.err(
                EType::PlaintextAggregation,
                anyhow!(ERROR_TRBFV_PLAINTEXT_META_MISSING),
            );

            return Ok(());
        };

        let committee_addresses = load_committee_addresses(ctx)?;
        let honest_committee_addresses = load_honest_committee_addresses(ctx)?;
        let initial_is_aggregator = load_is_active_aggregator(ctx);

        let value = ThresholdPlaintextAggregator::new(
            ThresholdPlaintextAggregatorParams {
                bus: self.bus.clone(),
                sortition: self.sortition.clone(),
                e3_id: ctx.e3_id.clone(),
                params_preset: meta.params_preset,
                committee_size: CiphernodesCommitteeSize::from_threshold(
                    meta.threshold_m,
                    meta.threshold_n,
                )
                .map_err(|e| {
                    anyhow!(
                        "Unknown committee size (threshold_m={}, threshold_n={}): {e}",
                        meta.threshold_m,
                        meta.threshold_n
                    )
                })?,
                proof_aggregation_enabled: meta.proof_aggregation_enabled,
                committee_addresses,
                honest_committee_addresses,
            },
            sync_state,
        )
        .start();

        // send to context
        ctx.set_event_recipient(
            "plaintext",
            Some(create_decryptionshare_buffer(value, initial_is_aggregator)),
        );

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::address;
    use e3_events::OrderedSet;
    use e3_utils::ArcBytes;
    use std::collections::{BTreeSet, HashMap};

    fn generating_c5_state() -> PublicKeyAggregatorState {
        let party_nodes = HashMap::from([
            (
                2u64,
                "0x70997970C51812dc3A010C7d01b50e0d17dc79C8".to_string(),
            ),
            (
                0u64,
                "0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65".to_string(),
            ),
            (
                1u64,
                "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC".to_string(),
            ),
        ]);

        PublicKeyAggregatorState::GeneratingC5Proof {
            public_key: ArcBytes::from_bytes(&[1, 2, 3]),
            keyshare_bytes: vec![],
            nodes: OrderedSet::new(),
            party_nodes,
            dkg_node_proofs: HashMap::new(),
            dkg_fold_attestations: HashMap::new(),
            honest_party_ids: BTreeSet::from([0, 2]),
            dishonest_parties: BTreeSet::from([1]),
            circuit_committee_n: 3,
            circuit_committee_h: 2,
            dkg_aggregation_correlation: None,
            dkg_aggregated_proof: None,
            c5_proof_pending: None,
            last_ec: None,
            nodes_fold_accumulator: None,
            nodes_fold_completed_slots: 0,
            nodes_fold_step_correlation: None,
        }
    }

    #[test]
    fn recovers_full_committee_addresses_from_generating_c5_state() -> Result<()> {
        let state = generating_c5_state();

        let addresses = publickey_state_committee_addresses(&state)?.expect("addresses");

        assert_eq!(
            addresses,
            vec![
                address!("0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65"),
                address!("0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"),
                address!("0x70997970C51812dc3A010C7d01b50e0d17dc79C8"),
            ]
        );
        Ok(())
    }

    #[test]
    fn recovers_honest_committee_addresses_from_generating_c5_state() -> Result<()> {
        let state = generating_c5_state();

        let addresses =
            publickey_state_honest_committee_addresses(&state)?.expect("honest addresses");

        assert_eq!(
            addresses,
            vec![
                address!("0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65"),
                address!("0x70997970C51812dc3A010C7d01b50e0d17dc79C8"),
            ]
        );
        Ok(())
    }

    #[test]
    fn recovers_honest_committee_addresses_from_keyshare_party_ids() -> Result<()> {
        let committee = vec![
            address!("0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65"),
            address!("0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"),
            address!("0x70997970C51812dc3A010C7d01b50e0d17dc79C8"),
        ];

        let addresses = honest_addresses_from_party_ids(&committee, &BTreeSet::from([0, 2]))?;

        assert_eq!(
            addresses,
            vec![
                address!("0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65"),
                address!("0x70997970C51812dc3A010C7d01b50e0d17dc79C8"),
            ]
        );
        Ok(())
    }

    #[test]
    fn rejects_honest_party_id_outside_full_committee() {
        let committee = vec![address!("0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65")];

        let err = honest_addresses_from_party_ids(&committee, &BTreeSet::from([1])).unwrap_err();

        assert!(err
            .to_string()
            .contains("honest party_id 1 is out of bounds"));
    }
}
