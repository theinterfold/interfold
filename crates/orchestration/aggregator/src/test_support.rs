// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use actix::{Actor, Addr, Recipient};
use anyhow::Result;
use e3_data::{InMemEventLog, InMemSequenceIndex, InMemStore};
use e3_event_system::test_support::EventFixture;
use e3_events::{
    prelude::*, BusHandle, Event, EventContextAccessors, EventContextSeq, EventStore,
    EventStoreQueryBy, EventStoreRouter, GetEvents, HistoryCollector, Insert, InsertBatch,
    InterfoldEvent, InterfoldEventData, Seed, SeqAgg, StoreKeys, Unsequenced,
};
use e3_fhe_params::{
    build_bfv_params_arc, create_deterministic_crp_from_default_seed, BfvParamSet,
    DEFAULT_BFV_PRESET,
};
use e3_test_support::{create_seed_from_u64, create_shared_rng_from_u64};
use e3_utils::SharedRng;
use fhe::{bfv::BfvParameters, mbfv::CommonRandomPoly};
use fhe_traits::Serialize;
use std::{collections::HashMap, sync::Arc, time::Duration};

/// Event-store reader whose chain aggregate 1 holds `events` in order.
pub(crate) fn history_reader(
    events: &[InterfoldEvent],
) -> Result<Recipient<EventStoreQueryBy<SeqAgg>>> {
    let mut store = EventStore::new(InMemSequenceIndex::new(), InMemEventLog::new())?;
    for event in events {
        store.store_event(InterfoldEvent::<Unsequenced>::new_with_timestamp(
            event.get_data().clone(),
            None,
            event.ts(),
            None,
            event.source(),
        ))?;
    }
    let global = EventStore::new(InMemSequenceIndex::new(), InMemEventLog::new())?;
    Ok(
        EventStoreRouter::new(HashMap::from([(0, global.start()), (1, store.start())]))
            .start()
            .recipient(),
    )
}

/// A complete Minimum projection and its opening, below request admission.
pub(crate) fn synchronized_opening(
    id: &e3_events::E3id,
) -> Result<(
    e3_request::canonical_key::CanonicalPublicKeys,
    InterfoldEvent,
)> {
    use alloy::primitives::{keccak256, Address};
    use e3_committee::CiphernodesCommitteeSize;
    use e3_committee_hash::{hash_committee_addresses, DkgSetupContext};
    use e3_events::{CiphertextOutputPublished, EventSource, SynchronizedDkgContext};
    use e3_fhe_params::BfvProfile;
    use e3_request::canonical_key::{
        CanonicalDkgAnchors, CanonicalPublicKey, CanonicalPublicKeys, SynchronizedDkgAuthority,
    };
    let profile = BfvProfile::SyncDecInsecure64;
    let size = CiphernodesCommitteeSize::Minimum;
    let (params, _) = profile.build_pair()?;
    let (n, t, q) = (params.degree(), params.plaintext(), params.moduli());
    let pk = e3_bfv_client::client::generate_public_key(n, t, q.to_vec())?;
    let pk_commitment = e3_bfv_client::compute_pk_commitment(pk.clone(), n, t, q.to_vec())?;
    let ct = e3_bfv_client::bfv_encrypt(vec![7u64], pk, n, t, q)?;
    let commitment = e3_bfv_client::compute_ct_commitment_with_params(&ct, &params)?;
    let committee: Vec<_> = (1..=3).map(Address::repeat_byte).collect();
    let interfold_address = Address::repeat_byte(4);
    let context = SynchronizedDkgContext {
        registry: Address::repeat_byte(5),
        verifying_contract: Address::repeat_byte(6),
        crypto_config_id: profile.crypto_config_id(size)?.0,
    };
    let binding = DkgSetupContext {
        interfold_address,
        committee_hash: hash_committee_addresses(&committee),
        crypto_config_id: context.crypto_config_id.into(),
    };
    let keys = CanonicalPublicKeys::default();
    keys.remember_synchronized_context(id.clone(), context)?;
    keys.insert_synchronized_dkg_authority(
        id.clone(),
        CanonicalPublicKey {
            pk_commitment,
            honest_committee: vec![committee[0], committee[2]],
            committee,
            params_profile: profile,
            committee_size: size,
            interfold_address,
            dkg_anchors: CanonicalDkgAnchors::Synchronized(SynchronizedDkgAuthority {
                version: 1,
                context,
                setup_binding: binding.hash(id.chain_id(), id.clone().try_into()?).0,
                dealer_batch: [1; 32],
                party_ids: vec![0, 2],
                threshold_pk_commits: vec![[2; 32]; 2],
                sk_agg_commits: vec![[3; 32]; 2],
                key_bundle_commits: vec![[4; 32]; 2],
            }),
        },
    )?;
    let bytes = vec![e3_utils::ArcBytes::from_bytes(&ct)];
    let opening = InterfoldEvent::<Unsequenced>::new_with_timestamp(
        CiphertextOutputPublished {
            e3_id: id.clone(),
            ciphertext_output: bytes.clone(),
            ciphertext_commitment: commitment,
        }
        .into(),
        None,
        1,
        Some(1),
        EventSource::Evm,
    )
    .into_sequenced(1);
    keys.remember_synchronized_output(id, keccak256(ct), commitment)?;
    keys.remember_synchronized_ciphertext_ready(id);
    keys.remember_synchronized_opening(id, &bytes, opening.get_ctx(), false)?;
    Ok((keys, opening))
}

#[allow(clippy::type_complexity)]
pub(crate) fn get_common_setup(
    param_set: Option<BfvParamSet>,
) -> Result<(
    BusHandle,
    SharedRng,
    Seed,
    Arc<BfvParameters>,
    CommonRandomPoly,
    Addr<HistoryCollector<InterfoldEvent>>,
    Addr<HistoryCollector<InterfoldEvent>>,
)> {
    let EventFixture {
        bus,
        errors,
        history,
    } = EventFixture::new()?;
    let rng = create_shared_rng_from_u64(42);
    let seed = Seed(create_seed_from_u64(123));
    let param_set = param_set.unwrap_or(DEFAULT_BFV_PRESET.into());
    let params = build_bfv_params_arc(
        param_set.degree,
        param_set.plaintext_modulus,
        param_set.moduli,
        None,
    );
    let crp_bytes = create_deterministic_crp_from_default_seed(&params).to_bytes();
    let crpoly = CommonRandomPoly::deserialize(&crp_bytes, &params)?;
    Ok((bus, rng, seed, params, crpoly, errors, history))
}

/// Startup replay commits snapshots for the events that it replays after a held result. Advance
/// the snapshot cursor of `store` past the logged event that `replayed` selects, so that the store
/// rejects writes under that event's revision.
pub(crate) async fn commit_replay_past(
    store: &Addr<InMemStore>,
    history: &Addr<HistoryCollector<InterfoldEvent>>,
    replayed: impl Fn(&InterfoldEventData) -> bool,
) -> Result<()> {
    for _ in 0..300 {
        let events = history.send(GetEvents::<InterfoldEvent>::new()).await?;
        if let Some(event) = events.iter().find(|event| replayed(event.get_data())) {
            let ctx = event.get_ctx();
            store
                .send(InsertBatch::new(vec![Insert::new(
                    StoreKeys::aggregate_seq(ctx.aggregate_id()).into_bytes(),
                    (ctx.seq() + 1).to_le_bytes().to_vec(),
                )]))
                .await??;
            return Ok(());
        }
        actix::clock::sleep(Duration::from_millis(10)).await;
    }
    anyhow::bail!("the replayed event was not logged")
}
