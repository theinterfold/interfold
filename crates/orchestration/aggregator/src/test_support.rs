// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use actix::Addr;
use anyhow::Result;
use e3_data::InMemStore;
use e3_event_system::test_support::EventFixture;
use e3_events::{
    BusHandle, Event, EventContextAccessors, EventContextSeq, GetEvents, HistoryCollector, Insert,
    InsertBatch, InterfoldEvent, InterfoldEventData, Seed, StoreKeys,
};
use e3_fhe_params::{
    build_bfv_params_arc, create_deterministic_crp_from_default_seed, BfvParamSet,
    DEFAULT_BFV_PRESET,
};
use e3_test_support::{create_seed_from_u64, create_shared_rng_from_u64};
use e3_utils::SharedRng;
use fhe::{bfv::BfvParameters, mbfv::CommonRandomPoly};
use fhe_traits::Serialize;
use std::{sync::Arc, time::Duration};

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
