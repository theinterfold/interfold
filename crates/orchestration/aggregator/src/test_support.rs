// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use actix::Addr;
use anyhow::Result;
use e3_event_system::test_support::EventFixture;
use e3_events::{BusHandle, HistoryCollector, InterfoldEvent, Seed};
use e3_fhe_params::{
    build_bfv_params_arc, create_deterministic_crp_from_default_seed, BfvParamSet,
    DEFAULT_BFV_PRESET,
};
use e3_test_support::{create_seed_from_u64, create_shared_rng_from_u64};
use e3_utils::SharedRng;
use fhe::{bfv::BfvParameters, mbfv::CommonRandomPoly};
use fhe_traits::Serialize;
use std::sync::Arc;

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
