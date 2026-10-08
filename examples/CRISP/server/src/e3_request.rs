// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! The parts of an E3 round request that the `/rounds/request` route and the CLI share.
//!
//! Each caller still owns its compute-provider-params encoding (bincode on the server, JSON in
//! the CLI) and the transaction itself.

use alloy::primitives::{Address, Bytes, U256};
use alloy::sol_types::SolValue;
use e3_sdk::evm_helpers::contracts::{CommitteeSize, InterfoldRead, InterfoldWrite};
use evm_helpers::CRISPContract;
use log::{error, info, warn};
use serde::Serialize;

use crate::config::CONFIG;
use crate::server::rpc;

/// The compute provider settings of a round.
#[derive(Debug, Serialize)]
pub struct ComputeProviderParams {
    pub name: String,
    pub parallel: bool,
    pub batch_size: u32,
}

impl ComputeProviderParams {
    pub fn from_config() -> Self {
        Self {
            name: CONFIG.e3_compute_provider_name.clone(),
            parallel: CONFIG.e3_compute_provider_parallel,
            batch_size: CONFIG.e3_compute_provider_batch_size,
        }
    }
}

/// A `CommitteeSize` with its name and the number of operators it requires.
#[derive(Debug, Clone, Copy)]
pub struct Committee {
    pub size: CommitteeSize,
    pub label: &'static str,
    pub members: u32,
}

/// The committee for `E3_COMMITTEE_SIZE` (0 = Minimum, 1 = Micro, 2 = Small).
pub fn committee(e3_committee_size: u8) -> eyre::Result<Committee> {
    let (size, label, members) = match e3_committee_size {
        0 => (CommitteeSize::Minimum, "Minimum", 3),
        1 => (CommitteeSize::Micro, "Micro", 9),
        2 => (CommitteeSize::Small, "Small", 19),
        invalid => eyre::bail!("Invalid committee size: {invalid}"),
    };
    Ok(Committee {
        size,
        label,
        members,
    })
}

/// Enable the E3 program if it is not enabled yet. A failure is logged and the request goes on:
/// `request_e3` then reverts with the real cause.
pub async fn ensure_program_enabled(
    contract: &(impl InterfoldRead + InterfoldWrite),
    program: Address,
) {
    match contract.is_e3_program_enabled(program).await {
        Ok(true) => info!("E3 Program already enabled"),
        Ok(false) => match contract.register_e3_program(program).await {
            Ok(receipt) => info!("E3 Program enabled. TxHash: {:?}", receipt.transaction_hash),
            Err(e) => warn!("Error enabling E3 Program: {e:?}"),
        },
        Err(e) => error!("Error checking E3 Program enabled: {e:?}"),
    }
}

/// The ABI-encoded custom params of a CRISP round.
///
/// `census_mode` is the `CRISPProgram.CensusMode` discriminant: 0 (TOKEN) or 2 (ONCHAIN). For an
/// ONCHAIN round `balance_threshold` is the `minVotingPower` floor in the token's raw units. The
/// round has two options and constant credits of one. The seventh field is the voting-power
/// divisor, which constant credits ignore; `_initRound` decodes exactly seven fields and reverts
/// on a shorter encoding.
pub fn custom_params(token: Address, balance_threshold: U256, census_mode: u64) -> Bytes {
    let num_options = U256::from(2);
    let credit_mode = U256::ZERO;
    let credits = U256::from(1);
    let voting_power_divisor = U256::ZERO;
    Bytes::from(
        (
            token,
            balance_threshold,
            num_options,
            credit_mode,
            credits,
            U256::from(census_mode),
            voting_power_divisor,
        )
            .abi_encode(),
    )
}

/// The `[start, end]` input window of a round requested now.
///
/// A program with an Avail finalization window starts voting after its worst-case key deadline;
/// any other program starts from the chain time. `E3_DURATION` includes the finalization tail in
/// both cases.
pub async fn voting_window(program: &CRISPContract) -> eyre::Result<[U256; 2]> {
    let avail_window = program.availability_finalization_window().await?;
    let now = rpc::latest_timestamp(rpc::provider().await?).await?;
    let base: u64 = if avail_window.is_zero() {
        now
    } else {
        let (timestamp, native) = program.earliest_voting_start_compatible(now).await?;
        if !native {
            warn!("CRISPProgram has no earliestVotingStart(); derived the schedule from Interfold");
        }
        timestamp.try_into()?
    };
    let start = base
        .checked_add(CONFIG.voting_start_buffer_seconds)
        .ok_or_else(|| eyre::eyre!("voting start overflow"))?;
    let end = start
        .checked_add(CONFIG.e3_duration)
        .ok_or_else(|| eyre::eyre!("voting end overflow"))?;
    Ok([U256::from(start), U256::from(end)])
}
