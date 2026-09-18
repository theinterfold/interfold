// SPDX-License-Identifier: LGPL-3.0-only

//! Read the deadlines frozen for an E3 when its committee was finalized.

use crate::{contracts::IInterfold, helpers::EthProvider};
use alloy::{primitives::Address, providers::Provider};
use anyhow::{ensure, Context, Result};
use e3_events::E3id;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CanonicalDkgTiming {
    pub deadline_unix_secs: u64,
    pub window_secs: u64,
}

pub async fn read_canonical_dkg_timing<P: Provider + Clone>(
    provider: &EthProvider<P>,
    contract_address: Address,
    e3_id: &E3id,
) -> Result<CanonicalDkgTiming> {
    let id = e3_id.clone().try_into()?;
    let contract = IInterfold::new(contract_address, provider.provider());
    let stage = contract.getE3Stage(id).call().await?;
    ensure!(
        stage == 2,
        "E3 {e3_id} is not at CommitteeFinalized (stage {stage})"
    );

    let deadline_unix_secs = contract
        .getDeadlines(id)
        .call()
        .await?
        .dkgDeadline
        .try_into()
        .context("DKG deadline does not fit in u64")?;
    let window_secs = contract
        .getE3TimeoutConfig(id)
        .call()
        .await?
        .dkgWindow
        .try_into()
        .context("DKG window does not fit in u64")?;
    ensure!(
        deadline_unix_secs > 0 && window_secs > 0,
        "E3 {e3_id} has no frozen DKG timing"
    );

    Ok(CanonicalDkgTiming {
        deadline_unix_secs,
        window_secs,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::{
        primitives::{Bytes, U256},
        providers::ProviderBuilder,
        sol_types::SolValue,
        transports::mock::Asserter,
    };

    #[tokio::test]
    async fn reads_the_e3_frozen_deadline_and_window() -> Result<()> {
        let asserter = Asserter::new();
        asserter.push_success(&"0x1");
        let provider =
            EthProvider::new(ProviderBuilder::new().connect_mocked_client(asserter.clone()))
                .await?;
        asserter.push_success(&Bytes::from(U256::from(2).abi_encode()));
        asserter.push_success(&Bytes::from(
            (U256::from(4_600), U256::ZERO, U256::ZERO).abi_encode(),
        ));
        asserter.push_success(&Bytes::from(
            (U256::from(3_600), U256::ZERO, U256::ZERO).abi_encode(),
        ));

        let timing =
            read_canonical_dkg_timing(&provider, Address::ZERO, &E3id::new("7", 1)).await?;

        assert_eq!(
            timing,
            CanonicalDkgTiming {
                deadline_unix_secs: 4_600,
                window_secs: 3_600,
            }
        );
        Ok(())
    }

    #[tokio::test]
    async fn does_not_start_dkg_before_committee_finalization() -> Result<()> {
        let asserter = Asserter::new();
        asserter.push_success(&"0x1");
        let provider =
            EthProvider::new(ProviderBuilder::new().connect_mocked_client(asserter.clone()))
                .await?;
        asserter.push_success(&Bytes::from(U256::from(1).abi_encode()));

        let error = read_canonical_dkg_timing(&provider, Address::ZERO, &E3id::new("7", 1))
            .await
            .unwrap_err();

        assert!(error.to_string().contains("not at CommitteeFinalized"));
        Ok(())
    }
}
