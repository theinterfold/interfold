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
        rpc::client::RpcClient,
        sol_types::{SolCall, SolValue},
        transports::{
            mock::{Asserter, MockTransport},
            TransportError, TransportFut,
        },
    };
    use alloy_json_rpc::{RequestPacket, ResponsePacket};
    use std::{
        sync::{Arc, Mutex},
        task::{Context as TaskContext, Poll},
    };
    use tower::Service;

    #[derive(Clone, Debug)]
    struct RecordingTransport {
        inner: MockTransport,
        requests: Arc<Mutex<Vec<(String, Option<String>)>>>,
    }

    impl RecordingTransport {
        fn new(asserter: Asserter) -> (Self, Arc<Mutex<Vec<(String, Option<String>)>>>) {
            let requests = Arc::new(Mutex::new(Vec::new()));
            (
                Self {
                    inner: MockTransport::new(asserter),
                    requests: requests.clone(),
                },
                requests,
            )
        }
    }

    impl Service<RequestPacket> for RecordingTransport {
        type Response = ResponsePacket;
        type Error = TransportError;
        type Future = TransportFut<'static>;

        fn poll_ready(&mut self, context: &mut TaskContext<'_>) -> Poll<Result<(), Self::Error>> {
            self.inner.poll_ready(context)
        }

        fn call(&mut self, request: RequestPacket) -> Self::Future {
            self.requests
                .lock()
                .unwrap()
                .extend(request.requests().iter().map(|request| {
                    (
                        request.method().to_string(),
                        request.params().map(|params| params.get().to_string()),
                    )
                }));
            self.inner.call(request)
        }
    }

    fn assert_contract_calls(
        requests: &Arc<Mutex<Vec<(String, Option<String>)>>>,
        contract_address: Address,
        e3_id: U256,
        selectors: &[[u8; 4]],
    ) {
        let requests = requests.lock().unwrap();
        assert_eq!(
            requests
                .iter()
                .map(|(method, _)| method.as_str())
                .collect::<Vec<_>>(),
            std::iter::once("eth_chainId")
                .chain(std::iter::repeat_n("eth_call", selectors.len()))
                .collect::<Vec<_>>()
        );

        for ((_, params), selector) in requests.iter().skip(1).zip(selectors) {
            let params: serde_json::Value =
                serde_json::from_str(params.as_deref().expect("eth_call must have parameters"))
                    .unwrap();
            let call = params
                .as_array()
                .and_then(|params| params.first())
                .and_then(serde_json::Value::as_object)
                .expect("eth_call must contain a transaction object");
            assert_eq!(
                call.get("to").and_then(serde_json::Value::as_str),
                Some(format!("{contract_address:#x}").as_str())
            );
            let input = call
                .get("input")
                .or_else(|| call.get("data"))
                .and_then(serde_json::Value::as_str)
                .expect("eth_call must contain calldata");
            let input = hex::decode(input.trim_start_matches("0x")).unwrap();
            assert_eq!(&input[..4], selector);
            assert_eq!(&input[4..], e3_id.to_be_bytes::<32>());
        }
    }

    #[tokio::test]
    async fn reads_the_e3_frozen_deadline_and_window() -> Result<()> {
        let asserter = Asserter::new();
        asserter.push_success(&"0x1");
        let (transport, requests) = RecordingTransport::new(asserter.clone());
        let provider = EthProvider::new(
            ProviderBuilder::new().connect_client(RpcClient::new(transport, true)),
        )
        .await?;
        asserter.push_success(&Bytes::from(U256::from(2).abi_encode()));
        asserter.push_success(&Bytes::from(
            (U256::from(4_600), U256::ZERO, U256::ZERO).abi_encode(),
        ));
        asserter.push_success(&Bytes::from(
            (U256::from(3_600), U256::ZERO, U256::ZERO).abi_encode(),
        ));

        let contract_address = Address::repeat_byte(0x11);
        let e3_id = E3id::new("7", 1);
        let encoded_id = e3_id.clone().try_into()?;
        let timing = read_canonical_dkg_timing(&provider, contract_address, &e3_id).await?;

        assert_eq!(
            timing,
            CanonicalDkgTiming {
                deadline_unix_secs: 4_600,
                window_secs: 3_600,
            }
        );
        assert_contract_calls(
            &requests,
            contract_address,
            encoded_id,
            &[
                IInterfold::getE3StageCall::SELECTOR,
                IInterfold::getDeadlinesCall::SELECTOR,
                IInterfold::getE3TimeoutConfigCall::SELECTOR,
            ],
        );
        Ok(())
    }

    #[tokio::test]
    async fn does_not_start_dkg_before_committee_finalization() -> Result<()> {
        let asserter = Asserter::new();
        asserter.push_success(&"0x1");
        let (transport, requests) = RecordingTransport::new(asserter.clone());
        let provider = EthProvider::new(
            ProviderBuilder::new().connect_client(RpcClient::new(transport, true)),
        )
        .await?;
        asserter.push_success(&Bytes::from(U256::from(1).abi_encode()));

        let contract_address = Address::repeat_byte(0x11);
        let e3_id = E3id::new("7", 1);
        let encoded_id = e3_id.clone().try_into()?;
        let error = read_canonical_dkg_timing(&provider, contract_address, &e3_id)
            .await
            .unwrap_err();

        assert!(error.to_string().contains("not at CommitteeFinalized"));
        assert_contract_calls(
            &requests,
            contract_address,
            encoded_id,
            &[IInterfold::getE3StageCall::SELECTOR],
        );
        Ok(())
    }
}
