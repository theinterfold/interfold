// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

mod helpers;
use alloy::{
    primitives::{Bytes, Uint},
    sol,
};
use e3_bfv_client::compute_pk_commitment;
use e3_evm_helpers::contracts::ReadOnly;
use e3_fhe_params::build_bfv_params_from_set_arc;
use e3_fhe_params::DEFAULT_BFV_PRESET;
use e3_indexer::{DataStore, InMemoryStore, InterfoldIndexer};
use eyre::Result;
use fhe::bfv::{PublicKey, SecretKey};
use fhe_traits::Serialize;
use helpers::setup_two_contracts;
use rand::rng;
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::time::sleep;
use EmitLogs::PublishMessage;
use Interfold::InputPublished;

sol!(
    #[sol(rpc)]
    Interfold,
    "tests/fixtures/fake_interfold.json"
);

sol!(
    #[sol(rpc)]
    EmitLogs,
    "tests/fixtures/emit_logs.json"
);

#[tokio::test]
async fn test_indexer() -> Result<()> {
    const E3_ID: u64 = 10;
    const _THRESHOLD: u64 = 10;
    const INDEXER_DELAY_MS: u64 = 30;

    let param_set = DEFAULT_BFV_PRESET.into();
    let params = build_bfv_params_from_set_arc(param_set);

    let (
        interfold_contract,
        interfold_address,
        emit_logs_contract,
        emit_logs_address,
        endpoint,
        _anvil,
    ) = setup_two_contracts().await?;

    let indexer = Arc::new(
        InterfoldIndexer::<InMemoryStore, ReadOnly>::from_endpoint_address_in_mem(
            &endpoint.to_string(),
            &[
                &interfold_address.to_string(),
                &emit_logs_address.to_string(),
            ],
        )
        .await?,
    );

    // Track InputPublished event count in store
    indexer
        .add_event_handler(move |_: InputPublished, ctx| async move {
            let mut store = ctx.store();
            store
                .modify("input_count", |counter: Option<u64>| {
                    Some(counter.map_or(1, |c| c + 1))
                })
                .await?;
            Ok(())
        })
        .await;

    // Collect PublishMessage events
    let captured_messages: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(vec![]));
    let captured_messages_for_handler = captured_messages.clone();

    indexer
        .add_event_handler(move |msg: PublishMessage, _ctx| {
            // Collect message
            let messages = captured_messages_for_handler.clone();
            async move {
                messages.lock().unwrap().push(msg.value);
                Ok(())
            }
        })
        .await;

    let indexer_listening = indexer.clone();
    tokio::spawn(async move { indexer_listening.listen().await });

    let mut rng = rng();
    let sk = SecretKey::random(&params, &mut rng);
    let pk = PublicKey::new(&sk, &mut rng);

    let pk_commitment = compute_pk_commitment(
        pk.to_bytes(),
        params.degree(),
        params.plaintext(),
        params.moduli().to_vec(),
    )
    .expect("Failed to compute public key commitment");
    let input_data = "Random data that wont actually be a string".to_string();
    let input_data_bytes = Bytes::from(input_data.clone().into_bytes());
    let ciphertext_output_data = vec![9, 8, 7, 6, 5, 4, 3, 2, 1];

    // first publish committee pk
    interfold_contract
        .emitCommitteePublished(
            Uint::from(E3_ID),
            Bytes::from(pk.to_bytes()),
            pk_commitment.into(),
            Bytes::default(),
        )
        .send()
        .await?
        .watch()
        .await?;

    interfold_contract
        .emitInputPublished(
            Uint::from(E3_ID),
            input_data_bytes.clone(),
            Uint::from(1111),
            Uint::from(1),
        )
        .send()
        .await?
        .watch()
        .await?;

    // Sending message from logs contract which indexer is listening to
    emit_logs_contract
        .emitPublishMessage("Hello from contract2!".into())
        .send()
        .await?
        .watch()
        .await?;

    interfold_contract
        .emitInputPublished(
            Uint::from(E3_ID),
            input_data_bytes.clone(),
            Uint::from(2222),
            Uint::from(2),
        )
        .send()
        .await?
        .watch()
        .await?;

    interfold_contract
        .emitInputPublished(
            Uint::from(E3_ID),
            input_data_bytes.clone(),
            Uint::from(3333),
            Uint::from(3),
        )
        .send()
        .await?
        .watch()
        .await?;

    sleep(Duration::from_millis(INDEXER_DELAY_MS)).await;

    {
        let messages_from_second_contract = captured_messages.lock().unwrap();
        assert_eq!(
            messages_from_second_contract
                .iter()
                .cloned()
                .collect::<Vec<_>>(),
            vec!["Hello from contract2!".to_string()]
        );
    }

    interfold_contract
        .emitCiphertextOutputPublished(
            Uint::from(E3_ID),
            Bytes::from(ciphertext_output_data.clone()),
        )
        .send()
        .await?
        .watch()
        .await?;

    sleep(Duration::from_millis(INDEXER_DELAY_MS)).await;

    let e3_state_after_output = indexer.get_e3(E3_ID).await?;

    assert_eq!(
        e3_state_after_output.ciphertext_output,
        ciphertext_output_data
    );

    let store = indexer.get_store();
    let total_inputs_processed = store.get::<u64>("input_count").await?.unwrap();
    assert_eq!(total_inputs_processed, 3);

    Ok(())
}

mod test_memory_leak {

    use e3_evm_helpers::{contracts::InterfoldContractFactory, event_listener::EventListener};

    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static DROP_COUNT: AtomicUsize = AtomicUsize::new(0);
    static CREATE_COUNT: AtomicUsize = AtomicUsize::new(0);

    #[derive(Clone)]
    struct LeakDetector(Arc<DropCounter>);

    #[derive(Debug)]
    struct DropCounter;

    impl Drop for DropCounter {
        fn drop(&mut self) {
            DROP_COUNT.fetch_add(1, Ordering::SeqCst);
        }
    }

    impl LeakDetector {
        fn new() -> Self {
            CREATE_COUNT.fetch_add(1, Ordering::SeqCst);
            Self(Arc::new(DropCounter))
        }
    }

    async fn create_indexer() -> Result<InterfoldIndexer<InMemoryStore, ReadOnly>> {
        let (_, interfold_address, _, _, endpoint, _anvil) = setup_two_contracts().await?;

        let listener =
            EventListener::create_contract_listener(&endpoint, &[&interfold_address]).await?;
        let contract = InterfoldContractFactory::create_read(&endpoint, &interfold_address).await?;

        InterfoldIndexer::<InMemoryStore, ReadOnly>::new_with_in_mem_store(listener, contract).await
    }

    sol! {
        #[derive(Debug)]
        event TestEvent();
    }

    #[tokio::test]
    async fn test_memory_leak() -> Result<()> {
        DROP_COUNT.store(0, Ordering::SeqCst);
        CREATE_COUNT.store(0, Ordering::SeqCst);

        {
            // Add an event handler that captures context
            let indexer = create_indexer().await?;
            let detector = LeakDetector::new();

            indexer
                .add_event_handler(move |event: TestEvent, _ctx| {
                    // This closure captures a ref to detector
                    let _captured = detector.clone();
                    println!("{:?}", _captured.0);
                    async move {
                        println!("Event received: {:?}", event);
                        Ok(())
                    }
                })
                .await;
        }

        // Delay to ensure everything is dropped.
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        let created = CREATE_COUNT.load(Ordering::SeqCst);
        let dropped = DROP_COUNT.load(Ordering::SeqCst);

        println!("Created: {}, Dropped: {}", created, dropped);

        // If the handler was dropped then the detector will be dropped too
        assert_eq!(
            created, dropped,
            "Memory leak detected! Created {} objects but only dropped {}",
            created, dropped
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_do_later_memory_leak() -> Result<()> {
        DROP_COUNT.store(0, Ordering::SeqCst);
        CREATE_COUNT.store(0, Ordering::SeqCst);

        {
            let indexer = create_indexer().await?;
            let detector = LeakDetector::new();

            // Schedule a callback far in the future that will never execute
            indexer
                .add_event_handler(move |_e: TestEvent, ctx| {
                    let detector = detector.clone();
                    async move {
                        ctx.do_later(u64::MAX, {
                            move |_timestamp, _ctx| {
                                let _captured = detector.clone();
                                async move {
                                    println!("This should never run");
                                    Ok(())
                                }
                            }
                        });

                        Ok(())
                    }
                })
                .await;
        }

        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        let created = CREATE_COUNT.load(Ordering::SeqCst);
        let dropped = DROP_COUNT.load(Ordering::SeqCst);

        println!("Created: {}, Dropped: {}", created, dropped);

        assert_eq!(
            created, dropped,
            "Memory leak detected in do_later! Created {} objects but only dropped {}",
            created, dropped
        );

        Ok(())
    }
}
