// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use alloy::node_bindings::Anvil;
use alloy::primitives::{Address, Bytes, B256, U256};
use e3_evm_helpers::contracts::{InterfoldContract, InterfoldWrite};
use evm_helpers::{is_insufficient_funds, CRISPContractFactory};
use eyre::Result;

/// Concurrent sends from one key all land, through the CRISP helpers and the Interfold helpers.
///
/// The server sends from one key in several tasks at the same time, and each send builds its own
/// provider. Interval mining keeps the transactions pending together, as a live chain does. Two
/// sends that take the same nonce fail or replace one another.
#[tokio::test]
async fn concurrent_sends_from_one_key_all_land() -> Result<()> {
    let anvil = Anvil::new().block_time(1).try_spawn()?;
    let endpoint = anvil.endpoint();
    let private_key = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
    // A call to an address without code succeeds, so the test needs no deployed contract.
    let target = Address::repeat_byte(0x42);
    let target_text = target.to_string();
    let merkle = CRISPContractFactory::create_write(&endpoint, &target_text, private_key).await?;
    let relay = CRISPContractFactory::create_write(&endpoint, &target_text, private_key).await?;
    let finalize = CRISPContractFactory::create_write(&endpoint, &target_text, private_key).await?;
    let interfold = InterfoldContract::new(&endpoint, private_key, &target_text).await?;

    let (merkle, relay, finalize, interfold) = tokio::join!(
        merkle.set_merkle_root(U256::from(1), U256::from(1)),
        relay.publish_input(U256::from(1), Bytes::from_static(&[1])),
        finalize.finalize_input(
            U256::from(1),
            target,
            B256::repeat_byte(1),
            B256::repeat_byte(2),
            0,
            Bytes::from_static(&[2]),
        ),
        interfold.register_e3_program(target),
    );
    merkle?;
    relay?;
    finalize?;
    interfold?;
    Ok(())
}

/// The relay falls back to the voter's wallet only when its key cannot pay. A send from a key
/// without funds must match, and a send that fails for another reason must not.
#[tokio::test]
async fn only_a_send_without_funds_counts_as_insufficient_funds() -> Result<()> {
    let anvil = Anvil::new().try_spawn()?;
    // Not an Anvil development account, so it holds no funds.
    let unfunded_key = "0x1111111111111111111111111111111111111111111111111111111111111111";
    let target = Address::repeat_byte(0x42).to_string();

    let unfunded =
        CRISPContractFactory::create_write(&anvil.endpoint(), &target, unfunded_key).await?;
    let error = unfunded
        .publish_input(U256::from(1), Bytes::from_static(&[1]))
        .await
        .expect_err("a key without funds cannot send");
    assert!(is_insufficient_funds(&error), "{error:?}");

    // Nothing listens on port 1, so this send fails without an answer from a node.
    let unreachable =
        CRISPContractFactory::create_write("http://127.0.0.1:1", &target, unfunded_key).await?;
    let error = unreachable
        .publish_input(U256::from(1), Bytes::from_static(&[1]))
        .await
        .expect_err("no node answers");
    assert!(!is_insufficient_funds(&error), "{error:?}");
    Ok(())
}
