// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Live ingestion: what a subscription log starts, and what the periodic backfill covers.

use super::*;
use futures_util::stream;
use std::pin::pin;

/// Block numbers of the logs delivered so far, in delivery order.
async fn delivered_blocks(rx: &mut mpsc::UnboundedReceiver<InterfoldEvmEvent>) -> Vec<Option<u64>> {
    tokio::task::yield_now().await;
    let mut blocks = Vec::new();
    while let Ok(InterfoldEvmEvent::Log(log)) = rx.try_recv() {
        blocks.push(log.log.block_number);
    }
    blocks
}

#[actix::test]
async fn a_live_log_at_zero_confirmations_delivers_the_blocks_the_stream_skipped(
) -> anyhow::Result<()> {
    // The reader backfilled through block 4 and then subscribed. Block 5 was mined between the
    // two, so the stream never carried its log. The first notification is for block 7.
    let provider = CappedLogProvider::new(7, MAX_LOG_WINDOW, "unused")
        .with_log(5)
        .with_log(7);
    let (next, mut rx) = setup_collector();
    let mut ts = TimestampTracker::new();
    let mut window = LogWindow::new();
    let filter = Filter::new();
    let mut last_block = 4;

    handle_live_log(
        &provider,
        &make_test_log(7),
        &filter,
        1,
        &next,
        &mut ts,
        &mut last_block,
        0,
        &mut window,
    )
    .await?;

    assert_eq!(delivered_blocks(&mut rx).await, vec![Some(5), Some(7)]);
    assert_eq!(last_block, 7);
    assert_eq!(provider.served(), vec![(5, 7)]);
    Ok(())
}

#[actix::test]
async fn a_live_log_from_a_block_the_backfill_read_makes_no_request() -> anyhow::Result<()> {
    // The backfill that the first notification of block 7 started read the whole block, so a
    // second log from block 7 is already delivered.
    let provider = CappedLogProvider::new(7, MAX_LOG_WINDOW, "unused").with_log(7);
    let (next, mut rx) = setup_collector();
    let mut ts = TimestampTracker::new();
    let mut window = LogWindow::new();
    let filter = Filter::new();
    let mut last_block = 7;

    handle_live_log(
        &provider,
        &make_test_log(7),
        &filter,
        1,
        &next,
        &mut ts,
        &mut last_block,
        0,
        &mut window,
    )
    .await?;

    assert!(provider.served().is_empty());
    assert!(delivered_blocks(&mut rx).await.is_empty());
    assert_eq!(last_block, 7);
    Ok(())
}

#[actix::test]
async fn a_live_log_with_a_positive_depth_waits_for_the_confirmed_backfill() -> anyhow::Result<()> {
    let mock = MockLogProvider::new(200);
    let (next, mut rx) = setup_collector();
    let mut ts = TimestampTracker::new();
    let mut window = LogWindow::new();
    let filter = Filter::new();
    let mut last_block = 188;

    handle_live_log(
        &mock,
        &make_test_log(200),
        &filter,
        1,
        &next,
        &mut ts,
        &mut last_block,
        12,
        &mut window,
    )
    .await?;
    assert_eq!(last_block, 188);
    assert_eq!(mock.get_logs_call_count(), 0);
    assert!(
        delivered_blocks(&mut rx).await.is_empty(),
        "unconfirmed log must not be emitted"
    );

    mock.set_block_number(211);
    mock.push_logs(Vec::new());
    backfill_to_head(
        &mock,
        &filter,
        1,
        &next,
        &mut ts,
        &mut last_block,
        12,
        &mut window,
    )
    .await?;
    assert_eq!(last_block, 199);
    assert!(
        delivered_blocks(&mut rx).await.is_empty(),
        "eleven blocks is not enough"
    );

    mock.set_block_number(212);
    mock.push_logs(vec![make_test_log(200)]);
    backfill_to_head(
        &mock,
        &filter,
        1,
        &next,
        &mut ts,
        &mut last_block,
        12,
        &mut window,
    )
    .await?;
    assert_eq!(last_block, 200);
    assert_eq!(delivered_blocks(&mut rx).await, vec![Some(200)]);
    Ok(())
}

#[actix::test]
async fn the_periodic_backfill_delivers_what_the_stream_did_not_announce_at_zero_confirmations() {
    tokio::time::pause();

    // The provider's head is still 7 when the stream announces block 9, so the backfill that the
    // announcement starts has nothing to read. Block 8 is never announced at all. Both logs arrive
    // through the periodic backfill once the head reaches 9.
    let provider = CappedLogProvider::new(7, MAX_LOG_WINDOW, "unused")
        .with_log(8)
        .with_log(9);
    let (next, mut rx) = setup_collector();
    let mut ts = TimestampTracker::new();
    let mut window = LogWindow::new();
    let filter = Filter::new();
    let mut last_block = 7;
    let (shutdown_tx, mut shutdown) = oneshot::channel();
    let poll_interval = Duration::from_secs(5);
    let mut stream = stream::iter(vec![make_test_log(9)]).chain(stream::pending());

    let stop = {
        let mut live = pin!(consume_live_logs(
            &provider,
            &mut stream,
            &filter,
            1,
            &next,
            &mut ts,
            &mut last_block,
            0,
            &mut window,
            poll_interval,
            &mut shutdown,
        ));

        tokio::select! {
            _ = &mut live => panic!("the subscription stays open"),
            _ = tokio::time::sleep(Duration::from_secs(1)) => {}
        }
        assert!(
            delivered_blocks(&mut rx).await.is_empty(),
            "the head has not reached the announced block"
        );
        provider.set_head(9);

        tokio::select! {
            _ = &mut live => panic!("the subscription stays open"),
            _ = tokio::time::sleep(poll_interval) => {}
        }
        shutdown_tx.send(()).unwrap();
        live.await
    };
    assert!(matches!(stop, LiveStop::Shutdown));

    assert_eq!(delivered_blocks(&mut rx).await, vec![Some(8), Some(9)]);
    assert_eq!(last_block, 9);
}
