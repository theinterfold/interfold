// SPDX-License-Identifier: LGPL-3.0-only

use super::*;
use crate::contracts::ISynchronizedDkgPublication;
use e3_request::canonical_key::CanonicalDkgAnchors;

#[derive(Debug)]
struct ConflictingAuthority;
impl std::fmt::Display for ConflictingAuthority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "on-chain synchronized authority differs from local publication"
        )
    }
}
impl std::error::Error for ConflictingAuthority {}

pub(super) fn is_terminal(error: &anyhow::Error) -> bool {
    error.is::<ConflictingAuthority>()
        || contains_error_selector(
            &format!("{error:?}"),
            ISynchronizedDkgPublication::InvalidSynchronizedDkgPublication::SELECTOR,
        )
}

pub(super) fn authority(
    candidate: &CanonicalPublicKey,
) -> Result<(Address, ISynchronizedDkgPublication::Authority)> {
    let CanonicalDkgAnchors::Synchronized(anchors) = &candidate.dkg_anchors else {
        anyhow::bail!("synchronized publication requires distinct setup authority");
    };
    Ok((
        anchors.context.registry,
        ISynchronizedDkgPublication::Authority {
            version: anchors.version,
            verifier: anchors.context.verifying_contract,
            cryptoConfigId: anchors.context.crypto_config_id.into(),
            setupBinding: anchors.setup_binding.into(),
            dealerBatch: anchors.dealer_batch.into(),
            pkCommitment: candidate.pk_commitment.into(),
            partyIds: anchors.party_ids.iter().copied().map(U256::from).collect(),
            thresholdPkCommits: anchors
                .threshold_pk_commits
                .iter()
                .copied()
                .map(B256::from)
                .collect(),
            skAggCommits: anchors
                .sk_agg_commits
                .iter()
                .copied()
                .map(B256::from)
                .collect(),
            keyBundleCommits: anchors
                .key_bundle_commits
                .iter()
                .copied()
                .map(B256::from)
                .collect(),
        },
    ))
}

async fn settled<P: Provider + WalletProvider + Clone + 'static>(
    provider: EthProvider<P>,
    registry: Address,
    id: U256,
    expected: ISynchronizedDkgPublication::Authority,
) -> Result<bool> {
    let contract = ISynchronizedDkgPublication::new(registry, provider.provider());
    let actual = contract.getSynchronizedDkgAuthority(id).call().await?;
    if actual.version == 0 {
        return Ok(false);
    }
    if actual != expected {
        return Err(ConflictingAuthority.into());
    }
    Ok(true)
}

/// Explicit below-admission qualification boundary. Uses confirmed selection/context and actual
/// registry/receipt checks; it does not enable runtime profile admission or install key authority.
pub async fn publish_synchronized_committee_definition<
    P: Provider + WalletProvider + Clone + 'static,
>(
    provider: EthProvider<P>,
    keys: &CanonicalPublicKeys,
    intent: &SynchronizedDkgPublicationReady,
) -> Result<Vec<TransactionReceipt>> {
    anyhow::ensure!(
        provider.chain_id() == intent.e3_id.chain_id(),
        "publication belongs to another chain"
    );
    let selection = keys
        .synchronized_selection(&intent.e3_id)
        .context("missing confirmed selection")?;
    let context = keys
        .synchronized_context(&intent.e3_id)
        .context("missing frozen context")?;
    let candidate = selection.validate_publication(context, intent)?;
    if let Some(confirmed) = keys.get(&intent.e3_id) {
        anyhow::ensure!(
            confirmed == candidate,
            "publication differs from confirmed authority"
        );
    }
    publish_validated(provider, intent, &candidate).await
}

pub(super) async fn publish_validated<P: Provider + WalletProvider + Clone + 'static>(
    provider: EthProvider<P>,
    intent: &SynchronizedDkgPublicationReady,
    candidate: &CanonicalPublicKey,
) -> Result<Vec<TransactionReceipt>> {
    let (registry, expected) = authority(candidate)?;
    let id: U256 = intent.e3_id.clone().try_into()?;
    let mut receipts = Vec::new();
    if !settled(provider.clone(), registry, id, expected.clone()).await? {
        let publication = ISynchronizedDkgPublication::Publication {
            pkCommitment: expected.pkCommitment,
            dealerBatch: expected.dealerBatch,
            partyIds: expected.partyIds.clone(),
            proof: encode_zk_proof(&intent.proof)?,
            signatures: intent
                .consents
                .iter()
                .map(|consent| Bytes::copy_from_slice(&consent.signature))
                .collect(),
        };
        let outcome = send_tx_idempotent(
            "publishSynchronizedCommittee",
            &["CommitteeNotFinalized"],
            || settled(provider.clone(), registry, id, expected.clone()),
            || {
                let provider = provider.clone();
                let publication = publication.clone();
                async move {
                    let contract = ISynchronizedDkgPublication::new(registry, provider.provider());
                    let pending = send_with_next_nonce(
                        &provider,
                        contract.publishSynchronizedCommittee(id, publication),
                    )
                    .await?;
                    let receipt = pending.get_receipt().await?;
                    require_successful_receipt("publish synchronized committee", &receipt)?;
                    Ok(receipt)
                }
            },
        )
        .await?;
        if let Some(receipt) = outcome.receipt() {
            receipts.push(receipt.clone());
        }
    }
    // A preflight/receipt is transaction settlement, not confirmed canonical-key admission.
    // Compare all anchors again before completing a partially published key after restart.
    anyhow::ensure!(
        settled(provider.clone(), registry, id, expected).await?,
        "synchronized authority unavailable after publication"
    );
    receipts.push(
        super::super::effects::publish_committee_public_key_to_registry(
            provider,
            registry,
            intent.e3_id.clone(),
            intent.expected.public_key.clone(),
        )
        .await?,
    );
    Ok(receipts)
}
