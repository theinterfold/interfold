// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! The check that each command that deletes node state runs (`node reset-data`, `nodes purge`).
//!
//! The chain cannot restore a key share or the evidence of a slash report, so these commands
//! refuse to delete key-share state for an E3 that the node has not seen complete, and slash
//! reports that the node has not submitted.

use anyhow::{bail, Context, Result};
use e3_data::{DataStore, Repositories};
use e3_events::{E3Stage, E3id, StoreKeys};
use e3_evm::{SlashingWriterRecoveryState, SlashingWriterRepositoryFactory};
use e3_request::E3LifecycleRepositoryFactory;
use std::collections::{BTreeMap, BTreeSet, HashMap};

/// The command and the node that a refusal names.
pub(crate) struct Deletion<'a> {
    /// The command's verb, as in "Refusing to reset".
    pub(crate) verb: &'static str,
    /// The node, or `None` for the node that the command runs on.
    pub(crate) node: Option<&'a str>,
}

impl Deletion<'_> {
    /// `node reset-data`, which runs on one node.
    pub(crate) const RESET: Deletion<'static> = Deletion {
        verb: "reset",
        node: None,
    };

    fn subject(&self) -> String {
        match self.node {
            Some(node) => format!("node `{node}`"),
            None => "this node".to_string(),
        }
    }

    fn possessive(&self) -> String {
        format!("{}'s", self.subject())
    }

    fn on_node(&self) -> String {
        self.node
            .map(|node| format!(" on node `{node}`"))
            .unwrap_or_default()
    }
}

fn capitalize(text: &str) -> String {
    let mut chars = text.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().chain(chars).collect(),
        None => String::new(),
    }
}

/// An E3 that this node has not seen complete, and for which it holds key-share state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ActiveE3 {
    pub(crate) e3_id: E3id,
    /// The stage in the lifecycle map, or `None` when the map has no entry for this E3.
    pub(crate) stage: Option<E3Stage>,
}

/// Key prefixes of the records that hold one E3's key-share state. The E3 ID follows each prefix.
const KEY_SHARE_PREFIXES: [&str; 4] = [
    StoreKeys::THRESHOLD_KEYSHARE_PREFIX,
    StoreKeys::THRESHOLD_KEYSHARE_RECOVERY_PREFIX,
    StoreKeys::THRESHOLD_KEYSHARE_RECOVERY_PAYLOADS_PREFIX,
    StoreKeys::THRESHOLD_KEYSHARE_BFV_KEY_PREFIX,
];

/// Find each E3 that has key-share state on this node and that this node has not seen complete.
///
/// The E3s come from the key-share records themselves, found by key prefix, and not from the
/// lifecycle stage map (`//e3_lifecycle`). A record whose E3 is missing from the map therefore
/// still counts, with no stage. Only a `Complete` entry shows that the E3 is over.
///
/// Both reads fail on a storage error. The ordinary read path reports a storage error and returns
/// `None`, and a failed read must never look like an absent key share. The records are not
/// decoded, because a store that an older release wrote can hold an older layout.
pub(crate) async fn active_e3s_with_key_shares(
    repositories: &Repositories,
) -> Result<Vec<ActiveE3>> {
    let stages: HashMap<E3id, E3Stage> = DataStore::from(repositories.e3_lifecycle())
        .read_checked()
        .await
        .context("failed to read the E3 lifecycle stage map")?
        .unwrap_or_default();
    let mut e3_ids = BTreeMap::new();
    for prefix in KEY_SHARE_PREFIXES {
        let keys = repositories
            .store
            .keys_with_prefix(prefix)
            .await
            .with_context(|| format!("failed to list the key-share records under {prefix}"))?;
        for key in keys {
            let e3_id = e3_id_after_prefix(&key, prefix)?;
            e3_ids.insert(e3_id.to_string(), e3_id);
        }
    }
    Ok(e3_ids
        .into_values()
        .filter_map(|e3_id| {
            let stage = stages.get(&e3_id).cloned();
            // The node records `Failed` also for its own local failures, such as a DKG timeout,
            // while the E3 can continue on chain. So only `Complete` ends the protection.
            (stage != Some(E3Stage::Complete)).then_some(ActiveE3 { e3_id, stage })
        })
        .collect())
}

/// The E3 ID in a key-share record key: the first path segment after `prefix`, written as
/// `<chain_id>:<id>`. A key that does not parse fails the check instead of being skipped.
fn e3_id_after_prefix(key: &[u8], prefix: &str) -> Result<E3id> {
    let unreadable = || {
        anyhow::anyhow!(
            "found a key-share record whose E3 this binary cannot read: {}",
            String::from_utf8_lossy(key)
        )
    };
    let rest = std::str::from_utf8(key)
        .ok()
        .and_then(|key| key.strip_prefix(prefix))
        .ok_or_else(unreadable)?;
    let segment = rest.split('/').next().unwrap_or_default();
    let (chain_id, id) = segment.split_once(':').ok_or_else(unreadable)?;
    let chain_id = chain_id.parse::<u64>().map_err(|_| unreadable())?;
    if id.is_empty() {
        return Err(unreadable());
    }
    Ok(E3id::new(id, chain_id))
}

/// Slash reports on one chain that this node has not submitted or seen settled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PendingSlashReports {
    pub(crate) chain_id: u64,
    pub(crate) count: usize,
}

/// Find each chain on which this node holds slash reports that it has not submitted or seen
/// settled. The completion of an E3 does not settle its slash reports, so a complete E3 can still
/// have one. A record that does not decode fails the check, as a failed read does.
pub(crate) async fn pending_slash_reports(
    repositories: &Repositories,
) -> Result<Vec<PendingSlashReports>> {
    let keys = repositories
        .store
        .keys_with_prefix(StoreKeys::SLASHING_WRITER_PREFIX)
        .await
        .context("failed to list the slash writer records")?;
    let mut chain_ids = BTreeSet::new();
    for key in &keys {
        let chain_id = chain_after_slashing_prefix(key)?;
        // The slash writer stores one record per chain, at this exact key. A record under any other
        // key would not be read below, so it fails the check instead of passing it unread.
        if key.as_slice() != StoreKeys::slashing_writer_recovery(chain_id).as_bytes() {
            bail!(
                "found a slash writer record that this binary cannot read: {}",
                String::from_utf8_lossy(key)
            );
        }
        chain_ids.insert(chain_id);
    }
    let mut pending = Vec::new();
    for chain_id in chain_ids {
        let state: Option<SlashingWriterRecoveryState> =
            DataStore::from(repositories.slashing_writer_recovery(chain_id))
                .read_checked()
                .await
                .with_context(|| format!("failed to read the slash reports of chain {chain_id}"))?;
        let count = state.map_or(0, |state| state.pending_count());
        if count > 0 {
            pending.push(PendingSlashReports { chain_id, count });
        }
    }
    Ok(pending)
}

/// The chain ID in a slash writer record key: the first path segment after the prefix.
fn chain_after_slashing_prefix(key: &[u8]) -> Result<u64> {
    std::str::from_utf8(key)
        .ok()
        .and_then(|key| key.strip_prefix(StoreKeys::SLASHING_WRITER_PREFIX))
        .and_then(|rest| rest.split('/').next())
        .and_then(|chain_id| chain_id.parse().ok())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "found a slash writer record whose chain this binary cannot read: {}",
                String::from_utf8_lossy(key)
            )
        })
}

/// Refuse the deletion when it would delete a key share that an active E3 needs.
///
/// `allow_active_e3s` overrides the refusal, and also a failed check, so that an operator can
/// still clear a store that this binary cannot read. An override returns the warning to print.
pub(crate) fn check_active_e3s(
    active_e3s: Result<Vec<ActiveE3>>,
    allow_active_e3s: bool,
    deletion: &Deletion,
) -> Result<Option<String>> {
    let active = match active_e3s {
        Ok(active) => active,
        Err(error) if allow_active_e3s => {
            return Ok(Some(format!(
                "Could not check for active E3s{}. Continuing because --allow-active-e3s is set: \
                 {error:#}",
                deletion.on_node()
            )));
        }
        // The CLI prints only the top-level message, so the cause goes into the message itself.
        Err(error) => bail!(
            "Refusing to {}, because the command cannot show that no active E3 needs a key share \
             from {}: {error:#}. The command deleted nothing, and it cannot list the E3s of {}. Do \
             not add --allow-active-e3s: it deletes every key share of {}. Start the node again \
             with the release that it ran before, and find the cause of the error.",
            deletion.verb,
            deletion.subject(),
            deletion.subject(),
            deletion.subject()
        ),
    };
    if active.is_empty() {
        return Ok(None);
    }

    let list = active
        .iter()
        .map(|e3| match &e3.stage {
            Some(stage) => format!("  - E3 {} at stage {stage:?}", e3.e3_id),
            None => format!("  - E3 {}, which the lifecycle map does not list", e3.e3_id),
        })
        .collect::<Vec<_>>()
        .join("\n");
    if allow_active_e3s {
        return Ok(Some(format!(
            "--allow-active-e3s is set. The {} deletes {} key share for these E3s, which {} has \
             not seen complete:\n{list}",
            deletion.verb,
            deletion.possessive(),
            deletion.subject()
        )));
    }
    bail!(
        "Refusing to {}. {} holds key-share state for these E3s, which {} has not seen \
         complete:\n{list}\nThe command deleted nothing. A {} permanently deletes {} key share for \
         each listed E3, and the chain cannot restore it. A `Failed` stage can be a local failure \
         while the E3 continues on chain. Until one day after its lifecycle deadline \
         (`getE3LifecycleDeadline`), the node can still submit slash reports for an E3. Keep this \
         state until each listed E3 is complete or failed on chain, and that day has passed. Then \
         run this command again with --allow-active-e3s.",
        deletion.verb,
        capitalize(&deletion.subject()),
        deletion.subject(),
        deletion.verb,
        deletion.possessive()
    )
}

/// Refuse the deletion when it would delete slash reports that this node has not submitted.
///
/// `allow_active_e3s` overrides the refusal, and also a failed check, as for active E3s. An
/// override returns the warning to print.
pub(crate) fn check_pending_slash_reports(
    pending: Result<Vec<PendingSlashReports>>,
    allow_active_e3s: bool,
    deletion: &Deletion,
) -> Result<Option<String>> {
    let pending = match pending {
        Ok(pending) => pending,
        Err(error) if allow_active_e3s => {
            return Ok(Some(format!(
                "Could not check for unsubmitted slash reports{}. Continuing because \
                 --allow-active-e3s is set: {error:#}",
                deletion.on_node()
            )));
        }
        Err(error) => bail!(
            "Refusing to {}, because the command cannot show that {} holds no unsubmitted slash \
             report: {error:#}. The command deleted nothing. Start the node again with the \
             release that it ran before, and find the cause of the error.",
            deletion.verb,
            deletion.subject()
        ),
    };
    if pending.is_empty() {
        return Ok(None);
    }
    let list = pending
        .iter()
        .map(|chain| format!("  - chain {}: {} report(s)", chain.chain_id, chain.count))
        .collect::<Vec<_>>()
        .join("\n");
    if allow_active_e3s {
        return Ok(Some(format!(
            "--allow-active-e3s is set. The {} deletes {} unsubmitted slash reports:\n{list}",
            deletion.verb,
            deletion.possessive()
        )));
    }
    bail!(
        "Refusing to {}. {} holds slash reports that it has not submitted:\n{list}\nThe command \
         deleted nothing. A {} deletes them, also for an E3 that is complete, and the chain cannot \
         restore their evidence. Start the node again with the release that it ran before, so \
         that it submits them, and run this command again when it holds none. To delete them \
         anyway, run this command again with --allow-active-e3s.",
        deletion.verb,
        capitalize(&deletion.subject()),
        deletion.verb
    )
}

/// Run both checks before refusing, so that one refusal lists every reason. An operator who
/// overrides a refusal for key shares must also see the slash reports that the override deletes.
pub(crate) fn check_deletion(
    active_e3s: Result<Vec<ActiveE3>>,
    slash_reports: Result<Vec<PendingSlashReports>>,
    allow_active_e3s: bool,
    deletion: &Deletion,
) -> Result<Option<String>> {
    merge_checks(
        check_active_e3s(active_e3s, allow_active_e3s, deletion),
        check_pending_slash_reports(slash_reports, allow_active_e3s, deletion),
    )
}

/// Combine two check results: one refusal with both reasons, or one warning with both.
pub(crate) fn merge_checks(
    first: Result<Option<String>>,
    second: Result<Option<String>>,
) -> Result<Option<String>> {
    match (first, second) {
        // The CLI prints only the top-level message, so both refusals go into one message.
        (Err(first), Err(second)) => bail!("{first}\n\n{second}"),
        (Err(refusal), Ok(_)) | (Ok(_), Err(refusal)) => Err(refusal),
        (Ok(Some(first)), Ok(Some(second))) => Ok(Some(format!("{first}\n{second}"))),
        (Ok(first), Ok(second)) => Ok(first.or(second)),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        active_e3s_with_key_shares, check_active_e3s, check_deletion, e3_id_after_prefix,
        pending_slash_reports, ActiveE3, Deletion, PendingSlashReports,
    };
    use e3_data::{DataStore, Repositories};
    use e3_events::{E3Stage, E3id, StoreKeys};
    use e3_keyshare::ThresholdKeyshareRepositoryFactory;
    use e3_request::E3LifecycleRepositoryFactory;
    use std::collections::HashMap;

    /// A slash report for `e3_id` that the slash writer has recorded and not yet submitted.
    pub(crate) fn unsubmitted_slash_report(e3_id: &E3id) -> e3_events::AccusationQuorumReached {
        e3_events::AccusationQuorumReached {
            e3_id: e3_id.clone(),
            accuser: alloy::primitives::Address::repeat_byte(1),
            accused: alloy::primitives::Address::repeat_byte(2),
            proof_type: e3_events::ProofType::C1PkGeneration,
            votes_for: Vec::new(),
            outcome: e3_events::AccusationOutcome::AccusedFaulted,
            evidence: alloy::primitives::Bytes::new(),
        }
    }

    /// A slash report that the node has not submitted counts on its chain, also for an E3 that is
    /// complete. A chain whose slash writer holds no report does not count.
    #[actix::test]
    async fn finds_unsubmitted_slash_reports() -> anyhow::Result<()> {
        use e3_evm::{SlashingWriterRecoveryState, SlashingWriterRepositoryFactory};
        let repositories = Repositories::in_mem();
        let complete = E3id::new("4", 1);
        repositories
            .e3_lifecycle()
            .write_sync(&HashMap::from([(complete.clone(), E3Stage::Complete)]))
            .await?;
        let mut pending = SlashingWriterRecoveryState::default();
        pending.record(unsubmitted_slash_report(&complete))?;
        repositories
            .slashing_writer_recovery(1)
            .write_sync(&pending)
            .await?;
        repositories
            .slashing_writer_recovery(2)
            .write_sync(&SlashingWriterRecoveryState::default())
            .await?;

        assert_eq!(
            pending_slash_reports(&repositories).await?,
            vec![PendingSlashReports {
                chain_id: 1,
                count: 1
            }]
        );
        Ok(())
    }

    /// Every E3 that is not `Complete` and has a key-share record blocks the reset, including a
    /// `Failed` one, because the node also records its own local failures as `Failed`. The
    /// records here do not decode as the current layout, as in a store that an older release
    /// wrote, so the check must find them by presence alone.
    #[actix::test]
    async fn finds_key_shares_of_e3s_that_are_not_complete() -> anyhow::Result<()> {
        let repositories = Repositories::in_mem();
        let key_published = E3id::new("1", 1);
        let ciphertext_ready = E3id::new("2", 1);
        let requested_without_share = E3id::new("3", 1);
        let complete = E3id::new("4", 1);
        let failed = E3id::new("5", 1);
        repositories
            .e3_lifecycle()
            .write_sync(&HashMap::from([
                (key_published.clone(), E3Stage::KeyPublished),
                (ciphertext_ready.clone(), E3Stage::CiphertextReady),
                (requested_without_share.clone(), E3Stage::Requested),
                (complete.clone(), E3Stage::Complete),
                (failed.clone(), E3Stage::Failed),
            ]))
            .await?;
        for e3_id in [&key_published, &ciphertext_ready, &complete, &failed] {
            DataStore::from(repositories.threshold_keyshare(e3_id))
                .write_sync(vec![0xde_u8, 0xad, 0xbe, 0xef])
                .await?;
        }
        assert!(
            repositories
                .threshold_keyshare(&key_published)
                .read()
                .await
                .is_err(),
            "the fixture must not decode as the current key-share layout"
        );

        let active = active_e3s_with_key_shares(&repositories).await?;

        assert_eq!(
            active,
            vec![
                ActiveE3 {
                    e3_id: key_published,
                    stage: Some(E3Stage::KeyPublished),
                },
                ActiveE3 {
                    e3_id: ciphertext_ready,
                    stage: Some(E3Stage::CiphertextReady),
                },
                ActiveE3 {
                    e3_id: failed,
                    stage: Some(E3Stage::Failed),
                },
            ]
        );
        Ok(())
    }

    /// Key-share state counts even when the lifecycle map has no entry for its E3, or when only
    /// the recovery records remain. The map is not the source of truth for what a reset deletes.
    #[actix::test]
    async fn finds_key_share_state_that_the_lifecycle_map_does_not_list() -> anyhow::Result<()> {
        let repositories = Repositories::in_mem();
        let listed_complete = E3id::new("1", 1);
        let unlisted = E3id::new("2", 1);
        let recovery_only = E3id::new("3", 31337);
        repositories
            .e3_lifecycle()
            .write_sync(&HashMap::from([(
                listed_complete.clone(),
                E3Stage::Complete,
            )]))
            .await?;
        for e3_id in [&listed_complete, &unlisted] {
            DataStore::from(repositories.threshold_keyshare(e3_id))
                .write_sync(vec![1_u8, 2, 3])
                .await?;
        }
        DataStore::from(repositories.threshold_keyshare_recovery(&recovery_only))
            .write_sync(vec![4_u8, 5, 6])
            .await?;

        let active = active_e3s_with_key_shares(&repositories).await?;

        assert_eq!(
            active,
            vec![
                ActiveE3 {
                    e3_id: unlisted,
                    stage: None,
                },
                ActiveE3 {
                    e3_id: recovery_only,
                    stage: None,
                },
            ]
        );
        let error = check_active_e3s(Ok(active), false, &Deletion::RESET)
            .expect_err("unlisted state must block");
        assert!(
            error
                .to_string()
                .contains("which the lifecycle map does not list"),
            "the refusal must say why the E3 is listed, got: {error}"
        );
        Ok(())
    }

    /// A missing lifecycle map does not make the store look empty of key shares.
    #[actix::test]
    async fn a_missing_lifecycle_map_does_not_hide_key_shares() -> anyhow::Result<()> {
        let repositories = Repositories::in_mem();
        let e3_id = E3id::new("7", 1);
        DataStore::from(repositories.threshold_keyshare(&e3_id))
            .write_sync(vec![1_u8])
            .await?;

        let active = active_e3s_with_key_shares(&repositories).await?;

        assert_eq!(active, vec![ActiveE3 { e3_id, stage: None }]);
        Ok(())
    }

    /// A key-share key that does not name an E3 fails the check. Skipping it could hide a share.
    #[test]
    fn a_key_share_key_without_an_e3_id_fails() {
        let prefix = StoreKeys::THRESHOLD_KEYSHARE_PREFIX;
        for key in [
            prefix.to_string(),
            format!("{prefix}not-an-e3"),
            format!("{prefix}x:1"),
            format!("{prefix}1:"),
        ] {
            assert!(
                e3_id_after_prefix(key.as_bytes(), prefix).is_err(),
                "{key:?} must not parse as an E3 ID"
            );
        }
        assert_eq!(
            e3_id_after_prefix(format!("{prefix}1:42/sub").as_bytes(), prefix).unwrap(),
            E3id::new("42", 1)
        );
    }

    /// A stage map that this binary cannot read blocks the reset, because the reset cannot show
    /// that no active E3 needs a key share. The override still lets an operator clear the store.
    #[actix::test]
    async fn an_unreadable_stage_map_blocks_the_reset_unless_overridden() -> anyhow::Result<()> {
        let repositories = Repositories::in_mem();
        DataStore::from(repositories.e3_lifecycle())
            .write_sync(vec![0xff_u8; 3])
            .await?;

        let error = check_active_e3s(
            active_e3s_with_key_shares(&repositories).await,
            false,
            &Deletion::RESET,
        )
        .expect_err("an unreadable stage map must block the reset");
        // The CLI prints only the top-level message, so it must carry the cause and the override.
        let message = error.to_string();
        assert!(
            message.contains("failed to read the E3 lifecycle stage map"),
            "the refusal must name the cause, got: {message}"
        );
        assert!(
            message.contains("--allow-active-e3s"),
            "the refusal must name the override, got: {message}"
        );

        let warning = check_active_e3s(
            active_e3s_with_key_shares(&repositories).await,
            true,
            &Deletion::RESET,
        )?;
        assert!(
            warning.is_some_and(|warning| warning.contains("--allow-active-e3s is set")),
            "the override must produce a warning"
        );
        Ok(())
    }

    /// The slash writer stores one record per chain at one exact key. A record under any other key
    /// under its prefix fails the check, also beside an empty record at the exact key, because the
    /// check would otherwise pass it unread.
    #[actix::test]
    async fn slash_records_under_unknown_keys_fail_the_check() -> anyhow::Result<()> {
        use e3_evm::{SlashingWriterRecoveryState, SlashingWriterRepositoryFactory};
        for unknown in [
            "//evm_writers/slashing/1/recovery/v2",
            "//evm_writers/slashing/01/recovery/v1",
        ] {
            let repositories = Repositories::in_mem();
            repositories
                .slashing_writer_recovery(1)
                .write_sync(&SlashingWriterRecoveryState::default())
                .await?;
            repositories
                .store
                .scope(unknown)
                .write_sync(vec![1_u8, 2, 3])
                .await?;

            let error = pending_slash_reports(&repositories)
                .await
                .expect_err("an unknown slash writer record must fail the check");
            assert!(
                error.to_string().contains("cannot read"),
                "the error must name the unreadable record {unknown}, got: {error}"
            );
        }
        Ok(())
    }

    /// One refusal lists the key shares and the slash reports. An operator who overrides a refusal
    /// for key shares therefore sees the slash reports that the override also deletes.
    #[test]
    fn one_refusal_lists_key_shares_and_slash_reports() -> anyhow::Result<()> {
        let active = || -> anyhow::Result<Vec<ActiveE3>> {
            Ok(vec![ActiveE3 {
                e3_id: E3id::new("3", 1),
                stage: Some(E3Stage::Failed),
            }])
        };
        let reports = || -> anyhow::Result<Vec<PendingSlashReports>> {
            Ok(vec![PendingSlashReports {
                chain_id: 1,
                count: 2,
            }])
        };

        let error = check_deletion(active(), reports(), false, &Deletion::RESET)
            .expect_err("key shares and slash reports must block the deletion");
        let message = error.to_string();
        assert!(
            message.contains("E3 1:3 at stage Failed"),
            "the refusal must list the E3, got: {message}"
        );
        assert!(
            message.contains("chain 1: 2 report(s)"),
            "the refusal must list the slash reports, got: {message}"
        );

        let warning = check_deletion(active(), reports(), true, &Deletion::RESET)?
            .expect("the override must produce a warning");
        assert!(
            warning.contains("E3 1:3 at stage Failed") && warning.contains("chain 1: 2 report(s)"),
            "the override warning must list both, got: {warning}"
        );
        Ok(())
    }
}
