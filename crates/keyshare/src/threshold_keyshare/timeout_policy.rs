// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

const ENCRYPTION_KEY_CUTOFF_BPS: u64 = 1000;
const THRESHOLD_SHARE_CUTOFF_BPS: u64 = 6000;
const DECRYPTION_KEY_SHARED_CUTOFF_BPS: u64 = 10000;

/// Share of the DKG window one roster epoch may use to collect every C4 share before the
/// next epoch is proposed. The C4 phase spans 40% of the window (from the 60% share cutoff
/// to the deadline), so 10% allows up to four epochs. Measure C4 wall time on the
/// production preset before lowering this.
const ROSTER_EPOCH_BPS: u64 = 1000;
pub(crate) const ROSTER_EPOCH_ENV: &str = "E3_DKG_ROSTER_EPOCH_SECS";
/// Budget for an epoch leader to publish its proposal, as basis points of the frozen DKG
/// window (1% = 186s on the 18600s floor). A leader that stays silent for this long is
/// skipped and the next party id leads. Gossip latency is seconds, so 1% is generous;
/// members that are not yet ready re-arm the same budget on every epoch they wait for.
const ROSTER_PROPOSAL_BPS: u64 = 100;
pub(crate) const ROSTER_PROPOSAL_ENV: &str = "E3_DKG_ROSTER_PROPOSAL_SECS";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
// Variant names mirror the DKG collection phases they gate; the shared `Collection`
// suffix is intentional domain vocabulary, not redundant naming.
#[allow(clippy::enum_variant_names)]
pub(crate) enum DkgTimeoutPhase {
    EncryptionKeyCollection,
    ThresholdShareCollection,
    DecryptionKeySharedCollection,
}

impl DkgTimeoutPhase {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::EncryptionKeyCollection => "encryption-key collection",
            Self::ThresholdShareCollection => "threshold-share collection",
            Self::DecryptionKeySharedCollection => "decryption-key-shared collection",
        }
    }

    pub(crate) fn override_env(self) -> &'static str {
        match self {
            Self::EncryptionKeyCollection => "E3_ENCRYPTION_KEY_COLLECTION_TIMEOUT_SECS",
            Self::ThresholdShareCollection => "E3_THRESHOLD_SHARE_COLLECTION_TIMEOUT_SECS",
            Self::DecryptionKeySharedCollection => {
                "E3_DECRYPTION_KEY_SHARED_COLLECTION_TIMEOUT_SECS"
            }
        }
    }

    fn cutoff_bps(self) -> u64 {
        match self {
            Self::EncryptionKeyCollection => ENCRYPTION_KEY_CUTOFF_BPS,
            Self::ThresholdShareCollection => THRESHOLD_SHARE_CUTOFF_BPS,
            Self::DecryptionKeySharedCollection => DECRYPTION_KEY_SHARED_CUTOFF_BPS,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DerivedTimeout {
    pub duration: Duration,
    pub description: String,
}

pub(crate) fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Budget for one roster epoch: the smaller of `ROSTER_EPOCH_BPS` of the window and the
/// time left until the canonical deadline. The epoch env value and the existing
/// decryption-key-shared collection override can only shorten it.
pub(crate) fn resolve_roster_epoch_timeout(
    dkg_deadline_unix_secs: Option<u64>,
    dkg_window_secs: Option<u64>,
) -> anyhow::Result<Duration> {
    let deadline = dkg_deadline_unix_secs
        .ok_or_else(|| anyhow::anyhow!("canonical DKG deadline is unavailable"))?;
    let window =
        dkg_window_secs.ok_or_else(|| anyhow::anyhow!("frozen DKG window is unavailable"))?;
    let remaining = deadline.saturating_sub(now_unix_secs());
    let epoch = phase_cutoff_secs(window, ROSTER_EPOCH_BPS).min(remaining);
    let epoch = [
        parse_env_secs(ROSTER_EPOCH_ENV),
        parse_env_secs(DkgTimeoutPhase::DecryptionKeySharedCollection.override_env()),
    ]
    .into_iter()
    .flatten()
    .fold(epoch, u64::min);
    Ok(Duration::from_secs(epoch))
}

/// Budget for one roster proposal: `ROSTER_PROPOSAL_BPS` of the window, capped by the time
/// left until the deadline. The env value can only shorten it.
pub(crate) fn resolve_roster_proposal_timeout(
    dkg_deadline_unix_secs: Option<u64>,
    dkg_window_secs: Option<u64>,
) -> anyhow::Result<Duration> {
    let deadline = dkg_deadline_unix_secs
        .ok_or_else(|| anyhow::anyhow!("canonical DKG deadline is unavailable"))?;
    let window =
        dkg_window_secs.ok_or_else(|| anyhow::anyhow!("frozen DKG window is unavailable"))?;
    let remaining = deadline.saturating_sub(now_unix_secs());
    let budget = phase_cutoff_secs(window, ROSTER_PROPOSAL_BPS).min(remaining);
    let budget = parse_env_secs(ROSTER_PROPOSAL_ENV)
        .map(|secs| secs.min(budget))
        .unwrap_or(budget);
    Ok(Duration::from_secs(budget))
}

pub(crate) fn resolve_timeout(
    phase: DkgTimeoutPhase,
    dkg_deadline_unix_secs: Option<u64>,
    dkg_window_secs: Option<u64>,
) -> anyhow::Result<DerivedTimeout> {
    let collector_override = parse_env_secs(phase.override_env());
    let deadline = dkg_deadline_unix_secs
        .ok_or_else(|| anyhow::anyhow!("canonical DKG deadline is unavailable"))?;
    let window =
        dkg_window_secs.ok_or_else(|| anyhow::anyhow!("frozen DKG window is unavailable"))?;

    resolve_timeout_from_inputs(phase, collector_override, deadline, window, now_unix_secs())
}

pub(crate) fn resolve_timeout_from_inputs(
    phase: DkgTimeoutPhase,
    collector_override_secs: Option<u64>,
    dkg_deadline_unix_secs: u64,
    dkg_window_secs: u64,
    now_unix_secs: u64,
) -> anyhow::Result<DerivedTimeout> {
    anyhow::ensure!(
        dkg_deadline_unix_secs > 0 && dkg_window_secs > 0,
        "canonical DKG timing is invalid"
    );
    let start = dkg_deadline_unix_secs.saturating_sub(dkg_window_secs);
    let cutoff = start
        .saturating_add(phase_cutoff_secs(dkg_window_secs, phase.cutoff_bps()))
        .min(dkg_deadline_unix_secs);
    let remaining_secs = cutoff.saturating_sub(now_unix_secs);
    let duration_secs = collector_override_secs
        .map(|override_secs| override_secs.min(remaining_secs))
        .unwrap_or(remaining_secs);

    Ok(DerivedTimeout {
        duration: Duration::from_secs(duration_secs),
        description: format!(
            "{} cutoff {} ({}% of frozen {}s DKG window, canonical deadline {}); optional {} can only shorten it",
            phase.label(),
            cutoff,
            phase.cutoff_bps() / 100,
            dkg_window_secs,
            dkg_deadline_unix_secs,
            phase.override_env(),
        ),
    })
}

fn parse_env_secs(name: &str) -> Option<u64> {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|secs| *secs > 0)
}

fn phase_cutoff_secs(dkg_window_secs: u64, cutoff_bps: u64) -> u64 {
    let scaled = dkg_window_secs.saturating_mul(cutoff_bps);
    let secs = scaled / 10_000;
    secs.max(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encryption_timeout_uses_remaining_dkg_budget() {
        let timeout = resolve_timeout_from_inputs(
            DkgTimeoutPhase::EncryptionKeyCollection,
            None,
            8_200,
            7200,
            1_600,
        )
        .unwrap();

        assert_eq!(timeout.duration, Duration::from_secs(120));
        assert!(timeout.description.contains("canonical deadline"));
    }

    #[test]
    fn threshold_share_timeout_uses_cumulative_cutoff() {
        let timeout = resolve_timeout_from_inputs(
            DkgTimeoutPhase::ThresholdShareCollection,
            None,
            8_200,
            7200,
            2_000,
        )
        .unwrap();

        assert_eq!(timeout.duration, Duration::from_secs(3320));
    }

    #[test]
    fn collector_override_can_only_shorten_canonical_budget() {
        let timeout = resolve_timeout_from_inputs(
            DkgTimeoutPhase::DecryptionKeySharedCollection,
            Some(45),
            8_200,
            7200,
            8_000,
        )
        .unwrap();

        assert_eq!(timeout.duration, Duration::from_secs(45));
        assert!(timeout
            .description
            .contains(DkgTimeoutPhase::DecryptionKeySharedCollection.override_env()));

        let past = resolve_timeout_from_inputs(
            DkgTimeoutPhase::DecryptionKeySharedCollection,
            Some(45),
            8_200,
            7200,
            8_300,
        )
        .unwrap();
        assert_eq!(past.duration, Duration::ZERO);
    }

    #[test]
    fn each_e3_keeps_its_frozen_deadline_across_restart() {
        let short = resolve_timeout_from_inputs(
            DkgTimeoutPhase::ThresholdShareCollection,
            None,
            4_600,
            3_600,
            2_000,
        )
        .unwrap();
        let long = resolve_timeout_from_inputs(
            DkgTimeoutPhase::ThresholdShareCollection,
            None,
            8_200,
            7_200,
            2_000,
        )
        .unwrap();
        let restarted_short = resolve_timeout_from_inputs(
            DkgTimeoutPhase::ThresholdShareCollection,
            None,
            4_600,
            3_600,
            2_600,
        )
        .unwrap();

        assert_eq!(short.duration, Duration::from_secs(1_160));
        assert_eq!(long.duration, Duration::from_secs(3_320));
        assert_eq!(restarted_short.duration, Duration::from_secs(560));
    }
}
