// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

const ENCRYPTION_KEY_CUTOFF_BPS: u64 = 1000;
const THRESHOLD_SHARE_CUTOFF_BPS: u64 = 7500;
const DECRYPTION_KEY_SHARED_CUTOFF_BPS: u64 = 10000;

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

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ThresholdShareSchedule {
    pub cutoff_delay: Duration,
    pub deadline_delay: Duration,
    pub cutoff_reached: bool,
    pub description: String,
}

pub(crate) fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
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

pub(crate) fn resolve_threshold_share_schedule(
    dkg_deadline_unix_secs: Option<u64>,
    dkg_window_secs: Option<u64>,
) -> anyhow::Result<ThresholdShareSchedule> {
    let collector_override =
        parse_env_secs(DkgTimeoutPhase::ThresholdShareCollection.override_env());
    let deadline = dkg_deadline_unix_secs
        .ok_or_else(|| anyhow::anyhow!("canonical DKG deadline is unavailable"))?;
    let window =
        dkg_window_secs.ok_or_else(|| anyhow::anyhow!("frozen DKG window is unavailable"))?;

    resolve_threshold_share_schedule_from_inputs(
        collector_override,
        deadline,
        window,
        now_unix_secs(),
    )
}

pub(crate) fn resolve_threshold_share_schedule_from_inputs(
    collector_override_secs: Option<u64>,
    dkg_deadline_unix_secs: u64,
    dkg_window_secs: u64,
    now_unix_secs: u64,
) -> anyhow::Result<ThresholdShareSchedule> {
    anyhow::ensure!(
        dkg_deadline_unix_secs > 0 && dkg_window_secs > 0,
        "canonical DKG timing is invalid"
    );
    anyhow::ensure!(
        now_unix_secs < dkg_deadline_unix_secs,
        "canonical DKG deadline {} has passed at {}",
        dkg_deadline_unix_secs,
        now_unix_secs
    );

    let phase = DkgTimeoutPhase::ThresholdShareCollection;
    let cutoff = phase_cutoff_unix_secs(dkg_deadline_unix_secs, dkg_window_secs, phase);
    let cutoff_reached = now_unix_secs >= cutoff;
    let canonical_cutoff_delay = cutoff.saturating_sub(now_unix_secs);
    let cutoff_delay_secs = collector_override_secs
        .map(|override_secs| override_secs.min(canonical_cutoff_delay))
        .unwrap_or(canonical_cutoff_delay);

    Ok(ThresholdShareSchedule {
        cutoff_delay: Duration::from_secs(cutoff_delay_secs),
        deadline_delay: Duration::from_secs(
            dkg_deadline_unix_secs.saturating_sub(now_unix_secs),
        ),
        cutoff_reached,
        description: format!(
            "threshold-share soft cutoff {} ({}% of frozen {}s DKG window) and canonical deadline {}; optional {} can only advance the soft cutoff",
            cutoff,
            phase.cutoff_bps() / 100,
            dkg_window_secs,
            dkg_deadline_unix_secs,
            phase.override_env(),
        ),
    })
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
    let cutoff = phase_cutoff_unix_secs(dkg_deadline_unix_secs, dkg_window_secs, phase);
    anyhow::ensure!(
        now_unix_secs < cutoff,
        "{} cutoff {} has passed at {}",
        phase.label(),
        cutoff,
        now_unix_secs
    );
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

pub(crate) fn phase_cutoff_unix_secs(
    dkg_deadline_unix_secs: u64,
    dkg_window_secs: u64,
    phase: DkgTimeoutPhase,
) -> u64 {
    let start = dkg_deadline_unix_secs.saturating_sub(dkg_window_secs);
    start
        .saturating_add(phase_cutoff_secs(dkg_window_secs, phase.cutoff_bps()))
        .min(dkg_deadline_unix_secs)
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

        assert_eq!(timeout.duration, Duration::from_secs(4_400));
    }

    #[test]
    fn threshold_share_schedule_keeps_the_canonical_deadline() {
        let schedule =
            resolve_threshold_share_schedule_from_inputs(None, 8_200, 7_200, 2_000).unwrap();

        assert_eq!(schedule.cutoff_delay, Duration::from_secs(4_400));
        assert_eq!(schedule.deadline_delay, Duration::from_secs(6_200));
        assert!(!schedule.cutoff_reached);
        assert!(schedule.description.contains("soft cutoff"));
    }

    #[test]
    fn threshold_share_schedule_recovers_after_the_soft_cutoff() {
        let schedule =
            resolve_threshold_share_schedule_from_inputs(None, 8_200, 7_200, 6_500).unwrap();

        assert_eq!(schedule.cutoff_delay, Duration::ZERO);
        assert_eq!(schedule.deadline_delay, Duration::from_secs(1_700));
        assert!(schedule.cutoff_reached);
    }

    #[test]
    fn threshold_share_override_does_not_shorten_the_hard_deadline() {
        let schedule =
            resolve_threshold_share_schedule_from_inputs(Some(45), 8_200, 7_200, 2_000).unwrap();

        assert_eq!(schedule.cutoff_delay, Duration::from_secs(45));
        assert_eq!(schedule.deadline_delay, Duration::from_secs(6_200));
    }

    #[test]
    fn threshold_share_schedule_rejects_the_canonical_deadline() {
        let error =
            resolve_threshold_share_schedule_from_inputs(None, 8_200, 7_200, 8_200).unwrap_err();

        assert!(error.to_string().contains("canonical DKG deadline"));
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
        .unwrap_err();
        assert!(past.to_string().contains("cutoff 8200 has passed"));
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

        assert_eq!(short.duration, Duration::from_secs(1_700));
        assert_eq!(long.duration, Duration::from_secs(4_400));
        assert_eq!(restarted_short.duration, Duration::from_secs(1_100));
    }
}
