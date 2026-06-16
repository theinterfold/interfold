// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub(crate) const DKG_WINDOW_ENV: &str = "E3_DKG_WINDOW_SECS";
pub(crate) const DEFAULT_DKG_WINDOW_SECS: u64 = 7200;

const ENCRYPTION_KEY_CUTOFF_BPS: u64 = 1000;
const THRESHOLD_SHARE_CUTOFF_BPS: u64 = 6000;
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

pub(crate) fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub(crate) fn resolve_timeout(
    phase: DkgTimeoutPhase,
    dkg_started_at_unix_secs: Option<u64>,
) -> DerivedTimeout {
    let collector_override = parse_env_secs(phase.override_env());
    let dkg_window_secs = parse_env_secs(DKG_WINDOW_ENV).unwrap_or(DEFAULT_DKG_WINDOW_SECS);

    resolve_timeout_from_inputs(
        phase,
        collector_override,
        dkg_window_secs,
        dkg_started_at_unix_secs,
        now_unix_secs(),
    )
}

pub(crate) fn resolve_timeout_from_inputs(
    phase: DkgTimeoutPhase,
    collector_override_secs: Option<u64>,
    dkg_window_secs: u64,
    dkg_started_at_unix_secs: Option<u64>,
    now_unix_secs: u64,
) -> DerivedTimeout {
    if let Some(override_secs) = collector_override_secs {
        return DerivedTimeout {
            duration: Duration::from_secs(override_secs),
            description: format!(
                "{} timeout override from {}={}s",
                phase.label(),
                phase.override_env(),
                override_secs
            ),
        };
    }

    let cutoff_secs = phase_cutoff_secs(dkg_window_secs, phase.cutoff_bps());
    let remaining_secs = match dkg_started_at_unix_secs {
        Some(started_at) => cutoff_secs.saturating_sub(now_unix_secs.saturating_sub(started_at)),
        None => cutoff_secs,
    };

    let description = match dkg_started_at_unix_secs {
        Some(started_at) => format!(
            "{} timeout derived from {}={}s, DKG start {}, cutoff {}% of DKG window",
            phase.label(),
            DKG_WINDOW_ENV,
            dkg_window_secs,
            started_at,
            phase.cutoff_bps() / 100
        ),
        None => format!(
            "{} timeout derived from {}={}s with missing DKG start, using full cutoff budget of {}%",
            phase.label(),
            DKG_WINDOW_ENV,
            dkg_window_secs,
            phase.cutoff_bps() / 100
        ),
    };

    DerivedTimeout {
        duration: Duration::from_secs(remaining_secs),
        description,
    }
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
            7200,
            Some(1_000),
            1_600,
        );

        assert_eq!(timeout.duration, Duration::from_secs(120));
        assert!(timeout.description.contains(DKG_WINDOW_ENV));
    }

    #[test]
    fn threshold_share_timeout_uses_cumulative_cutoff() {
        let timeout = resolve_timeout_from_inputs(
            DkgTimeoutPhase::ThresholdShareCollection,
            None,
            7200,
            Some(1_000),
            2_000,
        );

        assert_eq!(timeout.duration, Duration::from_secs(3320));
    }

    #[test]
    fn collector_override_wins_over_dkg_window() {
        let timeout = resolve_timeout_from_inputs(
            DkgTimeoutPhase::DecryptionKeySharedCollection,
            Some(45),
            7200,
            Some(1_000),
            8_000,
        );

        assert_eq!(timeout.duration, Duration::from_secs(45));
        assert!(timeout
            .description
            .contains(DkgTimeoutPhase::DecryptionKeySharedCollection.override_env()));
    }
}
