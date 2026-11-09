// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! What one run is: the preset it uses, the [`Fault`] injected into it, and the [`Expect`]ed
//! outcome. The runner reads the fault and gathers what the expectation needs; the assertions read
//! the expectation. A new outcome is a field of [`Expect`] and a check over it.

use anyhow::{bail, Result};
use e3_fhe_params::{BfvPreset, DEFAULT_BFV_PRESET};
use std::time::Duration;

/// Votes each synthetic voter casts, so the number of tallies the decryption must return. SS has
/// one committed noise set, so the run exercises one output rather than reuse it across tallies.
pub const VOTES_PER_VOTER: usize = 1;

/// Proof system and parameter family a run uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Preset {
    Insecure,
    Secure,
}

impl Preset {
    /// The preset for a benchmark mode, which is `insecure` or `secure`.
    pub fn from_mode(mode: &str) -> Result<Self> {
        match mode {
            "insecure" => Ok(Preset::Insecure),
            "secure" => Ok(Preset::Secure),
            other => bail!("unsupported BENCHMARK_MODE {other:?}: expected `insecure` or `secure`"),
        }
    }

    pub fn bfv_preset(self) -> BfvPreset {
        match self {
            Preset::Insecure => DEFAULT_BFV_PRESET,
            Preset::Secure => BfvPreset::SecureThreshold8192,
        }
    }

    /// Collection timeouts (encryption keys, threshold shares, decryption key shares) that the
    /// secure proofs need; insecure runs take the nodes' defaults or the caller's environment.
    pub(super) fn collection_timeouts_secs(self, small_committee: bool) -> Option<(u64, u64, u64)> {
        match (self, small_committee) {
            (Preset::Insecure, _) => None,
            (Preset::Secure, true) => Some((7_200, 46_000, 46_000)),
            (Preset::Secure, false) => Some((1_800, 7_200, 7_200)),
        }
    }

    /// How long a run waits for the public key and for the plaintext. These bound the harness
    /// only; protocol deadlines come from the synthetic DKG window.
    pub(super) fn flow_timeouts(self, small_committee: bool) -> (Duration, Duration) {
        let (pubkey, plaintext) = match (self, small_committee) {
            (Preset::Insecure, _) => (5_000, 1_000),
            (Preset::Secure, true) => (45_000, 6_000),
            (Preset::Secure, false) => (15_000, 3_000),
        };
        (Duration::from_secs(pubkey), Duration::from_secs(plaintext))
    }
}

/// A fault the run injects at a known protocol point.
#[derive(Debug, Clone, Copy)]
pub enum Fault {
    None,
    /// The committee party disconnects once it has published its encryption key (C0) and a peer
    /// has seen it. It can no longer share its DKG material, so the aggregator must
    /// select a roster without it.
    OfflineAfterC0 {
        party_id: usize,
    },
    /// A DKG roster member other than the aggregator stops while its C4 proof is pending and
    /// restarts from its persisted stores. `party_id` is the member to restart when it
    /// qualifies; otherwise the first member that does is.
    RestartDuringC4 {
        party_id: usize,
    },
    /// A DKG roster member other than the aggregator stops while its C6 share-decryption proof
    /// is pending, before it publishes its decryption share, and restarts from its persisted
    /// stores. `party_id` is chosen as for [`Fault::RestartDuringC4`].
    RestartDuringC6 {
        party_id: usize,
    },
}

impl Fault {
    pub(super) fn offline_party(self) -> Option<usize> {
        match self {
            Fault::OfflineAfterC0 { party_id } => Some(party_id),
            _ => None,
        }
    }

    /// Only a run that restarts a node gives its nodes persistent stores.
    pub(super) fn restarts_a_node(self) -> bool {
        matches!(
            self,
            Fault::RestartDuringC4 { .. } | Fault::RestartDuringC6 { .. }
        )
    }
}

/// The share a restarted party's pending proof owed, which it had not published when it stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwedShare {
    /// The C4 share (`DecryptionKeyShared`).
    C4DecryptionKey,
    /// The C6 decryption share (`DecryptionshareCreated`).
    C6Decryption,
}

/// What a finished run must show, beyond what every run owes: the key and plaintext it produced,
/// the roster its key lists, and no faults.
#[derive(Debug, Clone, Copy)]
pub struct Expect {
    /// A party the DKG roster must leave out.
    pub roster_excludes: Option<usize>,
    /// A standby party (N > H) still deals its C4 share, since it replaces a roster member that
    /// drops out. Only owed when the run aggregates proofs.
    pub standby_deals: bool,
    /// The restarted party publishes the share its pending proof owed.
    pub restarted_share: Option<OwedShare>,
}

impl Expect {
    /// Every party online: nobody is left off the roster and the standby party deals.
    fn online() -> Self {
        Self {
            roster_excludes: None,
            standby_deals: true,
            restarted_share: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Scenario {
    pub preset: Preset,
    pub fault: Fault,
    pub expect: Expect,
    /// Frozen DKG window given to every node. `None` derives a window far beyond the flow
    /// timeouts, so no protocol deadline can fire during the run.
    pub dkg_window: Option<Duration>,
    /// Jobs the shared Rayon pool runs at once.
    pub concurrent_jobs: usize,
}

impl Scenario {
    /// The committee has a standby party (N > H); the run completes with every party online
    /// and the standby party still deals its C4 share.
    pub fn standby_node() -> Self {
        Self {
            preset: Preset::Insecure,
            fault: Fault::None,
            expect: Expect::online(),
            dkg_window: Some(Duration::from_secs(1200)),
            concurrent_jobs: 1,
        }
    }

    /// Party `party_id` goes offline after C0 and the run completes without it.
    pub fn offline_after_c0(party_id: usize) -> Self {
        Self {
            fault: Fault::OfflineAfterC0 { party_id },
            expect: Expect {
                roster_excludes: Some(party_id),
                standby_deals: false,
                restarted_share: None,
            },
            ..Self::standby_node()
        }
    }

    /// Roster member `party_id` restarts from its persisted stores while its C4 proof is pending;
    /// the run completes with it.
    pub fn restart_during_c4(party_id: usize) -> Self {
        Self {
            fault: Fault::RestartDuringC4 { party_id },
            expect: Expect {
                restarted_share: Some(OwedShare::C4DecryptionKey),
                ..Expect::online()
            },
            ..Self::standby_node()
        }
    }

    /// Roster member `party_id` restarts from its persisted stores while its C6 proof is pending;
    /// the run completes with it.
    pub fn restart_during_c6(party_id: usize) -> Self {
        Self {
            fault: Fault::RestartDuringC6 { party_id },
            expect: Expect {
                restarted_share: Some(OwedShare::C6Decryption),
                ..Expect::online()
            },
            ..Self::standby_node()
        }
    }

    /// Every party online, with the DKG window left open.
    pub fn benchmark(preset: Preset, concurrent_jobs: usize) -> Self {
        Self {
            preset,
            fault: Fault::None,
            expect: Expect::online(),
            dkg_window: None,
            concurrent_jobs,
        }
    }
}
