// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Restart decisions that startup derives from the local E3 lifecycle.

use e3_events::{E3Stage, E3id};
use std::collections::{HashMap, HashSet};

/// The E3s whose local lifecycle stage is terminal at startup. Their restored work does not
/// resume.
pub(super) fn terminal_e3s(lifecycle_stages: &HashMap<E3id, E3Stage>) -> HashSet<E3id> {
    lifecycle_stages
        .iter()
        .filter(|(_, stage)| stage.is_terminal())
        .map(|(e3_id, _)| e3_id.clone())
        .collect()
}

/// The failed E3s that keep their contexts only for accusation or slashing work, with their local
/// lifecycle stage. Their protocol actors learn of the failure at `EffectsEnabled`.
pub(super) fn fail_on_restart(
    lifecycle_stages: &HashMap<E3id, E3Stage>,
    kept_failures: &HashSet<E3id>,
) -> HashMap<E3id, E3Stage> {
    kept_failures
        .iter()
        .map(|e3_id| {
            let stage = lifecycle_stages.get(e3_id).cloned();
            (e3_id.clone(), stage.unwrap_or(E3Stage::None))
        })
        .collect()
}

/// The stages that the compute gate starts from: a failed E3 that keeps its context only for
/// accusation or slashing work runs no compute.
pub(super) fn compute_gate_stages(
    lifecycle_stages: &HashMap<E3id, E3Stage>,
    kept_failures: &HashSet<E3id>,
) -> HashMap<E3id, E3Stage> {
    let mut stages = lifecycle_stages.clone();
    stages.extend(
        kept_failures
            .iter()
            .map(|e3_id| (e3_id.clone(), E3Stage::Failed)),
    );
    stages
}

/// The E3s whose data-availability work ends at startup: finished E3s, and failed E3s that keep
/// their contexts only for accusation or slashing work.
pub(super) fn work_ended_on_restart(
    lifecycle_stages: &HashMap<E3id, E3Stage>,
    kept_failures: &HashSet<E3id>,
) -> HashSet<E3id> {
    let mut ended = terminal_e3s(lifecycle_stages);
    ended.extend(kept_failures.iter().cloned());
    ended
}

#[cfg(test)]
mod tests {
    use super::{compute_gate_stages, fail_on_restart, work_ended_on_restart};
    use e3_events::{E3Stage, E3id};
    use std::collections::{HashMap, HashSet};

    /// A failed E3 that keeps its context only for accusation or slashing work learns of the
    /// failure at `EffectsEnabled`, runs no compute, and ends its data-availability work. Other
    /// E3s keep their decisions.
    #[test]
    fn a_kept_failure_ends_its_work_on_restart() {
        let (kept, active, complete) = (E3id::new("1", 1), E3id::new("2", 1), E3id::new("3", 1));
        let lifecycle = HashMap::from([
            (kept.clone(), E3Stage::CommitteeFinalized),
            (active.clone(), E3Stage::KeyPublished),
            (complete.clone(), E3Stage::Complete),
        ]);
        let kept_failures = HashSet::from([kept.clone()]);

        assert_eq!(
            fail_on_restart(&lifecycle, &kept_failures),
            HashMap::from([(kept.clone(), E3Stage::CommitteeFinalized)])
        );
        let gate = compute_gate_stages(&lifecycle, &kept_failures);
        assert_eq!(gate.get(&kept), Some(&E3Stage::Failed));
        assert_eq!(gate.get(&active), Some(&E3Stage::KeyPublished));
        assert_eq!(
            work_ended_on_restart(&lifecycle, &kept_failures),
            HashSet::from([kept, complete])
        );
    }
}
