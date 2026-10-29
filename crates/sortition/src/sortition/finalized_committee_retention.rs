// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use e3_committee::Committee;
use e3_events::{E3Stage, E3id};
use std::collections::HashMap;

/// Pure lifecycle policy for restart-critical finalized committee state.
pub struct FinalizedCommitteeRetention;

impl FinalizedCommitteeRetention {
    pub fn remove(committees: &mut HashMap<E3id, Committee>, e3_id: &E3id) -> bool {
        committees.remove(e3_id).is_some()
    }

    pub fn prune_terminal(
        committees: &mut HashMap<E3id, Committee>,
        lifecycle: &HashMap<E3id, E3Stage>,
    ) -> usize {
        let before = committees.len();
        committees.retain(|e3_id, _| {
            !matches!(
                lifecycle.get(e3_id),
                Some(E3Stage::Complete | E3Stage::Failed)
            )
        });
        before - committees.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn committee() -> Committee {
        Committee::new(vec![])
    }

    #[test]
    fn startup_pruning_removes_only_known_terminal_committees() {
        let complete = E3id::new("1", 1);
        let failed = E3id::new("2", 1);
        let active = E3id::new("3", 1);
        let unknown = E3id::new("4", 1);
        let mut committees = HashMap::from([
            (complete.clone(), committee()),
            (failed.clone(), committee()),
            (active.clone(), committee()),
            (unknown.clone(), committee()),
        ]);
        let lifecycle = HashMap::from([
            (complete.clone(), E3Stage::Complete),
            (failed.clone(), E3Stage::Failed),
            (active.clone(), E3Stage::KeyPublished),
        ]);

        assert_eq!(
            FinalizedCommitteeRetention::prune_terminal(&mut committees, &lifecycle),
            2
        );
        assert_eq!(
            committees
                .keys()
                .cloned()
                .collect::<std::collections::HashSet<_>>(),
            std::collections::HashSet::from([active, unknown])
        );
    }
}
