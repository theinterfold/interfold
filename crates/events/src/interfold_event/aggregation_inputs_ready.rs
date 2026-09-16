// SPDX-License-Identifier: LGPL-3.0-only

use crate::E3id;
use actix::Message;
use serde::{Deserialize, Serialize};
use std::fmt::{self, Display};

/// Aggregation work that can move between deterministic committee members.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AggregationPhase {
    PublicKey,
    Plaintext,
    DkgRoster,
}

impl Display for AggregationPhase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DkgRoster => write!(f, "DKG roster"),
            Self::PublicKey => write!(f, "public-key"),
            Self::Plaintext => write!(f, "plaintext"),
        }
    }
}

/// Confirms that this node persisted all inputs for an aggregation phase.
///
/// The selector starts its progress timer only after this event. A promoted
/// standby can therefore resume the work from its persisted actor state.
#[derive(Message, Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[rtype(result = "()")]
pub struct AggregationInputsReady {
    pub e3_id: E3id,
    pub phase: AggregationPhase,
}

impl Display for AggregationInputsReady {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "AggregationInputsReady {{ e3_id: {}, phase: {} }}",
            self.e3_id, self.phase
        )
    }
}

#[cfg(test)]
mod tests {
    use super::AggregationPhase;

    #[test]
    fn new_phase_does_not_renumber_persisted_variants() {
        assert_eq!(
            bincode::serialize(&AggregationPhase::PublicKey).unwrap(),
            0_u32.to_le_bytes()
        );
        assert_eq!(
            bincode::serialize(&AggregationPhase::Plaintext).unwrap(),
            1_u32.to_le_bytes()
        );
        assert_eq!(
            bincode::serialize(&AggregationPhase::DkgRoster).unwrap(),
            2_u32.to_le_bytes()
        );
    }
}
