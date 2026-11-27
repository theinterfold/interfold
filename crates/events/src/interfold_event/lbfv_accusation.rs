// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Accusation and commitment-consistency events of the l-BFV path.
//!
//! The l-BFV row proofs repeat one proof type once per row, so a [`ProofType`] alone does not
//! name the disputed proof: a [`ProofIdentity`] does. The trBFV events
//! ([`ProofFailureAccusation`], [`AccusationQuorumReached`], [`PartyProofData`],
//! [`CommitmentConsistencyCheckRequested`], [`CommitmentConsistencyViolation`]) name it by
//! [`ProofType`] only, and their bincode layout is persisted and on the wire. They stay as they
//! are; the events here carry the row for l-BFV E3s.
//!
//! Every trBFV event converts into its l-BFV form with instance zero. The reverse conversion
//! fails for a row instance other than zero, which a trBFV event cannot name. The accusation
//! workflow runs on the l-BFV forms and publishes the form of the E3's proving path.

use crate::{
    AccusationOutcome, AccusationQuorumReached, AccusationVote,
    CommitmentConsistencyCheckRequested, CommitmentConsistencyViolation, CorrelationId, E3id,
    PartyProofData, ProofFailureAccusation, ProofIdentity, ProofType, SignedProofPayload,
    VerificationKind,
};
use actix::Message;
use alloy::primitives::{Address, Bytes};
use e3_utils::utility_types::ArcBytes;
use serde::{Deserialize, Serialize};
use std::fmt::{self, Display};

/// An l-BFV event names a row instance that its trBFV form cannot carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("proof instance {0} has no trBFV form")]
pub struct RowInstanceNotRepresentable(pub u32);

/// [`ProofFailureAccusation`] of an l-BFV E3: the accusation plus the disputed proof's row.
#[derive(Message, Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[rtype(result = "()")]
pub struct LbfvProofFailureAccusation {
    pub e3_id: E3id,
    /// Ethereum address of the accusing node.
    pub accuser: Address,
    /// Ethereum address of the accused node.
    pub accused: Address,
    /// Party ID of the accused node.
    pub accused_party_id: u64,
    /// Which proof type allegedly failed.
    pub proof_type: ProofType,
    /// Row index for a multirow proof type. Singleton proof types use zero.
    pub proof_instance: u32,
    /// keccak256 hash of (data + proof) as received by the accuser.
    pub data_hash: [u8; 32],
    /// Unix time at which the accuser created this accusation.
    pub issued_at: u64,
    /// Unix-seconds deadline after which votes for this accusation expire.
    pub deadline: u64,
    /// For C3a/C3b: the signed proof payload so other nodes can re-verify.
    pub signed_payload: Option<SignedProofPayload>,
    /// ECDSA signature of the accuser over the accusation fields.
    pub signature: ArcBytes,
}

impl LbfvProofFailureAccusation {
    /// The disputed proof.
    pub fn identity(&self) -> ProofIdentity {
        ProofIdentity {
            proof_type: self.proof_type,
            instance: self.proof_instance,
        }
    }
}

impl From<ProofFailureAccusation> for LbfvProofFailureAccusation {
    fn from(accusation: ProofFailureAccusation) -> Self {
        Self {
            e3_id: accusation.e3_id,
            accuser: accusation.accuser,
            accused: accusation.accused,
            accused_party_id: accusation.accused_party_id,
            proof_type: accusation.proof_type,
            proof_instance: 0,
            data_hash: accusation.data_hash,
            issued_at: accusation.issued_at,
            deadline: accusation.deadline,
            signed_payload: accusation.signed_payload,
            signature: accusation.signature,
        }
    }
}

impl TryFrom<LbfvProofFailureAccusation> for ProofFailureAccusation {
    type Error = RowInstanceNotRepresentable;

    fn try_from(accusation: LbfvProofFailureAccusation) -> Result<Self, Self::Error> {
        if accusation.proof_instance != 0 {
            return Err(RowInstanceNotRepresentable(accusation.proof_instance));
        }
        Ok(Self {
            e3_id: accusation.e3_id,
            accuser: accusation.accuser,
            accused: accusation.accused,
            accused_party_id: accusation.accused_party_id,
            proof_type: accusation.proof_type,
            data_hash: accusation.data_hash,
            issued_at: accusation.issued_at,
            deadline: accusation.deadline,
            signed_payload: accusation.signed_payload,
            signature: accusation.signature,
        })
    }
}

impl Display for LbfvProofFailureAccusation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "LbfvProofFailureAccusation {{ e3_id: {}, accuser: {}, accused: {}, proof_type: {:?}, \
             proof_instance: {} }}",
            self.e3_id, self.accuser, self.accused, self.proof_type, self.proof_instance
        )
    }
}

/// [`AccusationQuorumReached`] of an l-BFV E3: the decision plus the disputed proof's row.
#[derive(Message, Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[rtype(result = "()")]
pub struct LbfvAccusationQuorumReached {
    pub e3_id: E3id,
    /// Address of the node that originally accused.
    pub accuser: Address,
    /// Address of the accused node.
    pub accused: Address,
    /// Which proof type was disputed.
    pub proof_type: ProofType,
    /// Row index for a multirow proof type. Singleton proof types use zero.
    pub proof_instance: u32,
    /// Votes from nodes that agreed the proof is bad.
    pub votes_for: Vec<AccusationVote>,
    /// The quorum decision.
    pub outcome: AccusationOutcome,
    /// Raw `abi.encode(proof.data, public_signals)`, the preimage of every voter's `data_hash`.
    /// Empty when this node had no raw bytes locally.
    pub evidence: Bytes,
}

impl From<AccusationQuorumReached> for LbfvAccusationQuorumReached {
    fn from(quorum: AccusationQuorumReached) -> Self {
        Self {
            e3_id: quorum.e3_id,
            accuser: quorum.accuser,
            accused: quorum.accused,
            proof_type: quorum.proof_type,
            proof_instance: 0,
            votes_for: quorum.votes_for,
            outcome: quorum.outcome,
            evidence: quorum.evidence,
        }
    }
}

impl TryFrom<LbfvAccusationQuorumReached> for AccusationQuorumReached {
    type Error = RowInstanceNotRepresentable;

    fn try_from(quorum: LbfvAccusationQuorumReached) -> Result<Self, Self::Error> {
        if quorum.proof_instance != 0 {
            return Err(RowInstanceNotRepresentable(quorum.proof_instance));
        }
        Ok(Self {
            e3_id: quorum.e3_id,
            accuser: quorum.accuser,
            accused: quorum.accused,
            proof_type: quorum.proof_type,
            votes_for: quorum.votes_for,
            outcome: quorum.outcome,
            evidence: quorum.evidence,
        })
    }
}

impl Display for LbfvAccusationQuorumReached {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "LbfvAccusationQuorumReached {{ e3_id: {}, accused: {}, proof_type: {:?}, \
             proof_instance: {}, outcome: {} }}",
            self.e3_id, self.accused, self.proof_type, self.proof_instance, self.outcome
        )
    }
}

/// [`PartyProofData`] of an l-BFV E3: each proof carries its [`ProofIdentity`].
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LbfvPartyProofData {
    pub party_id: u64,
    pub address: Address,
    /// Each entry is a `(proof_identity, public_signals, data_hash, proof_data)` tuple; see
    /// [`PartyProofData::proofs`].
    pub proofs: Vec<(ProofIdentity, ArcBytes, [u8; 32], ArcBytes)>,
}

impl From<PartyProofData> for LbfvPartyProofData {
    fn from(party: PartyProofData) -> Self {
        Self {
            party_id: party.party_id,
            address: party.address,
            proofs: party
                .proofs
                .into_iter()
                .map(|(proof_type, signals, hash, data)| {
                    (
                        ProofIdentity {
                            proof_type,
                            instance: 0,
                        },
                        signals,
                        hash,
                        data,
                    )
                })
                .collect(),
        }
    }
}

impl TryFrom<LbfvPartyProofData> for PartyProofData {
    type Error = RowInstanceNotRepresentable;

    fn try_from(party: LbfvPartyProofData) -> Result<Self, Self::Error> {
        let proofs = party
            .proofs
            .into_iter()
            .map(|(identity, signals, hash, data)| {
                if identity.instance != 0 {
                    return Err(RowInstanceNotRepresentable(identity.instance));
                }
                Ok((identity.proof_type, signals, hash, data))
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            party_id: party.party_id,
            address: party.address,
            proofs,
        })
    }
}

/// [`CommitmentConsistencyCheckRequested`] of an l-BFV E3.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LbfvCommitmentConsistencyCheckRequested {
    pub e3_id: E3id,
    pub kind: VerificationKind,
    pub correlation_id: CorrelationId,
    pub party_proofs: Vec<LbfvPartyProofData>,
}

impl From<CommitmentConsistencyCheckRequested> for LbfvCommitmentConsistencyCheckRequested {
    fn from(request: CommitmentConsistencyCheckRequested) -> Self {
        Self {
            e3_id: request.e3_id,
            kind: request.kind,
            correlation_id: request.correlation_id,
            party_proofs: request.party_proofs.into_iter().map(Into::into).collect(),
        }
    }
}

impl TryFrom<LbfvCommitmentConsistencyCheckRequested> for CommitmentConsistencyCheckRequested {
    type Error = RowInstanceNotRepresentable;

    fn try_from(request: LbfvCommitmentConsistencyCheckRequested) -> Result<Self, Self::Error> {
        Ok(Self {
            e3_id: request.e3_id,
            kind: request.kind,
            correlation_id: request.correlation_id,
            party_proofs: request
                .party_proofs
                .into_iter()
                .map(PartyProofData::try_from)
                .collect::<Result<_, _>>()?,
        })
    }
}

/// [`CommitmentConsistencyViolation`] of an l-BFV E3: the disputed proof's row is named.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LbfvCommitmentConsistencyViolation {
    pub e3_id: E3id,
    /// Party whose commitment is inconsistent.
    pub accused_party_id: u64,
    /// Recovered Ethereum address of the accused party.
    pub accused_address: Address,
    /// The proof type (source side) whose commitment value doesn't match.
    pub proof_type: ProofType,
    /// Row index for a multirow proof type. Singleton proof types use zero.
    pub proof_instance: u32,
    /// `keccak256(abi.encode(proof.data, public_signals))` of the accused party's proof.
    pub data_hash: [u8; 32],
    /// Raw `abi.encode(proof.data, public_signals)`, the preimage of `data_hash`.
    pub evidence: Bytes,
}

impl From<CommitmentConsistencyViolation> for LbfvCommitmentConsistencyViolation {
    fn from(violation: CommitmentConsistencyViolation) -> Self {
        Self {
            e3_id: violation.e3_id,
            accused_party_id: violation.accused_party_id,
            accused_address: violation.accused_address,
            proof_type: violation.proof_type,
            proof_instance: 0,
            data_hash: violation.data_hash,
            evidence: violation.evidence,
        }
    }
}

impl TryFrom<LbfvCommitmentConsistencyViolation> for CommitmentConsistencyViolation {
    type Error = RowInstanceNotRepresentable;

    fn try_from(violation: LbfvCommitmentConsistencyViolation) -> Result<Self, Self::Error> {
        if violation.proof_instance != 0 {
            return Err(RowInstanceNotRepresentable(violation.proof_instance));
        }
        Ok(Self {
            e3_id: violation.e3_id,
            accused_party_id: violation.accused_party_id,
            accused_address: violation.accused_address,
            proof_type: violation.proof_type,
            data_hash: violation.data_hash,
            evidence: violation.evidence,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CommitmentConsistencyCheckRequested, ProofType};

    fn accusation() -> ProofFailureAccusation {
        ProofFailureAccusation {
            e3_id: E3id::new("7", 31337),
            accuser: Address::repeat_byte(1),
            accused: Address::repeat_byte(2),
            accused_party_id: 3,
            proof_type: ProofType::C3aSkShareEncryption,
            data_hash: [4; 32],
            issued_at: 5,
            deadline: 6,
            signed_payload: None,
            signature: ArcBytes::from_bytes(&[7, 8]),
        }
    }

    fn quorum() -> AccusationQuorumReached {
        AccusationQuorumReached {
            e3_id: E3id::new("7", 31337),
            accuser: Address::repeat_byte(1),
            accused: Address::repeat_byte(2),
            proof_type: ProofType::C1PkGeneration,
            votes_for: Vec::new(),
            outcome: AccusationOutcome::AccusedFaulted,
            evidence: Bytes::from_static(&[9]),
        }
    }

    fn party() -> PartyProofData {
        PartyProofData {
            party_id: 1,
            address: Address::repeat_byte(2),
            proofs: vec![(
                ProofType::C0PkBfv,
                ArcBytes::from_bytes(&[3]),
                [4; 32],
                ArcBytes::from_bytes(&[5]),
            )],
        }
    }

    fn violation() -> CommitmentConsistencyViolation {
        CommitmentConsistencyViolation {
            e3_id: E3id::new("7", 31337),
            accused_party_id: 1,
            accused_address: Address::repeat_byte(2),
            proof_type: ProofType::C2aSkShareComputation,
            data_hash: [3; 32],
            evidence: Bytes::from_static(&[4]),
        }
    }

    /// The bincode bytes of the trBFV events, written out by field type: little-endian fixed-width
    /// integers, `u64` length prefixes, `u32` variant indexes, byte strings (addresses included)
    /// with a length prefix and `[u8; 32]` without one. They are the layouts the trBFV events had
    /// before l-BFV; a field that is added, reordered or retyped fails here.
    #[test]
    fn trbfv_events_keep_their_encoded_layout() {
        let prefixed = |bytes: &[u8]| [&(bytes.len() as u64).to_le_bytes()[..], bytes].concat();
        let e3_id = [&1u64.to_le_bytes()[..], b"7", &31337u64.to_le_bytes()].concat();
        let accuser = prefixed(&[1; 20]);
        let accused = prefixed(&[2; 20]);

        assert_eq!(
            bincode::serialize(&accusation()).unwrap(),
            [
                &e3_id[..],
                &accuser,
                &accused,
                &3u64.to_le_bytes(), // accused_party_id
                &4u32.to_le_bytes(), // ProofType::C3aSkShareEncryption
                &[4; 32],            // data_hash
                &5u64.to_le_bytes(), // issued_at
                &6u64.to_le_bytes(), // deadline
                &[0],                // signed_payload: None
                &prefixed(&[7, 8]),  // signature
            ]
            .concat()
        );

        assert_eq!(
            bincode::serialize(&quorum()).unwrap(),
            [
                &e3_id[..],
                &accuser,
                &accused,
                &1u32.to_le_bytes(), // ProofType::C1PkGeneration
                &0u64.to_le_bytes(), // votes_for: empty
                &0u32.to_le_bytes(), // AccusationOutcome::AccusedFaulted
                &prefixed(&[9]),     // evidence
            ]
            .concat()
        );

        // A trBFV proof is named by its proof type alone, so a proof entry is `[0, 0, 0, 0]` plus
        // its signals, hash and data.
        assert_eq!(
            bincode::serialize(&party()).unwrap(),
            [
                &1u64.to_le_bytes()[..], // party_id
                &prefixed(&[2; 20]),     // address
                &1u64.to_le_bytes(),     // one proof
                &0u32.to_le_bytes(),     // ProofType::C0PkBfv
                &prefixed(&[3]),         // public signals
                &[4; 32],                // data hash
                &prefixed(&[5]),         // proof data
            ]
            .concat()
        );

        assert_eq!(
            bincode::serialize(&violation()).unwrap(),
            [
                &e3_id[..],
                &1u64.to_le_bytes(), // accused_party_id
                &accused,            // accused_address
                &2u32.to_le_bytes(), // ProofType::C2aSkShareComputation
                &[3; 32],            // data_hash
                &prefixed(&[4]),     // evidence
            ]
            .concat()
        );
    }

    #[test]
    fn a_trbfv_event_round_trips_through_its_lbfv_form_with_row_zero() {
        let a = LbfvProofFailureAccusation::from(accusation());
        assert_eq!(a.proof_instance, 0);
        assert_eq!(ProofFailureAccusation::try_from(a).unwrap(), accusation());

        let q = LbfvAccusationQuorumReached::from(quorum());
        assert_eq!(q.proof_instance, 0);
        assert_eq!(AccusationQuorumReached::try_from(q).unwrap(), quorum());

        let request = CommitmentConsistencyCheckRequested {
            e3_id: E3id::new("7", 31337),
            kind: VerificationKind::ShareProofs,
            correlation_id: CorrelationId::new(),
            party_proofs: vec![party()],
        };
        let lbfv = LbfvCommitmentConsistencyCheckRequested::from(request.clone());
        assert_eq!(lbfv.party_proofs[0].proofs[0].0.instance, 0);
        assert_eq!(
            CommitmentConsistencyCheckRequested::try_from(lbfv).unwrap(),
            request
        );

        let v = LbfvCommitmentConsistencyViolation::from(violation());
        assert_eq!(v.proof_instance, 0);
        assert_eq!(
            CommitmentConsistencyViolation::try_from(v).unwrap(),
            violation()
        );
    }

    #[test]
    fn a_row_has_no_trbfv_form() {
        let row = 2;
        assert_eq!(
            ProofFailureAccusation::try_from(LbfvProofFailureAccusation {
                proof_instance: row,
                ..accusation().into()
            }),
            Err(RowInstanceNotRepresentable(row))
        );
        assert_eq!(
            AccusationQuorumReached::try_from(LbfvAccusationQuorumReached {
                proof_instance: row,
                ..quorum().into()
            }),
            Err(RowInstanceNotRepresentable(row))
        );
        assert_eq!(
            CommitmentConsistencyViolation::try_from(LbfvCommitmentConsistencyViolation {
                proof_instance: row,
                ..violation().into()
            }),
            Err(RowInstanceNotRepresentable(row))
        );
        let mut party = LbfvPartyProofData::from(party());
        party.proofs[0].0.instance = row;
        assert_eq!(
            PartyProofData::try_from(party),
            Err(RowInstanceNotRepresentable(row))
        );
    }

    /// New event types go after main's last one, so the stored index of every trBFV event holds.
    #[test]
    fn the_lbfv_events_come_after_the_trbfv_events() {
        use crate::{EventType, InterfoldEventData};
        let data_index = |data: InterfoldEventData| {
            u32::from_le_bytes(bincode::serialize(&data).unwrap()[..4].try_into().unwrap())
        };
        let type_index = |event_type: EventType| {
            u32::from_le_bytes(
                bincode::serialize(&event_type).unwrap()[..4]
                    .try_into()
                    .unwrap(),
            )
        };
        assert_eq!(data_index(quorum().into()), 0);
        assert_eq!(data_index(accusation().into()), 3);

        let last_main = type_index(EventType::SynchronizedDkgPublicationReady);
        for event_type in [
            EventType::LbfvProofFailureAccusation,
            EventType::LbfvAccusationQuorumReached,
            EventType::LbfvCommitmentConsistencyCheckRequested,
            EventType::LbfvCommitmentConsistencyViolation,
        ] {
            assert!(type_index(event_type) > last_main, "{event_type}");
        }
    }
}
