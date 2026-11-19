// SPDX-License-Identifier: LGPL-3.0-only

//! Synchronized same-owner links use their own exact public layouts. C2→C4 membership is checked
//! against the complete verified batch by keyshare, not by the legacy cross-party blame/cache rule.

use super::{CommitmentLink, FieldValue, LinkScope};
use e3_committee::CiphernodesCommitteeSize;
use e3_events::ProofType;
use e3_fhe_params::BfvProfile;
use e3_zk_config::{
    synchronized::{public_signals::PublicSignals, Configs},
    CircuitName,
};
use std::sync::Arc;

#[derive(Clone, Copy)]
enum Kind {
    C1ToC2,
    C3ToC2,
    C3ToC0,
    C4ToC2,
}

struct Link {
    config: Arc<Configs>,
    kind: Kind,
}

pub(super) fn links(
    profile: BfvProfile,
    committee: CiphernodesCommitteeSize,
) -> anyhow::Result<Vec<Box<dyn CommitmentLink>>> {
    let config = Arc::new(Configs::for_profile(profile, committee)?);
    Ok([Kind::C1ToC2, Kind::C3ToC2, Kind::C3ToC0, Kind::C4ToC2]
        .into_iter()
        .map(|kind| {
            Box::new(Link {
                config: config.clone(),
                kind,
            }) as Box<dyn CommitmentLink>
        })
        .collect())
}

impl CommitmentLink for Link {
    fn name(&self) -> &'static str {
        match self.kind {
            Kind::C1ToC2 => "sync C1->C2 sk/context",
            Kind::C3ToC2 => "sync C3->C2 packed message",
            Kind::C3ToC0 => "sync C3->C0 recipient pk",
            Kind::C4ToC2 => "sync C4->C2 outgoing root/context",
        }
    }

    fn source_proof_type(&self) -> ProofType {
        match self.kind {
            Kind::C1ToC2 => ProofType::C1PkGeneration,
            Kind::C3ToC2 | Kind::C3ToC0 => ProofType::C3aSkShareEncryption,
            Kind::C4ToC2 => ProofType::C4aSkShareDecryption,
        }
    }

    fn target_proof_type(&self) -> ProofType {
        match self.kind {
            Kind::C3ToC0 => ProofType::C0PkBfv,
            _ => ProofType::C2aSkShareComputation,
        }
    }

    fn scope(&self) -> LinkScope {
        match self.kind {
            Kind::C3ToC0 => LinkScope::SourceMustExistInTargets,
            _ => LinkScope::SameParty,
        }
    }

    fn extract_source_values(&self, signals: &[u8]) -> Vec<FieldValue> {
        let circuit = self.source_proof_type().circuit_names()[0];
        let Ok(public) = PublicSignals::decode(&self.config, circuit, signals) else {
            return Vec::new();
        };
        match self.kind {
            Kind::C1ToC2 | Kind::C4ToC2 => {
                let value = match self.kind {
                    Kind::C1ToC2 => public.sk_commitment(),
                    _ => public.outgoing_root(),
                };
                public
                    .identity_fields()
                    .unwrap()
                    .into_iter()
                    .chain(value)
                    .collect()
            }
            Kind::C3ToC2 => public.message_commitments().unwrap().to_vec(),
            Kind::C3ToC0 => public.pk_commitment().into_iter().collect(),
        }
    }

    fn check_signals(&self, source: &[FieldValue], target: &[u8]) -> bool {
        let circuit = self.target_proof_type().circuit_names()[0];
        let Ok(public) = PublicSignals::decode(&self.config, circuit, target) else {
            return false;
        };
        match self.kind {
            Kind::C1ToC2 | Kind::C4ToC2 => {
                let value = match self.kind {
                    Kind::C1ToC2 => public.sk_commitment(),
                    _ => public.outgoing_root(),
                };
                source.len() == 4
                    && source[..3] == public.identity_fields().unwrap()
                    && Some(source[3]) == value
            }
            Kind::C3ToC2 => {
                source.len() == 1 && public.message_commitments().unwrap().contains(&source[0])
            }
            Kind::C3ToC0 => source.len() == 1 && Some(source[0]) == public.pk_commitment(),
        }
    }

    fn check_consistency(
        &self,
        source: &[FieldValue],
        target: &[u8],
        source_party: u64,
        target_party: u64,
    ) -> bool {
        if !self.check_signals(source, target) {
            return false;
        }
        if matches!(self.kind, Kind::C3ToC0) {
            return true;
        }
        let public =
            PublicSignals::decode(&self.config, CircuitName::SkShareComputation, target).unwrap();
        source_party == target_party && public.party_id().map(u64::from) == Some(target_party)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn field(value: u8) -> FieldValue {
        let mut field = [0; 32];
        field[31] = value;
        field
    }

    #[test]
    fn sync_links_are_exact_profile_specific_and_bind_same_owner_context() {
        let config = Arc::new(
            Configs::for_profile(
                BfvProfile::SyncDecInsecure64,
                CiphernodesCommitteeSize::Minimum,
            )
            .unwrap(),
        );
        let c2: Vec<_> = [1, 2, 2, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14]
            .into_iter()
            .flat_map(field)
            .collect();
        for (kind, fields) in [
            (Kind::C1ToC2, vec![1, 2, 2, 4, 15]),
            (Kind::C3ToC2, vec![15, 9, 16]),
            (
                Kind::C4ToC2,
                vec![1, 2, 2, 0, 2, 14, 5, 6, 7, 8, 9, 10, 17, 18],
            ),
        ] {
            let link = Link {
                config: config.clone(),
                kind,
            };
            let bytes: Vec<_> = fields.into_iter().flat_map(field).collect();
            let values = link.extract_source_values(&bytes);
            assert!(link.check_consistency(&values, &c2, 2, 2));
            assert!(!link.check_consistency(&values, &c2, 0, 2));
            assert!(!link.check_signals(&values, &c2[..c2.len() - 32]));
            assert!(link
                .extract_source_values(&bytes[..bytes.len() - 1])
                .is_empty());
            let mut changed = c2.clone();
            changed[3 * 32 + 31] ^= 1;
            changed[13 * 32 + 31] ^= 1;
            changed[8 * 32 + 31] ^= 1;
            assert!(!link.check_signals(&values, &changed));
            if !matches!(kind, Kind::C3ToC2) {
                let mut changed = c2.clone();
                changed[31] ^= 1;
                assert!(!link.check_signals(&values, &changed));
            }
        }
        let links = super::super::default_links(
            BfvProfile::SyncDecInsecure64,
            CiphernodesCommitteeSize::Minimum,
        )
        .unwrap();
        assert_eq!(links.len(), 4);
        assert!(links.iter().all(|link| !matches!(
            link.source_proof_type(),
            ProofType::C2aSkShareComputation
                | ProofType::C2bESmShareComputation
                | ProofType::C6ThresholdShareDecryption
        )));
        assert_eq!(
            super::super::default_links(
                BfvProfile::SsInsecure64,
                CiphernodesCommitteeSize::Minimum
            )
            .unwrap()
            .len(),
            12
        );
    }
}
