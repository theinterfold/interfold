// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use alloy_primitives::{Address, Bytes, B256, U256};
use alloy_sol_types::{SolEvent, SolValue};
use e3_committee::CiphernodesCommitteeSize;
use e3_evm_contracts::{
    IBondingRegistry, ICiphernodeRegistry, IInterfold, IRandomnessProvider, ISlashingManager,
};
use e3_protocol::{
    dkg::{AttestationContext, KeyAnchor},
    node::{ChainEvent, ChainFact, CryptoParams, DataRef, FailureReason, LogPosition, Stage},
    E3Id, UnixSecs,
};
use std::collections::{BTreeMap, BTreeSet};

/// The contracts of one chain whose logs the node reads.
#[derive(Clone, Debug)]
pub struct Contracts {
    pub chain_id: u64,
    pub interfold: Address,
    pub registry: Address,
    pub bonding: Address,
    /// The slashing managers, whose release of an E3 ends accusations about it: the Interfold's
    /// at start, then each one it sets.
    pub slashing: BTreeSet<Address>,
    /// The randomness providers whose fulfillments the node reads: the registry's at start, then
    /// each one a request names or governance sets.
    pub randomness: BTreeSet<Address>,
    /// The crypto configuration this build runs for each parameter set; a request for another is
    /// skipped.
    pub crypto_configs: BTreeMap<u8, B256>,
}

impl Contracts {
    /// The contracts whose logs the node reads.
    pub fn addresses(&self) -> Vec<Address> {
        [self.interfold, self.registry, self.bonding]
            .into_iter()
            .chain(self.randomness.iter().copied())
            .chain(self.slashing.iter().copied())
            .collect()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RawLog {
    pub address: Address,
    pub topics: Vec<B256>,
    pub data: Bytes,
    pub at: LogPosition,
    /// The block's timestamp.
    pub time: UnixSecs,
    pub transaction: B256,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Decoded {
    Fact(ChainEvent),
    Read(PendingRead),
}

/// A fact that needs contract state before the node can take it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum PendingRead {
    /// `E3Requested`, with the parts its transaction logged: the ticket price the registry froze,
    /// and the committee seed if the registry already accepted it. `CommitteeRequested`, which
    /// would carry the price, is declared but never emitted.
    Request {
        at: LogPosition,
        time: UnixSecs,
        e3: E3Id,
        params: CryptoParams,
        interfold: Address,
        attestation: AttestationContext,
        owner_cap: bool,
    },
    /// `SortitionCommitteeFinalized`, which the registry logs only for a finalized committee,
    /// with its members: their DKG deadline from `getDeadlines` and window from
    /// `getE3TimeoutConfig`.
    DkgTiming {
        at: LogPosition,
        time: UnixSecs,
        e3: E3Id,
        members: Vec<Address>,
    },
    /// `RandomnessFulfilled`: the committee seed and deadline the registry accepted.
    Seed {
        at: LogPosition,
        time: UnixSecs,
        e3: E3Id,
    },
    /// `CommitteeProofPublished`, with the roster its proof names: the ciphertext's deadline from
    /// `getDeadlines`.
    Key {
        at: LogPosition,
        time: UnixSecs,
        e3: E3Id,
        committee: Vec<Address>,
        roster: Vec<Address>,
        commitment: B256,
        anchors: BTreeMap<Address, KeyAnchor>,
    },
    /// `CiphertextOutputReferencePublished`: its decryption deadline from `getDeadlines`.
    Ciphertext {
        at: LogPosition,
        time: UnixSecs,
        e3: E3Id,
        ciphertext: DataRef,
    },
}

/// A log the node cannot read safely; ingestion stops rather than guess.
#[derive(Debug, thiserror::Error)]
pub enum DecodeError {
    #[error("malformed {event} log: {source}")]
    Malformed {
        event: &'static str,
        source: alloy_sol_types::Error,
    },
    #[error("unknown {kind} value {value}")]
    UnknownEnum { kind: &'static str, value: u8 },
    #[error("the key proof does not name an ordered roster of committee slots")]
    Roster,
}

/// The parts of a request that its transaction logs before `E3Requested`.
#[derive(Default)]
struct RequestParts {
    attestation: Option<AttestationContext>,
    owner_cap: bool,
}

/// Decodes `logs`, whole blocks in chain order. A request pairs logs of one transaction, and a
/// transaction never spans blocks, so nothing carries over between calls.
pub(crate) fn decode(contracts: &Contracts, logs: &[RawLog]) -> Result<Vec<Decoded>, DecodeError> {
    let mut decoder = Decoder {
        contracts,
        requests: BTreeMap::new(),
    };
    let mut decoded = Vec::new();
    for log in logs {
        decoded.extend(decoder.decode(log)?);
    }
    Ok(decoded)
}

struct Decoder<'a> {
    contracts: &'a Contracts,
    /// Request parts per transaction and E3, until its `E3Requested`.
    requests: BTreeMap<(B256, U256), RequestParts>,
}

impl Decoder<'_> {
    fn decode(&mut self, log: &RawLog) -> Result<Option<Decoded>, DecodeError> {
        let Some(&topic) = log.topics.first() else {
            return Ok(None);
        };
        let c = self.contracts;
        if log.address == c.interfold {
            self.interfold(log, topic)
        } else if log.address == c.registry {
            self.registry(log, topic)
        } else if log.address == c.bonding {
            self.bonding(log, topic)
        } else if c.slashing.contains(&log.address)
            && topic == ISlashingManager::E3DependenciesReleased::SIGNATURE_HASH
        {
            let event: ISlashingManager::E3DependenciesReleased =
                decode_event(log, "E3DependenciesReleased")?;
            let e3 = self.e3(event.e3Id);
            Ok(Some(self.fact(log, ChainFact::DependenciesReleased { e3 })))
        } else if c.randomness.contains(&log.address)
            && topic == IRandomnessProvider::RandomnessFulfilled::SIGNATURE_HASH
        {
            let event: IRandomnessProvider::RandomnessFulfilled =
                decode_event(log, "RandomnessFulfilled")?;
            Ok(Some(Decoded::Read(PendingRead::Seed {
                at: log.at,
                time: log.time,
                e3: self.e3(event.e3Id),
            })))
        } else {
            Ok(None)
        }
    }

    fn interfold(&mut self, log: &RawLog, topic: B256) -> Result<Option<Decoded>, DecodeError> {
        use IInterfold as I;
        let fact = match topic {
            I::E3Requested::SIGNATURE_HASH => {
                let event: I::E3Requested = decode_event(log, "E3Requested")?;
                return Ok(self.requested(log, event));
            }
            I::CiphertextOutputReferencePublished::SIGNATURE_HASH => {
                let event: I::CiphertextOutputReferencePublished =
                    decode_event(log, "CiphertextOutputReferencePublished")?;
                return Ok(Some(Decoded::Read(PendingRead::Ciphertext {
                    at: log.at,
                    time: log.time,
                    e3: self.e3(event.e3Id),
                    ciphertext: DataRef {
                        hash: event.contentHash,
                        block: event.availabilityBlock,
                        leaf: event.availabilityLeafIndex,
                    },
                })));
            }
            I::E3StageChanged::SIGNATURE_HASH => {
                let event: I::E3StageChanged = decode_event(log, "E3StageChanged")?;
                any_stage(event.previousStage)?;
                ChainFact::StageChanged {
                    e3: self.e3(event.e3Id),
                    stage: stage(event.newStage)?,
                }
            }
            I::E3Failed::SIGNATURE_HASH => {
                let event: I::E3Failed = decode_event(log, "E3Failed")?;
                any_stage(event.failedAtStage)?;
                ChainFact::Failed {
                    e3: self.e3(event.e3Id),
                    reason: failure(event.reason)?,
                }
            }
            I::SlashingManagerSet::SIGNATURE_HASH => {
                let event: I::SlashingManagerSet = decode_event(log, "SlashingManagerSet")?;
                ChainFact::SlashingManager {
                    manager: event.slashingManager,
                }
            }
            I::E3FailureProcessed::SIGNATURE_HASH => {
                let event: I::E3FailureProcessed = decode_event(log, "E3FailureProcessed")?;
                ChainFact::FailureSettled {
                    e3: self.e3(event.e3Id),
                }
            }
            _ => return Ok(None),
        };
        Ok(Some(self.fact(log, fact)))
    }

    fn registry(&mut self, log: &RawLog, topic: B256) -> Result<Option<Decoded>, DecodeError> {
        use ICiphernodeRegistry as R;
        let fact = match topic {
            R::DkgFoldAttestationContextEstablished::SIGNATURE_HASH => {
                let event: R::DkgFoldAttestationContextEstablished =
                    decode_event(log, "DkgFoldAttestationContextEstablished")?;
                self.parts(log.transaction, event.e3Id).attestation = Some(AttestationContext {
                    registry: event.registry,
                    verifier: event.dkgFoldAttestationVerifier,
                });
                return Ok(None);
            }
            R::CommitteeBondOwnerCapEnabled::SIGNATURE_HASH => {
                let event: R::CommitteeBondOwnerCapEnabled =
                    decode_event(log, "CommitteeBondOwnerCapEnabled")?;
                self.parts(log.transaction, event.e3Id).owner_cap = true;
                return Ok(None);
            }
            R::SortitionCommitteeFinalized::SIGNATURE_HASH => {
                let event: R::SortitionCommitteeFinalized =
                    decode_event(log, "SortitionCommitteeFinalized")?;
                return Ok(Some(Decoded::Read(PendingRead::DkgTiming {
                    at: log.at,
                    time: log.time,
                    e3: self.e3(event.e3Id),
                    members: event.committee,
                })));
            }
            R::CommitteeProofPublished::SIGNATURE_HASH => {
                let event: R::CommitteeProofPublished =
                    decode_event(log, "CommitteeProofPublished")?;
                let (roster, anchors) = roster(&event.nodes, &event.proof, event.pkCommitment)?;
                return Ok(Some(Decoded::Read(PendingRead::Key {
                    at: log.at,
                    time: log.time,
                    e3: self.e3(event.e3Id),
                    committee: event.nodes,
                    roster,
                    commitment: event.pkCommitment,
                    anchors,
                })));
            }
            R::CommitteeRandomnessRequested::SIGNATURE_HASH => {
                let event: R::CommitteeRandomnessRequested =
                    decode_event(log, "CommitteeRandomnessRequested")?;
                ChainFact::RandomnessProvider {
                    provider: event.provider,
                }
            }
            R::RandomnessProviderSet::SIGNATURE_HASH => {
                let event: R::RandomnessProviderSet = decode_event(log, "RandomnessProviderSet")?;
                ChainFact::RandomnessProvider {
                    provider: event.randomnessProvider,
                }
            }
            R::CommitteeMemberExpelled::SIGNATURE_HASH => {
                let event: R::CommitteeMemberExpelled =
                    decode_event(log, "CommitteeMemberExpelled")?;
                ChainFact::MemberExpelled {
                    e3: self.e3(event.e3Id),
                    member: event.node,
                }
            }
            R::CiphernodeAdded::SIGNATURE_HASH => {
                let event: R::CiphernodeAdded = decode_event(log, "CiphernodeAdded")?;
                ChainFact::OperatorEnabled {
                    operator: event.node,
                    enabled: true,
                }
            }
            R::CiphernodeRemoved::SIGNATURE_HASH => {
                let event: R::CiphernodeRemoved = decode_event(log, "CiphernodeRemoved")?;
                ChainFact::OperatorEnabled {
                    operator: event.node,
                    enabled: false,
                }
            }
            R::AccusationVoteValiditySet::SIGNATURE_HASH => {
                let event: R::AccusationVoteValiditySet =
                    decode_event(log, "AccusationVoteValiditySet")?;
                ChainFact::VoteValidity {
                    secs: u64::try_from(event.accusationVoteValidity).unwrap_or(u64::MAX),
                }
            }
            _ => return Ok(None),
        };
        Ok(Some(self.fact(log, fact)))
    }

    fn bonding(&mut self, log: &RawLog, topic: B256) -> Result<Option<Decoded>, DecodeError> {
        use IBondingRegistry as B;
        let fact = match topic {
            B::OperatorActivationChanged::SIGNATURE_HASH => {
                let event: B::OperatorActivationChanged =
                    decode_event(log, "OperatorActivationChanged")?;
                ChainFact::OperatorActive {
                    operator: event.operator,
                    active: event.active,
                }
            }
            B::TicketBalanceUpdated::SIGNATURE_HASH => {
                let event: B::TicketBalanceUpdated = decode_event(log, "TicketBalanceUpdated")?;
                ChainFact::TicketBalance {
                    operator: event.operator,
                    balance: event.newBalance,
                }
            }
            B::BondOwnerSet::SIGNATURE_HASH => {
                let event: B::BondOwnerSet = decode_event(log, "BondOwnerSet")?;
                ChainFact::BondOwner {
                    operator: event.operator,
                    owner: event.bondOwner,
                }
            }
            B::EligibilityConfigurationVersionUpdated::SIGNATURE_HASH => {
                ChainFact::EligibilityReset
            }
            B::ConfigurationUpdated::SIGNATURE_HASH => {
                let event: B::ConfigurationUpdated = decode_event(log, "ConfigurationUpdated")?;
                if !affects_eligibility(event.parameter) {
                    return Ok(None);
                }
                ChainFact::EligibilityReset
            }
            _ => return Ok(None),
        };
        Ok(Some(self.fact(log, fact)))
    }

    /// A request with the parts its transaction logged before it. Its time is its block's: the
    /// registry records the request's `block.timestamp`. A request for a crypto configuration or
    /// committee size this build does not support is skipped.
    fn requested(&mut self, log: &RawLog, event: IInterfold::E3Requested) -> Option<Decoded> {
        let parts = self.requests.remove(&(log.transaction, event.e3Id))?;
        let supported =
            self.contracts.crypto_configs.get(&event.e3.paramSet) == Some(&event.cryptoConfigId);
        let size = committee_size(event.e3.committeeSize)?;
        let (Some(attestation), true) = (parts.attestation, supported) else {
            return None;
        };
        Some(Decoded::Read(PendingRead::Request {
            at: log.at,
            time: log.time,
            e3: self.e3(event.e3Id),
            params: CryptoParams {
                param_set: event.e3.paramSet,
                committee_size: size,
                seed: B256::from(event.e3.seed),
            },
            interfold: log.address,
            attestation,
            owner_cap: parts.owner_cap,
        }))
    }

    fn parts(&mut self, transaction: B256, e3: U256) -> &mut RequestParts {
        self.requests.entry((transaction, e3)).or_default()
    }

    fn fact(&self, log: &RawLog, fact: ChainFact) -> Decoded {
        Decoded::Fact(ChainEvent {
            at: log.at,
            time: log.time,
            fact,
        })
    }

    fn e3(&self, number: U256) -> E3Id {
        E3Id {
            chain_id: self.contracts.chain_id,
            number,
        }
    }
}

fn decode_event<E: SolEvent>(log: &RawLog, event: &'static str) -> Result<E, DecodeError> {
    E::decode_raw_log(log.topics.iter().copied(), &log.data)
        .map_err(|source| DecodeError::Malformed { event, source })
}

/// The roster from the key proof's public inputs, laid out as the deployed key verifier reads
/// them: `abi.encode(bytes proof, bytes32[] inputs)` with `6 + 3H` inputs for a roster of H (the
/// verifier picks its circuit by that count), the roster's committee slots at `[2, 2 + H)` in
/// ascending order, and the key commitment last. Each member's key commitments sit at
/// `5 + H + k` and `5 + 2H + k`, where `DkgFoldAttestationVerifier` reads the anchors the
/// registry stores.
fn roster(
    committee: &[Address],
    proof: &[u8],
    commitment: B256,
) -> Result<(Vec<Address>, BTreeMap<Address, KeyAnchor>), DecodeError> {
    let (_, inputs) = <(Bytes, Vec<B256>)>::abi_decode_params(proof).map_err(|source| {
        DecodeError::Malformed {
            event: "CommitteeProofPublished",
            source,
        }
    })?;
    let h = inputs.len().saturating_sub(6) / 3;
    if h == 0 || inputs.len() != 6 + 3 * h || inputs.last() != Some(&commitment) {
        return Err(DecodeError::Roster);
    }
    let slots: Vec<usize> = inputs[2..2 + h]
        .iter()
        .map(|slot| usize::try_from(U256::from_be_bytes(slot.0)).unwrap_or(usize::MAX))
        .collect();
    let ordered = slots.windows(2).all(|pair| pair[0] < pair[1])
        && slots.iter().all(|slot| *slot < committee.len());
    if !ordered {
        return Err(DecodeError::Roster);
    }
    let roster: Vec<Address> = slots.into_iter().map(|slot| committee[slot]).collect();
    let anchors = roster.iter().enumerate().map(|(k, member)| {
        let anchor = KeyAnchor {
            sk_agg_commit: inputs[5 + h + k],
            esm_agg_commit: inputs[5 + 2 * h + k],
        };
        (*member, anchor)
    });
    Ok((roster.clone(), anchors.collect()))
}

/// `BondingRegistry` names its parameters as left-aligned ASCII in a `bytes32`.
fn affects_eligibility(parameter: B256) -> bool {
    [
        "ticketPrice",
        "requiredCiphernodeBond",
        "ciphernodeBondActiveBps",
        "minTicketBalance",
    ]
    .iter()
    .any(|name| parameter == B256::right_padding_from(name.as_bytes()))
}

fn committee_size(value: u8) -> Option<CiphernodesCommitteeSize> {
    match value {
        0 => Some(CiphernodesCommitteeSize::Minimum),
        1 => Some(CiphernodesCommitteeSize::Micro),
        2 => Some(CiphernodesCommitteeSize::Small),
        _ => None,
    }
}

/// Checks a stage the node does not use: a value it does not know means the contracts changed.
fn any_stage(value: u8) -> Result<(), DecodeError> {
    match value {
        0 => Ok(()),
        value => stage(value).map(|_| ()),
    }
}

fn stage(value: u8) -> Result<Stage, DecodeError> {
    Ok(match value {
        1 => Stage::Requested,
        2 => Stage::CommitteeFinalized,
        3 => Stage::KeyPublished,
        4 => Stage::CiphertextReady,
        5 => Stage::Complete,
        6 => Stage::Failed,
        _ => {
            return Err(DecodeError::UnknownEnum {
                kind: "stage",
                value,
            })
        }
    })
}

fn failure(value: u8) -> Result<FailureReason, DecodeError> {
    use FailureReason::*;
    let reasons = [
        None,
        CommitteeFormationTimeout,
        InsufficientCommitteeMembers,
        DkgTimeout,
        DkgInvalidShares,
        NoInputsReceived,
        ComputeTimeout,
        ComputeProviderExpired,
        ComputeProviderFailed,
        RequesterCancelled,
        DecryptionTimeout,
        DecryptionInvalidShares,
        VerificationFailed,
    ];
    reasons
        .get(usize::from(value))
        .copied()
        .ok_or(DecodeError::UnknownEnum {
            kind: "failure reason",
            value,
        })
}

#[cfg(test)]
mod tests;
