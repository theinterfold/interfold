// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use alloy_primitives::{Address, Bytes, B256, U256};
use alloy_sol_types::{SolEvent, SolValue};
use e3_committee::CiphernodesCommitteeSize;
use e3_evm_contracts::{IBondingRegistry, ICiphernodeRegistry, IInterfold, IRandomnessProvider};
use e3_protocol::{
    dkg::AttestationContext,
    node::{
        ChainEvent, ChainFact, CommitteeRequest, CryptoParams, FailureReason, LogPosition, Stage,
    },
    E3Id, UnixSecs,
};
use std::collections::{BTreeMap, BTreeSet};

/// Events the shared bindings do not carry.
mod extra {
    alloy_sol_types::sol! {
        event CommitteeBondOwnerCapEnabled(uint256 indexed e3Id);
        event AccusationVoteValiditySet(uint256 accusationVoteValidity);
        event IdentityPolicyUpdated(uint48 timepoint, address registry, bool required);
    }
}

/// The contracts of one chain whose logs the node reads.
#[derive(Clone, Debug)]
pub struct Contracts {
    pub chain_id: u64,
    pub interfold: Address,
    pub registry: Address,
    pub bonding: Address,
    /// Every randomness provider the registry used, so a restart reads old fulfillments too.
    pub randomness: BTreeSet<Address>,
    /// The crypto configuration this build supports; requests for another are skipped.
    pub crypto_config: B256,
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
pub enum Decoded {
    Fact(ChainEvent),
    Read(PendingRead),
}

/// A fact that needs contract state at its block before the node can take it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PendingRead {
    /// `CommitteeFinalized`: its DKG deadline from `getDeadlines` and window from
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
    /// `CiphertextOutputPublished`: its bytes go into the blob store, with the decryption deadline
    /// from `getDeadlines`.
    Ciphertext {
        at: LogPosition,
        time: UnixSecs,
        e3: E3Id,
        ciphertext: Bytes,
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
    #[error("the key proof does not name {0} ordered committee slots")]
    Roster(usize),
}

/// The parts of a request that its transaction logs before `E3Requested`.
#[derive(Default)]
struct RequestParts {
    attestation: Option<AttestationContext>,
    request: Option<(UnixSecs, U256)>,
    owner_cap: bool,
}

pub struct Decoder {
    contracts: Contracts,
    /// Request parts per transaction and E3, until its `E3Requested`.
    requests: BTreeMap<(B256, U256), RequestParts>,
    /// `SortitionCommitteeFinalized` members per transaction and E3, until its
    /// `CommitteeFinalized`.
    finalized: BTreeMap<(B256, U256), Vec<Address>>,
    /// Each requested E3's committee size, which the key proof's layout depends on.
    sizes: BTreeMap<U256, CiphernodesCommitteeSize>,
}

impl Decoder {
    pub fn new(contracts: Contracts) -> Self {
        Self {
            contracts,
            requests: BTreeMap::new(),
            finalized: BTreeMap::new(),
            sizes: BTreeMap::new(),
        }
    }

    pub fn decode(&mut self, log: &RawLog) -> Result<Vec<Decoded>, DecodeError> {
        let Some(&topic) = log.topics.first() else {
            return Ok(Vec::new());
        };
        let c = &self.contracts;
        let fact = if log.address == c.interfold {
            self.interfold(log, topic)?
        } else if log.address == c.registry {
            self.registry(log, topic)?
        } else if log.address == c.bonding {
            self.bonding(log, topic)?
        } else if c.randomness.contains(&log.address)
            && topic == IRandomnessProvider::RandomnessFulfilled::SIGNATURE_HASH
        {
            let event: IRandomnessProvider::RandomnessFulfilled =
                decode(log, "RandomnessFulfilled")?;
            return Ok(vec![Decoded::Read(PendingRead::Seed {
                at: log.at,
                time: log.time,
                e3: self.e3(event.e3Id),
            })]);
        } else {
            None
        };
        Ok(fact.into_iter().collect())
    }

    fn interfold(&mut self, log: &RawLog, topic: B256) -> Result<Option<Decoded>, DecodeError> {
        use IInterfold as I;
        let fact = match topic {
            I::E3Requested::SIGNATURE_HASH => {
                let event: I::E3Requested = decode(log, "E3Requested")?;
                return Ok(self.requested(log, event));
            }
            I::CommitteeFinalized::SIGNATURE_HASH => {
                let event: I::CommitteeFinalized = decode(log, "CommitteeFinalized")?;
                let members = self
                    .finalized
                    .remove(&(log.transaction, event.e3Id))
                    .unwrap_or_default();
                return Ok(Some(Decoded::Read(PendingRead::DkgTiming {
                    at: log.at,
                    time: log.time,
                    e3: self.e3(event.e3Id),
                    members,
                })));
            }
            I::CiphertextOutputPublished::SIGNATURE_HASH => {
                let event: I::CiphertextOutputPublished = decode(log, "CiphertextOutputPublished")?;
                return Ok(Some(Decoded::Read(PendingRead::Ciphertext {
                    at: log.at,
                    time: log.time,
                    e3: self.e3(event.e3Id),
                    ciphertext: event.ciphertextOutput,
                })));
            }
            I::E3StageChanged::SIGNATURE_HASH => {
                let event: I::E3StageChanged = decode(log, "E3StageChanged")?;
                ChainFact::StageChanged {
                    e3: self.e3(event.e3Id),
                    stage: stage(event.newStage)?,
                }
            }
            I::E3Failed::SIGNATURE_HASH => {
                let event: I::E3Failed = decode(log, "E3Failed")?;
                self.sizes.remove(&event.e3Id);
                ChainFact::Failed {
                    e3: self.e3(event.e3Id),
                    reason: failure(event.reason)?,
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
                    decode(log, "DkgFoldAttestationContextEstablished")?;
                self.parts(log.transaction, event.e3Id).attestation = Some(AttestationContext {
                    registry: event.registry,
                    verifier: event.dkgFoldAttestationVerifier,
                });
                return Ok(None);
            }
            R::CommitteeRequested::SIGNATURE_HASH => {
                let event: R::CommitteeRequested = decode(log, "CommitteeRequested")?;
                let time = UnixSecs::try_from(event.requestBlock).unwrap_or(UnixSecs::MAX);
                self.parts(log.transaction, event.e3Id).request = Some((time, event.ticketPrice));
                return Ok(None);
            }
            extra::CommitteeBondOwnerCapEnabled::SIGNATURE_HASH => {
                let event: extra::CommitteeBondOwnerCapEnabled =
                    decode(log, "CommitteeBondOwnerCapEnabled")?;
                self.parts(log.transaction, event.e3Id).owner_cap = true;
                return Ok(None);
            }
            R::SortitionCommitteeFinalized::SIGNATURE_HASH => {
                let event: R::SortitionCommitteeFinalized =
                    decode(log, "SortitionCommitteeFinalized")?;
                self.finalized
                    .insert((log.transaction, event.e3Id), event.committee);
                return Ok(None);
            }
            R::CommitteeProofPublished::SIGNATURE_HASH => {
                let event: R::CommitteeProofPublished = decode(log, "CommitteeProofPublished")?;
                let Some(size) = self.sizes.get(&event.e3Id) else {
                    return Ok(None);
                };
                let roster = roster(
                    &event.nodes,
                    &event.proof,
                    size.values().h,
                    event.pkCommitment,
                )?;
                ChainFact::KeyPublished {
                    e3: self.e3(event.e3Id),
                    committee: event.nodes,
                    roster,
                    commitment: event.pkCommitment,
                }
            }
            R::CommitteeMemberExpelled::SIGNATURE_HASH => {
                let event: R::CommitteeMemberExpelled = decode(log, "CommitteeMemberExpelled")?;
                ChainFact::MemberExpelled {
                    e3: self.e3(event.e3Id),
                    member: event.node,
                }
            }
            extra::AccusationVoteValiditySet::SIGNATURE_HASH => {
                let event: extra::AccusationVoteValiditySet =
                    decode(log, "AccusationVoteValiditySet")?;
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
                let event: B::OperatorActivationChanged = decode(log, "OperatorActivationChanged")?;
                ChainFact::OperatorActive {
                    operator: event.operator,
                    active: event.active,
                }
            }
            B::TicketBalanceUpdated::SIGNATURE_HASH => {
                let event: B::TicketBalanceUpdated = decode(log, "TicketBalanceUpdated")?;
                ChainFact::TicketBalance {
                    operator: event.operator,
                    balance: event.newBalance,
                }
            }
            B::BondOwnerSet::SIGNATURE_HASH => {
                let event: B::BondOwnerSet = decode(log, "BondOwnerSet")?;
                ChainFact::BondOwner {
                    operator: event.operator,
                    owner: event.bondOwner,
                }
            }
            B::EligibilityConfigurationVersionUpdated::SIGNATURE_HASH => {
                ChainFact::EligibilityReset
            }
            B::ConfigurationUpdated::SIGNATURE_HASH => {
                let event: B::ConfigurationUpdated = decode(log, "ConfigurationUpdated")?;
                if !affects_eligibility(event.parameter) {
                    return Ok(None);
                }
                ChainFact::EligibilityReset
            }
            extra::IdentityPolicyUpdated::SIGNATURE_HASH => {
                let event: extra::IdentityPolicyUpdated = decode(log, "IdentityPolicyUpdated")?;
                ChainFact::IdentityPolicy {
                    required: event.required,
                }
            }
            _ => return Ok(None),
        };
        Ok(Some(self.fact(log, fact)))
    }

    /// A request becomes a fact with the parts its transaction logged before it. A request for a
    /// crypto configuration or committee size this build does not support is skipped.
    fn requested(&mut self, log: &RawLog, event: IInterfold::E3Requested) -> Option<Decoded> {
        let parts = self.requests.remove(&(log.transaction, event.e3Id))?;
        let supported = event.cryptoConfigId == self.contracts.crypto_config;
        let size = committee_size(event.e3.committeeSize)?;
        let (Some(attestation), Some((time, ticket_price)), true) =
            (parts.attestation, parts.request, supported)
        else {
            return None;
        };
        self.sizes.insert(event.e3Id, size);
        let fact = ChainFact::E3Requested {
            e3: self.e3(event.e3Id),
            params: CryptoParams {
                param_set: event.e3.paramSet,
                committee_size: size,
                seed: B256::from(event.e3.seed),
            },
            interfold: log.address,
            attestation,
            request: CommitteeRequest {
                time,
                ticket_price,
                owner_cap: parts.owner_cap,
            },
        };
        Some(self.fact(log, fact))
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

fn decode<E: SolEvent>(log: &RawLog, event: &'static str) -> Result<E, DecodeError> {
    E::decode_raw_log(log.topics.iter().copied(), &log.data)
        .map_err(|source| DecodeError::Malformed { event, source })
}

/// The roster from the key proof's public inputs, as `CiphernodeRegistryOwnable` lays them out:
/// `abi.encode(bytes proof, bytes32[] inputs)` with `6 + 3H` inputs, the selected party IDs at
/// `[2, 2 + H)`, ascending, and the key commitment last.
fn roster(
    committee: &[Address],
    proof: &[u8],
    h: usize,
    commitment: B256,
) -> Result<Vec<Address>, DecodeError> {
    let (_, inputs) = <(Bytes, Vec<B256>)>::abi_decode_params(proof).map_err(|source| {
        DecodeError::Malformed {
            event: "CommitteeProofPublished",
            source,
        }
    })?;
    if inputs.len() != 6 + 3 * h || inputs.last() != Some(&commitment) {
        return Err(DecodeError::Roster(h));
    }
    let slots: Vec<usize> = inputs[2..2 + h]
        .iter()
        .map(|slot| usize::try_from(U256::from_be_bytes(slot.0)).unwrap_or(usize::MAX))
        .collect();
    let ordered = slots.windows(2).all(|pair| pair[0] < pair[1])
        && slots.iter().all(|slot| *slot < committee.len());
    if !ordered {
        return Err(DecodeError::Roster(h));
    }
    Ok(slots.into_iter().map(|slot| committee[slot]).collect())
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
