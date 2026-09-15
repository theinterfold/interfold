// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Shared public-domain inputs for secure l-BFV row proofs.

use crate::{CiphernodesCommittee, CircuitsErrors};
use alloy::primitives::{Address, B256, U256};
use e3_committee_hash::{
    hash_lbfv_accepted_party_set, lbfv_proof_session_limbs, LbfvProofDomainContext,
};
use e3_fhe_params::LBFV_CONSTANTS_VERSION;

/// Canonical field representation of the l-BFV proof-session identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LbfvProofSession {
    pub session_id_hi: u128,
    pub session_id_lo: u128,
}

/// Canonical field representation of the accepted party-set hash.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LbfvAcceptedPartySet {
    pub accepted_party_set_hash_hi: u128,
    pub accepted_party_set_hash_lo: u128,
}

/// Validate the supported l-BFV proof context and derive its session limbs.
pub fn lbfv_proof_session(
    context: LbfvProofDomainContext,
) -> Result<LbfvProofSession, CircuitsErrors> {
    if context.protocol_version == 0 {
        return Err(CircuitsErrors::Other(
            "l-BFV proof protocol version must be nonzero".to_string(),
        ));
    }
    if context.chain_id == 0 {
        return Err(CircuitsErrors::Other(
            "l-BFV proof chain ID must be nonzero".to_string(),
        ));
    }
    if context.interfold_address == Address::ZERO {
        return Err(CircuitsErrors::Other(
            "l-BFV proof Interfold address must be nonzero".to_string(),
        ));
    }
    if context.e3_id == U256::ZERO {
        return Err(CircuitsErrors::Other(
            "l-BFV proof E3 ID must be nonzero".to_string(),
        ));
    }
    if context.crypto_config_id == B256::ZERO {
        return Err(CircuitsErrors::Other(
            "l-BFV proof crypto configuration ID must be nonzero".to_string(),
        ));
    }
    if context.finalized_committee_hash == B256::ZERO {
        return Err(CircuitsErrors::Other(
            "l-BFV proof finalized committee hash must be nonzero".to_string(),
        ));
    }
    if context.lbfv_constants_version != LBFV_CONSTANTS_VERSION {
        return Err(CircuitsErrors::Other(format!(
            "l-BFV constants version must be {LBFV_CONSTANTS_VERSION}; received {}",
            context.lbfv_constants_version
        )));
    }
    if context.ciphertext_level != 0 || context.key_level != 0 {
        return Err(CircuitsErrors::Other(format!(
            "l-BFV row proofs support only ciphertext level 0 and key level 0; received ({}, {})",
            context.ciphertext_level, context.key_level
        )));
    }

    let limbs = lbfv_proof_session_limbs(context);
    Ok(LbfvProofSession {
        session_id_hi: limbs.hi,
        session_id_lo: limbs.lo,
    })
}

/// Validate one generation party ID against the full committee size.
pub fn validate_lbfv_generation_party_id(
    party_id: u32,
    committee: &CiphernodesCommittee,
) -> Result<(), CircuitsErrors> {
    if usize::try_from(party_id).map_or(true, |id| id >= committee.n) {
        return Err(CircuitsErrors::Other(format!(
            "l-BFV generation party ID {party_id} must be less than {}",
            committee.n
        )));
    }
    Ok(())
}

/// Validate and derive the accepted party-set hash for aggregation.
pub fn lbfv_accepted_party_set(
    party_ids: &[u32],
    committee: &CiphernodesCommittee,
) -> Result<LbfvAcceptedPartySet, CircuitsErrors> {
    let hash = hash_lbfv_accepted_party_set(party_ids, committee.n, committee.h)
        .map_err(CircuitsErrors::Other)?;
    let limbs = e3_committee_hash::split_hash_to_field_limbs(hash);
    Ok(LbfvAcceptedPartySet {
        accepted_party_set_hash_hi: limbs.hi,
        accepted_party_set_hash_lo: limbs.lo,
    })
}

/// Return deterministic nonzero context for circuit samples and code generation.
pub fn sample_lbfv_proof_domain() -> LbfvProofDomainContext {
    LbfvProofDomainContext {
        protocol_version: 4,
        chain_id: 31_337,
        interfold_address: Address::repeat_byte(0x11),
        e3_id: U256::from(7),
        crypto_config_id: B256::repeat_byte(0x22),
        finalized_committee_hash: B256::repeat_byte(0x33),
        lbfv_constants_version: LBFV_CONSTANTS_VERSION,
        ciphertext_level: 0,
        key_level: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CiphernodesCommitteeSize;

    #[test]
    fn sample_context_produces_canonical_session_limbs() {
        let session = lbfv_proof_session(sample_lbfv_proof_domain()).unwrap();
        assert_ne!((session.session_id_hi, session.session_id_lo), (0, 0));
    }

    #[test]
    fn generation_party_id_must_be_in_range() {
        let committee = CiphernodesCommitteeSize::Minimum.values();
        validate_lbfv_generation_party_id(2, &committee).unwrap();
        assert!(validate_lbfv_generation_party_id(3, &committee).is_err());
    }

    #[test]
    fn accepted_set_must_be_exact_and_canonical() {
        let committee = CiphernodesCommitteeSize::Minimum.values();
        lbfv_accepted_party_set(&[0, 2], &committee).unwrap();
        assert!(lbfv_accepted_party_set(&[0], &committee).is_err());
        assert!(lbfv_accepted_party_set(&[1, 1], &committee).is_err());
        assert!(lbfv_accepted_party_set(&[2, 1], &committee).is_err());
        assert!(lbfv_accepted_party_set(&[0, 3], &committee).is_err());
    }
}
