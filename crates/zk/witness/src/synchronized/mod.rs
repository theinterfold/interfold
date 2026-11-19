// SPDX-License-Identifier: LGPL-3.0-only

//! Deterministic private-input preparation for the disabled synchronized DKG leaves.
//! The caller owns authenticated setup context, peer commitments and encrypted secret storage.

pub mod commitments;
pub mod pk_generation;
pub mod share_computation;
pub mod share_decryption;

use crate::WitnessError;
use e3_zk_config::synchronized::Configs;

pub type SetupBinding = [u128; 2];
pub type KeyBytes = [u8; 32];

fn invalid(message: &str) -> WitnessError {
    WitnessError::Other(message.into())
}

fn owner(config: &Configs, id: u32) -> Result<(), WitnessError> {
    if id as usize >= config.committee.values().n {
        return Err(invalid("party is outside the synchronized committee"));
    }
    Ok(())
}

fn keys(config: &Configs, keys: &[KeyBytes], count: usize) -> Result<(), WitnessError> {
    if keys.len() != count {
        return Err(invalid(
            "directed PRF key dimensions do not match the statement",
        ));
    }
    if keys
        .iter()
        .any(|key| key[config.key_bits / 8..].iter().any(|&byte| byte != 0))
    {
        return Err(invalid("PRF key exceeds the synchronized profile width"));
    }
    Ok(())
}

fn dealers(config: &Configs, ids: &[u32]) -> Result<(), WitnessError> {
    if ids.len() != config.committee.values().h || ids.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(invalid("dealers must be the canonical H-wide roster"));
    }
    for &id in ids {
        owner(config, id)?;
    }
    Ok(())
}

fn binding_json(binding: SetupBinding) -> serde_json::Value {
    serde_json::json!([binding[0].to_string(), binding[1].to_string()])
}
