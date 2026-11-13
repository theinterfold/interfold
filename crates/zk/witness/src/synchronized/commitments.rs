// SPDX-License-Identifier: LGPL-3.0-only

//! Matches `core/synchronized/commitments.nr`, not the upstream PRF's key-to-field map.

use super::{dealers, invalid, keys, owner, KeyBytes, SetupBinding};
use crate::{compute_commitments, WitnessError};
use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use e3_zk_config::{field::bigint_to_field, field::get_zkp_modulus, synchronized::Configs};
use num_bigint::{BigInt, Sign};

const DOMAIN: [u8; 64] = {
    let label = b"interfold:sync-dkg:v1";
    let mut output = [0; 64];
    let mut index = 0;
    while index < label.len() {
        output[index] = label[index];
        index += 1;
    }
    output
};

fn prefix(role: u64, config: &Configs, binding: SetupBinding) -> Vec<Fr> {
    vec![
        Fr::from(role),
        Fr::from(config.profile_id[0]),
        Fr::from(config.profile_id[1]),
        Fr::from(binding[0]),
        Fr::from(binding[1]),
        Fr::from(config.committee.values().n as u64),
        Fr::from(config.key_bits as u64),
    ]
}

fn commit(payload: Vec<Fr>) -> BigInt {
    let pattern = [0x80000000 | payload.len() as u32, 1];
    let digest = compute_commitments(payload, DOMAIN, pattern)[0];
    BigInt::from_bytes_le(Sign::Plus, &digest.into_bigint().to_bytes_le())
}

fn key_field(
    config: &Configs,
    binding: SetupBinding,
    dealer: u32,
    recipient: u32,
    key: &KeyBytes,
) -> Result<Fr, WitnessError> {
    owner(config, dealer)?;
    owner(config, recipient)?;
    keys(config, std::slice::from_ref(key), 1)?;
    let mut payload = prefix(1, config, binding);
    payload.extend([Fr::from(dealer), Fr::from(recipient)]);
    payload.extend(key.iter().map(|&byte| Fr::from(byte)));
    Ok(bigint_to_field(&commit(payload)))
}

pub fn directed_key(
    config: &Configs,
    binding: SetupBinding,
    dealer: u32,
    recipient: u32,
    key: &KeyBytes,
) -> Result<BigInt, WitnessError> {
    Ok(BigInt::from_bytes_le(
        Sign::Plus,
        &key_field(config, binding, dealer, recipient, key)?
            .into_bigint()
            .to_bytes_le(),
    ))
}

pub fn outgoing_root(
    config: &Configs,
    binding: SetupBinding,
    dealer: u32,
    outgoing: &[KeyBytes],
) -> Result<BigInt, WitnessError> {
    owner(config, dealer)?;
    keys(config, outgoing, config.committee.values().n)?;
    let mut payload = prefix(2, config, binding);
    payload.push(Fr::from(dealer));
    for (recipient, key) in outgoing.iter().enumerate() {
        payload.push(key_field(config, binding, dealer, recipient as u32, key)?);
    }
    Ok(commit(payload))
}

pub fn key_bundle(
    config: &Configs,
    binding: SetupBinding,
    recipient: u32,
    dealer_ids: &[u32],
    sk_commitment: &BigInt,
    outgoing: &[KeyBytes],
    incoming: &[KeyBytes],
) -> Result<BigInt, WitnessError> {
    owner(config, recipient)?;
    dealers(config, dealer_ids)?;
    keys(config, outgoing, config.committee.values().n)?;
    keys(config, incoming, config.committee.values().h)?;
    if sk_commitment.sign() == Sign::Minus || sk_commitment >= &get_zkp_modulus() {
        return Err(invalid("SK commitment is not a canonical scalar"));
    }
    let mut payload = prefix(3, config, binding);
    payload.extend([
        Fr::from(recipient),
        Fr::from(dealer_ids.len() as u64),
        bigint_to_field(sk_commitment),
    ]);
    for (&dealer, incoming) in dealer_ids.iter().zip(incoming) {
        let out = key_field(
            config,
            binding,
            recipient,
            dealer,
            &outgoing[dealer as usize],
        )?;
        let received = key_field(config, binding, dealer, recipient, incoming)?;
        if recipient == dealer && out != received {
            return Err(invalid("own PRF key directions differ"));
        }
        payload.extend([Fr::from(dealer), out, received]);
    }
    Ok(commit(payload))
}
