// SPDX-License-Identifier: LGPL-3.0-only

//! Deterministic encoding of the disabled dealer/recipient joins. These inputs carry proofs, not
//! signature/chain authority. Callers authenticate children and supply canonical context/roster.

use super::{binding_json, dealers, invalid, owner, SetupBinding};
use crate::{compute_vk_hash, WitnessError};
use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use e3_zk_config::{
    field::get_zkp_modulus,
    synchronized::{
        public_signals::{Field, PublicSignals},
        Configs,
    },
    CircuitName,
};
use num_bigint::{BigInt, Sign};
use serde_json::{json, Value};

pub struct Child<'a> {
    pub circuit: CircuitName,
    pub proof: &'a [u8],
    pub public_signals: &'a [u8],
}

pub struct VerificationKey<'a> {
    pub fields: &'a [u8],
    pub hash: Field,
}

/// Ordered immediate keys and all descendants of the recipient setup proof. The setup circuit's
/// own VK is selected separately by its verifier, not recursively included in itself.
pub struct VerificationKeys<'a> {
    pub c0: VerificationKey<'a>,
    pub c1: VerificationKey<'a>,
    pub c2: VerificationKey<'a>,
    pub c3: VerificationKey<'a>,
    pub c4: VerificationKey<'a>,
    pub node: VerificationKey<'a>,
}

pub(crate) fn hash(fields: &[Field]) -> Result<Field, WitnessError> {
    for field in fields {
        canonical(field).map_err(|error| WitnessError::VerificationKey(error.to_string()))?;
    }
    let value = compute_vk_hash(
        fields
            .iter()
            .map(|field| Fr::from_be_bytes_mod_order(field))
            .collect(),
    );
    Ok(value.into_bigint().to_bytes_be().try_into().unwrap())
}

impl VerificationKeys<'_> {
    pub fn dealer_tree(&self) -> Result<Field, WitnessError> {
        hash(&[self.c1.hash, self.c2.hash, self.c3.hash])
    }

    pub fn setup_tree(&self) -> Result<Field, WitnessError> {
        hash(&[
            self.node.hash,
            self.dealer_tree()?,
            self.c0.hash,
            self.c2.hash,
            self.c4.hash,
        ])
    }
}

fn canonical(field: &Field) -> Result<(), WitnessError> {
    if BigInt::from_bytes_be(Sign::Plus, field) >= get_zkp_modulus() {
        return Err(invalid("noncanonical recursive field"));
    }
    Ok(())
}

pub(crate) fn fields(bytes: &[u8]) -> Result<Value, WitnessError> {
    if bytes.is_empty() || !bytes.len().is_multiple_of(32) {
        return Err(invalid("recursive fields must be nonempty 32-byte scalars"));
    }
    let mut result = Vec::new();
    for bytes in bytes.chunks_exact(32) {
        canonical(bytes.try_into().unwrap())?;
        result.push(format!("0x{}", hex::encode(bytes)));
    }
    Ok(json!(result))
}

pub(crate) fn statement(
    config: &Configs,
    child: &Child<'_>,
    expected: CircuitName,
) -> Result<PublicSignals, WitnessError> {
    if child.circuit != expected {
        return Err(invalid("unexpected synchronized child circuit"));
    }
    PublicSignals::decode(config, expected, child.public_signals)
        .map_err(|error| invalid(&error.to_string()))
}

fn identity(public: &PublicSignals, binding: SetupBinding, id: u32) -> Result<(), WitnessError> {
    if public.binding() != Some(binding) || public.party_id() != Some(id) {
        return Err(invalid("child belongs to another setup or party"));
    }
    Ok(())
}

pub(crate) fn insert_child(
    json: &mut Value,
    prefix: &str,
    child: &Child<'_>,
    key: &VerificationKey<'_>,
) -> Result<(), WitnessError> {
    canonical(&key.hash).map_err(|error| WitnessError::VerificationKey(error.to_string()))?;
    json[format!("{prefix}_vk")] =
        fields(key.fields).map_err(|error| WitnessError::VerificationKey(error.to_string()))?;
    json[format!("{prefix}_key_hash")] = json!(format!("0x{}", hex::encode(key.hash)));
    json[format!("{prefix}_proof")] = fields(child.proof)?;
    json[format!("{prefix}_public")] = fields(child.public_signals)?;
    Ok(())
}

/// Only public statements are hashed. Cryptographic verification/authentication belongs to the
/// caller; malformed layouts, identity, shape, order and mixed genealogy are rejected here.
pub fn dealer_batch(
    config: &Configs,
    binding: SetupBinding,
    roster: &[u32],
    nodes: &[Child<'_>],
) -> Result<Field, WitnessError> {
    dealers(config, roster)?;
    if nodes.len() != roster.len() {
        return Err(invalid("incomplete dealer batch"));
    }
    let mut payload = super::commitments::prefix(5, config, binding);
    payload.extend([
        Fr::from(roster.len() as u64),
        Fr::from(config.threshold.moduli().len() as u64),
    ]);
    let mut tree = None;
    for (&id, node) in roster.iter().zip(nodes) {
        let public = statement(config, node, CircuitName::NodeFold)?;
        identity(&public, binding, id)?;
        if tree.is_some_and(|expected| public.tree_hash() != Some(expected)) {
            return Err(invalid("mixed dealer genealogy"));
        }
        tree = public.tree_hash();
        payload.extend(
            public
                .fields()
                .iter()
                .map(|field| Fr::from_be_bytes_mod_order(field)),
        );
    }
    let value = super::commitments::commit(payload);
    let (_, bytes) = value.to_bytes_be();
    let mut field = [0; 32];
    field[32 - bytes.len()..].copy_from_slice(&bytes);
    Ok(field)
}

/// Complete non-self C3 fan-out, recipient-major then threshold CRT-major. Explicit slot metadata
/// cannot hide omissions or duplicates: its only supported order is derived from the owner/config.
pub fn dealer(
    config: &Configs,
    binding: SetupBinding,
    id: u32,
    c1: Child<'_>,
    c2: Child<'_>,
    c3: &[Child<'_>],
    keys: &VerificationKeys<'_>,
) -> Result<Value, WitnessError> {
    owner(config, id)?;
    let generation = statement(config, &c1, CircuitName::PkGeneration)?;
    let sharing = statement(config, &c2, CircuitName::SkShareComputation)?;
    identity(&generation, binding, id)?;
    identity(&sharing, binding, id)?;
    if generation.sk_commitment() != sharing.sk_commitment() {
        return Err(invalid("C1/C2 secret differs"));
    }
    let n = config.committee.values().n;
    let l = config.threshold.moduli().len();
    if c3.len() != (n - 1) * l {
        return Err(invalid("incomplete non-self C3 fan-out"));
    }
    let mut slot = 0;
    for recipient in (0..n).filter(|&recipient| recipient != id as usize) {
        let mut key = None;
        for limb in 0..l {
            let public = statement(config, &c3[slot], CircuitName::ShareEncryption)?;
            if public.message_commitments().unwrap()[0]
                != sharing.message_commitments().unwrap()[recipient * l + limb]
            {
                return Err(invalid("C2/C3 message differs"));
            }
            if key.is_some_and(|key| Some(key) != public.pk_commitment()) {
                return Err(invalid("C3 recipient key differs across CRT rows"));
            }
            key = public.pk_commitment();
            slot += 1;
        }
    }
    let mut input = json!({"setup_binding": binding_json(binding), "dealer_id": id});
    insert_child(&mut input, "c1", &c1, &keys.c1)?;
    insert_child(&mut input, "c2", &c2, &keys.c2)?;
    // A single VK verifies every C3 row.
    insert_child(&mut input, "c3", &c3[0], &keys.c3)?;
    input.as_object_mut().unwrap().remove("c3_proof");
    input["c3_proofs"] = Value::Array(
        c3.iter()
            .map(|child| fields(child.proof))
            .collect::<Result<_, _>>()?,
    );
    input["c3_public"] = Value::Array(
        c3.iter()
            .map(|child| fields(child.public_signals))
            .collect::<Result<_, _>>()?,
    );
    Ok(input)
}

/// Join the selected dealers to one recipient, including recipients outside H. Its own C2 is
/// needed even outside H to anchor the outgoing half of the bidirectional bundle.
#[allow(clippy::too_many_arguments)]
pub fn recipient(
    config: &Configs,
    binding: SetupBinding,
    id: u32,
    roster: &[u32],
    c0: Child<'_>,
    c2: Child<'_>,
    c4: Child<'_>,
    nodes: &[Child<'_>],
    keys: &VerificationKeys<'_>,
) -> Result<Value, WitnessError> {
    owner(config, id)?;
    dealers(config, roster)?;
    let pk = statement(config, &c0, CircuitName::PkBfv)?;
    let own = statement(config, &c2, CircuitName::SkShareComputation)?;
    let opening = statement(config, &c4, CircuitName::DkgShareDecryption)?;
    identity(&own, binding, id)?;
    identity(&opening, binding, id)?;
    if opening.dealers().as_deref() != Some(roster)
        || own.outgoing_root() != opening.outgoing_root()
        || nodes.len() != roster.len()
    {
        return Err(invalid("C4 roster or outgoing-root anchor differs"));
    }
    let l = config.threshold.moduli().len();
    let tree = keys.dealer_tree()?;
    for (row, (&dealer, node)) in roster.iter().zip(nodes).enumerate() {
        let public = statement(config, node, CircuitName::NodeFold)?;
        identity(&public, binding, dealer)?;
        if public.tree_hash() != Some(tree) {
            return Err(WitnessError::VerificationKey(
                "dealer genealogy differs from the local verifier keys".into(),
            ));
        }
        let messages = public.message_commitments().unwrap();
        if messages[id as usize * l..(id as usize + 1) * l]
            != opening.message_commitments().unwrap()[row * l..(row + 1) * l]
        {
            return Err(invalid("C2/C4 message differs"));
        }
        if dealer == id {
            if public.outgoing_root() != own.outgoing_root()
                || public.message_commitments() != own.message_commitments()
            {
                return Err(invalid("own C2 contribution differs"));
            }
        } else if public.recipient_keys().unwrap()[id as usize] != pk.pk_commitment().unwrap() {
            return Err(invalid("C3 key differs from recipient C0"));
        }
    }
    let mut input = json!({
        "expected_tree_hash": format!("0x{}", hex::encode(keys.setup_tree()?)),
        "setup_binding": binding_json(binding),
        "recipient_id": id,
        "dealer_ids": roster,
    });
    insert_child(&mut input, "c0", &c0, &keys.c0)?;
    insert_child(&mut input, "c2", &c2, &keys.c2)?;
    insert_child(&mut input, "c4", &c4, &keys.c4)?;
    insert_child(&mut input, "node", &nodes[0], &keys.node)?;
    input.as_object_mut().unwrap().remove("node_proof");
    input["node_proofs"] = Value::Array(
        nodes
            .iter()
            .map(|child| fields(child.proof))
            .collect::<Result<_, _>>()?,
    );
    input["node_public"] = Value::Array(
        nodes
            .iter()
            .map(|child| fields(child.public_signals))
            .collect::<Result<_, _>>()?,
    );
    Ok(input)
}

#[cfg(test)]
mod tests {
    use super::*;
    use e3_committee::CiphernodesCommitteeSize;
    use e3_fhe_params::BfvProfile;

    fn key(fields: &[u8], hash: u8) -> VerificationKey<'_> {
        let mut value = [0; 32];
        value[31] = hash;
        VerificationKey {
            fields,
            hash: value,
        }
    }

    fn keys(fields: &[u8]) -> VerificationKeys<'_> {
        VerificationKeys {
            c0: key(fields, 1),
            c1: key(fields, 2),
            c2: key(fields, 3),
            c3: key(fields, 4),
            c4: key(fields, 5),
            node: key(fields, 6),
        }
    }

    #[test]
    fn every_descendant_and_its_position_affects_the_setup_anchor() {
        let bytes = [0; 32];
        let original = keys(&bytes).setup_tree().unwrap();
        for index in 0..6 {
            let mut changed = keys(&bytes);
            let hash = match index {
                0 => &mut changed.c0.hash,
                1 => &mut changed.c1.hash,
                2 => &mut changed.c2.hash,
                3 => &mut changed.c3.hash,
                4 => &mut changed.c4.hash,
                _ => &mut changed.node.hash,
            };
            hash[31] += 10;
            assert_ne!(changed.setup_tree().unwrap(), original);
        }
        let mut changed = keys(&bytes);
        std::mem::swap(&mut changed.c1, &mut changed.c3);
        assert_ne!(changed.setup_tree().unwrap(), original);
        changed.c0.hash = [255; 32];
        assert!(changed.setup_tree().is_err());
        assert!(fields(&[0; 31]).is_err());
        assert!(fields(&[255; 32]).is_err());
    }

    #[test]
    fn incomplete_or_misordered_fanout_is_not_encoded() {
        let config = Configs::for_profile(
            BfvProfile::SyncDecInsecure64,
            CiphernodesCommitteeSize::Minimum,
        )
        .unwrap();
        let mut c1 = vec![0; 5 * 32];
        let mut c2 = vec![0; 14 * 32];
        // Context [1,2], dealer 2. Same SK anchor and explicit recipient/CRT messages.
        for public in [&mut c1, &mut c2] {
            public[31] = 1;
            public[63] = 2;
            public[95] = 2;
        }
        for slot in 0..9 {
            c2[(4 + slot) * 32 + 31] = slot as u8 + 1;
        }
        let bytes = [0; 32]; // Synthetic proof bytes test encoding only.
        let mut transport = vec![vec![0; 3 * 32]; 6];
        for (slot, public) in transport.iter_mut().enumerate() {
            public[31] = (slot / 3) as u8 + 10;
            public[63] = slot as u8 + 1;
        }
        let attempt = |transport: &[Vec<u8>]| {
            dealer(
                &config,
                [1, 2],
                2,
                Child {
                    circuit: CircuitName::PkGeneration,
                    proof: &bytes,
                    public_signals: &c1,
                },
                Child {
                    circuit: CircuitName::SkShareComputation,
                    proof: &bytes,
                    public_signals: &c2,
                },
                &transport
                    .iter()
                    .map(|public| Child {
                        circuit: CircuitName::ShareEncryption,
                        proof: &bytes,
                        public_signals: public,
                    })
                    .collect::<Vec<_>>(),
                &keys(&bytes),
            )
        };
        assert!(attempt(&transport).is_ok());
        assert!(attempt(&transport[..5]).is_err());
        transport.swap(0, 1);
        assert!(attempt(&transport).is_err());
        transport.swap(0, 1);
        transport[5][31] += 1;
        assert!(attempt(&transport).is_err());
    }

    #[test]
    fn batch_commits_every_public_slot_not_only_the_threshold_keys() {
        let config = Configs::for_profile(
            BfvProfile::SyncDecInsecure64,
            CiphernodesCommitteeSize::Minimum,
        )
        .unwrap();
        let mut rows = vec![vec![0; 27 * 32]; 2];
        for (row, bytes) in rows.iter_mut().enumerate() {
            bytes[31] = 10;
            bytes[63] = 20;
            bytes[95] = (2 * row) as u8;
            bytes[127] = 100;
        }
        let attempt = |rows: &[Vec<u8>]| {
            dealer_batch(
                &config,
                [10, 20],
                &[0, 2],
                &rows
                    .iter()
                    .map(|bytes| Child {
                        circuit: CircuitName::NodeFold,
                        proof: &[],
                        public_signals: bytes,
                    })
                    .collect::<Vec<_>>(),
            )
        };
        let original = attempt(&rows).unwrap();
        for row in 0..2 {
            for slot in 4..27 {
                let mut altered = rows.clone();
                altered[row][slot * 32 + 31] ^= 1;
                assert_ne!(attempt(&altered).unwrap(), original);
            }
        }
        assert!(attempt(&rows[..1]).is_err());
        rows.swap(0, 1);
        assert!(attempt(&rows).is_err());
    }
}
