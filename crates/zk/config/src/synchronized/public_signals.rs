// SPDX-License-Identifier: LGPL-3.0-only

//! Exact public layouts of synchronized DKG definitions, excluding Honk protocol fields.

use super::Configs;
use crate::{field::get_zkp_modulus, CircuitName, ConfigError};
use num_bigint::{BigInt, Sign};

pub type Field = [u8; 32];

pub struct PublicSignals {
    circuit: CircuitName,
    fields: Vec<Field>,
    n: usize,
    l: usize,
    h: usize,
}

impl PublicSignals {
    pub fn decode(
        config: &Configs,
        circuit: CircuitName,
        encoded: &[u8],
    ) -> Result<Self, ConfigError> {
        let invalid = || ConfigError::Other("invalid synchronized public-signal layout".into());
        let count = config.public_inputs(circuit).ok_or_else(invalid)?
            + config.public_outputs(circuit).ok_or_else(invalid)?;
        if encoded.len() != count * 32 {
            return Err(invalid());
        }
        let fields: Vec<Field> = encoded
            .chunks_exact(32)
            .map(|field| field.try_into().unwrap())
            .collect();
        if fields
            .iter()
            .any(|field| BigInt::from_bytes_be(Sign::Plus, field) >= get_zkp_modulus())
        {
            return Err(invalid());
        }
        let result = Self {
            circuit,
            fields,
            n: config.committee.values().n,
            l: config.threshold.moduli().len(),
            h: config.committee.values().h,
        };
        if matches!(
            circuit,
            CircuitName::PkGeneration
                | CircuitName::SkShareComputation
                | CircuitName::DkgShareDecryption
                | CircuitName::NodeFold
                | CircuitName::NodesFold
        ) {
            let start = result.identity_start();
            for field in &result.fields[start..start + 2] {
                if field[..16] != [0; 16] {
                    return Err(invalid());
                }
            }
            if result.party_id().is_none_or(|id| id as usize >= result.n) {
                return Err(invalid());
            }
        }
        if matches!(
            circuit,
            CircuitName::DkgShareDecryption | CircuitName::NodesFold
        ) {
            let dealers = result.dealers().ok_or_else(invalid)?;
            if dealers.iter().any(|&dealer| dealer as usize >= result.n)
                || dealers.windows(2).any(|pair| pair[0] >= pair[1])
            {
                return Err(invalid());
            }
        }
        Ok(result)
    }

    pub fn binding(&self) -> Option<[u128; 2]> {
        self.party_id()?;
        let start = self.identity_start();
        Some([
            u128::from_be_bytes(self.fields[start][16..].try_into().unwrap()),
            u128::from_be_bytes(self.fields[start + 1][16..].try_into().unwrap()),
        ])
    }

    pub fn fields(&self) -> &[Field] {
        &self.fields
    }

    pub fn identity_fields(&self) -> Option<[Field; 3]> {
        self.party_id()?;
        let start = self.identity_start();
        Some(self.fields[start..start + 3].try_into().unwrap())
    }

    pub fn ciphertext_commitment(&self) -> Option<Field> {
        (self.circuit == CircuitName::ShareEncryption).then(|| self.fields[2])
    }

    pub fn party_id(&self) -> Option<u32> {
        matches!(
            self.circuit,
            CircuitName::PkGeneration
                | CircuitName::SkShareComputation
                | CircuitName::DkgShareDecryption
                | CircuitName::NodeFold
                | CircuitName::NodesFold
        )
        .then(|| decode_id(&self.fields[self.identity_start() + 2]))
        .flatten()
    }

    pub fn sk_commitment(&self) -> Option<Field> {
        match self.circuit {
            CircuitName::PkGeneration | CircuitName::SkShareComputation => Some(self.fields[3]),
            CircuitName::DkgShareDecryption => Some(self.fields[self.fields.len() - 2]),
            CircuitName::NodesFold => Some(self.fields[self.fields.len() - 2]),
            _ => None,
        }
    }

    pub fn pk_commitment(&self) -> Option<Field> {
        match self.circuit {
            CircuitName::PkGeneration => Some(self.fields[4]),
            CircuitName::PkBfv | CircuitName::ShareEncryption => Some(self.fields[0]),
            CircuitName::NodeFold => Some(self.fields[4]),
            _ => None,
        }
    }

    pub fn outgoing_root(&self) -> Option<Field> {
        match self.circuit {
            CircuitName::SkShareComputation => self.fields.last().copied(),
            CircuitName::DkgShareDecryption => Some(self.fields[3 + self.h]),
            CircuitName::NodeFold => Some(self.fields[5]),
            _ => None,
        }
    }

    pub fn message_commitments(&self) -> Option<&[Field]> {
        match self.circuit {
            CircuitName::SkShareComputation => Some(&self.fields[4..4 + self.n * self.l]),
            CircuitName::DkgShareDecryption => {
                Some(&self.fields[4 + self.h..4 + self.h + self.h * self.l])
            }
            CircuitName::ShareEncryption => Some(&self.fields[1..2]),
            CircuitName::NodeFold => Some(&self.fields[6..6 + self.n * self.l]),
            _ => None,
        }
    }

    pub fn dealers(&self) -> Option<Vec<u32>> {
        let start = match self.circuit {
            CircuitName::DkgShareDecryption => 3,
            CircuitName::NodesFold => 4,
            _ => return None,
        };
        self.fields[start..start + self.h]
            .iter()
            .map(decode_id)
            .collect()
    }

    pub fn key_bundle(&self) -> Option<Field> {
        matches!(
            self.circuit,
            CircuitName::DkgShareDecryption | CircuitName::NodesFold
        )
        .then(|| *self.fields.last().unwrap())
    }

    pub fn tree_hash(&self) -> Option<Field> {
        match self.circuit {
            CircuitName::NodeFold => Some(self.fields[3]),
            CircuitName::NodesFold => Some(self.fields[0]),
            _ => None,
        }
    }

    pub fn recipient_keys(&self) -> Option<&[Field]> {
        (self.circuit == CircuitName::NodeFold)
            .then(|| &self.fields[6 + self.n * self.l..6 + self.n * self.l + self.n])
    }

    pub fn ciphertext_commitments(&self) -> Option<&[Field]> {
        (self.circuit == CircuitName::NodeFold)
            .then(|| &self.fields[6 + self.n * self.l + self.n..])
    }

    pub fn threshold_keys(&self) -> Option<&[Field]> {
        (self.circuit == CircuitName::NodesFold).then(|| &self.fields[4 + self.h..4 + 2 * self.h])
    }

    fn identity_start(&self) -> usize {
        usize::from(self.circuit == CircuitName::NodesFold)
    }
}

fn decode_id(field: &Field) -> Option<u32> {
    (field[..28] == [0; 28]).then(|| u32::from_be_bytes(field[28..].try_into().unwrap()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use e3_committee::CiphernodesCommitteeSize;
    use e3_fhe_params::BfvProfile;

    #[test]
    fn exact_sync_layout_rejects_noncanonical_fields_context_and_rosters() {
        let config = Configs::for_profile(
            BfvProfile::SyncDecInsecure64,
            CiphernodesCommitteeSize::Minimum,
        )
        .unwrap();
        for circuit in CircuitName::SYNCHRONIZED_DKG {
            let count =
                config.public_inputs(circuit).unwrap() + config.public_outputs(circuit).unwrap();
            let mut bytes = vec![0; count * 32];
            if matches!(
                circuit,
                CircuitName::DkgShareDecryption | CircuitName::NodesFold
            ) {
                let start = if circuit == CircuitName::NodesFold {
                    4
                } else {
                    3
                };
                bytes[(start + 1) * 32 + 31] = 2; // Non-prefix H=[0,2].
            }
            let public = PublicSignals::decode(&config, circuit, &bytes).unwrap();
            assert!(PublicSignals::decode(&config, circuit, &bytes[..bytes.len() - 1]).is_err());
            let mut longer = bytes.clone();
            longer.extend([0; 32]);
            assert!(PublicSignals::decode(&config, circuit, &longer).is_err());
            let (_, modulus) = get_zkp_modulus().to_bytes_be();
            let mut noncanonical = bytes.clone();
            noncanonical[..32].copy_from_slice(&modulus);
            assert!(PublicSignals::decode(&config, circuit, &noncanonical).is_err());
            if public.binding().is_some() {
                let start = public.identity_start();
                let mut large_context = bytes.clone();
                large_context[start * 32 + 15] = 1;
                assert!(PublicSignals::decode(&config, circuit, &large_context).is_err());
                let mut outside = bytes.clone();
                outside[(start + 2) * 32 + 31] = 3;
                assert!(PublicSignals::decode(&config, circuit, &outside).is_err());
                outside[(start + 2) * 32] = 1;
                assert!(PublicSignals::decode(&config, circuit, &outside).is_err());
            }
            if matches!(
                circuit,
                CircuitName::DkgShareDecryption | CircuitName::NodesFold
            ) {
                assert_eq!(public.dealers(), Some(vec![0, 2]));
                let start = if circuit == CircuitName::NodesFold {
                    4
                } else {
                    3
                };
                bytes[(start + 1) * 32 + 31] = 0;
                assert!(PublicSignals::decode(&config, circuit, &bytes).is_err());
            }
        }
    }
}
