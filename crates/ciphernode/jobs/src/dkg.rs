// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::{dkg_preset, Blobs, JobError, JobRunner};
use alloy_primitives::keccak256;
use e3_fhe_params::BfvParamSet;
use e3_protocol::{
    dkg::{DkgWork, DkgWorkResult, OwnKey},
    node::CryptoParams,
    proof::ZkProof,
    BlobRef,
};
use e3_trbfv::helpers::serialize_secret_key;
use fhe::bfv::{PublicKey, SecretKey};
use fhe_traits::{DeserializeParametrized, Serialize};
use rand::rngs::OsRng;
use rand_core::UnwrapErr;

impl<B: Blobs> JobRunner<B> {
    pub(crate) fn run_dkg(
        &self,
        params: &CryptoParams,
        work: &DkgWork,
    ) -> Result<DkgWorkResult, JobError> {
        match work {
            DkgWork::MakeEncryptionKey => self.make_encryption_key(params),
            DkgWork::CheckEncryptionKey { sender, key, proof } => {
                Ok(DkgWorkResult::EncryptionKeyChecked {
                    sender: *sender,
                    valid: self.check_encryption_key(params, key, proof)?,
                })
            }
            _ => Err(JobError::NotImplemented("this DKG job")),
        }
    }

    fn make_encryption_key(&self, params: &CryptoParams) -> Result<DkgWorkResult, JobError> {
        let bfv = BfvParamSet::from(dkg_preset(params)?).build_arc();
        let mut rng = UnwrapErr(OsRng);
        let secret = SecretKey::random(&bfv, &mut rng);
        let public = PublicKey::new(&secret, &mut rng).to_bytes();
        let secret = serialize_secret_key(&secret).map_err(|e| JobError::Crypto(e.to_string()))?;
        Ok(DkgWorkResult::EncryptionKeyMade(OwnKey {
            public: self.blobs.put(&public),
            secret: self.seal(&secret)?,
            proof: placeholder_c0(&public, &self.blobs),
        }))
    }

    /// A key counts when it decodes under the request's DKG parameters and its proof commits to
    /// it.
    fn check_encryption_key(
        &self,
        params: &CryptoParams,
        key: &BlobRef,
        proof: &ZkProof,
    ) -> Result<bool, JobError> {
        let bfv = BfvParamSet::from(dkg_preset(params)?).build_arc();
        let Ok(bytes) = self.blobs.get(key) else {
            return Ok(false);
        };
        let decodes = PublicKey::from_bytes(&bytes, &bfv).is_ok();
        Ok(decodes && proof.public_inputs == [keccak256(&bytes)])
    }
}

/// Stands in for the C0 proof until the prover is wired in: it commits to the key's bytes, as
/// the real proof's key commitment does, and proves nothing.
fn placeholder_c0(public: &[u8], blobs: &impl Blobs) -> ZkProof {
    ZkProof {
        data: blobs.put(b"placeholder C0 proof"),
        public_inputs: vec![keccak256(public)],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MemoryBlobs;
    use alloy_primitives::B256;
    use e3_committee::CiphernodesCommitteeSize;
    use e3_crypto::Cipher;
    use e3_trbfv::helpers::deserialize_secret_key;

    /// The insecure 64-degree set, which development chains use.
    fn params() -> CryptoParams {
        let param_set = (0..=u8::MAX)
            .find(|set| {
                e3_fhe_params::BfvPreset::from_on_chain_param_set(*set)
                    == Some(e3_fhe_params::BfvPreset::InsecureThreshold64)
            })
            .expect("development chains support the insecure set");
        CryptoParams {
            param_set,
            committee_size: CiphernodesCommitteeSize::Minimum,
            seed: B256::ZERO,
        }
    }

    async fn runner() -> JobRunner<MemoryBlobs> {
        let cipher = Cipher::from_password("test password").await.unwrap();
        JobRunner::new(MemoryBlobs::default(), cipher)
    }

    fn made(runner: &JobRunner<MemoryBlobs>) -> OwnKey {
        match runner.make_encryption_key(&params()).unwrap() {
            DkgWorkResult::EncryptionKeyMade(own) => own,
            other => panic!("a key, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_made_key_passes_its_check_and_its_secret_stays_sealed() {
        let runner = runner().await;
        let own = made(&runner);
        assert!(runner
            .check_encryption_key(&params(), &own.public, &own.proof)
            .unwrap());

        let sealed = runner.blobs.get(&own.secret).unwrap();
        let bfv = BfvParamSet::from(dkg_preset(&params()).unwrap()).build_arc();
        assert!(
            deserialize_secret_key(&sealed, &bfv).is_err(),
            "the stored secret is sealed"
        );
        let secret = runner.cipher.decrypt_data(&sealed).unwrap();
        assert!(deserialize_secret_key(&secret, &bfv).is_ok());
    }

    #[tokio::test]
    async fn a_key_fails_its_check_when_its_proof_commits_to_other_bytes_or_it_does_not_decode() {
        let runner = runner().await;
        let own = made(&runner);
        let other = made(&runner);
        assert!(!runner
            .check_encryption_key(&params(), &own.public, &other.proof)
            .unwrap());
        let garbage = runner.blobs.put(b"not a key");
        let proof = ZkProof {
            public_inputs: vec![keccak256(b"not a key")],
            ..own.proof.clone()
        };
        assert!(!runner
            .check_encryption_key(&params(), &garbage, &proof)
            .unwrap());
        let missing = BlobRef::of(b"never stored");
        assert!(!runner
            .check_encryption_key(&params(), &missing, &proof)
            .unwrap());
    }
}
