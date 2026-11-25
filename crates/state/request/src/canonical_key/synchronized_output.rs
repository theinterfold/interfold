// SPDX-License-Identifier: LGPL-3.0-only

use super::*;
use anyhow::Context;
use e3_committee_hash::decryption_domain_limbs;

#[derive(Default, Clone, Debug)]
pub(super) struct Publication {
    ready: bool,
    output: Option<(B256, [u8; 32])>,
    // Only populated after opening the exact confirmed bytes. Retiring the publication drops it.
    plan: Arc<std::sync::OnceLock<SynchronizedDecryptionPlan>>,
}

/// Read-only Minimum C6 definition derived from confirmed facts. Never deserialize a plan
/// from a peer or snapshot to authorize work: rederive it, then compare the local record.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct SynchronizedDecryptionPlan {
    e3_id: E3id,
    profile: BfvProfile,
    committee: CiphernodesCommitteeSize,
    authority: SynchronizedDkgAuthority,
    owners: Vec<Address>,
    ciphertext_hash: B256,
    ciphertext_commitment: [u8; 32],
    c0_commitment: [u8; 32],
    domain: [u128; 2],
}

impl SynchronizedDecryptionPlan {
    /// On-disk v1 binding. Changes to the serialized plan need a checkpoint migration.
    pub fn local_contribution_binding_v1(&self, owner: u32) -> Result<B256> {
        Ok(keccak256(bincode::serialize(&(
            "interfold/synchronized/C6/local/v1",
            self,
            owner,
        ))?))
    }

    pub fn e3_id(&self) -> &E3id {
        &self.e3_id
    }

    pub fn profile(&self) -> BfvProfile {
        self.profile
    }

    pub fn committee(&self) -> CiphernodesCommitteeSize {
        self.committee
    }

    pub fn designated(&self) -> &[u32] {
        &self.authority.party_ids[..self.committee.values().threshold + 1]
    }

    pub fn signer(&self, party: u32) -> Result<Address> {
        let row = self
            .designated()
            .binary_search(&party)
            .map_err(|_| anyhow::anyhow!("party is not a designated decryptor"))?;
        Ok(self.owners[row])
    }

    pub fn matches_setup(&self, authority: &SynchronizedDkgAuthority) -> bool {
        authority == &self.authority
    }

    /// Compare a decoded C6 row with the independently selected chain facts.
    pub fn matches_c6(
        &self,
        party: u32,
        signals: &e3_zk_config::synchronized::public_signals::PublicSignals,
    ) -> bool {
        let Ok(row) = self.designated().binary_search(&party) else {
            return false;
        };
        let binding =
            e3_committee_hash::split_decryption_domain(self.authority.setup_binding.into());
        signals.binding() == Some([binding.hi, binding.lo])
            && signals.party_id() == Some(party)
            && signals.dealers().as_deref() == Some(&self.authority.party_ids)
            && signals.decryption_domain() == Some(self.domain)
            && signals.ciphertext_commitment() == Some(self.ciphertext_commitment)
            && signals.c0_commitment() == Some(self.c0_commitment)
            && signals.sk_commitment() == Some(self.authority.sk_agg_commits[row])
            && signals.key_bundle() == Some(self.authority.key_bundle_commits[row])
    }
}

#[cfg(test)]
mod binding_tests {
    use super::*;

    #[test]
    fn non_prefix_owner_v1_checkpoint_binding() -> Result<()> {
        let mut plan = SynchronizedDecryptionPlan {
            e3_id: E3id::new("7", 31337),
            profile: BfvProfile::SyncDecInsecure64,
            committee: CiphernodesCommitteeSize::Minimum,
            authority: SynchronizedDkgAuthority {
                version: 1,
                context: e3_events::SynchronizedDkgContext {
                    registry: Address::repeat_byte(1),
                    verifying_contract: Address::repeat_byte(2),
                    crypto_config_id: [3; 32],
                },
                setup_binding: [4; 32],
                dealer_batch: [5; 32],
                party_ids: vec![0, 2],
                threshold_pk_commits: vec![[6; 32], [7; 32]],
                sk_agg_commits: vec![[8; 32], [9; 32]],
                key_bundle_commits: vec![[10; 32], [11; 32]],
            },
            owners: vec![Address::repeat_byte(12), Address::repeat_byte(13)],
            ciphertext_hash: B256::repeat_byte(14),
            ciphertext_commitment: [15; 32],
            c0_commitment: [16; 32],
            domain: [17, 18],
        };
        let binding = plan.local_contribution_binding_v1(2)?;
        assert_eq!(
            binding,
            alloy::primitives::b256!(
                "a33af4df180d615eebbc46c965edcd07872d8d1ebc2974da896e31e7234c8d74"
            )
        );
        plan.authority.context.crypto_config_id[0] ^= 1;
        assert_ne!(plan.local_contribution_binding_v1(2)?, binding);
        Ok(())
    }
}

impl CanonicalPublicKeys {
    /// Projection input only. Local DA hydration supplies bytes, never either binding.
    pub fn remember_synchronized_output(
        &self,
        id: &E3id,
        hash: B256,
        commitment: [u8; 32],
    ) -> Result<()> {
        let mut keys = self.0.write().expect("canonical key lock");
        let publication = keys.synchronized_outputs.entry(id.clone()).or_default();
        ensure!(
            publication
                .output
                .is_none_or(|old| old == (hash, commitment)),
            "confirmed synchronized ciphertext changed"
        );
        publication.output = Some((hash, commitment));
        Ok(())
    }

    pub fn remember_synchronized_ciphertext_ready(&self, id: &E3id) {
        self.0
            .write()
            .expect("canonical key lock")
            .synchronized_outputs
            .entry(id.clone())
            .or_default()
            .ready = true;
    }

    pub fn retire_synchronized_output(&self, id: &E3id) {
        self.0
            .write()
            .expect("canonical key lock")
            .synchronized_outputs
            .remove(id);
    }

    /// Below admission: this does not enable a profile, schedule effects or certify a deadline.
    /// Missing confirmed facts defer; a mismatched candidate is an error and reserves no slot.
    pub fn synchronized_decryption_definition(
        &self,
        id: &E3id,
        profile: BfvProfile,
        ciphertexts: &[ArcBytes],
    ) -> Result<Option<SynchronizedDecryptionPlan>> {
        ensure!(
            profile == BfvProfile::SyncDecInsecure64,
            "no synchronized registry route for profile"
        );
        let [bytes] = ciphertexts else {
            anyhow::bail!("expected exactly one synchronized ciphertext")
        };
        let (key, (hash, commitment), cached) = {
            let keys = self.0.read().expect("canonical key lock");
            let Some(key) = keys.authority.get(id) else {
                return Ok(None);
            };
            ensure!(key.params_profile == profile, "request profile mismatch");
            let Some(publication) = keys.synchronized_outputs.get(id).filter(|p| p.ready) else {
                return Ok(None);
            };
            let Some(output) = publication.output else {
                return Ok(None);
            };
            (key.clone(), output, publication.plan.clone())
        };
        let CanonicalDkgAnchors::Synchronized(a) = &key.dkg_anchors else {
            anyhow::bail!("expected synchronized DKG authority")
        };
        ensure!(
            keccak256(&bytes[..]) == hash,
            "ciphertext differs from confirmed publication"
        );
        if let Some(plan) = cached.get() {
            return Ok(Some(plan.clone()));
        }
        let params = BfvParamSet::from(profile.threshold_preset()).build_arc();
        let c0_commitment =
            e3_bfv_client::client::validate_synchronized_ciphertext(bytes, &params, commitment)?;
        let domain = decryption_domain_limbs(
            id.chain_id(),
            id.clone().try_into().context("invalid E3 id")?,
            key.domain(key.interfold_address),
            hash,
        );
        Ok(Some(
            cached
                .get_or_init(|| SynchronizedDecryptionPlan {
                    e3_id: id.clone(),
                    profile,
                    committee: key.committee_size,
                    authority: a.clone(),
                    owners: key.honest_committee,
                    ciphertext_hash: hash,
                    ciphertext_commitment: commitment,
                    c0_commitment,
                    domain: [domain.hi, domain.lo],
                })
                .clone(),
        ))
    }
}
