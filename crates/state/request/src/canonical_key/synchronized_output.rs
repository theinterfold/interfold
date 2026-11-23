// SPDX-License-Identifier: LGPL-3.0-only

use super::*;
use anyhow::Context;
use e3_committee_hash::decryption_domain_limbs;

#[derive(Default, Clone, Debug)]
pub(super) struct Publication {
    ready: bool,
    output: Option<(B256, [u8; 32])>,
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
        let (key, output) = {
            let keys = self.0.read().expect("canonical key lock");
            let Some(key) = keys.authority.get(id) else {
                return Ok(None);
            };
            ensure!(key.params_profile == profile, "request profile mismatch");
            let Some(output) = keys
                .synchronized_outputs
                .get(id)
                .filter(|p| p.ready)
                .and_then(|p| p.output)
            else {
                return Ok(None);
            };
            (key.clone(), output)
        };
        let CanonicalDkgAnchors::Synchronized(a) = &key.dkg_anchors else {
            anyhow::bail!("expected synchronized DKG authority")
        };
        let (hash, commitment) = output;
        ensure!(
            keccak256(&bytes[..]) == hash,
            "ciphertext differs from confirmed publication"
        );
        let params = BfvParamSet::from(profile.threshold_preset()).build_arc();
        let c0_commitment =
            e3_bfv_client::client::validate_synchronized_ciphertext(bytes, &params, commitment)?;
        let domain = decryption_domain_limbs(
            id.chain_id(),
            id.clone().try_into().context("invalid E3 id")?,
            key.domain(key.interfold_address),
            hash,
        );
        Ok(Some(SynchronizedDecryptionPlan {
            e3_id: id.clone(),
            profile,
            committee: key.committee_size,
            authority: a.clone(),
            owners: key.honest_committee,
            ciphertext_hash: hash,
            ciphertext_commitment: commitment,
            c0_commitment,
            domain: [domain.hi, domain.lo],
        }))
    }
}
