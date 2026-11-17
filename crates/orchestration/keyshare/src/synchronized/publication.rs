// SPDX-License-Identifier: LGPL-3.0-only

//! Consent and the read-only #2050 handoff. Neither admits a profile nor implements decryption.

use super::*;
use alloy::signers::local::PrivateKeySigner;
use e3_events::{
    synchronized_dkg_roster_hash, SignedSynchronizedDkgAttestation,
    SynchronizedDkgAttestationPayload, SynchronizedSetupAnchors,
};
use e3_polynomial::CrtPolynomial;
use e3_polynomial_fhe::FromFhePolynomial;
use e3_request::canonical_key::{
    CanonicalDkgAnchors, CanonicalPublicKeys, SynchronizedDkgAuthority,
};
use e3_utils::ArcBytes;
use e3_zk_witness::threshold::pk_aggregation::PkAggregationCircuitData;
use fhe::bfv::PublicKey;
use fhe::mbfv::{Aggregate, PublicKeyShare};
use fhe_traits::Serialize as _;

/// Context-bound sealed inputs for a later C6 implementation. No plaintext keys or work admission.
pub struct ConfirmedSynchronizedDkgSetup<'a> {
    profile: e3_fhe_params::BfvProfile,
    committee: CiphernodesCommitteeSize,
    recipient: u32,
    public_key: ArcBytes,
    authority: SynchronizedDkgAuthority,
    sk_commitment: [u8; 32],
    key_bundle: [u8; 32],
    outgoing_keys: &'a SealedPrfKeys,
    incoming_keys: &'a SealedPrfKeys,
}

impl ConfirmedSynchronizedDkgSetup<'_> {
    pub fn profile(&self) -> e3_fhe_params::BfvProfile {
        self.profile
    }
    pub fn committee(&self) -> CiphernodesCommitteeSize {
        self.committee
    }
    pub fn recipient(&self) -> u32 {
        self.recipient
    }
    pub fn public_key(&self) -> &ArcBytes {
        &self.public_key
    }
    pub fn authority(&self) -> &SynchronizedDkgAuthority {
        &self.authority
    }
    pub fn sk_commitment(&self) -> [u8; 32] {
        self.sk_commitment
    }
    pub fn key_bundle(&self) -> [u8; 32] {
        self.key_bundle
    }
    pub fn outgoing_keys(&self) -> &SealedPrfKeys {
        self.outgoing_keys
    }
    pub fn incoming_keys(&self) -> &SealedPrfKeys {
        self.incoming_keys
    }
}

impl SynchronizedDkgRecovery {
    /// Rebuild C5 inputs only from the authenticated native contributions saved at C4 fixation.
    pub fn publication_key(
        &self,
        selected: &CiphernodeSelected,
        setup: &SynchronizedSetupAnchors,
    ) -> Result<PublicKey> {
        let config = e3_zk_config::synchronized::Configs::for_profile(
            selected.params_profile,
            CiphernodesCommitteeSize::from_threshold(selected.threshold_m, selected.threshold_n)?,
        )?;
        ensure!(
            self.threshold_pk_shares.keys().copied().collect::<Vec<_>>() == self.dealer_ids
                && setup.dealers == self.dealer_ids
                && self.dealer_ids.len() == config.committee.values().h,
            "publication requires the complete fixed native PK-share roster"
        );
        let crp = e3_fhe_params::create_deterministic_crp_from_default_seed(&config.threshold);
        let shares = self
            .threshold_pk_shares
            .values()
            .map(|bytes| {
                let share = PublicKeyShare::deserialize(bytes, &config.threshold, crp.clone())?;
                ensure!(
                    share.to_bytes().as_slice() == &**bytes,
                    "noncanonical native PK share"
                );
                Ok(share)
            })
            .collect::<Result<Vec<_>>>()?;
        let public_key = PublicKey::from_shares(shares.clone())?;
        let input = e3_zk_witness::synchronized::publication::c5(
            &config,
            &PkAggregationCircuitData {
                public_key: public_key.clone(),
                pk0_shares: shares
                    .iter()
                    .map(|share| CrtPolynomial::from_fhe_polynomial(share.p0_share()))
                    .collect(),
            },
        )?;
        let commitments = input
            .expected_threshold_pk_commitments
            .iter()
            .map(commitment_field)
            .collect::<Result<Vec<_>>>()?;
        ensure!(
            commitments == setup.threshold_keys,
            "recipient setup differs from independently retained native PK shares"
        );
        Ok(public_key)
    }

    pub(super) fn validate_setup(
        &self,
        selected: &CiphernodeSelected,
        interfold: Address,
        setup: &SynchronizedSetupAnchors,
        cipher: &Cipher,
    ) -> Result<()> {
        self.validate(selected, interfold, cipher)?;
        ensure!(
            setup.binding == setup_binding(&self.context, &selected.e3_id)?
                && setup.recipient == self.context.party_id
                && setup.dealers == self.dealer_ids
                && setup.threshold_keys.len() == self.dealer_ids.len()
                && self.sk_commitment == Some(setup.sk_commitment)
                && self.key_bundle == Some(setup.key_bundle),
            "verified setup does not match the recovered private material"
        );
        Ok(())
    }

    /// Invoke only for the actor's correlated, locally verified recipient setup and independently
    /// aggregated native PK. The frozen domain comes from confirmed history, never a candidate.
    #[allow(clippy::too_many_arguments)]
    pub fn attest_publication(
        &self,
        selected: &CiphernodeSelected,
        interfold: Address,
        keys: &CanonicalPublicKeys,
        setup: &SynchronizedSetupAnchors,
        public_key: &PublicKey,
        signer: &PrivateKeySigner,
        cipher: &Cipher,
    ) -> Result<SignedSynchronizedDkgAttestation> {
        self.validate_setup(selected, interfold, setup, cipher)?;
        ensure!(
            self.publication_key(selected, setup)?.to_bytes() == public_key.to_bytes(),
            "publication key differs from the authenticated native dealer batch"
        );
        ensure!(
            setup.dealers.contains(&setup.recipient),
            "only selected H recipients consent to publication"
        );
        ensure!(
            selected.committee[setup.recipient as usize].parse::<Address>()? == signer.address(),
            "publication signer does not own the recipient slot"
        );
        let context = keys
            .synchronized_context(&selected.e3_id)
            .context("request-frozen synchronized signing context is unavailable")?;
        ensure!(
            context.crypto_config_id == selected.crypto_config_id,
            "synchronized signing context has another configuration"
        );
        let config = e3_zk_config::synchronized::Configs::for_profile(
            selected.params_profile,
            CiphernodesCommitteeSize::from_threshold(selected.threshold_m, selected.threshold_n)?,
        )?;
        ensure!(
            public_key.params == config.threshold && public_key.c.len() == 2,
            "publication native PK belongs to another profile"
        );
        let pk_commitment =
            e3_zk_witness::threshold::user_data_encryption::compute_public_key_commitment(
                &config.threshold,
                public_key,
            )?;
        SignedSynchronizedDkgAttestation::sign(
            SynchronizedDkgAttestationPayload {
                e3_id: selected.e3_id.clone(),
                context,
                setup_binding: self
                    .context
                    .setup
                    .hash(
                        selected.e3_id.chain_id(),
                        selected.e3_id.clone().try_into()?,
                    )
                    .0,
                roster_hash: synchronized_dkg_roster_hash(&setup.dealers),
                dealer_batch: setup.dealer_batch,
                pk_commitment,
                party_id: setup.recipient,
                sk_agg_commit: setup.sk_commitment,
                key_bundle_commit: setup.key_bundle,
            },
            signer,
        )
    }

    /// The setup verdict must already be admitted by the actor's local worker correlation. For an
    /// outside-H recipient, its own verified setup joins the same chain batch/threshold keys.
    pub fn confirmed_setup<'a>(
        &'a self,
        selected: &CiphernodeSelected,
        interfold: Address,
        keys: &CanonicalPublicKeys,
        setup: &SynchronizedSetupAnchors,
        cipher: &Cipher,
    ) -> Result<ConfirmedSynchronizedDkgSetup<'a>> {
        self.validate_setup(selected, interfold, setup, cipher)?;
        let key = keys
            .get(&selected.e3_id)
            .context("confirmed synchronized DKG authority is unavailable")?;
        let CanonicalDkgAnchors::Synchronized(authority) = &key.dkg_anchors else {
            anyhow::bail!("SS ESM anchors cannot authorize synchronized setup");
        };
        let committee = selected
            .committee
            .iter()
            .map(|node| node.parse::<Address>())
            .collect::<Result<Vec<_>, _>>()?;
        ensure!(
            key.params_profile == selected.params_profile
                && key.interfold_address == interfold
                && key.committee == committee
                && authority.party_ids == setup.dealers
                && authority.threshold_pk_commits == setup.threshold_keys
                && authority.dealer_batch == setup.dealer_batch
                && keys.synchronized_context(&selected.e3_id) == Some(authority.context),
            "recovered setup differs from confirmed request/batch authority"
        );
        if let Some(row) = authority
            .party_ids
            .iter()
            .position(|&party| party == setup.recipient)
        {
            ensure!(
                authority.sk_agg_commits[row] == setup.sk_commitment
                    && authority.key_bundle_commits[row] == setup.key_bundle,
                "selected recipient anchors differ from chain authority"
            );
        }
        let public_key = keys
            .public_key(&selected.e3_id)
            .context("confirmed public-key bytes are unavailable")?;
        // This is DKG byte/commitment validation, not C6 profile admission.
        key.validate_dkg_key(&public_key)?;
        ensure!(
            self.publication_key(selected, setup)?.to_bytes().as_slice() == &*public_key,
            "confirmed key differs from the authenticated native dealer batch"
        );
        Ok(ConfirmedSynchronizedDkgSetup {
            profile: key.params_profile,
            committee: key.committee_size,
            recipient: setup.recipient,
            public_key,
            authority: authority.clone(),
            sk_commitment: setup.sk_commitment,
            key_bundle: setup.key_bundle,
            outgoing_keys: &self.outgoing_keys,
            incoming_keys: self
                .incoming_keys
                .as_ref()
                .context("missing recovered incoming keys")?,
        })
    }
}
