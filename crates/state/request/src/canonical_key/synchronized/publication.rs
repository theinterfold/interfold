// SPDX-License-Identifier: LGPL-3.0-only

//! Validate a local publication candidate against confirmed pre-publication facts. This produces
//! no canonical authority: only the confirmed-history projection can install the returned anchors.

use super::*;
use crate::canonical_key::CanonicalDkgAnchors;
use anyhow::Context as _;
use e3_events::{synchronized_dkg_roster_hash, SynchronizedDkgPublicationReady};
use e3_zk_config::{
    synchronized::{public_signals::PublicSignals, Configs},
    CircuitName,
};

impl SynchronizedDkgSelection {
    pub fn validate_publication(
        &self,
        context: SynchronizedDkgContext,
        intent: &SynchronizedDkgPublicationReady,
    ) -> Result<CanonicalPublicKey> {
        ensure!(
            intent.params_profile == self.params_profile
                && intent.committee_size == self.committee_size
                && context.crypto_config_id
                    == self.params_profile.crypto_config_id(self.committee_size)?.0
                && intent.context.setup
                    == (DkgSetupContext {
                        interfold_address: self.interfold_address,
                        committee_hash: hash_committee_addresses(&self.committee),
                        crypto_config_id: context.crypto_config_id.into(),
                    })
                && (intent.context.party_id as usize) < self.committee.len()
                && intent.proof.circuit == CircuitName::DkgAggregator
                && !intent.proof.data.is_empty(),
            "local publication differs from confirmed request/committee"
        );
        let expected = &intent.expected;
        let config = Configs::for_profile(self.params_profile, self.committee_size)?;
        let public =
            PublicSignals::decode(&config, intent.proof.circuit, &intent.proof.public_signals)?;
        let setup_binding = intent
            .context
            .setup
            .hash(intent.e3_id.chain_id(), intent.e3_id.clone().try_into()?)
            .0;
        let pk_commitment = public
            .pk_commitment()
            .context("publication has no PK commitment")?;
        let authority = SynchronizedDkgAuthority {
            version: 1,
            context,
            setup_binding,
            dealer_batch: expected.dealer_batch,
            party_ids: expected.dealers.clone(),
            threshold_pk_commits: expected.threshold_keys.clone(),
            sk_agg_commits: expected.sk_commitments.clone(),
            key_bundle_commits: expected.key_bundles.clone(),
        };
        let candidate = CanonicalPublicKey {
            pk_commitment,
            committee: self.committee.clone(),
            honest_committee: expected
                .dealers
                .iter()
                .map(|&id| {
                    self.committee
                        .get(id as usize)
                        .copied()
                        .context("publication party outside committee")
                })
                .collect::<Result<_>>()?,
            params_profile: self.params_profile,
            committee_size: self.committee_size,
            interfold_address: self.interfold_address,
            dkg_anchors: CanonicalDkgAnchors::Synchronized(authority.clone()),
        };
        authority.validate(&intent.e3_id, &candidate)?;
        candidate.validate_dkg_key(&expected.public_key)?;
        let binding = [
            u128::from_be_bytes(setup_binding[..16].try_into()?),
            u128::from_be_bytes(setup_binding[16..].try_into()?),
        ];
        ensure!(
            public.binding() == Some(binding)
                && public.dealers().as_deref() == Some(expected.dealers.as_slice())
                && public.threshold_keys() == Some(expected.threshold_keys.as_slice())
                && public.dealer_batch() == Some(expected.dealer_batch)
                && public.recipient_sk_commitments() == Some(expected.sk_commitments.as_slice())
                && public.recipient_key_bundles() == Some(expected.key_bundles.as_slice())
                && intent.consents.len() == self.committee_size.values().h,
            "publication proof differs from native/setup expectations"
        );
        for (slot, signed) in intent.consents.iter().enumerate() {
            let payload = &signed.payload;
            let party = expected.dealers[slot];
            ensure!(
                payload.e3_id == intent.e3_id
                    && payload.context == context
                    && payload.party_id == party
                    && payload.setup_binding == setup_binding
                    && payload.roster_hash == synchronized_dkg_roster_hash(&expected.dealers)
                    && payload.dealer_batch == expected.dealer_batch
                    && payload.pk_commitment == pk_commitment
                    && payload.sk_agg_commit == expected.sk_commitments[slot]
                    && payload.key_bundle_commit == expected.key_bundles[slot]
                    && signed.recover_address()? == self.committee[party as usize],
                "publication lacks exact ordered all-H consent"
            );
        }
        Ok(candidate)
    }
}
