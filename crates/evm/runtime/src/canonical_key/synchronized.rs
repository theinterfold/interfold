// SPDX-License-Identifier: LGPL-3.0-only

//! Join confirmed request context, authority event and proof observation in the shared projection.

use super::*;
use crate::contracts::ISynchronizedDkgPublication;
use e3_events::{
    EvmLogObserved, SynchronizedDkgContextEstablished, SYNCHRONIZED_DKG_CONTEXT_SCHEMA_VERSION,
};
use e3_fhe_params::BfvDecryptionProtocol;
use e3_request::canonical_key::SynchronizedDkgAuthority;
use e3_zk_config::{
    synchronized::{public_signals::PublicSignals, Configs},
    CircuitName,
};

#[derive(Debug)]
pub(super) struct UnsupportedVersion(&'static str);

impl std::fmt::Display for UnsupportedVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "unsupported synchronized {} version", self.0)
    }
}

impl std::error::Error for UnsupportedVersion {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct SynchronizedPublicationObservation {
    committee: Vec<Address>,
    commitment: [u8; 32],
    fields: Vec<B256>,
}

impl CanonicalKeyProjection {
    pub(super) fn record_synchronized_context(
        &mut self,
        data: &SynchronizedDkgContextEstablished,
    ) -> Result<()> {
        if !self
            .interfold_addresses
            .contains_key(&data.e3_id.chain_id())
        {
            return Ok(());
        }
        if data.schema_version != SYNCHRONIZED_DKG_CONTEXT_SCHEMA_VERSION {
            return Err(UnsupportedVersion("DKG signing context").into());
        }
        self.keys
            .remember_synchronized_context(data.e3_id.clone(), data.context)?;
        self.finish_synchronized(&data.e3_id)
    }

    pub(super) fn record_synchronized_authority(
        &mut self,
        event: &InterfoldEvent,
        log: &EvmLogObserved,
    ) -> Result<()> {
        if !self.interfold_addresses.contains_key(&log.chain_id) {
            return Ok(());
        }
        let topics = log
            .topics
            .iter()
            .map(|topic| topic.parse::<B256>())
            .collect::<Result<Vec<_>, _>>()?;
        if topics.first()
            != Some(&ISynchronizedDkgPublication::SynchronizedDkgAuthorityPublished::SIGNATURE_HASH)
        {
            return Ok(());
        }
        let decoded =
            ISynchronizedDkgPublication::SynchronizedDkgAuthorityPublished::decode_raw_log(
                topics, &log.data,
            )?;
        let id = E3id::new(decoded.e3Id.to_string(), log.chain_id);
        ensure!(
            log.e3_id.as_ref() == Some(&id)
                && event.aggregate_id().to_chain_id() == Some(log.chain_id),
            "synchronized authority observation has inconsistent request identity"
        );
        if decoded.authority.version != 1 {
            return Err(UnsupportedVersion("authority").into());
        }
        if let Some(previous) = self.synchronized_authorities.get(&id) {
            ensure!(
                previous == &decoded.authority,
                "confirmed synchronized authority changed"
            );
        } else {
            self.synchronized_authorities
                .insert(id.clone(), decoded.authority);
        }
        self.finish_synchronized(&id)?;
        self.restore_bytes(&id)
    }

    pub(super) fn record_synchronized_proof(
        &mut self,
        id: &E3id,
        committee: Vec<Address>,
        commitment: [u8; 32],
        proof: &[u8],
    ) -> Result<()> {
        let (_, fields) = <(Bytes, Vec<B256>)>::abi_decode_params(proof)?;
        let observation = SynchronizedPublicationObservation {
            committee,
            commitment,
            fields,
        };
        if let Some(previous) = self.synchronized_proofs.get(id) {
            ensure!(
                previous == &observation,
                "confirmed synchronized publication changed"
            );
        } else {
            self.synchronized_proofs.insert(id.clone(), observation);
        }
        self.finish_synchronized(id)
    }

    pub(super) fn finish_synchronized(&mut self, id: &E3id) -> Result<()> {
        let (Some(request), Some(context), Some(authority), Some(publication)) = (
            self.requests.get(id),
            self.keys.synchronized_context(id),
            self.synchronized_authorities.get(id),
            self.synchronized_proofs.get(id),
        ) else {
            return Ok(());
        };
        ensure!(
            request.params_profile.protocol() == BfvDecryptionProtocol::Synchronized,
            "synchronized publication cannot supply SS authority"
        );
        let size =
            CiphernodesCommitteeSize::from_threshold(request.threshold_m, request.threshold_n)?;
        let ids = authority
            .partyIds
            .iter()
            .map(|id| u32::try_from(*id))
            .collect::<Result<Vec<_>, _>>()?;
        ensure!(
            authority.verifier == context.verifying_contract
                && authority.cryptoConfigId.0 == context.crypto_config_id
                && authority.cryptoConfigId.0 == request.crypto_config_id
                && authority.pkCommitment.0 == publication.commitment,
            "synchronized publication differs from the frozen request or key"
        );
        let data = SynchronizedDkgAuthority {
            version: authority.version,
            context,
            setup_binding: authority.setupBinding.0,
            dealer_batch: authority.dealerBatch.0,
            party_ids: ids,
            threshold_pk_commits: authority
                .thresholdPkCommits
                .iter()
                .map(|value| value.0)
                .collect(),
            sk_agg_commits: authority.skAggCommits.iter().map(|value| value.0).collect(),
            key_bundle_commits: authority
                .keyBundleCommits
                .iter()
                .map(|value| value.0)
                .collect(),
        };
        let config = Configs::for_profile(request.params_profile, size)?;
        let fields: Vec<u8> = publication
            .fields
            .iter()
            .flat_map(|field| field.0)
            .collect();
        let public = PublicSignals::decode(&config, CircuitName::DkgAggregator, &fields)?;
        let binding = [
            u128::from_be_bytes(data.setup_binding[..16].try_into()?),
            u128::from_be_bytes(data.setup_binding[16..].try_into()?),
        ];
        ensure!(
            public.binding() == Some(binding)
                && public.dealers().as_deref() == Some(data.party_ids.as_slice())
                && public.threshold_keys() == Some(data.threshold_pk_commits.as_slice())
                && public.dealer_batch() == Some(data.dealer_batch)
                && public.recipient_sk_commitments() == Some(data.sk_agg_commits.as_slice())
                && public.recipient_key_bundles() == Some(data.key_bundle_commits.as_slice())
                && public.pk_commitment() == Some(publication.commitment),
            "confirmed synchronized proof and authority rows disagree"
        );
        let honest_committee = data
            .party_ids
            .iter()
            .map(|&party| {
                publication
                    .committee
                    .get(party as usize)
                    .copied()
                    .context("synchronized party outside committee")
            })
            .collect::<Result<Vec<_>>>()?;
        self.keys.insert_synchronized_dkg_authority(
            id.clone(),
            CanonicalPublicKey {
                pk_commitment: publication.commitment,
                committee: publication.committee.clone(),
                honest_committee,
                params_profile: request.params_profile,
                committee_size: size,
                interfold_address: self.interfold_addresses[&id.chain_id()],
                dkg_anchors: CanonicalDkgAnchors::Synchronized(data),
            },
        )?;
        self.restore_bytes(id)
    }
}
