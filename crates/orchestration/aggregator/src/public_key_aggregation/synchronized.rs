// SPDX-License-Identifier: LGPL-3.0-only

//! Deterministic synchronized publication planning. A local recipient verdict fixes the batch;
//! peer signatures authenticate contributions but never choose that batch or authorize chain I/O.

use alloy::primitives::Address;
use anyhow::{ensure, Context, Result};
use e3_committee::CiphernodesCommitteeSize;
use e3_events::*;
use e3_request::E3Meta;
use e3_utils::ArcBytes;
use e3_zk_config::{
    synchronized::{public_signals::PublicSignals, Configs},
    CircuitName,
};
use fhe::{
    bfv::PublicKey,
    mbfv::{Aggregate, PublicKeyShare},
};
use fhe_traits::Serialize as _;
use std::collections::BTreeMap;

#[path = "synchronized/record.rs"]
mod record;
pub use record::PublicationRecord;

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PublicationPlan {
    pub(crate) selected: CiphernodeSelected,
    pub(crate) local: TypedEvent<SynchronizedRecipientProofReady>,
}

impl PublicationPlan {
    /// Definition-only planning from an already admitted local verdict. This does not authorize
    /// effects or verify proof bodies; the actor and correlated worker own those boundaries.
    pub fn new(
        selected: CiphernodeSelected,
        local: TypedEvent<SynchronizedRecipientProofReady>,
        interfold: Address,
    ) -> Result<Self> {
        let plan = Self { selected, local };
        plan.validate(interfold)?;
        Ok(plan)
    }

    pub(crate) fn config(&self) -> Result<Configs> {
        Ok(Configs::for_profile(
            self.selected.params_profile,
            CiphernodesCommitteeSize::from_threshold(
                self.selected.threshold_m,
                self.selected.threshold_n,
            )?,
        )?)
    }

    pub(crate) fn members(&self) -> Result<Vec<Address>> {
        self.selected
            .committee
            .iter()
            .map(|s| s.parse().map_err(Into::into))
            .collect()
    }

    pub(crate) fn validate(&self, interfold: Address) -> Result<()> {
        E3Meta::from(&self.selected).validate_identity()?;
        let config = self.config()?;
        let members = self.members()?;
        ensure!(
            self.local.get_ctx().source() == EventSource::Local
                && self.local.e3_id == self.selected.e3_id
                && u64::from(self.local.context.party_id) == self.selected.party_id
                && members.len() == config.committee.values().n
                && members.windows(2).all(|p| p[0] < p[1])
                && self.local.context.setup.interfold_address == interfold
                && self.local.context.setup.committee_hash
                    == e3_committee_hash::hash_committee_addresses(&members)
                && self.local.context.setup.crypto_config_id.as_slice()
                    == self.selected.crypto_config_id,
            "publication intent differs from canonical selection"
        );
        let public = self.recipient_public(&self.local.context, &self.local.proof)?;
        let anchors = &self.local.setup;
        ensure!(
            public.binding() == Some(anchors.binding)
                && public.party_id() == Some(anchors.recipient)
                && public.dealers().as_deref() == Some(anchors.dealers.as_slice())
                && public.threshold_keys() == Some(anchors.threshold_keys.as_slice())
                && public.dealer_batch() == Some(anchors.dealer_batch)
                && public.sk_commitment() == Some(anchors.sk_commitment)
                && public.key_bundle() == Some(anchors.key_bundle),
            "local publication anchors differ from admitted recipient verdict"
        );
        Ok(())
    }

    fn recipient_public(
        &self,
        context: &SynchronizedProofContext,
        proof: &Proof,
    ) -> Result<PublicSignals> {
        ensure!(
            context.setup == self.local.context.setup && proof.circuit == CircuitName::NodesFold,
            "recipient join has another context or role"
        );
        let config = self.config()?;
        let binding =
            e3_zk_prover::synchronized::request_binding(&config, context, &self.selected.e3_id)?;
        let public = PublicSignals::decode(&config, proof.circuit, &proof.public_signals)?;
        ensure!(
            public.binding() == Some(binding) && public.party_id() == Some(context.party_id),
            "recipient join statement has another request or owner"
        );
        Ok(public)
    }

    pub(crate) fn recipient(
        &self,
        message: &SynchronizedDkgProofPublished,
    ) -> Result<PublicSignals> {
        ensure!(
            message.e3_id == self.selected.e3_id
                && message.role == SynchronizedDkgProofRole::Recipient
                && self.members()?.get(message.context.party_id as usize)
                    == Some(&message.recover_address()?),
            "recipient join signer does not own the canonical slot"
        );
        let public = self.recipient_public(&message.context, &message.proof)?;
        let setup = &self.local.setup;
        let local = self.recipient_public(&self.local.context, &self.local.proof)?;
        ensure!(
            setup.dealers.contains(&message.context.party_id)
                && public.dealers().as_deref() == Some(setup.dealers.as_slice())
                && public.threshold_keys() == Some(setup.threshold_keys.as_slice())
                && public.dealer_batch() == Some(setup.dealer_batch)
                && public.tree_hash() == local.tree_hash(),
            "recipient join differs from the locally fixed batch"
        );
        Ok(public)
    }

    pub(crate) fn keyshare(&self, message: &KeyshareCreated) -> Result<()> {
        let members = self.members()?;
        let owner = u32::try_from(message.party_id)?;
        let signer = members
            .get(owner as usize)
            .context("keyshare owner outside committee")?;
        let signed = message
            .signed_pk_generation_proof
            .as_ref()
            .context("missing signed C1")?;
        ensure!(
            message.e3_id == self.selected.e3_id
                && message.node.parse::<Address>()? == *signer
                && signed.payload.e3_id == self.selected.e3_id
                && signed.payload.proof_type == ProofType::C1PkGeneration
                && signed.payload.proof.circuit == CircuitName::PkGeneration
                && signed.verify_address(signer)?,
            "native PK contribution is not authenticated for its slot"
        );
        let config = self.config()?;
        let public = PublicSignals::decode(
            &config,
            CircuitName::PkGeneration,
            &signed.payload.proof.public_signals,
        )?;
        let crp = e3_fhe_params::create_deterministic_crp_from_default_seed(&config.threshold);
        let share = PublicKeyShare::deserialize(&message.pubkey, &config.threshold, crp.clone())?;
        ensure!(
            share.to_bytes().as_slice() == &*message.pubkey,
            "noncanonical native PK share"
        );
        let commitment = e3_zk_witness::compute_pk_commitment_from_keyshare_bytes(
            &message.pubkey,
            &config.threshold,
            &crp,
        )?;
        let slot = self
            .local
            .setup
            .dealers
            .iter()
            .position(|&id| id == owner)
            .context("native PK contribution is outside the fixed roster")?;
        ensure!(
            public.binding() == Some(self.local.setup.binding)
                && public.party_id() == Some(owner)
                && public.pk_commitment() == Some(commitment)
                && self.local.setup.threshold_keys[slot] == commitment,
            "native PK contribution differs from the admitted recipient setup"
        );
        Ok(())
    }

    pub fn c5_request(
        &self,
        shares: &BTreeMap<u32, KeyshareCreated>,
    ) -> Result<PkAggregationProofRequest> {
        let config = self.config()?;
        let crp = e3_fhe_params::create_deterministic_crp_from_default_seed(&config.threshold);
        let mut native = Vec::new();
        let mut bytes = Vec::new();
        for id in &self.local.setup.dealers {
            let share = shares
                .get(id)
                .context("missing selected native PK contribution")?;
            self.keyshare(share)?;
            native.push(PublicKeyShare::deserialize(
                &share.pubkey,
                &config.threshold,
                crp.clone(),
            )?);
            bytes.push(share.pubkey.clone());
        }
        let key = PublicKey::from_shares(native)?;
        let dims = config.committee.values();
        Ok(PkAggregationProofRequest {
            keyshare_bytes: bytes,
            aggregated_pk_bytes: ArcBytes::from_bytes(&key.to_bytes()),
            params_profile: self.selected.params_profile,
            committee_n: dims.n,
            committee_h: dims.h,
            committee_threshold: dims.threshold,
        })
    }

    pub(crate) fn pk_commitment(&self, request: &PkAggregationProofRequest) -> Result<[u8; 32]> {
        use fhe_traits::DeserializeParametrized;
        let config = self.config()?;
        let key = PublicKey::from_bytes(&request.aggregated_pk_bytes, &config.threshold)?;
        Ok(
            e3_zk_witness::threshold::user_data_encryption::compute_public_key_commitment(
                &config.threshold,
                &key,
            )?,
        )
    }

    pub(crate) fn validate_c5(
        &self,
        request: &PkAggregationProofRequest,
        proof: &Proof,
    ) -> Result<()> {
        ensure!(
            proof.circuit == CircuitName::PkAggregation,
            "not a C5 proof"
        );
        let public = PublicSignals::decode(&self.config()?, proof.circuit, &proof.public_signals)?;
        ensure!(
            public.threshold_keys() == Some(self.local.setup.threshold_keys.as_slice())
                && public.pk_commitment() == Some(self.pk_commitment(request)?),
            "C5 result differs from the independent native PK"
        );
        Ok(())
    }

    pub fn publication_request(
        &self,
        native: &PkAggregationProofRequest,
        c5: &Proof,
        recipients: &BTreeMap<u32, SynchronizedDkgProofPublished>,
    ) -> Result<SynchronizedDkgProofRequest> {
        self.validate_c5(native, c5)?;
        let mut proofs = Vec::new();
        let mut sk = Vec::new();
        let mut bundles = Vec::new();
        for id in &self.local.setup.dealers {
            let message = recipients
                .get(id)
                .context("missing selected recipient join")?;
            let public = self.recipient(message)?;
            sk.push(public.sk_commitment().context("missing recipient SK")?);
            bundles.push(public.key_bundle().context("missing recipient keys")?);
            proofs.push(message.proof.clone());
        }
        Ok(SynchronizedDkgProofRequest {
            params_profile: self.selected.params_profile,
            committee_size: self.config()?.committee,
            context: self.local.context.clone(),
            job: SynchronizedDkgProofJob::Publication {
                recipients: proofs,
                c5: c5.clone(),
                expected: SynchronizedPublicationExpectation {
                    dealers: self.local.setup.dealers.clone(),
                    threshold_keys: self.local.setup.threshold_keys.clone(),
                    dealer_batch: self.local.setup.dealer_batch,
                    sk_commitments: sk,
                    key_bundles: bundles,
                    public_key: native.aggregated_pk_bytes.clone(),
                },
            },
        })
    }

    pub fn consent(
        &self,
        context: SynchronizedDkgContext,
        native: &PkAggregationProofRequest,
        recipients: &BTreeMap<u32, SynchronizedDkgProofPublished>,
        signed: &SignedSynchronizedDkgAttestation,
    ) -> Result<()> {
        let payload = &signed.payload;
        let recipient = recipients
            .get(&payload.party_id)
            .context("consent has no recipient join")?;
        let public = self.recipient(recipient)?;
        ensure!(
            payload.e3_id == self.selected.e3_id
                && payload.context == context
                && context.crypto_config_id == self.selected.crypto_config_id
                && self.members()?.get(payload.party_id as usize)
                    == Some(&signed.recover_address()?)
                && payload.setup_binding
                    == self
                        .local
                        .context
                        .setup
                        .hash(
                            self.selected.e3_id.chain_id(),
                            self.selected.e3_id.clone().try_into()?,
                        )
                        .0
                && payload.roster_hash == synchronized_dkg_roster_hash(&self.local.setup.dealers)
                && payload.dealer_batch == self.local.setup.dealer_batch
                && payload.pk_commitment == self.pk_commitment(native)?
                && Some(payload.sk_agg_commit) == public.sk_commitment()
                && Some(payload.key_bundle_commit) == public.key_bundle(),
            "recipient consent differs from the frozen context or exact publication anchors"
        );
        Ok(())
    }

    pub fn validate_publication(
        &self,
        native: &PkAggregationProofRequest,
        request: &SynchronizedDkgProofRequest,
        proof: &Proof,
    ) -> Result<()> {
        let SynchronizedDkgProofJob::Publication { expected, .. } = &request.job else {
            anyhow::bail!("not a publication request");
        };
        ensure!(
            proof.circuit == CircuitName::DkgAggregator,
            "not a publication proof"
        );
        let public = PublicSignals::decode(&self.config()?, proof.circuit, &proof.public_signals)?;
        ensure!(
            public.binding() == Some(self.local.setup.binding)
                && public.dealers().as_deref() == Some(expected.dealers.as_slice())
                && public.threshold_keys() == Some(expected.threshold_keys.as_slice())
                && public.dealer_batch() == Some(expected.dealer_batch)
                && public.recipient_sk_commitments() == Some(expected.sk_commitments.as_slice())
                && public.recipient_key_bundles() == Some(expected.key_bundles.as_slice())
                && public.pk_commitment() == Some(self.pk_commitment(native)?),
            "publication worker result differs from the dispatched native/setup expectations"
        );
        // The correlated production worker checks the configured recursive VK tree and verifies
        // the EVM proof before returning. Peer proofs cannot enter this result boundary.
        Ok(())
    }
}
