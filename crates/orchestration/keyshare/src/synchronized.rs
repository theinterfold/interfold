// SPDX-License-Identifier: LGPL-3.0-only

//! Request-bound encrypted material for the disabled synchronized DKG workflow.

use alloy::primitives::Address;
use anyhow::{ensure, Context, Result};
use e3_committee::CiphernodesCommitteeSize;
use e3_committee_hash::{hash_committee_addresses, DkgSetupContext};
use e3_crypto::Cipher;
use e3_events::{CiphernodeSelected, E3id, SynchronizedProofContext};
use e3_fhe_params::BfvDecryptionProtocol;
use e3_trbfv::synchronized::SealedPrfKeys;

mod publication;
pub use publication::ConfirmedSynchronizedDkgSetup;
mod setup;
pub use setup::SynchronizedSetupIntent;

pub fn decode_statement(
    config: &e3_zk_config::synchronized::Configs,
    binding: [u128; 2],
    owner: u32,
    kind: e3_events::ProofType,
    signed: &e3_events::SignedProofPayload,
    e3_id: &E3id,
) -> Result<e3_zk_config::synchronized::public_signals::PublicSignals> {
    ensure!(
        signed.payload.e3_id == *e3_id && signed.payload.proof_type == kind,
        "synchronized proof belongs to another request or role"
    );
    let circuit = kind.circuit_names()[0];
    ensure!(
        signed.payload.proof.circuit == circuit,
        "synchronized proof names another circuit"
    );
    let signals = e3_zk_config::synchronized::public_signals::PublicSignals::decode(
        config,
        circuit,
        &signed.payload.proof.public_signals,
    )?;
    ensure!(
        signals.binding() == Some(binding) && signals.party_id() == Some(owner),
        "synchronized proof context or owner differs"
    );
    Ok(signals)
}

/// Called only after the complete dealer message has authenticated its full-committee slot.
pub fn validate_received_share(
    selected: &CiphernodeSelected,
    interfold: Address,
    message: &e3_events::ThresholdShareCreated,
) -> Result<()> {
    use e3_events::ProofType;
    use e3_zk_config::{
        synchronized::{public_signals::PublicSignals, Configs},
        CircuitName,
    };
    use fhe::bfv::Ciphertext;
    use fhe_traits::DeserializeParametrized;
    let context = proof_context(selected, interfold)?;
    ensure!(
        message.e3_id == selected.e3_id && message.target_party_id == selected.party_id,
        "synchronized share targets another request or recipient"
    );
    let committee =
        CiphernodesCommitteeSize::from_threshold(selected.threshold_m, selected.threshold_n)?;
    let config = Configs::for_profile(selected.params_profile, committee)?;
    let binding = setup_binding(&context, &message.e3_id)?;
    let dealer: u32 = message.share.party_id.try_into()?;
    let c2 = message
        .signed_c2a_proof
        .as_ref()
        .context("missing synchronized C2")?;
    let signals = decode_statement(
        &config,
        binding,
        dealer,
        ProofType::C2aSkShareComputation,
        c2,
        &message.e3_id,
    )?;
    ensure!(
        message.signed_c2b_proof.is_none()
            && message.signed_c3b_proofs.is_empty()
            && message.share.esi_sss.is_empty(),
        "synchronized shares cannot carry SS smudging proofs or ciphertexts"
    );
    let l = config.threshold.moduli().len();
    ensure!(
        message.signed_c3a_proofs.len() == l,
        "synchronized share requires every threshold CRT-row proof"
    );
    ensure!(
        message.share.sk_sss.len() == 1,
        "recipient transport must contain exactly its own slot"
    );
    let ciphertext = message
        .share
        .sk_sss
        .clone_share(0)
        .context("missing encrypted synchronized share")?;
    ensure!(
        ciphertext.num_moduli() == l,
        "synchronized ciphertext multiplicity differs"
    );
    let expected_signer = selected
        .committee
        .get(dealer as usize)
        .context("dealer outside committee")?
        .parse::<Address>()?;
    ensure!(
        c2.recover_address()? == expected_signer,
        "synchronized C2 signer does not own the dealer slot"
    );
    let messages = signals.message_commitments().unwrap();
    for (row, proof) in message.signed_c3a_proofs.iter().enumerate() {
        ensure!(
            proof.payload.e3_id == message.e3_id
                && proof.payload.proof_type == ProofType::C3aSkShareEncryption
                && proof.payload.proof.circuit == CircuitName::ShareEncryption
                && proof.recover_address()? == expected_signer,
            "synchronized C3 role or dealer authentication differs"
        );
        let public = PublicSignals::decode(
            &config,
            CircuitName::ShareEncryption,
            &proof.payload.proof.public_signals,
        )?;
        ensure!(
            public.message_commitments().unwrap()[0]
                == messages[selected.party_id as usize * l + row],
            "C3 does not encrypt this exact recipient/CRT C2 message"
        );
        let ct = Ciphertext::from_bytes(&ciphertext.ciphertext_bytes()[row], &config.transport)?;
        ensure!(
            ct.len() == 2,
            "synchronized transport requires two ciphertext components"
        );
        let ct0 =
            e3_zk_witness::encoding::fhe_poly_to_crt_centered(&ct[0], config.transport.moduli())?;
        let ct1 =
            e3_zk_witness::encoding::fhe_poly_to_crt_centered(&ct[1], config.transport.moduli())?;
        let commitment = e3_zk_witness::compute_ciphertext_commitment(
            &ct0,
            &ct1,
            config.share_encryption.bits.ct_bit,
        );
        let expected = commitment_field(&commitment)?;
        ensure!(
            public.ciphertext_commitment() == Some(expected),
            "C3 ciphertext does not match signed transport"
        );
    }
    Ok(())
}

pub fn validate_c4_message(
    selected: &CiphernodeSelected,
    interfold: Address,
    message: &e3_events::DecryptionKeyShared,
    roster: Option<&std::collections::BTreeSet<u64>>,
    material: Option<&SynchronizedDkgRecovery>,
) -> Result<()> {
    let context = proof_context(selected, interfold)?;
    ensure!(
        message.e3_id == selected.e3_id,
        "C4 message belongs to another E3"
    );
    let signer = selected
        .committee
        .get(message.party_id as usize)
        .context("C4 owner is outside committee")?
        .parse::<Address>()?;
    ensure!(
        message.recover_address()? == signer && message.node.parse::<Address>()? == signer,
        "C4 message is not authenticated by its canonical owner"
    );
    ensure!(
        message.signed_e_sm_decryption_proofs.is_empty(),
        "synchronized C4 cannot contain a smudging proof"
    );
    let proof = &message.signed_sk_decryption_proof;
    ensure!(
        proof.recover_address()? == signer,
        "C4 proof signer differs from its owner"
    );
    let config = e3_zk_config::synchronized::Configs::for_profile(
        selected.params_profile,
        CiphernodesCommitteeSize::from_threshold(selected.threshold_m, selected.threshold_n)?,
    )?;
    let public = decode_statement(
        &config,
        setup_binding(&context, &message.e3_id)?,
        message.party_id.try_into()?,
        e3_events::ProofType::C4aSkShareDecryption,
        proof,
        &message.e3_id,
    )?;
    if let Some(roster) = roster {
        ensure!(
            public
                .dealers()
                .unwrap()
                .iter()
                .map(|&id| id as u64)
                .collect::<std::collections::BTreeSet<_>>()
                == *roster,
            "C4 names another accepted H roster"
        );
    }
    if let Some(material) = material.filter(|saved| saved.incoming_keys.is_some()) {
        material.validate_c4(&config, &message.e3_id, message.party_id.try_into()?, proof)?;
    }
    Ok(())
}

pub(crate) fn commitment_field(value: &num_bigint::BigInt) -> Result<[u8; 32]> {
    ensure!(
        value.sign() != num_bigint::Sign::Minus && value < &e3_zk_config::field::get_zkp_modulus(),
        "commitment is not a canonical field"
    );
    let (_, bytes) = value.to_bytes_be();
    let mut field = [0; 32];
    field[32 - bytes.len()..].copy_from_slice(&bytes);
    Ok(field)
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SynchronizedDkgRecovery {
    pub context: SynchronizedProofContext,
    /// Exact successful encrypted native response; retries cannot replace randomized contributions.
    pub generation_response_hash: [u8; 32],
    pub outgoing_keys: SealedPrfKeys,
    pub incoming_keys: Option<SealedPrfKeys>,
    pub dealer_ids: Vec<u32>,
    pub sk_commitment: Option<[u8; 32]>,
    pub key_bundle: Option<[u8; 32]>,
    /// Public statements copied only from the exact verified dealer batch, before large transport
    /// payloads retire. C4 compares every selected row, not an absence in a partial proof cache.
    pub c2_statements: std::collections::BTreeMap<u32, e3_utils::ArcBytes>,
    /// Exact native PK shares from the fixed, authenticated dealer batch, retained after encrypted
    /// transport retires. Recipient results must match commitments derived from these bytes.
    pub threshold_pk_shares: std::collections::BTreeMap<u32, e3_utils::ArcBytes>,
}

pub fn proof_context(
    selected: &CiphernodeSelected,
    interfold_address: Address,
) -> Result<SynchronizedProofContext> {
    ensure!(
        selected.params_profile.protocol() == BfvDecryptionProtocol::Synchronized,
        "SS cannot carry synchronized DKG material"
    );
    let committee =
        CiphernodesCommitteeSize::from_threshold(selected.threshold_m, selected.threshold_n)?;
    selected.params_profile.validate_committee(committee)?;
    ensure!(
        selected
            .params_profile
            .crypto_config_id(committee)?
            .as_slice()
            == selected.crypto_config_id,
        "DKG selection has another crypto configuration"
    );
    let (threshold, _) = selected.params_profile.build_pair()?;
    ensure!(
        &*selected.params == e3_fhe_params::encode_bfv_params(&threshold).as_slice(),
        "DKG selection parameter bytes differ from its profile"
    );
    let members = selected
        .committee
        .iter()
        .map(|member| member.parse::<Address>())
        .collect::<Result<Vec<_>, _>>()?;
    ensure!(
        !interfold_address.is_zero()
            && members.len() == committee.values().n
            && members.windows(2).all(|pair| pair[0] < pair[1])
            && selected.party_id < members.len() as u64,
        "DKG context requires the complete canonical ordered committee"
    );
    Ok(SynchronizedProofContext {
        party_id: selected.party_id.try_into()?,
        setup: DkgSetupContext {
            interfold_address,
            committee_hash: hash_committee_addresses(&members),
            crypto_config_id: selected.crypto_config_id.into(),
        },
    })
}

pub fn setup_binding(context: &SynchronizedProofContext, e3_id: &E3id) -> Result<[u128; 2]> {
    Ok(context
        .setup
        .binding(e3_id.chain_id(), e3_id.clone().try_into()?))
}

impl SynchronizedDkgRecovery {
    /// Public native intent for recipient collection. The caller still owns runtime admission,
    /// local event source and effect fencing; this definition API never signs or dispatches.
    pub fn recipient_inputs(
        &self,
        selected: &CiphernodeSelected,
        interfold: Address,
        transport_key: &fhe::bfv::PublicKey,
        cipher: &Cipher,
    ) -> Result<e3_events::SynchronizedRecipientInputsReady> {
        self.validate(selected, interfold, cipher)?;
        let committee =
            CiphernodesCommitteeSize::from_threshold(selected.threshold_m, selected.threshold_n)?;
        let config =
            e3_zk_config::synchronized::Configs::for_profile(selected.params_profile, committee)?;
        ensure!(
            transport_key.params == config.transport && transport_key.c.len() == 2,
            "recipient transport key belongs to another profile"
        );
        let key = e3_zk_witness::dkg::pk::Inputs::compute(&config.pk, transport_key)?;
        Ok(e3_events::SynchronizedRecipientInputsReady {
            e3_id: selected.e3_id.clone(),
            params_profile: selected.params_profile,
            committee_size: committee,
            context: self.context.clone(),
            dealers: self.dealer_ids.clone(),
            transport_key: commitment_field(&e3_zk_witness::compute_dkg_pk_commitment(
                &key.pk0is,
                &key.pk1is,
                config.pk.pk_bit,
            ))?,
            sk_commitment: self
                .sk_commitment
                .context("recipient intent has no native SK anchor")?,
            key_bundle: self
                .key_bundle
                .context("recipient intent has no native bundle anchor")?,
            c2_statements: self.c2_statements.clone(),
        })
    }

    pub fn validate(
        &self,
        selected: &CiphernodeSelected,
        interfold_address: Address,
        cipher: &Cipher,
    ) -> Result<()> {
        ensure!(
            self.context == proof_context(selected, interfold_address)?,
            "saved DKG context differs from selection"
        );
        let binding = setup_binding(&self.context, &selected.e3_id)?;
        self.outgoing_keys.open(
            selected.params_profile,
            binding,
            self.context.party_id,
            selected.threshold_n,
            cipher,
        )?;
        if let Some(incoming) = &self.incoming_keys {
            let committee = CiphernodesCommitteeSize::from_threshold(
                selected.threshold_m,
                selected.threshold_n,
            )?
            .values();
            ensure!(
                self.dealer_ids.len() == committee.h
                    && self
                        .dealer_ids
                        .iter()
                        .all(|&id| (id as usize) < committee.n)
                    && self.dealer_ids.windows(2).all(|ids| ids[0] < ids[1])
                    && self.sk_commitment.is_some()
                    && self.key_bundle.is_some(),
                "saved synchronized C4 material is incomplete"
            );
            let incoming = incoming.open(
                selected.params_profile,
                binding,
                self.context.party_id,
                committee.h,
                cipher,
            )?;
            let outgoing = self.outgoing_keys.open(
                selected.params_profile,
                binding,
                self.context.party_id,
                committee.n,
                cipher,
            )?;
            let config = e3_zk_config::synchronized::Configs::for_profile(
                selected.params_profile,
                CiphernodesCommitteeSize::from_threshold(
                    selected.threshold_m,
                    selected.threshold_n,
                )?,
            )?;
            let sk = num_bigint::BigInt::from_bytes_be(
                num_bigint::Sign::Plus,
                &self.sk_commitment.unwrap(),
            );
            commitment_field(&sk)?;
            let bundle = e3_zk_witness::synchronized::commitments::key_bundle(
                &config,
                binding,
                self.context.party_id,
                &self.dealer_ids,
                &sk,
                &outgoing
                    .iter()
                    .map(|key| *key.as_bytes())
                    .collect::<Vec<_>>(),
                &incoming
                    .iter()
                    .map(|key| *key.as_bytes())
                    .collect::<Vec<_>>(),
            )?;
            ensure!(
                self.key_bundle == Some(commitment_field(&bundle)?),
                "saved synchronized keys do not open their C4 bundle"
            );
            let expected: std::collections::BTreeSet<_> = self
                .dealer_ids
                .iter()
                .copied()
                .chain([self.context.party_id])
                .collect();
            ensure!(
                self.c2_statements
                    .keys()
                    .copied()
                    .collect::<std::collections::BTreeSet<_>>()
                    == expected,
                "saved synchronized C2 provenance is incomplete"
            );
            ensure!(
                self.threshold_pk_shares.keys().copied().collect::<Vec<_>>() == self.dealer_ids,
                "saved synchronized native PK shares differ from the fixed roster"
            );
            for (&party, statement) in &self.c2_statements {
                let signals = e3_zk_config::synchronized::public_signals::PublicSignals::decode(
                    &config,
                    e3_zk_config::CircuitName::SkShareComputation,
                    statement,
                )?;
                ensure!(
                    signals.binding() == Some(binding) && signals.party_id() == Some(party),
                    "saved C2 provenance belongs to another setup"
                );
                if party == self.context.party_id {
                    let root = e3_zk_witness::synchronized::commitments::outgoing_root(
                        &config,
                        binding,
                        party,
                        &outgoing
                            .iter()
                            .map(|key| *key.as_bytes())
                            .collect::<Vec<_>>(),
                    )?;
                    ensure!(
                        signals.outgoing_root() == Some(commitment_field(&root)?),
                        "saved outgoing keys do not open their C2 root"
                    );
                }
            }
        } else {
            ensure!(
                self.dealer_ids.is_empty()
                    && self.sk_commitment.is_none()
                    && self.key_bundle.is_none()
                    && self.c2_statements.is_empty()
                    && self.threshold_pk_shares.is_empty(),
                "saved synchronized C4 material has no incoming keys"
            );
        }
        Ok(())
    }

    pub fn validate_pending(
        &self,
        selected: &CiphernodeSelected,
        pending: &e3_events::ThresholdSharePending,
        cipher: &Cipher,
    ) -> Result<()> {
        use e3_trbfv::shares::SharedSecret;
        use e3_zk_config::DkgInputType;
        let committee =
            CiphernodesCommitteeSize::from_threshold(selected.threshold_m, selected.threshold_n)?;
        let values = committee.values();
        let (threshold, _) = selected.params_profile.build_pair()?;
        let l = threshold.moduli().len();
        ensure!(
            pending.e3_id == selected.e3_id
                && pending.full_share.party_id == selected.party_id
                && pending.proof_request.params_profile == selected.params_profile
                && pending.proof_request.committee_size == committee
                && pending.proof_request.synchronized.as_ref() == Some(&self.context)
                && pending.proof_request.e_sm.is_none()
                && pending.proof_request.pk0_share == pending.full_share.pk_share
                && pending.sk_share_computation_request.secret_raw == pending.proof_request.sk
                && pending.sk_share_computation_request.params_profile == selected.params_profile
                && pending.sk_share_computation_request.committee_size == committee
                && pending.sk_share_computation_request.dkg_input_type == DkgInputType::SecretKey
                && pending
                    .sk_share_computation_request
                    .synchronized
                    .as_ref()
                    .is_some_and(|sync| {
                        sync.context == self.context && sync.outgoing_keys == self.outgoing_keys
                    })
                && pending.e_sm_share_computation_request.is_none()
                && pending.e_sm_share_encryption_requests.is_empty()
                && pending.full_share.esi_sss.is_empty()
                && pending.own_esi_shares_raw.is_empty()
                && pending.full_share.sk_sss.len() == values.n
                && pending.recipient_party_ids.len() >= values.h
                && pending
                    .recipient_party_ids
                    .iter()
                    .all(|&id| id < values.n as u64)
                && pending.recipient_party_ids.contains(&selected.party_id)
                && pending
                    .recipient_party_ids
                    .windows(2)
                    .all(|ids| ids[0] < ids[1]),
            "saved synchronized proof plan differs from its canonical request"
        );
        let expected: Vec<_> = (0..values.n)
            .filter(|&recipient| recipient != selected.party_id as usize)
            .flat_map(|recipient| (0..l).map(move |row| (recipient, row)))
            .collect();
        ensure!(
            pending.sk_share_encryption_requests.len() == expected.len(),
            "saved C3 plan is incomplete"
        );
        for (request, (recipient, row)) in pending.sk_share_encryption_requests.iter().zip(expected)
        {
            let ciphertext = pending
                .full_share
                .sk_sss
                .clone_share(recipient)
                .context("saved C3 recipient is missing")?;
            ensure!(
                request.params_profile == selected.params_profile
                    && request.committee_size == committee
                    && request.dkg_input_type == DkgInputType::SecretKey
                    && request.esi_index == 0
                    && request.recipient_party_id == recipient
                    && request.row_index == row
                    && ciphertext.num_moduli() == l
                    && request.ciphertext_raw == ciphertext.ciphertext_bytes()[row],
                "saved C3 request differs from its transport plan"
            );
        }
        let own: Vec<Vec<u64>> = bincode::deserialize(&pending.own_sk_share_raw.access(cipher)?)?;
        let own = crate::domain::vec_of_rows_to_shamir_share(&own, threshold.degree())?;
        let (residue, incoming) =
            e3_trbfv::synchronized::unpack_key(selected.params_profile, &own)?;
        let shares: SharedSecret = bincode::deserialize(
            &pending
                .sk_share_computation_request
                .secret_sss_raw
                .access(cipher)?,
        )?;
        let outgoing = self.outgoing_keys.open(
            selected.params_profile,
            setup_binding(&self.context, &selected.e3_id)?,
            self.context.party_id,
            values.n,
            cipher,
        )?;
        ensure!(
            residue == shares.extract_party_share(selected.party_id as usize)?
                && incoming.as_bytes() == outgoing[selected.party_id as usize].as_bytes(),
            "saved own packed share differs from the successful C2 contribution"
        );
        Ok(())
    }

    /// Validate C4 public claims against the complete accepted dealer batch. Signature and actual
    /// proof verification remain separate owner boundaries; an incomplete cache cannot accuse C2.
    pub fn validate_c4(
        &self,
        config: &e3_zk_config::synchronized::Configs,
        e3_id: &E3id,
        owner: u32,
        signed: &e3_events::SignedProofPayload,
    ) -> Result<()> {
        use e3_zk_config::{synchronized::public_signals::PublicSignals, CircuitName};
        let binding = setup_binding(&self.context, e3_id)?;
        let c4 = decode_statement(
            config,
            binding,
            owner,
            e3_events::ProofType::C4aSkShareDecryption,
            signed,
            e3_id,
        )?;
        ensure!(
            c4.dealers().as_ref() == Some(&self.dealer_ids),
            "C4 names another accepted roster"
        );
        let own_c2 = self
            .c2_statements
            .get(&owner)
            .context("C4 owner's authenticated outgoing root is unavailable")?;
        let own_c2 = PublicSignals::decode(config, CircuitName::SkShareComputation, own_c2)?;
        ensure!(
            own_c2.binding() == Some(binding) && own_c2.party_id() == Some(owner),
            "C4 owner's C2 belongs to another context"
        );
        ensure!(
            c4.outgoing_root() == own_c2.outgoing_root(),
            "C4 outgoing root differs from its owner's C2"
        );
        let l = config.threshold.moduli().len();
        let claimed = c4.message_commitments().unwrap();
        for (row, dealer) in self.dealer_ids.iter().enumerate() {
            let c2 = self
                .c2_statements
                .get(dealer)
                .context("C4 has no authenticated dealer C2 statement")?;
            let c2 = PublicSignals::decode(config, CircuitName::SkShareComputation, c2)?;
            ensure!(
                c2.binding() == Some(binding) && c2.party_id() == Some(*dealer),
                "C4 dealer's C2 belongs to another context"
            );
            let messages = c2.message_commitments().unwrap();
            ensure!(
                claimed[row * l..(row + 1) * l]
                    == messages[owner as usize * l..(owner as usize + 1) * l],
                "C4 does not open the exact recipient/CRT dealer messages"
            );
        }
        if owner == self.context.party_id {
            ensure!(
                c4.sk_commitment() == self.sk_commitment && c4.key_bundle() == self.key_bundle,
                "own C4 differs from saved synchronized decryption material"
            );
        }
        Ok(())
    }
}
