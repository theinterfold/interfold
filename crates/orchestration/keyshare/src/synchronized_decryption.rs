// SPDX-License-Identifier: LGPL-3.0-only

use crate::domain::{AggregatingDecryptionKey, DecryptionKeyPlan};
use crate::synchronized::{
    commitment_field, decode_statement, setup_binding, SynchronizedDkgRecovery,
};
use anyhow::{ensure, Context, Result};
use e3_crypto::Cipher;
use e3_events::{
    DkgShareDecryptionProofRequest, E3id, ProofType, SignedProofPayload,
    SynchronizedShareDecryption, ThresholdShare,
};
use e3_trbfv::{
    calculate_decryption_key::CalculateDecryptionKeyRequest,
    helpers::deserialize_secret_key,
    shares::EncryptableVec,
    synchronized::{unpack_key, SealedPrfKeys},
    TrBFVConfig,
};
use e3_zk_config::{synchronized::Configs, DkgInputType};
use e3_zk_witness::synchronized::{commitments, share_decryption};
use fhe::trbfv::ShareManager;
use num_bigint::{BigInt, Sign};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

#[allow(clippy::too_many_arguments)]
pub(crate) fn plan_decryption(
    cipher: &Cipher,
    config: &Configs,
    trbfv: TrBFVConfig,
    current: &AggregatingDecryptionKey,
    shares: &[Arc<ThresholdShare>],
    selected: &BTreeSet<u64>,
    proofs: &BTreeMap<u64, SignedProofPayload>,
    material: &SynchronizedDkgRecovery,
    e3_id: &E3id,
) -> Result<DecryptionKeyPlan> {
    let committee = config.committee.values();
    let owner = material.context.party_id;
    ensure!(
        selected.len() == committee.h
            && selected.iter().all(|&id| id < committee.n as u64)
            && trbfv.num_parties() as usize == committee.n
            && trbfv.threshold() as usize == committee.threshold
            && e3_fhe_params::encode_bfv_params(&trbfv.params())
                == e3_fhe_params::encode_bfv_params(&config.threshold)
            && current.own_esi_shares_raw.is_empty(),
        "synchronized aggregation requires its exact profile, H roster and no SS material"
    );
    let binding = setup_binding(&material.context, e3_id)?;
    let outgoing =
        material
            .outgoing_keys
            .open(config.profile, binding, owner, committee.n, cipher)?;
    let own_c2 = proofs
        .get(&(owner as u64))
        .context("owner's C2 root is unavailable")?;
    let own_c2 = decode_statement(
        config,
        binding,
        owner,
        ProofType::C2aSkShareComputation,
        own_c2,
        e3_id,
    )?;
    let root = own_c2.outgoing_root().unwrap();
    let keys = zeroize::Zeroizing::new(
        outgoing
            .iter()
            .map(|key| *key.as_bytes())
            .collect::<Vec<_>>(),
    );
    ensure!(
        commitment_field(&commitments::outgoing_root(config, binding, owner, &keys)?)? == root,
        "saved outgoing keys do not open the owner's C2 root"
    );
    let raw = current.sk_bfv.access(cipher)?;
    let secret = deserialize_secret_key(&raw, &config.transport)?;
    let own = zeroize::Zeroizing::new(bincode::deserialize::<Vec<Vec<u64>>>(
        &current.own_sk_share_raw.access(cipher)?,
    )?);
    let mut ciphertexts = Vec::new();
    let mut packed_rows = zeroize::Zeroizing::new(Vec::new());
    let mut residues = Vec::new();
    let mut incoming = Vec::new();
    let mut expected_commitments = Vec::new();
    let mut dealer_ids = Vec::new();
    for &dealer in selected {
        let c2 = proofs
            .get(&dealer)
            .context("selected verified dealer has no C2 proof")?;
        let c2 = decode_statement(
            config,
            binding,
            dealer.try_into()?,
            ProofType::C2aSkShareComputation,
            c2,
            e3_id,
        )?;
        let messages = c2.message_commitments().unwrap();
        let l = config.threshold.moduli().len();
        expected_commitments.push(messages[owner as usize * l..(owner as usize + 1) * l].to_vec());
        let packed = if dealer == owner as u64 {
            crate::domain::vec_of_rows_to_shamir_share(&own, config.threshold.degree())?
        } else {
            let matching: Vec<_> = shares
                .iter()
                .filter(|share| share.party_id == dealer)
                .collect();
            ensure!(
                matching.len() <= 1,
                "duplicate selected synchronized dealer"
            );
            let Some(share) = matching.first() else {
                return Ok(DecryptionKeyPlan::Insufficient);
            };
            ensure!(
                share.esi_sss.is_empty(),
                "synchronized dealer supplied SS smudging material"
            );
            let slot = if share.sk_sss.len() == 1 {
                0
            } else {
                owner as usize
            };
            let encrypted = share
                .sk_sss
                .clone_share(slot)
                .context("selected dealer has no recipient ciphertext")?;
            ensure!(
                encrypted.num_moduli() == l,
                "selected dealer has another CRT multiplicity"
            );
            ciphertexts.extend(encrypted.ciphertext_bytes().iter().cloned());
            encrypted.decrypt(&secret, &config.transport, config.threshold.degree())?
        };
        let (residue, key) = unpack_key(config.profile, &packed)?;
        residues.push(residue);
        incoming.push(key);
        packed_rows.push(packed.rows().into_iter().map(|row| row.to_vec()).collect());
        dealer_ids.push(dealer.try_into()?);
    }
    let field = |bytes: &[u8; 32]| BigInt::from_bytes_be(Sign::Plus, bytes);
    // Open the actual plaintexts against the authenticated C2 messages before saving key material.
    share_decryption::Inputs::compute(
        config,
        binding,
        share_decryption::Data {
            recipient_id: owner,
            dealer_ids: dealer_ids.clone(),
            expected_outgoing_root: field(&root),
            expected_commitments: expected_commitments
                .iter()
                .map(|row| row.iter().map(field).collect())
                .collect(),
            packed_shares: packed_rows,
            outgoing_keys: keys.clone(),
            incoming_keys: incoming
                .iter()
                .map(|key| *key.as_bytes())
                .collect::<Vec<_>>()
                .into(),
        },
    )?;
    let manager = ShareManager::new(committee.n, committee.threshold, config.threshold.clone())?;
    let aggregate = manager.aggregate_collected_shares(
        &residues
            .iter()
            .map(|share| share.view().to_owned())
            .collect::<Vec<_>>(),
    )?;
    let aggregate =
        e3_zk_witness::encoding::fhe_poly_to_crt_centered(&aggregate, config.threshold.moduli())?;
    let sk_commitment =
        e3_zk_witness::compute_aggregated_shares_commitment(&aggregate, config.aggregate_bit);
    let incoming_bytes = zeroize::Zeroizing::new(
        incoming
            .iter()
            .map(|key| *key.as_bytes())
            .collect::<Vec<_>>(),
    );
    let bundle = commitments::key_bundle(
        config,
        binding,
        owner,
        &dealer_ids,
        &sk_commitment,
        &keys,
        &incoming_bytes,
    )?;
    let own_idx = dealer_ids.iter().position(|&id| id == owner);
    let request = DkgShareDecryptionProofRequest {
        sk_bfv: current.sk_bfv.clone(),
        honest_ciphertexts_raw: ciphertexts,
        num_honest_parties: committee.h,
        num_moduli: config.threshold.moduli().len(),
        own_plaintext_idx: own_idx,
        own_share_raw: own_idx.map(|_| current.own_sk_share_raw.clone()),
        dkg_input_type: DkgInputType::SecretKey,
        params_profile: config.profile,
        committee_size: config.committee,
        synchronized: Some(SynchronizedShareDecryption {
            context: material.context.clone(),
            dealer_ids: dealer_ids.clone(),
            expected_outgoing_root: root,
            expected_commitments,
            outgoing_keys: material.outgoing_keys.clone(),
        }),
    };
    Ok(DecryptionKeyPlan::Proceed {
        calc_request: CalculateDecryptionKeyRequest {
            trbfv_config: trbfv,
            sk_sss_collected: residues.encrypt(cipher)?,
            esi_sss_collected: Vec::new(),
        },
        sk_request: request,
        esm_requests: Vec::new(),
        honest_party_ids: selected.clone(),
        synchronized: Some(SynchronizedDkgRecovery {
            context: material.context.clone(),
            generation_response_hash: material.generation_response_hash,
            outgoing_keys: material.outgoing_keys.clone(),
            incoming_keys: Some(SealedPrfKeys::seal(
                config.profile,
                binding,
                owner,
                &incoming,
                cipher,
            )?),
            dealer_ids,
            sk_commitment: Some(commitment_field(&sk_commitment)?),
            key_bundle: Some(commitment_field(&bundle)?),
            c2_statements: proofs
                .iter()
                .filter(|(id, _)| selected.contains(id) || **id == owner as u64)
                .map(|(&id, proof)| {
                    Ok((
                        u32::try_from(id)?,
                        proof.payload.proof.public_signals.clone(),
                    ))
                })
                .collect::<Result<_>>()?,
            threshold_pk_shares: selected
                .iter()
                .map(|&id| {
                    let bytes = if id == u64::from(owner) {
                        current.pk_share.clone()
                    } else {
                        shares
                            .iter()
                            .find(|share| share.party_id == id)
                            .context("selected dealer has no native PK share")?
                            .pk_share
                            .clone()
                    };
                    Ok((u32::try_from(id)?, bytes))
                })
                .collect::<Result<_>>()?,
        }),
    })
}
