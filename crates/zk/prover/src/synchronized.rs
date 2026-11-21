// SPDX-License-Identifier: LGPL-3.0-only

//! Encrypted-request preparation for the isolated synchronized DKG leaves. These adapters do not
//! admit the profile or authenticate caller-supplied chain context.

pub mod dealer;
pub mod decryption;
pub mod execution;
pub mod provenance;
pub mod publication;
pub mod recipient;

use crate::{Provable, ZkError};
use anyhow::{ensure, Context, Result};
use e3_crypto::Cipher;
use e3_events::{
    DkgShareDecryptionProofRequest, E3id, PkGenerationProofRequest, ShareComputationProofRequest,
    SynchronizedProofContext,
};
use e3_polynomial::CrtPolynomial;
use e3_polynomial_fhe::FromFhePolynomial as _;
use e3_trbfv::{
    helpers::{deserialize_secret_key, try_poly_ntt_from_bytes, try_poly_pb_from_bytes},
    shares::{ShamirShare, SharedSecret},
    synchronized::unpack_key,
};
use e3_zk_config::{synchronized::Configs, CircuitName, DkgInputType};
use e3_zk_witness::synchronized::{pk_generation, share_computation, share_decryption};
use fhe::bfv::{Ciphertext, Encoding};
use fhe_traits::{DeserializeParametrized, FheDecoder, FheDecrypter};
use ndarray::Array2;
use num_bigint::{BigInt, Sign};

pub fn request_binding(
    config: &Configs,
    context: &SynchronizedProofContext,
    e3_id: &E3id,
) -> Result<[u128; 2]> {
    ensure!(
        context.setup.crypto_config_id == config.profile.crypto_config_id(config.committee)?
            && !context.setup.interfold_address.is_zero()
            && !context.setup.committee_hash.is_zero()
            && (context.party_id as usize) < config.committee.values().n,
        "synchronized proof context does not match its profile/committee"
    );
    Ok(context
        .setup
        .binding(e3_id.chain_id(), e3_id.clone().try_into()?))
}

pub fn prepare_pk_generation(
    config: &Configs,
    req: &PkGenerationProofRequest,
    e3_id: &E3id,
    cipher: &Cipher,
) -> Result<pk_generation::Inputs> {
    ensure!(
        req.params_profile == config.profile
            && req.committee_size == config.committee
            && req.e_sm.is_none(),
        "C1 request belongs to another protocol"
    );
    let context = req
        .synchronized
        .as_ref()
        .context("synchronized C1 has no setup context")?;
    let binding = request_binding(config, context, e3_id)?;
    let sk = req.sk.access(cipher)?;
    let error = req.eek.access(cipher)?;
    let data = pk_generation::Data {
        pk0_share: CrtPolynomial::from_fhe_polynomial(&try_poly_ntt_from_bytes(
            &req.pk0_share,
            &config.threshold,
        )?),
        sk: CrtPolynomial::from_fhe_polynomial(&try_poly_pb_from_bytes(&sk, &config.threshold)?),
        eek: CrtPolynomial::from_fhe_polynomial(&try_poly_ntt_from_bytes(
            &error,
            &config.threshold,
        )?),
    };
    Ok(pk_generation::Inputs::compute(
        config,
        binding,
        context.party_id,
        &data,
    )?)
}

pub fn prepare_share_computation(
    config: &Configs,
    req: &ShareComputationProofRequest,
    e3_id: &E3id,
    cipher: &Cipher,
) -> Result<share_computation::Inputs> {
    ensure!(
        req.params_profile == config.profile
            && req.committee_size == config.committee
            && req.dkg_input_type == DkgInputType::SecretKey,
        "C2 request belongs to another protocol"
    );
    let sync = req
        .synchronized
        .as_ref()
        .context("synchronized C2 has no directed-key material")?;
    let binding = request_binding(config, &sync.context, e3_id)?;
    let keys = sync.outgoing_keys.open(
        config.profile,
        binding,
        sync.context.party_id,
        config.committee.values().n,
        cipher,
    )?;
    let raw = req.secret_raw.access(cipher)?;
    let shared = req.secret_sss_raw.access(cipher)?;
    let secret = try_poly_pb_from_bytes(&raw, &config.threshold)?;
    let mut secret = CrtPolynomial::from_fhe_polynomial(&secret);
    secret.center(config.threshold.moduli())?;
    let shares: SharedSecret = bincode::deserialize(&shared)?;
    Ok(share_computation::Inputs::compute(
        config,
        binding,
        sync.context.party_id,
        share_computation::Data {
            secret,
            secret_sss: shares
                .moduli_data()
                .iter()
                .map(|limb| limb.mapv(BigInt::from))
                .collect(),
            outgoing_keys: keys
                .iter()
                .map(|key| *key.as_bytes())
                .collect::<Vec<_>>()
                .into(),
        },
    )?)
}

pub fn prepare_share_decryption(
    config: &Configs,
    req: &DkgShareDecryptionProofRequest,
    e3_id: &E3id,
    cipher: &Cipher,
) -> Result<share_decryption::Inputs> {
    ensure!(
        req.params_profile == config.profile
            && req.committee_size == config.committee
            && req.dkg_input_type == DkgInputType::SecretKey,
        "C4 request belongs to another protocol"
    );
    let sync = req
        .synchronized
        .as_ref()
        .context("synchronized C4 has no authenticated openings")?;
    let binding = request_binding(config, &sync.context, e3_id)?;
    let h = config.committee.values().h;
    let l = config.threshold.moduli().len();
    let n = config.threshold.degree();
    ensure!(
        req.num_honest_parties == h
            && req.num_moduli == l
            && sync.dealer_ids.len() == h
            && sync.dealer_ids.windows(2).all(|ids| ids[0] < ids[1])
            && sync
                .dealer_ids
                .iter()
                .all(|&id| (id as usize) < config.committee.values().n),
        "synchronized C4 requires the exact ordered H roster and threshold CRT shape"
    );
    let own = sync
        .dealer_ids
        .iter()
        .position(|&id| id == sync.context.party_id);
    ensure!(
        req.own_plaintext_idx == own && req.own_share_raw.is_some() == own.is_some(),
        "C4 own row is not the recipient's roster position"
    );
    ensure!(
        req.honest_ciphertexts_raw.len() == (h - usize::from(own.is_some())) * l,
        "C4 external ciphertext multiplicity differs"
    );
    let raw = req.sk_bfv.access(cipher)?;
    let secret = deserialize_secret_key(&raw, &config.transport)?;
    let own_share: Option<zeroize::Zeroizing<Vec<Vec<u64>>>> = req
        .own_share_raw
        .as_ref()
        .map(|raw| {
            let decrypted = raw.access(cipher)?;
            Ok::<_, anyhow::Error>(zeroize::Zeroizing::new(bincode::deserialize(&decrypted)?))
        })
        .transpose()?;
    let keys = sync.outgoing_keys.open(
        config.profile,
        binding,
        sync.context.party_id,
        config.committee.values().n,
        cipher,
    )?;
    let mut packed_shares = zeroize::Zeroizing::new(Vec::with_capacity(h));
    let mut incoming_keys = zeroize::Zeroizing::new(Vec::with_capacity(h));
    let mut external = req.honest_ciphertexts_raw.iter();
    for row in 0..h {
        let mut coefficients = if Some(row) == own {
            own_share
                .as_ref()
                .context("missing own C4 plaintext")?
                .clone()
        } else {
            let mut limbs = zeroize::Zeroizing::new(Vec::with_capacity(l));
            for _ in 0..l {
                let raw = external.next().context("missing C4 transport ciphertext")?;
                let ct = Ciphertext::from_bytes(raw, &config.transport)?;
                let plaintext = secret.try_decrypt(&ct)?;
                limbs.push(Vec::<u64>::try_decode(&plaintext, Encoding::poly())?);
            }
            limbs
        };
        ensure!(
            coefficients.len() == l && coefficients.iter().all(|limb| limb.len() == n),
            "C4 plaintext has another ring/CRT shape"
        );
        let packed = ShamirShare::new(Array2::from_shape_vec(
            (l, n),
            coefficients.iter().flatten().copied().collect(),
        )?);
        let (_, key) = unpack_key(config.profile, &packed)?;
        incoming_keys.push(*key.as_bytes());
        packed_shares.push(std::mem::take(&mut *coefficients));
    }
    let field = |bytes: &[u8; 32]| BigInt::from_bytes_be(Sign::Plus, bytes);
    Ok(share_decryption::Inputs::compute(
        config,
        binding,
        share_decryption::Data {
            recipient_id: sync.context.party_id,
            dealer_ids: sync.dealer_ids.clone(),
            expected_outgoing_root: field(&sync.expected_outgoing_root),
            expected_commitments: sync
                .expected_commitments
                .iter()
                .map(|row| row.iter().map(field).collect())
                .collect(),
            packed_shares,
            outgoing_keys: keys
                .iter()
                .map(|key| *key.as_bytes())
                .collect::<Vec<_>>()
                .into(),
            incoming_keys,
        },
    )?)
}

pub struct PkGenerationCircuit;
impl Provable for PkGenerationCircuit {
    type Config = Configs;
    type Input = pk_generation::Inputs;
    fn circuit(&self) -> CircuitName {
        CircuitName::PkGeneration
    }
    fn build_inputs(
        &self,
        _: &Configs,
        input: &Self::Input,
    ) -> Result<noirc_abi::InputMap, ZkError> {
        crate::circuits::utils::inputs_json_to_input_map(&input.to_json())
    }
}

pub struct ShareComputationCircuit;
impl Provable for ShareComputationCircuit {
    type Config = Configs;
    type Input = share_computation::Inputs;
    fn circuit(&self) -> CircuitName {
        CircuitName::SkShareComputation
    }
    fn build_inputs(
        &self,
        _: &Configs,
        input: &Self::Input,
    ) -> Result<noirc_abi::InputMap, ZkError> {
        crate::circuits::utils::inputs_json_to_input_map(&input.to_json())
    }
}

pub struct ShareDecryptionCircuit;
impl Provable for ShareDecryptionCircuit {
    type Config = Configs;
    type Input = share_decryption::Inputs;
    fn circuit(&self) -> CircuitName {
        CircuitName::DkgShareDecryption
    }
    fn build_inputs(
        &self,
        _: &Configs,
        input: &Self::Input,
    ) -> Result<noirc_abi::InputMap, ZkError> {
        crate::circuits::utils::inputs_json_to_input_map(&input.to_json())
    }
}
