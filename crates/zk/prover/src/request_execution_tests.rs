// SPDX-License-Identifier: LGPL-3.0-only

use super::*;
use e3_events::{CorrelationId, PartyProofsToVerify, ProofPayload, ProofType, SignedProofPayload};
use e3_utils::ArcBytes;

fn unavailable_prover(root: &std::path::Path) -> ZkProver {
    ZkProver::new(&ZkBackend {
        base_dir: root.to_owned(),
        bb_binary: root.join("absent-bb"),
        circuits_dir: root.join("circuits"),
        work_dir: root.join("work"),
        config: Default::default(),
        using_custom_bb: true,
        bb_timeout: Duration::from_secs(1),
    })
}

#[actix::test]
async fn c0_execution_uses_the_profile_dkg_and_artifact_namespace() {
    use e3_fhe_params::BfvProfile;
    use fhe::bfv::SecretKey;
    use fhe_traits::Serialize as _;

    let temp = tempfile::tempdir().unwrap();
    let prover = unavailable_prover(temp.path());
    let cipher = Cipher::from_password("execution-test").await.unwrap();
    let mut insecure_key = ArcBytes::default();
    for (profile, directory) in [
        (BfvProfile::SsInsecure64, "insecure-64/minimum"),
        (BfvProfile::SsSecure8192, "secure-8192/minimum"),
    ] {
        let (_, dkg) = profile.build_pair().unwrap();
        let mut rng = rand::rng();
        let secret = SecretKey::random(&dkg, &mut rng);
        let key = ArcBytes::from_bytes(&PublicKey::new(&secret, &mut rng).to_bytes());
        if profile == BfvProfile::SsInsecure64 {
            insecure_key = key.clone();
        }
        let request = ComputeRequest::zk(
            ZkRequest::PkBfv(PkBfvProofRequest::new(
                key,
                profile,
                CiphernodesCommitteeSize::Minimum,
            )),
            CorrelationId::new(),
            E3id::new("7", 31_337),
        );
        let error = execute_zk_request(&prover, &cipher, request.clone(), &mut |_| {}).unwrap_err();
        assert_eq!(error.request(), &request);
        // A valid DKG key reaches the exact SS artifact path, not a threshold-key decoder or a
        // fallback namespace. The deliberately absent circuit is a local error, not a proof verdict.
        assert!(
            matches!(error.get_err(), ComputeRequestErrorKind::Zk(ZkEventError::ProofGenerationFailed(message))
            if message.contains(&format!("{directory}/recursive/dkg/pk/pk.json")))
        );
    }

    // Synchronized and SS profiles share threshold parameters. Even with a valid SS key, a
    // disabled profile must fail before any artifact lookup or prover work.
    let request = ComputeRequest::zk(
        ZkRequest::PkBfv(PkBfvProofRequest::new(
            insecure_key,
            BfvProfile::SyncDecInsecure64,
            CiphernodesCommitteeSize::Minimum,
        )),
        CorrelationId::new(),
        E3id::new("8", 31_337),
    );
    let error = execute_zk_request(&prover, &cipher, request.clone(), &mut |_| {}).unwrap_err();
    assert_eq!(error.request(), &request);
    assert!(
        matches!(error.get_err(), ComputeRequestErrorKind::Zk(ZkEventError::InvalidParams(message))
        if message.contains("sync-insecure-64") && message.contains("disabled"))
    );
    assert!(!prover.work_dir().exists());
}

#[actix::test]
async fn dkg_generation_rejects_disabled_profiles_before_reading_witnesses() {
    use e3_fhe_params::BfvProfile;
    let temp = tempfile::tempdir().unwrap();
    let prover = unavailable_prover(temp.path());
    let cipher = Cipher::from_password("execution-test").await.unwrap();
    let secret = || e3_crypto::SensitiveBytes::from_encrypted(&[]);
    let profile = BfvProfile::SyncDecInsecure64;
    let committee = CiphernodesCommitteeSize::Minimum;
    let kinds = [
        ZkRequest::PkGeneration(PkGenerationProofRequest::new(
            ArcBytes::default(),
            secret(),
            secret(),
            secret(),
            profile,
            committee,
        )),
        ZkRequest::ShareComputation(ShareComputationProofRequest {
            secret_raw: secret(),
            secret_sss_raw: secret(),
            dkg_input_type: DkgInputType::SecretKey,
            params_profile: profile,
            committee_size: committee,
        }),
        ZkRequest::ShareEncryption(ShareEncryptionProofRequest {
            share_row_raw: secret(),
            ciphertext_raw: ArcBytes::default(),
            recipient_pk_raw: ArcBytes::default(),
            u_rns_raw: secret(),
            e0_rns_raw: secret(),
            e1_rns_raw: secret(),
            dkg_input_type: DkgInputType::SecretKey,
            params_profile: profile,
            committee_size: committee,
            recipient_party_id: 0,
            row_index: 0,
            esi_index: 0,
        }),
        ZkRequest::DkgShareDecryption(DkgShareDecryptionProofRequest {
            sk_bfv: secret(),
            honest_ciphertexts_raw: Vec::new(),
            num_honest_parties: 2,
            num_moduli: 3,
            own_plaintext_idx: None,
            own_share_raw: None,
            dkg_input_type: DkgInputType::SecretKey,
            params_profile: profile,
            committee_size: committee,
        }),
    ];
    for kind in kinds {
        let request = ComputeRequest::zk(kind, CorrelationId::new(), E3id::new("7", 31_337));
        let error = execute_zk_request(&prover, &cipher, request.clone(), &mut |_| {}).unwrap_err();
        assert_eq!(error.request(), &request);
        assert!(
            matches!(error.get_err(), ComputeRequestErrorKind::Zk(ZkEventError::InvalidParams(message))
            if message.contains("sync-insecure-64") && message.contains("disabled"))
        );
    }
    assert!(!prover.work_dir().exists());
}

#[actix::test]
async fn verification_execution_preserves_correlations_and_error_classification() {
    let temp = tempfile::tempdir().unwrap();
    let prover = unavailable_prover(temp.path());
    let cipher = Cipher::from_password("execution-test").await.unwrap();
    let e3_id = E3id::new("7", 31_337);
    let signed = SignedProofPayload {
        payload: ProofPayload {
            e3_id: e3_id.clone(),
            proof_type: ProofType::C3aSkShareEncryption,
            proof: Proof::new(
                e3_zk_config::CircuitName::ShareEncryption,
                ArcBytes::from_bytes(&[1]),
                ArcBytes::default(),
            ),
        },
        // Authentication is the upstream verification actor's boundary, not this executor's.
        signature: ArcBytes::default(),
    };
    let bundle = |signed_proofs| VerifyShareProofsRequest {
        party_proofs: vec![PartyProofsToVerify {
            sender_party_id: 2,
            signed_proofs,
        }],
        params_preset: BfvPreset::InsecureThreshold64,
        committee_size: CiphernodesCommitteeSize::Minimum,
    };
    for reverify in [false, true] {
        let kind = |bundle| {
            if reverify {
                ZkRequest::ReverifyAccusedProof(bundle)
            } else {
                ZkRequest::VerifyShareProofs(bundle)
            }
        };
        let request = ComputeRequest::zk(
            kind(bundle(vec![signed.clone()])),
            CorrelationId::new(),
            e3_id.clone(),
        );
        let error = execute_zk_request(&prover, &cipher, request.clone(), &mut |_| {
            panic!("verification reported fold timing")
        })
        .unwrap_err();
        assert_eq!(error.request(), &request);
        assert!(
            matches!(error.get_err(), ComputeRequestErrorKind::Zk(ZkEventError::ProofGenerationFailed(message)) if message.contains("verifier process failed"))
        );

        // A wrong circuit is a completed rejection, unlike an unavailable verifier process.
        let mut wrong = signed.clone();
        wrong.payload.proof.circuit = e3_zk_config::CircuitName::PkBfv;
        let request = ComputeRequest::zk(
            kind(bundle(vec![wrong.clone()])),
            CorrelationId::new(),
            e3_id.clone(),
        );
        let response = execute_zk_request(&prover, &cipher, request.clone(), &mut |_| {}).unwrap();
        assert_eq!(response.correlation_id, request.correlation_id);
        assert_eq!(response.e3_id, request.e3_id);
        let ZkResponse::VerifyShareProofs(result) = response.try_into_zk().unwrap() else {
            panic!("wrong response variant")
        };
        assert!(!result.party_results[0].all_verified);
        assert_eq!(result.party_results[0].sender_party_id, 2);
        assert_eq!(
            result.party_results[0].failed_signed_payload.as_ref(),
            Some(&wrong)
        );
    }
}

#[actix::test]
async fn execution_rejects_a_native_request_without_touching_its_secret() {
    let temp = tempfile::tempdir().unwrap();
    let prover = unavailable_prover(temp.path());
    let cipher = Cipher::from_password("execution-test").await.unwrap();
    let request = ComputeRequest::trbfv(
        e3_trbfv::TrBFVRequest::GenEsiSss(e3_trbfv::gen_esi_sss::GenEsiSssRequest {
            trbfv_config: e3_trbfv::TrBFVConfig::new(ArcBytes::default(), 3, 1),
            e_sm_raw: e3_crypto::SensitiveBytes::from_encrypted(&[]),
        }),
        CorrelationId::new(),
        E3id::new("7", 31_337),
    );
    let error = execute_zk_request(&prover, &cipher, request.clone(), &mut |_| {}).unwrap_err();
    assert_eq!(error.request(), &request);
    assert!(
        matches!(error.get_err(), ComputeRequestErrorKind::Zk(ZkEventError::InvalidParams(message)) if message == "expected a ZK request")
    );
}
