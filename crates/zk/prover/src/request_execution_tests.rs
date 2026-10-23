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
                e3_events::CircuitName::ShareEncryption,
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
        wrong.payload.proof.circuit = e3_events::CircuitName::PkBfv;
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
