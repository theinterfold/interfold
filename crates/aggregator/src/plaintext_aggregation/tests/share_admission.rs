// SPDX-License-Identifier: LGPL-3.0-only

use super::*;

#[derive(Debug)]
enum Forgery {
    InvalidSignature,
    WrongSigner,
    WrongE3,
    CorruptShare,
    WrongCircuit,
    WrongProofType,
    WrongCiphertext,
}

#[actix::test]
async fn forged_share_cannot_reserve_an_honest_partys_slot() -> Result<()> {
    for forgery in [
        Forgery::InvalidSignature,
        Forgery::WrongSigner,
        Forgery::WrongE3,
        Forgery::CorruptShare,
        Forgery::WrongCircuit,
        Forgery::WrongProofType,
        Forgery::WrongCiphertext,
    ] {
        let (mut aggregator, _, e3_id) =
            build_plaintext_aggregator(collecting_state(), true).await?;
        let ciphertexts = &test_ciphertexts()[..1];
        let (mut shares, mut proofs) = share_with_matching_commitment(&e3_id, 0, ciphertexts);
        match forgery {
            Forgery::InvalidSignature => proofs[0].signature = ArcBytes::from_bytes(&[0; 65]),
            Forgery::WrongSigner => {
                proofs[0] = SignedProofPayload::sign(proofs[0].payload.clone(), &test_signer(1))?;
            }
            Forgery::WrongE3 => {
                proofs[0].payload.e3_id = E3id::new("43", 1);
                proofs[0] = SignedProofPayload::sign(proofs[0].payload.clone(), &test_signer(0))?;
            }
            Forgery::CorruptShare => shares[0] = ArcBytes::from_bytes(&[0]),
            Forgery::WrongCircuit => proofs[0].payload.proof.circuit = CircuitName::DkgAggregator,
            Forgery::WrongProofType => {
                proofs[0].payload.proof_type = ProofType::C0PkBfv;
                proofs[0] = SignedProofPayload::sign(proofs[0].payload.clone(), &test_signer(0))?;
            }
            Forgery::WrongCiphertext => {
                (_, proofs) = share_with_matching_commitment(&e3_id, 0, &test_ciphertexts()[1..]);
            }
        }
        let ec = test_ctx(EffectsEnabled::new());
        aggregator.add_share(0, shares, proofs, &ec)?;
        let state = Collecting::try_from(aggregator.state.try_get()?)?;
        assert!(state.shares.is_empty(), "{forgery:?} reserved a slot");
        assert!(state.rejected_parties.is_empty());
        for party in 0..2 {
            let (shares, proofs) = share_with_matching_commitment(&e3_id, party, ciphertexts);
            aggregator.add_share(party, shares, proofs, &ec)?;
        }
        assert!(matches!(
            aggregator.state.get(),
            Some(ThresholdPlaintextAggregatorState::VerifyingC6(_))
        ));
    }
    Ok(())
}

#[actix::test]
async fn valid_proofs_cannot_be_reordered_between_ciphertexts() -> Result<()> {
    let ciphertexts = test_ciphertexts();
    let initial = ThresholdPlaintextAggregatorState::init(
        1,
        3,
        Seed([0; 32]),
        ciphertexts.clone(),
        test_params(),
    );
    let (mut aggregator, _, e3_id) = build_plaintext_aggregator(initial, true).await?;
    let (mut shares, mut proofs) = share_with_matching_commitment(&e3_id, 0, &ciphertexts);
    shares.swap(0, 1);
    proofs.swap(0, 1);
    let ec = test_ctx(EffectsEnabled::new());
    aggregator.add_share(0, shares, proofs, &ec)?;
    let state = Collecting::try_from(aggregator.state.try_get()?)?;
    assert!(state.shares.is_empty());
    let (shares, proofs) = share_with_matching_commitment(&e3_id, 0, &ciphertexts);
    aggregator.add_share(0, shares, proofs, &ec)?;
    let state = Collecting::try_from(aggregator.state.try_get()?)?;
    assert!(state.shares.contains_key(&0));
    Ok(())
}
