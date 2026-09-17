// SPDX-License-Identifier: LGPL-3.0-only

//! Signed-proof state updates and compute-result routing.

use super::*;

impl ThresholdKeyshare {
    /// Store the signed C1 proof in workflow state.
    pub fn handle_pk_generation_proof_signed(
        &mut self,
        msg: TypedEvent<PkGenerationProofSigned>,
    ) -> Result<()> {
        let (msg, ec) = msg.into_components();
        let state = self.state.try_get()?;

        // Only accept proof for our own party
        if msg.party_id != state.party_id {
            return Ok(());
        }

        info!(
            "Received PkGenerationProofSigned for party {} E3 {}",
            msg.party_id, msg.e3_id
        );

        self.store_signed_pk_generation_proof(&ec, msg.signed_proof.clone())?;
        if let Err(error) = self.record_lbfv_c1_proof(msg.signed_proof, ec.clone()) {
            error!("Rejected local l-BFV C1 proof: {error}");
            return self.fail_lbfv_generation(ec);
        }
        self.try_finish_deferred_keyshare_publish(ec)?;

        Ok(())
    }

    /// Handle DkgProofSigned - stores the signed proof in state based on proof type (C2a, C2b, C3a or C3b)
    pub fn handle_share_computation_proof_signed(
        &mut self,
        msg: TypedEvent<DkgProofSigned>,
    ) -> Result<()> {
        let (msg, ec) = msg.into_components();
        let state = self.state.try_get()?;

        if msg.party_id != state.party_id {
            return Ok(());
        }

        let proof_type = msg.signed_proof.payload.proof_type;
        info!(
            "Received DkgProofSigned ({:?}) for party {} E3 {}",
            proof_type, msg.party_id, msg.e3_id
        );

        self.state.try_mutate(&ec, |s| {
            let current: AggregatingDecryptionKey = s.clone().try_into()?;
            let updated = match proof_type {
                ProofType::C2aSkShareComputation => AggregatingDecryptionKey {
                    signed_sk_share_computation_proof: Some(msg.signed_proof),
                    ..current
                },
                ProofType::C2bESmShareComputation => AggregatingDecryptionKey {
                    signed_e_sm_share_computation_proof: Some(msg.signed_proof),
                    ..current
                },
                ProofType::C3aSkShareEncryption => {
                    let mut updated = current;
                    updated
                        .signed_sk_share_encryption_proofs
                        .push(msg.signed_proof);
                    updated
                }
                ProofType::C3bESmShareEncryption => {
                    let mut updated = current;
                    updated
                        .signed_e_sm_share_encryption_proofs
                        .push(msg.signed_proof);
                    updated
                }
                other => {
                    warn!("Unexpected proof type {:?} in DkgProofSigned", other);
                    current
                }
            };
            s.new_state(KeyshareState::AggregatingDecryptionKey(updated))
        })?;

        self.maybe_publish_dkg_ready(ec)?;

        Ok(())
    }

    pub fn handle_compute_response(
        &mut self,
        msg: TypedEvent<ComputeResponse>,
        self_addr: Addr<Self>,
    ) -> Result<()> {
        match &msg.response {
            ComputeResponseKind::TrBFV(trbfv) => match trbfv {
                TrBFVResponse::GenEsiSss(_) => self.handle_gen_esi_sss_response(msg),
                TrBFVResponse::GenPkShareAndSkSss(_) => {
                    self.handle_gen_pk_share_and_sk_sss_response(msg)
                }
                TrBFVResponse::GenLbfvKeyShares(_) => {
                    let ec = msg.get_ctx().clone();
                    if let Err(error) = self.handle_lbfv_generation_response(msg) {
                        error!("Rejected local l-BFV generation response: {error}");
                        self.fail_lbfv_generation(ec)?;
                    }
                    Ok(())
                }
                TrBFVResponse::CalculateDecryptionKey(_) => {
                    self.handle_calculate_decryption_key_response(msg, self_addr)
                }
                TrBFVResponse::CalculateDecryptionShare(_) => {
                    self.handle_calculate_decryption_share_response(msg)
                }
                _ => Ok(()),
            },
            // ZK responses: proofs and verification are handled by
            // ProofRequestActor and ShareVerificationActor respectively.
            ComputeResponseKind::Zk(
                ZkResponse::LbfvPkGeneration(_) | ZkResponse::RlkGeneration(_),
            ) => {
                let ec = msg.get_ctx().clone();
                if let Err(error) = self.handle_lbfv_proof_response(msg) {
                    error!("Rejected local l-BFV row proof response: {error}");
                    self.fail_lbfv_generation(ec)?;
                }
                Ok(())
            }
            ComputeResponseKind::Zk(_) => Ok(()),
        }
    }
}
