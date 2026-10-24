// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE

use crate::traits::Provable;
use e3_events::CircuitName;
use e3_zk_witness::dkg::share_decryption::ShareDecryptionCircuitData;

use crate::ZkError;

#[derive(Debug)]
pub struct ShareDecryptionCircuit;

impl Provable for ShareDecryptionCircuit {
    fn build_inputs(
        &self,
        config: &Self::Config,
        input: &Self::Input,
    ) -> Result<noirc_abi::InputMap, ZkError> {
        let _ = (config, input);
        Err(ZkError::InputsGenerationFailed(
            "C4 is proven as a limb chain; its final inputs need the limb proofs".into(),
        ))
    }

    /// Proves the limb chain and the final C4 proof (see
    /// [`crate::circuits::aggregation::c4_chain`]).
    fn prove_with_variant(
        &self,
        prover: &crate::ZkProver,
        config: &Self::Config,
        input: &Self::Input,
        e3_id: &str,
        variant: e3_events::CircuitVariant,
        artifacts_dir: &str,
    ) -> Result<e3_events::Proof, ZkError> {
        crate::circuits::aggregation::c4_chain::prove_share_decryption_chain(
            prover,
            config,
            input,
            e3_id,
            variant,
            artifacts_dir,
        )
    }

    type Config = e3_zk_config::dkg::share_decryption::Configs;
    type Input = ShareDecryptionCircuitData;

    fn circuit(&self) -> CircuitName {
        CircuitName::DkgShareDecryption
    }
}
