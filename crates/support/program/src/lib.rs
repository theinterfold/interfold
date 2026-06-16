// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use e3_compute_provider::FHEInputs;
use e3_fhe_params::decode_bfv_params_arc;
use fhe::bfv::Ciphertext;
use fhe_traits::{DeserializeParametrized, Serialize};

/// CRISP Implementation of the CiphertextProcessor function
pub fn fhe_processor(fhe_inputs: &FHEInputs) -> Vec<u8> {
    let params = decode_bfv_params_arc(&fhe_inputs.params).expect("Failed to decode BFV params");

    let mut sum = Ciphertext::zero(&params);
    for ciphertext_bytes in &fhe_inputs.ciphertexts {
        let ciphertext = Ciphertext::from_bytes(&ciphertext_bytes.0, &params).unwrap();
        sum += &ciphertext;
    }

    sum.to_bytes()
}
