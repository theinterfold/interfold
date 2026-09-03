// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Proof-emission tests: the C2a/C2b witness payloads built from a party's
//! ACTUAL dealt material satisfy every circuit constraint, through the same
//! zk-helpers pipeline `nargo` consumes.

use super::proofs::*;
use e3_crypto::Cipher;
use e3_fhe::CkksFhe;
use e3_zk_helpers::threshold::user_data_encryption_ckks::insecure_512_ckks;
use fhe_traits::Serialize as FheSerialize;
use rand::RngCore;
use std::sync::{Arc, Mutex};

const N_PARTIES: usize = 3;
const THRESHOLD: usize = 1;
const SMUDGING_BITS: usize = 20;

#[actix::test]
async fn dealt_material_satisfies_c2_circuits() {
    // The committee shape must match the checked-in insecure circuit
    // configs (minimum committee: n=3, t=1), and the params must be the
    // CKKS insecure preset the circuits were generated for.
    let preset = insecure_512_ckks().unwrap();
    let params = preset.params.clone();

    let mut seed = [0u8; 32];
    rand::rng().fill_bytes(&mut seed);
    let rng = Arc::new(Mutex::new(
        <rand_chacha::ChaCha20Rng as rand::SeedableRng>::from_seed(rand::random::<[u8; 32]>()),
    ));
    let fhe = CkksFhe::from_encoded(&params.to_bytes(), seed, N_PARTIES, THRESHOLD, rng).unwrap();
    let cipher = Cipher::from_password("test-only-password").await.unwrap();

    let material = fhe.generate_keyshare(SMUDGING_BITS).unwrap();

    // Build witnesses -> reconstruct circuit data -> run the full
    // constraint check (secret consistency, range, RS parity).
    verify_ckks_share_witnesses(&preset, &material, N_PARTIES, THRESHOLD, &cipher).unwrap();

    // Tampered dealt share must be rejected: flip one coefficient of one
    // dealt row and the parity/consistency checks fail.
    let mut tampered = material;
    tampered.sk_sss[0][tampered.cols + 1] ^= 1;
    assert!(
        verify_ckks_share_witnesses(&preset, &tampered, N_PARTIES, THRESHOLD, &cipher).is_err(),
        "tampered dealt share must fail C2 verification"
    );
}
