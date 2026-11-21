// SPDX-License-Identifier: LGPL-3.0-only
use crate::math::{
    commitments::{
        compute_aggregated_shares_commitment_checked, compute_ciphertext_commitment_checked,
    },
    polynomial::Polynomial,
};
use super::{commitments::key_bundle, threshold_decryption::secure_share};

// Small ring, same secure statement. Equal directed keys cancel and shifted=B represents zero
// noise, so the all-zero native polynomials yield an all-zero product and decryption share.
struct Case {
    sk: Field,
    bundle: Field,
    ct: Field,
    product_constant: Field,
    shifted: Field,
}

fn fixture() -> Case {
    let polys = [Polynomial::new([0; 8]); 2];
    let sk = compute_aggregated_shares_commitment_checked::<8, 2, 9>(polys);
    let ct = compute_ciphertext_commitment_checked::<8, 2, 9>(polys, polys);
    let bundle = key_bundle::<3, 2, 256>([1, 2], [3, 4], 0, [0, 2], sk, [[0; 32]; 3], [[0; 32]; 2]);
    Case { sk, bundle, ct, product_constant: 0, shifted: 7 }
}

impl Case {
    fn check(self) {
        let mut product = [[0; 8]; 2];
        product[0][7] = self.product_constant;
        let mut shifted = [7; 8];
        shifted[0] = self.shifted;
        let _ = secure_share::<8, 2, 2, 1, 3, 9, 256, 10>(
            [3, 4],
            0,
            [0, 2],
            self.sk,
            self.bundle,
            self.ct,
            [[0; 32]; 3],
            [[0; 32]; 2],
            [[0; 8]; 2],
            [[[0; 8]; 2]; 2],
            shifted,
            [[0; 8]; 2],
            product,
            [257, 769],
            [1, 2],
            7,
        );
    }
}

#[test]
fn valid_secure_openings() {
    fixture().check();
}

#[test(should_fail_with = "Wrong synchronized SK opening")]
fn secure_sk_anchor() {
    let mut case = fixture();
    case.sk += 1;
    case.check();
}

#[test(should_fail_with = "Wrong synchronized key bundle opening")]
fn secure_bundle_anchor() {
    let mut case = fixture();
    case.bundle += 1;
    case.check();
}

#[test(should_fail_with = "Wrong synchronized ciphertext opening")]
fn secure_ciphertext_anchor() {
    let mut case = fixture();
    case.ct += 1;
    case.check();
}

#[test(should_fail_with = "Wrong negacyclic product")]
fn secure_product_identity() {
    let mut case = fixture();
    case.product_constant = 1;
    case.check();
}

#[test(should_fail_with = "call to assert_max_bit_size")]
fn secure_noise_precedes_product_check() {
    // The product alone has the distinct rejection above. It prevents a later quotient
    // range check from accidentally satisfying this assertion if the noise check disappears.
    let mut case = fixture();
    case.product_constant = 1;
    case.shifted = 15;
    case.check();
}
