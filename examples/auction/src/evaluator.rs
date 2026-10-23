// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use fhe::bfv::{Ciphertext, Plaintext};
use fhe::lbfv::LBFVRelinearizationKey;
use std::cell::Cell;

/// Homomorphic products for the E3 program, counted so that the designs can be compared.
pub struct Evaluator<'a> {
    relinearization: &'a LBFVRelinearizationKey,
    ciphertext_products: Cell<usize>,
    plaintext_products: Cell<usize>,
}

impl<'a> Evaluator<'a> {
    pub fn new(relinearization: &'a LBFVRelinearizationKey) -> Self {
        Evaluator {
            relinearization,
            ciphertext_products: Cell::new(0),
            plaintext_products: Cell::new(0),
        }
    }

    /// ct×ct, relinearized back to two components. Each call adds one level of depth.
    pub fn mul(&self, a: &Ciphertext, b: &Ciphertext) -> Ciphertext {
        self.ciphertext_products
            .set(self.ciphertext_products.get() + 1);
        let mut product = a * b;
        self.relinearization
            .relinearizes(&mut product)
            .expect("a ct×ct product has three components");
        product
    }

    pub fn mul_plain(&self, a: &Ciphertext, b: &Plaintext) -> Ciphertext {
        self.plaintext_products
            .set(self.plaintext_products.get() + 1);
        a * b
    }

    /// `∏ cts` with a balanced tree: `n - 1` products at depth `⌈log2 n⌉`.
    pub fn product(&self, cts: &[Ciphertext]) -> Ciphertext {
        match cts {
            [] => panic!("the product of no ciphertexts is not defined"),
            [single] => single.clone(),
            _ => {
                let (left, right) = cts.split_at(cts.len() / 2);
                self.mul(&self.product(left), &self.product(right))
            }
        }
    }

    /// `(∏ u_i, Σ_i x_i · ∏_{j≠i} u_j)`: `3(n - 1)` products at depth `⌈log2 n⌉`.
    ///
    /// Merges pairs with `(P1, E1) · (P2, E2) = (P1·P2, E1·P2 + P1·E2)`. With `u = 1 - x` on 0/1
    /// slots, the second value is 1 exactly in the slots where one `x_i` is 1.
    pub fn product_and_exactly_one(
        &self,
        u: &[Ciphertext],
        x: &[Ciphertext],
    ) -> (Ciphertext, Ciphertext) {
        assert_eq!(u.len(), x.len());
        match u.len() {
            0 => panic!("the product of no ciphertexts is not defined"),
            1 => (u[0].clone(), x[0].clone()),
            n => {
                let middle = n / 2;
                let (p1, e1) = self.product_and_exactly_one(&u[..middle], &x[..middle]);
                let (p2, e2) = self.product_and_exactly_one(&u[middle..], &x[middle..]);
                let exactly_one = &self.mul(&e1, &p2) + &self.mul(&p1, &e2);
                (self.mul(&p1, &p2), exactly_one)
            }
        }
    }

    pub fn ciphertext_products(&self) -> usize {
        self.ciphertext_products.get()
    }

    pub fn plaintext_products(&self) -> usize {
        self.plaintext_products.get()
    }
}
