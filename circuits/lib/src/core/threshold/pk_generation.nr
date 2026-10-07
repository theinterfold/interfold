// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::math::commitments::{
    compute_share_computation_e_sm_commitment, compute_share_computation_sk_commitment,
    compute_threshold_pk_challenge, compute_threshold_pk_commitment,
};
use crate::math::helpers::flatten;
use crate::math::polynomial::{negacyclic_kernel, Polynomial};

/// Parameters for threshold public key generation (C1).
pub struct Configs<let N: u32, let L: u32> {
    /// CRT moduli: [q_0, q_1, ..., q_{L-1}]
    pub qis: [Field; L],
    /// Bound for error polynomial (eek) coefficients
    pub eek_bound: Field,
    /// Bound for secret key polynomial (sk) coefficients
    pub sk_bound: Field,
    /// Bound for the lifted smudging noise polynomial (e_sm) coefficients
    pub e_sm_bound: Field,
    /// Bounds for the per-modulus residues of e_sm: (q_i - 1) / 2
    pub e_sm_limb_bounds: [Field; L],
    /// Bounds for the CRT quotients of e_sm: (e_sm_bound + (q_i - 1) / 2) / q_i
    pub e_sm_quotient_bounds: [Field; L],
    /// Bounds for the `r` polynomials: the mod-q quotients of the identity reduced modulo
    /// `X^N + 1`. Reducing the identity makes the cyclotomic quotient's term identically zero, so
    /// the separate `r2` bound is gone and this one covers what `r1` and `r2` carried between them.
    pub r_bounds: [Field; L],
}

impl<let N: u32, let L: u32> Configs<N, L> {
    pub fn new(
        qis: [Field; L],
        eek_bound: Field,
        sk_bound: Field,
        e_sm_bound: Field,
        e_sm_limb_bounds: [Field; L],
        e_sm_quotient_bounds: [Field; L],
        r_bounds: [Field; L],
    ) -> Self {
        Configs {
            qis,
            eek_bound,
            sk_bound,
            e_sm_bound,
            e_sm_limb_bounds,
            e_sm_quotient_bounds,
            r_bounds,
        }
    }
}

/// Threshold public key contribution (C1).
///
/// **Role:** Prove one party's TrBFV public-key contribution from hidden `sk`, `eek`, `e_sm`, and
/// quotients (`pk1` limb is the CRS `a`).
///
/// **Verifies:** Range checks on witnesses; evaluation form of `pk0 = -a*sk + eek + ...` at the FS challenge.
///
/// **Produces (tuple order):**
/// - `commit(sk)` -> C2a (share computation).
/// - `commit(pk_trbfv)` -> C5 (pk aggregation).
/// - `commit(e_sm)` -> C2b (share computation).
pub struct PkGeneration<let N: u32, let L: u32, let BIT_EEK: u32, let BIT_SK: u32, let BIT_E_SM: u32, let BIT_E_SM_LIFTED: u32, let BIT_E_SM_QUOTIENT: u32, let BIT_R: u32, let BIT_PK: u32> {
    /// Cryptographic parameters including bounds, moduli, and constants.
    configs: Configs<N, L>,

    /// Common Reference String polynomials (public witnesses)
    /// One polynomial per modulus i
    a: [Polynomial<N>; L],

    /// Error polynomial (secret witness)
    /// Small coefficients sampled from error distribution
    eek: Polynomial<N>,

    /// Secret key polynomial (secret witness)
    /// Small coefficients sampled from CBD (Centered Binomial Distribution)
    sk: Polynomial<N>,

    /// Smudging noise polynomial per modulus (secret witness).
    /// Centered CRT residues of `e_sm_lifted`; these are what C2b Shamir-splits.
    e_sm: [Polynomial<N>; L],

    /// Smudging noise over the integers (secret witness).
    /// The `e_sm_bound` range check applies here, not to the residues: `e_sm_bound` exceeds every
    /// modulus, so checking a residue against it constrains nothing.
    e_sm_lifted: Polynomial<N>,

    /// CRT quotients that tie `e_sm_lifted` to each residue (secret witnesses)
    e_sm_quotients: [Polynomial<N>; L],

    /// Mod-q quotients of the identity reduced modulo `X^N + 1` (secret witnesses).
    ///
    /// The unreduced identity needed two: `r1` of degree `2N-1` for the modulus switch and `r2` of
    /// degree `N-1` for the cyclotomic reduction. Checking the identity in the reduced ring makes
    /// the `r2` term identically zero and shortens `r1` to `N` coefficients, so one witness of
    /// degree `N-1` replaces both. `r[i]` is `r1[i] mod X^N + 1`.
    r: [Polynomial<N>; L],

    /// Threshold public key first component per modulus (committed witness). Second component is a[i].
    pk0: [Polynomial<N>; L],
}

impl<let N: u32, let L: u32, let BIT_EEK: u32, let BIT_SK: u32, let BIT_E_SM: u32, let BIT_E_SM_LIFTED: u32, let BIT_E_SM_QUOTIENT: u32, let BIT_R: u32, let BIT_PK: u32> PkGeneration<N, L, BIT_EEK, BIT_SK, BIT_E_SM, BIT_E_SM_LIFTED, BIT_E_SM_QUOTIENT, BIT_R, BIT_PK> {
    pub fn new(
        configs: Configs<N, L>,
        a: [Polynomial<N>; L],
        eek: Polynomial<N>,
        sk: Polynomial<N>,
        e_sm: [Polynomial<N>; L],
        e_sm_lifted: Polynomial<N>,
        e_sm_quotients: [Polynomial<N>; L],
        r: [Polynomial<N>; L],
        pk0: [Polynomial<N>; L],
    ) -> Self {
        PkGeneration { configs, a, eek, sk, e_sm, e_sm_lifted, e_sm_quotients, r, pk0 }
    }

    /// Flattens all witness data into a single array for Fiat-Shamir challenge generation.
    ///
    /// Uses commitments for sk and pk rather than full polynomials to reduce constraint
    /// count while maintaining binding properties. e_sm is not included in the payload.
    fn payload(self, sk_commitment: Field, pk_commitment: Field) -> [Field] {
        let mut inputs: [Field] = [].as_vector();

        // Flatten CRS polynomials a (L polynomials of degree N)
        inputs = flatten::<_, _, BIT_PK>(inputs, self.a);

        // Flatten error polynomial eek (1 polynomial of degree N)
        inputs = flatten::<_, _, BIT_EEK>(inputs, [self.eek]);

        // Use commitments instead of full polynomials
        inputs = inputs.push_back(sk_commitment);
        inputs = inputs.push_back(pk_commitment);

        // Flatten the reduced quotient polynomials (L polynomials of degree N-1). The unreduced
        // form absorbed `r1` at degree 2N-1 and `r2` on top of it; the reduced one absorbs neither.
        inputs = flatten::<_, _, BIT_R>(inputs, self.r);

        inputs
    }

    /// Executes the threshold public key generation circuit.
    ///
    /// Returns `(commit(sk), commit(pk_trbfv), commit(e_sm))` as documented on the struct.
    pub fn execute(self) -> (Field, Field, Field) {
        // Step 1: Range-check secret witnesses (sk, eek, e_sm, quotients).
        self.perform_range_checks();

        // Step 2: Tie the committed e_sm residues to the bounded lifted value.
        self.verify_e_sm_crt_consistency();

        // Step 3: Derive commitments for the FS transcript.
        let sk_commitment = compute_share_computation_sk_commitment::<N, BIT_SK>(self.sk);
        let e_sm_commitment =
            compute_share_computation_e_sm_commitment::<N, L, BIT_E_SM>(self.e_sm);
        let pk_commitment = compute_threshold_pk_commitment::<N, L, BIT_PK>(self.pk0);

        // Step 4: Fiat-Shamir challenge and per-modulus evaluation checks.
        let gamma = self.generate_challenge(sk_commitment, pk_commitment);
        self.verify_evaluations(gamma);

        // Step 5: Return commitments for downstream circuits.
        (sk_commitment, pk_commitment, e_sm_commitment)
    }

    /// Generates Fiat-Shamir challenge values using the SAFE cryptographic sponge.
    ///
    /// Returns a single challenge point `gamma` used to verify key generation
    /// equations for all CRT moduli via the Schwartz-Zippel lemma.
    fn generate_challenge(self, sk_commitment: Field, pk_commitment: Field) -> Field {
        let inputs = self.payload(sk_commitment, pk_commitment);

        compute_threshold_pk_challenge(inputs)
    }

    /// Performs range checks on all secret witness values.
    ///
    /// These bounds are critical for BFV security-large coefficients would
    /// break the scheme's hardness assumptions (Ring-LWE).
    fn perform_range_checks(self) {
        // Check that error polynomial has small coefficients
        self.eek.range_check_2bounds::<BIT_EEK>(self.configs.eek_bound, self.configs.eek_bound);

        // Check that secret key polynomial has small coefficients
        self.sk.range_check_2bounds::<BIT_SK>(self.configs.sk_bound, self.configs.sk_bound);

        // Check the smudging noise over the integers. The residues cannot carry this bound:
        // e_sm_bound exceeds every q_i, so a residue satisfies it for free.
        self.e_sm_lifted.range_check_2bounds::<BIT_E_SM_LIFTED>(
            self.configs.e_sm_bound,
            self.configs.e_sm_bound,
        );

        // Check quotient terms are within expected bounds (per modulus)
        for i in 0..L {
            // pk0 is committed here and re-opened from that commitment by C5. The commitment packs
            // BIT_PK-wide coefficients into shared carriers, so an unbounded coefficient can
            // overflow its slot and give the same commitment a second opening. Pin it to a centered
            // residue, matching the bound C5 applies.
            let pk_bound: Field = (self.configs.qis[i] - 1) / 2;
            self.pk0[i].range_check_2bounds::<BIT_PK>(pk_bound, pk_bound);

            // Together with the lifted bound and `verify_e_sm_crt_consistency`, these force each
            // e_sm[i] to be the centered residue of a genuinely bounded integer polynomial.
            self.e_sm[i].range_check_2bounds::<BIT_E_SM>(
                self.configs.e_sm_limb_bounds[i],
                self.configs.e_sm_limb_bounds[i],
            );

            self.e_sm_quotients[i].range_check_2bounds::<BIT_E_SM_QUOTIENT>(
                self.configs.e_sm_quotient_bounds[i],
                self.configs.e_sm_quotient_bounds[i],
            );

            // The reduced identity is checked at a single point, so every coefficient it reads
            // needs a real bound for the field equality to imply the integer one. `r` is the only
            // quotient left to bound; `pk0`, `eek` and `sk` are bounded above, and `a` is the
            // compile-time CRP.
            self.r[i].range_check_2bounds::<BIT_R>(
                self.configs.r_bounds[i],
                self.configs.r_bounds[i],
            );
        }
    }

    /// Binds each residue `e_sm[i]` to the lifted `e_sm_lifted`.
    ///
    /// `q_i` is invertible modulo the proof-system prime, so this equation alone holds for any
    /// `e_sm[i]`. It carries weight only with the bounds applied in `perform_range_checks`, which
    /// keep every term far below the prime and so make the equation hold over the integers.
    fn verify_e_sm_crt_consistency(self) {
        for i in 0..L {
            for j in 0..N {
                assert(
                    self.e_sm_lifted.coefficients[j]
                        == self.e_sm[i].coefficients[j]
                            + self.e_sm_quotients[i].coefficients[j] * self.configs.qis[i],
                    "Smudging noise CRT consistency failed",
                );
            }
        }
    }

    /// Verifies the BFV key generation equation for all CRT moduli using Schwartz-Zippel.
    ///
    /// The identity is checked **reduced modulo `X^N + 1`**:
    ///   `pk0[i] == -(a[i] * sk mod X^N + 1) + eek + r[i] * q_i`
    /// where the unreduced form carried an extra `r2[i] * (gamma^N + 1)` term. Reducing makes that
    /// term identically zero, so the witness and its range check disappear rather than being
    /// checked; `r1` shortens to `r` at the same time.
    ///
    /// `negacyclic_kernel(sk, gamma)[j]` is `(X^(N-1-j) * sk mod X^N + 1)(gamma)`, so
    /// `a[i].dot(kernel)` evaluates `a[i] * sk mod X^N + 1` at gamma without the product ever
    /// entering the witness. One kernel serves every modulus, since `sk` and gamma are shared.
    ///
    /// Everything the identity reads is bounded — `pk0`, `eek` and `sk` by `perform_range_checks`,
    /// `r` likewise, and `a` is the compile-time CRP — so the equality over the field implies the
    /// equality over the integers, which is what lets a single evaluation point stand in for the
    /// polynomial identity.
    fn verify_evaluations(self, gamma: Field) {
        let kernel = negacyclic_kernel(self.sk, gamma);

        for i in 0..L {
            // Move every term except the product onto one side, so the product is evaluated once
            // through the kernel and compared against a plain polynomial evaluation.
            let mut residual: [Field; N] = [0; N];
            for j in 0..N {
                residual[j] = self.pk0[i].coefficients[j]
                    - self.eek.coefficients[j]
                    - self.configs.qis[i] * self.r[i].coefficients[j];
            }

            assert(
                Polynomial::new(residual).eval(gamma) == -self.a[i].dot(kernel),
                "Public key equation 1 failed",
            );
        }
    }
}

/// The reduced identity accepts an honest witness.
///
/// Worked at `N = 4`, `L = 1`, `q = 97`, so the negacyclic product is checkable by hand:
/// `a * sk mod X^4 + 1` is `-50X^3 - 30X^2 - 10X - 50`, and `-(a * sk) + eek` is
/// `[51, 28, 10, 53]`, which `r = [-1, 0, 0, -1]` brings into the centered window as
/// `pk0 = [-46, 28, 10, -44]`.
///
/// This is the test that pins the coefficient-order convention. `eval` is Horner from index 0, so
/// `Polynomial::new` takes coefficients **highest degree first**, and `negacyclic_kernel` is built to
/// match. Reverse either one and the identity silently fails to hold.
#[test]
fn honest_reduced_identity_holds() {
    let a = Polynomial::new([30, 40, -20, 10]);
    let sk = Polynomial::new([0, 1, 0, -1]);
    let eek = Polynomial::new([1, -2, 0, 3]);
    let r = Polynomial::new([-1, 0, 0, -1]);
    let pk0 = Polynomial::new([-46, 28, 10, -44]);

    // One limb, so the CRT split is trivial: the lifted value equals the residue.
    let e_sm = Polynomial::new([1, 0, 0, -1]);
    let e_sm_quotients = Polynomial::new([0, 0, 0, 0]);

    // qis, eek_bound, sk_bound, e_sm_bound, e_sm_limb_bounds, e_sm_quotient_bounds, r_bounds
    let configs: Configs<4, 1> = Configs::new([97], 20, 1, 100, [48], [1], [1]);
    let c: PkGeneration<4, 1, 6, 2, 7, 8, 2, 2, 7> = PkGeneration::new(
        configs,
        [a],
        eek,
        sk,
        [e_sm],
        e_sm,
        [e_sm_quotients],
        [r],
        [pk0],
    );
    let _ = c.execute();
}

/// A tampered quotient must break the evaluation check.
///
/// `r` is the only witness the reduction left to carry the mod-q slack, so this is what stops a
/// prover choosing `pk0` freely: shifting one coefficient of `r` moves `pk0` off the identity by a
/// multiple of `q` and Schwartz-Zippel rejects it.
#[test(should_fail)]
fn tampered_quotient_is_rejected() {
    let a = Polynomial::new([30, 40, -20, 10]);
    let sk = Polynomial::new([0, 1, 0, -1]);
    let eek = Polynomial::new([1, -2, 0, 3]);
    // Honest r is [-1, 0, 0, -1]; flip the last coefficient's sign.
    let r = Polynomial::new([-1, 0, 0, 1]);
    let pk0 = Polynomial::new([-46, 28, 10, -44]);

    let e_sm = Polynomial::new([1, 0, 0, -1]);
    let e_sm_quotients = Polynomial::new([0, 0, 0, 0]);

    let configs: Configs<4, 1> = Configs::new([97], 20, 1, 100, [48], [1], [1]);
    let c: PkGeneration<4, 1, 6, 2, 7, 8, 2, 2, 7> = PkGeneration::new(
        configs,
        [a],
        eek,
        sk,
        [e_sm],
        e_sm,
        [e_sm_quotients],
        [r],
        [pk0],
    );
    let _ = c.execute();
}
