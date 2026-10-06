// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Poseidon2 PRF used by synchronized decryption.
//!
//! The absorb order matches `fhe.rs` `trbfv::prf`: party ids are 1-based, and
//! ciphertext coefficients are absorbed low degree first. Circuit polynomials
//! store the highest degree first.

use crate::math::commitments::compute_prf_key_commitment;
use crate::math::modulo::U64::ModU64;
use crate::math::polynomial::Polynomial;
use crate::math::safe::SafeSponge;

global ABSORB_FLAG: u32 = 0x80000000;

/// Domain separator `fhe.rs/trbfv/prf/poseidon2/ctx`.
pub global DS_PRF_CTX: [u8; 64] = [
    0x66, 0x68, 0x65, 0x2e, 0x72, 0x73, 0x2f, 0x74, 0x72, 0x62, 0x66, 0x76, 0x2f, 0x70, 0x72, 0x66,
    0x2f, 0x70, 0x6f, 0x73, 0x65, 0x69, 0x64, 0x6f, 0x6e, 0x32, 0x2f, 0x63, 0x74, 0x78, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// Domain separator `fhe.rs/trbfv/prf/poseidon2/eval`.
pub global DS_PRF_EVAL: [u8; 64] = [
    0x66, 0x68, 0x65, 0x2e, 0x72, 0x73, 0x2f, 0x74, 0x72, 0x62, 0x66, 0x76, 0x2f, 0x70, 0x72, 0x66,
    0x2f, 0x70, 0x6f, 0x73, 0x65, 0x69, 0x64, 0x6f, 0x6e, 0x32, 0x2f, 0x65, 0x76, 0x61, 0x6c, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// Map key bits to the BN254 scalar. Bit 0 is the least significant bit.
pub fn prf_key_field<let KEY_BITS: u32>(bits: [Field; KEY_BITS]) -> Field {
    let mut acc = 0;
    let mut weight = 1;
    for i in 0..KEY_BITS {
        assert(bits[i] * (bits[i] - 1) == 0, "PRF key bit is not binary");
        acc = acc + (bits[i] * weight);
        weight = weight * 2;
    }
    acc
}

fn append_ciphertext_poly<let N: u32, let L: u32>(
    mut input: [Field],
    poly: [Polynomial<N>; L],
) -> [Field] {
    input = input.push_back(L as Field);
    input = input.push_back(N as Field);
    for row in 0..L {
        for col in 0..N {
            input = input.push_back(poly[row].coefficients[N - 1 - col]);
        }
    }
    input
}

/// Unkeyed digest `H(S, ct)`. `decryptors` is a strictly increasing list of 1-based party ids.
pub fn prf_context_digest<let N: u32, let L: u32, let H: u32>(
    decryptors: [Field; H],
    ct0: [Polynomial<N>; L],
    ct1: [Polynomial<N>; L],
) -> [Field; 2] {
    let absorb_len: u32 = H + 7 + (2 * L * N);
    let mut input: [Field] = [H as Field].as_vector();
    for i in 0..H {
        input = input.push_back(decryptors[i]);
    }
    input = input.push_back(0);
    input = input.push_back(2);
    input = append_ciphertext_poly(input, ct0);
    input = append_ciphertext_poly(input, ct1);
    assert(input.len() as u32 == absorb_len, "PRF context length mismatch");

    let mut sponge = SafeSponge::start([ABSORB_FLAG | absorb_len, 2], DS_PRF_CTX);
    sponge.absorb(input);
    let squeezed = sponge.squeeze();
    sponge.finish();
    [squeezed[0], squeezed[1]]
}

/// Evaluate `F_k` and reduce each coefficient into its CRT residue.
pub fn prf_evaluate<let N: u32, let L: u32>(
    key: Field,
    digest: [Field; 2],
    qis: [Field; L],
) -> [Polynomial<N>; L] {
    let squeeze_len: u32 = L * N;
    let mut sponge = SafeSponge::start([ABSORB_FLAG | 3, squeeze_len], DS_PRF_EVAL);
    sponge.absorb([key, digest[0], digest[1]].as_vector());
    let squeezed = sponge.squeeze();
    sponge.finish();

    let mut polys: [Polynomial<N>; L] = [Polynomial::new([0; N]); L];
    for row in 0..L {
        let qmod = ModU64::new(qis[row] as u64);
        let mut coeffs: [Field; N] = [0; N];
        for col in 0..N {
            coeffs[N - 1 - col] = qmod.reduce_mod(squeezed[(row * N) + col]);
        }
        polys[row] = Polynomial::new(coeffs);
    }
    polys
}

fn assert_canonical_decryptors<let H: u32, let N_PARTIES: u32>(ids: [Field; H]) {
    for i in 0..H {
        let id = ids[i] as u32;
        assert(ids[i] == id as Field, "Decryptor id is not canonical");
        assert(id >= 1, "Decryptor id is zero");
        assert(id <= N_PARTIES, "Decryptor id is out of range");
        if i > 0 {
            assert((ids[i - 1] as u32) < id, "Decryptor ids are not sorted");
        }
    }
}

fn party_in_set<let H: u32>(decryptors: [Field; H], party_id_one_based: Field) -> bool {
    let mut seen = false;
    for i in 0..H {
        if decryptors[i] == party_id_one_based {
            seen = true;
        }
    }
    seen
}

fn add_mask_difference<let N: u32, let L: u32>(
    mask: [Polynomial<N>; L],
    positive: [Polynomial<N>; L],
    negative: [Polynomial<N>; L],
    qis: [Field; L],
) -> [Polynomial<N>; L] {
    let mut next: [Polynomial<N>; L] = [Polynomial::new([0; N]); L];
    for row in 0..L {
        let q = qis[row];
        let qmod = ModU64::new(q as u64);
        let mut coeffs: [Field; N] = [0; N];
        for col in 0..N {
            let combined = mask[row].coefficients[col] + positive[row].coefficients[col] + q
                - negative[row].coefficients[col];
            coeffs[col] = qmod.reduce_mod(combined);
        }
        next[row] = Polynomial::new(coeffs);
    }
    next
}

/// Build `r_i = Σ_{j in S, j ≠ i} (F_{k_ij}(H) - F_{k_ji}(H))`.
///
/// Outgoing key `k_ij` is committed under recipient `j`. Incoming key `k_ji` is
/// committed under recipient `i`.
pub fn prf_decryption_mask<let N: u32, let L: u32, let KEY_BITS: u32, let N_PARTIES: u32, let H: u32>(
    party_idx: u32,
    decryptors: [Field; H],
    outgoing_bits: [[Field; KEY_BITS]; N_PARTIES],
    incoming_bits: [[Field; KEY_BITS]; N_PARTIES],
    outgoing_commitments: [Field; N_PARTIES],
    incoming_commitments: [Field; N_PARTIES],
    ct0: [Polynomial<N>; L],
    ct1: [Polynomial<N>; L],
    qis: [Field; L],
) -> [Polynomial<N>; L] {
    assert(party_idx < N_PARTIES, "Party index is out of range");
    assert_canonical_decryptors::<H, N_PARTIES>(decryptors);
    let self_id = (party_idx + 1) as Field;
    assert(party_in_set(decryptors, self_id), "Party is outside the decryptor set");

    let digest = prf_context_digest(decryptors, ct0, ct1);
    let mut mask: [Polynomial<N>; L] = [Polynomial::new([0; N]); L];

    for other in 0..N_PARTIES {
        let other_id = (other + 1) as Field;
        if (other != party_idx) & party_in_set(decryptors, other_id) {
            assert(
                compute_prf_key_commitment(other as Field, outgoing_bits[other])
                    == outgoing_commitments[other],
                "Outgoing PRF key commitment mismatch",
            );
            assert(
                compute_prf_key_commitment(party_idx as Field, incoming_bits[other])
                    == incoming_commitments[other],
                "Incoming PRF key commitment mismatch",
            );
            let outgoing = prf_evaluate(prf_key_field(outgoing_bits[other]), digest, qis);
            let incoming = prf_evaluate(prf_key_field(incoming_bits[other]), digest, qis);
            mask = add_mask_difference(mask, outgoing, incoming, qis);
        }
    }

    mask
}
