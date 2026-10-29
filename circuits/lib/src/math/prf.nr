// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Poseidon2 PRF used by synchronized decryption.
//!
//! The context absorb matches `fhe.rs` `trbfv::prf`: party ids are 1-based,
//! the ciphertext level is 0, and the ciphertext enters as the checked
//! commitment of the opened polynomials. Evaluation squeezes `ceil(N/3)`
//! field elements per limb. A full group of three residues is one integer
//! reconstruction. Partial tails still use successive division. Circuit
//! polynomials store the highest degree first.

use crate::math::commitments::{
    compute_ciphertext_commitment_checked, compute_packed_prf_key_commitment,
};
use crate::math::modulo::U64::ModU64;
use crate::math::modulo::unconstrained_U64::{__reduce_field_witness_u64, __reduce_witness_u64};
use crate::math::polynomial::Polynomial;
use crate::math::safe::SafeSponge;

global ABSORB_FLAG: u32 = 0x80000000;

/// Bind a packed native message to its key bits and return the unpacked residue row.
pub fn unpack_key_row<let N: u32, let BITS: u32>(
    packed: [Field; N],
    bits: [bool; BITS],
    q: Field,
    row: u32,
) -> [Field; N] {
    assert(BITS <= N);
    let mut residues = packed;
    for j in 0..N {
        let bit = if (row == 0) & (j < BITS) {
            bits[j] as Field
        } else {
            0
        };
        let value = packed[j] - bit * q;
        value.assert_max_bit_size::<64>();
        (q - 1 - value).assert_max_bit_size::<64>();
        residues[j] = value;
    }
    residues
}

pub fn packed_key<let BITS: u32>(bits: [bool; BITS]) -> Field {
    let mut key: Field = 0;
    let mut place: Field = 1;
    for i in 0..BITS {
        key += (bits[i] as Field) * place;
        place += place;
    }
    key
}

#[test]
fn packed_share_bits_round_trip() {
    assert(unpack_key_row([0, 98, 96, 17], [false, true], 97, 0) == [0, 1, 96, 17]);
    assert(packed_key([true, false, true]) == 5);
}

#[test(should_fail)]
fn packed_share_rejects_a_different_key_bit() {
    let _ = unpack_key_row([0, 98, 96, 17], [false, false], 97, 0);
}

#[test(should_fail)]
fn other_limbs_cannot_carry_key_bits() {
    let _ = unpack_key_row([0, 98, 96, 17], [false, true], 97, 1);
}

/// Domain separator `fhe.rs/trbfv/prf/poseidon2/ctx-cmt`.
pub global DS_PRF_CTX: [u8; 64] = [
    0x66, 0x68, 0x65, 0x2e, 0x72, 0x73, 0x2f, 0x74, 0x72, 0x62, 0x66, 0x76, 0x2f, 0x70, 0x72, 0x66,
    0x2f, 0x70, 0x6f, 0x73, 0x65, 0x69, 0x64, 0x6f, 0x6e, 0x32, 0x2f, 0x63, 0x74, 0x78, 0x2d, 0x63,
    0x6d, 0x74, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// Domain separator `fhe.rs/trbfv/prf/poseidon2/eval-x3`.
pub global DS_PRF_EVAL: [u8; 64] = [
    0x66, 0x68, 0x65, 0x2e, 0x72, 0x73, 0x2f, 0x74, 0x72, 0x62, 0x66, 0x76, 0x2f, 0x70, 0x72, 0x66,
    0x2f, 0x70, 0x6f, 0x73, 0x65, 0x69, 0x64, 0x6f, 0x6e, 0x32, 0x2f, 0x65, 0x76, 0x61, 0x6c, 0x2d,
    0x78, 0x33, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// Map a centered residue in `(-q/2, q/2]` to the native residue in `[0, q)`.
pub fn native_residue(centered: Field, q: Field) -> Field {
    let half = (q - 1) / 2;
    let shifted = centered + half;
    let negative = (shifted as u128) < (half as u128);
    centered + (negative as Field) * q
}

/// Unkeyed digest `H(S, ct)`. `decryptors` is a strictly increasing list of 1-based party ids.
///
/// `ct_commitment` is the checked ciphertext commitment already compared with `ct0` and `ct1`.
/// Level 0 and two components match C6's opened ciphertext. `L` and `N` are absorbed so the
/// digest also binds the ring shape.
pub fn prf_context_digest<let N: u32, let L: u32, let H: u32>(
    decryptors: [Field; H],
    ct_commitment: Field,
) -> [Field; 2] {
    let absorb_len: u32 = H + 6;
    // |S|, S, level, component count, L, N, checked ciphertext commitment.
    let mut input = [0; H + 6];
    input[0] = H as Field;
    for i in 0..H {
        input[1 + i] = decryptors[i];
    }
    input[H + 1] = 0;
    input[H + 2] = 2;
    input[H + 3] = L as Field;
    input[H + 4] = N as Field;
    input[H + 5] = ct_commitment;

    let mut sponge = SafeSponge::start([ABSORB_FLAG | absorb_len, 2], DS_PRF_CTX);
    sponge.absorb(input.as_vector());
    let squeezed = sponge.squeeze();
    sponge.finish();
    [squeezed[0], squeezed[1]]
}

/// `2^{B-1} <= q < 2^B`.
///
/// `B` is the preset constant `Q_BIT`: 27 for insecure-64, 60 for secure-8192.
/// See `circuits/lib/src/README.md`. If a set is added or its moduli change, update `Q_BIT`.
fn assert_modulus_width<let B: u32>(q: Field) {
    assert(B >= 2);
    assert(B <= 62);
    // `q >= 2^{B-1}` makes the high quotient smaller than `2^{257-3B}`.
    assert(257 - 3 * B <= 253);
    let lower = 2.pow_32((B - 1) as Field);
    let upper = 2.pow_32(B as Field);
    assert((q as u128) >= (lower as u128), "modulus is below its bit width");
    assert((q as u128) < (upper as u128), "modulus does not fit its bit width");
}

/// `H = floor((p-1)/q^3)` and `R = (p-1) mod q^3`, from the checked division chain.
///
/// These bounds are not hints. Three `quot_rem` steps on the canonical integer
/// `p-1` fix them, once per limb.
fn limb_split_bounds(qmod: ModU64) -> (Field, Field) {
    let q = qmod.get_mod_field();
    let (quotient0, residue0) = qmod.quot_rem(-1);
    let (quotient1, residue1) = qmod.quot_rem(quotient0);
    let (high, residue2) = qmod.quot_rem(quotient1);
    (high, residue0 + residue1 * q + residue2 * q * q)
}

/// Hint the base-`q` digits. `constrain_three_residues` is what makes them unique.
fn hint_three_residues(x: Field, modulus: u64) -> (Field, Field, Field, Field) {
    // Safety: constrain_three_residues checks every digit, the high quotient, and reconstruction.
    let (quotient0, residue0) = unsafe { __reduce_field_witness_u64(x, modulus) };
    // Safety: constrain_three_residues checks every digit, the high quotient, and reconstruction.
    let (quotient1, residue1) = unsafe { __reduce_field_witness_u64(quotient0, modulus) };
    // Safety: constrain_three_residues checks every digit, the high quotient, and reconstruction.
    let (high, residue2) = unsafe { __reduce_field_witness_u64(quotient1, modulus) };
    (high, residue0, residue1, residue2)
}

/// Force `x = h q^3 + r2 q^2 + r1 q + r0` as integers, with `0 <= ri < q`.
///
/// `B` is this limb's bit length. Digits use two `B`-bit checks, the low part
/// uses `3B`, and the high quotient uses `257-3B`. Together with `h <= H` and
/// `low <= R` when `h = H`, the reconstruction lies in `[0, p-1]`. `H` and `R`
/// come from the checked division of `p-1`.
fn constrain_three_residues<let B: u32>(
    q: Field,
    x: Field,
    high: Field,
    residue0: Field,
    residue1: Field,
    residue2: Field,
    high_bound: Field,
    low_bound: Field,
) {
    assert_modulus_width::<B>(q);
    residue0.assert_max_bit_size::<B>();
    (q - 1 - residue0).assert_max_bit_size::<B>();
    residue1.assert_max_bit_size::<B>();
    (q - 1 - residue1).assert_max_bit_size::<B>();
    residue2.assert_max_bit_size::<B>();
    (q - 1 - residue2).assert_max_bit_size::<B>();

    let square = q * q;
    let low = residue0 + residue1 * q + residue2 * square;
    low.assert_max_bit_size::<3 * B>();
    high.assert_max_bit_size::<257 - 3 * B>();
    (high_bound - high).assert_max_bit_size::<257 - 3 * B>();
    let at_bound = (high == high_bound) as Field;
    (at_bound * (low_bound - low)).assert_max_bit_size::<3 * B>();
    assert(high * square * q + low == x);
}

fn split_full_group<let B: u32>(
    qmod: ModU64,
    x: Field,
    high_bound: Field,
    low_bound: Field,
) -> (Field, Field, Field) {
    let (high, residue0, residue1, residue2) = hint_three_residues(x, qmod.m);
    constrain_three_residues::<B>(
        qmod.get_mod_field(),
        x,
        high,
        residue0,
        residue1,
        residue2,
        high_bound,
        low_bound,
    );
    (residue0, residue1, residue2)
}

fn squeezed_row<let N: u32, let L: u32>(
    squeezed: [Field; L * ((N + 2) / 3)],
    row: u32,
) -> [Field; (N + 2) / 3] {
    let groups: u32 = (N + 2) / 3;
    let mut row_squeezed = [0; (N + 2) / 3];
    for group in 0..groups {
        row_squeezed[group] = squeezed[row * groups + group];
    }
    row_squeezed
}

fn fill_limb<let B: u32, let N: u32>(
    q: Field,
    row_squeezed: [Field; (N + 2) / 3],
    high_bound: Field,
    low_bound: Field,
) -> Polynomial<N> {
    assert_modulus_width::<B>(q);
    let qmod = ModU64::new(q as u64);
    let full_groups: u32 = N / 3;
    let tail: u32 = N % 3;
    let mut coeffs: [Field; N] = [0; N];
    for group in 0..full_groups {
        let (residue0, residue1, residue2) =
            split_full_group::<B>(qmod, row_squeezed[group], high_bound, low_bound);
        let start = group * 3;
        coeffs[N - 1 - start] = residue0;
        coeffs[N - 1 - start - 1] = residue1;
        coeffs[N - 1 - start - 2] = residue2;
    }
    // Partial tails keep the checked single-residue division.
    if tail == 1 {
        coeffs[N - 1 - full_groups * 3] = qmod.reduce_field(row_squeezed[full_groups]);
    }
    if tail == 2 {
        let (quotient0, residue0) = qmod.quot_rem(row_squeezed[full_groups]);
        let residue1 = qmod.reduce_field(quotient0);
        let start = full_groups * 3;
        coeffs[N - 1 - start] = residue0;
        coeffs[N - 1 - start - 1] = residue1;
    }
    Polynomial::new(coeffs)
}

fn limb_bounds<let L: u32>(qis: [Field; L]) -> ([Field; L], [Field; L]) {
    let mut high_bounds = [0; L];
    let mut low_bounds = [0; L];
    for row in 0..L {
        let (high, low) = limb_split_bounds(ModU64::new(qis[row] as u64));
        high_bounds[row] = high;
        low_bounds[row] = low;
    }
    (high_bounds, low_bounds)
}

fn squeeze_key<let N: u32, let L: u32>(
    key: Field,
    digest: [Field; 2],
) -> [Field; L * ((N + 2) / 3)] {
    let groups: u32 = (N + 2) / 3;
    let squeeze_len: u32 = L * groups;
    let mut sponge = SafeSponge::start([ABSORB_FLAG | 3, squeeze_len], DS_PRF_EVAL);
    sponge.absorb([key, digest[0], digest[1]].as_vector());
    let squeezed = sponge.squeeze_array::<L * ((N + 2) / 3)>();
    sponge.finish();
    squeezed
}

/// One width for every limb. `L` is the modulus count.
pub fn prf_evaluate<let N: u32, let L: u32, let B: u32>(
    key: Field,
    digest: [Field; 2],
    qis: [Field; L],
    high_bounds: [Field; L],
    low_bounds: [Field; L],
) -> [Polynomial<N>; L] {
    let squeezed = squeeze_key::<N, L>(key, digest);
    let mut polys: [Polynomial<N>; L] = [Polynomial::new([0; N]); L];
    for row in 0..L {
        polys[row] = fill_limb::<B, N>(
            qis[row],
            squeezed_row(squeezed, row),
            high_bounds[row],
            low_bounds[row],
        );
    }
    polys
}

/// Two limbs whose bit lengths differ. The supported parameter sets do not need this:
/// every insecure-64 threshold modulus is 27 bits and every secure-8192 one is 60.
fn prf_evaluate_two<let N: u32, let B0: u32, let B1: u32>(
    key: Field,
    digest: [Field; 2],
    qis: [Field; 2],
    high_bounds: [Field; 2],
    low_bounds: [Field; 2],
) -> [Polynomial<N>; 2] {
    let squeezed = squeeze_key::<N, 2>(key, digest);
    [
        fill_limb::<B0, N>(
            qis[0],
            squeezed_row::<N, 2>(squeezed, 0),
            high_bounds[0],
            low_bounds[0],
        ),
        fill_limb::<B1, N>(
            qis[1],
            squeezed_row::<N, 2>(squeezed, 1),
            high_bounds[1],
            low_bounds[1],
        ),
    ]
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

fn decryptor_position<let H: u32>(decryptors: [Field; H], party_id_one_based: Field) -> u32 {
    let mut seen = false;
    let mut position = 0;
    for i in 0..H {
        if decryptors[i] == party_id_one_based {
            seen = true;
            position = i;
        }
    }
    assert(seen, "Party is outside the decryptor set");
    position
}

/// Add one peer's `outgoing + q - incoming` without reducing.
///
/// Each residue is in `[0, q)`, so one peer contributes a value in `[0, 2q)`.
/// After `T` peers the accumulator is below `2 T q`. `T` fits in a `u32` and
/// `q < 2^62`, so the accumulator is below `2^95` and does not wrap the scalar
/// field. Its quotient by `q` is below `2^33`.
fn accumulate_mask_difference<let N: u32, let L: u32>(
    mask: [Polynomial<N>; L],
    positive: [Polynomial<N>; L],
    negative: [Polynomial<N>; L],
    qis: [Field; L],
) -> [Polynomial<N>; L] {
    let mut next: [Polynomial<N>; L] = [Polynomial::new([0; N]); L];
    for row in 0..L {
        let q = qis[row];
        let mut coeffs: [Field; N] = [0; N];
        for col in 0..N {
            coeffs[col] = mask[row].coefficients[col] + positive[row].coefficients[col] + q
                - negative[row].coefficients[col];
        }
        next[row] = Polynomial::new(coeffs);
    }
    next
}

/// Canonical residue of an accumulator whose quotient is below `2^33`.
fn reduce_accumulated_coefficient(qmod: ModU64, accumulated: Field) -> Field {
    // Safety: the quotient is range-checked below, and the remainder is checked into `[0, q)`.
    let quotient = unsafe { __reduce_witness_u64(accumulated, qmod.m) } as Field;
    quotient.assert_max_bit_size::<33>();
    let q = qmod.get_mod_field();
    let remainder = accumulated - quotient * q;
    remainder.assert_max_bit_size::<62>();
    (q - 1 - remainder).assert_max_bit_size::<62>();
    assert(quotient * q + remainder == accumulated);
    remainder
}

fn reduce_accumulated_mask<let N: u32, let L: u32>(
    mask: [Polynomial<N>; L],
    qis: [Field; L],
) -> [Polynomial<N>; L] {
    let mut reduced: [Polynomial<N>; L] = [Polynomial::new([0; N]); L];
    for row in 0..L {
        let qmod = ModU64::new(qis[row] as u64);
        let mut coeffs: [Field; N] = [0; N];
        for col in 0..N {
            coeffs[col] = reduce_accumulated_coefficient(qmod, mask[row].coefficients[col]);
        }
        reduced[row] = Polynomial::new(coeffs);
    }
    reduced
}

/// Build `r_i = Σ_{j in S, j ≠ i} (F_{k_ij}(H) - F_{k_ji}(H))`.
///
/// Outgoing key `k_ij` is committed under recipient `j`. Incoming key `k_ji` is
/// committed under recipient `i`. `ct_commitment` must be the checked commitment
/// of the ciphertext this mask is applied to; C6 checks that opening first.
pub fn prf_decryption_mask<let N: u32, let L: u32, let N_PARTIES: u32, let H: u32, let B: u32>(
    party_idx: u32,
    decryptors: [Field; H],
    outgoing_keys: [Field; N_PARTIES],
    incoming_keys: [Field; N_PARTIES],
    outgoing_commitments: [Field; N_PARTIES],
    incoming_commitments: [Field; N_PARTIES],
    ct_commitment: Field,
    qis: [Field; L],
) -> [Polynomial<N>; L] {
    // H here is the designated set length (T+1), not DKG's selected-dealer count.
    assert(party_idx < N_PARTIES, "Party index is out of range");
    assert(H > 0);
    assert_canonical_decryptors::<H, N_PARTIES>(decryptors);
    let self_id = (party_idx + 1) as Field;
    let own_position = decryptor_position(decryptors, self_id);

    let digest = prf_context_digest::<N, L, H>(decryptors, ct_commitment);
    let (high_bounds, low_bounds) = limb_bounds(qis);
    let mut mask: [Polynomial<N>; L] = [Polynomial::new([0; N]); L];

    // A witness-dependent `if` does not skip circuit work. Select exactly H-1
    // peers first, so only their two PRF streams are expanded by the compiler.
    // `T = H - 1` is the number of accumulated peers.
    for slot in 0..(H - 1) {
        let peer_position = if slot < own_position { slot } else { slot + 1 };
        let other = (decryptors[peer_position] as u32) - 1;
        assert(
            compute_packed_prf_key_commitment(other as Field, outgoing_keys[other])
                == outgoing_commitments[other],
            "Outgoing PRF key commitment mismatch",
        );
        assert(
            compute_packed_prf_key_commitment(party_idx as Field, incoming_keys[other])
                == incoming_commitments[other],
            "Incoming PRF key commitment mismatch",
        );
        let outgoing =
            prf_evaluate::<N, L, B>(outgoing_keys[other], digest, qis, high_bounds, low_bounds);
        let incoming =
            prf_evaluate::<N, L, B>(incoming_keys[other], digest, qis, high_bounds, low_bounds);
        mask = accumulate_mask_difference(mask, outgoing, incoming, qis);
    }

    reduce_accumulated_mask(mask, qis)
}

/// Same mask as `prf_decryption_mask` for two limbs that do not share a bit length.
fn prf_decryption_mask_two<let N: u32, let N_PARTIES: u32, let H: u32, let B0: u32, let B1: u32>(
    party_idx: u32,
    decryptors: [Field; H],
    outgoing_keys: [Field; N_PARTIES],
    incoming_keys: [Field; N_PARTIES],
    outgoing_commitments: [Field; N_PARTIES],
    incoming_commitments: [Field; N_PARTIES],
    ct_commitment: Field,
    qis: [Field; 2],
) -> [Polynomial<N>; 2] {
    assert(party_idx < N_PARTIES, "Party index is out of range");
    assert(H > 0);
    assert_canonical_decryptors::<H, N_PARTIES>(decryptors);
    let self_id = (party_idx + 1) as Field;
    let own_position = decryptor_position(decryptors, self_id);

    let digest = prf_context_digest::<N, 2, H>(decryptors, ct_commitment);
    let (high_bounds, low_bounds) = limb_bounds(qis);
    let mut mask: [Polynomial<N>; 2] = [Polynomial::new([0; N]); 2];

    for slot in 0..(H - 1) {
        let peer_position = if slot < own_position { slot } else { slot + 1 };
        let other = (decryptors[peer_position] as u32) - 1;
        assert(
            compute_packed_prf_key_commitment(other as Field, outgoing_keys[other])
                == outgoing_commitments[other],
            "Outgoing PRF key commitment mismatch",
        );
        assert(
            compute_packed_prf_key_commitment(party_idx as Field, incoming_keys[other])
                == incoming_commitments[other],
            "Incoming PRF key commitment mismatch",
        );
        let outgoing = prf_evaluate_two::<N, B0, B1>(
            outgoing_keys[other],
            digest,
            qis,
            high_bounds,
            low_bounds,
        );
        let incoming = prf_evaluate_two::<N, B0, B1>(
            incoming_keys[other],
            digest,
            qis,
            high_bounds,
            low_bounds,
        );
        mask = accumulate_mask_difference(mask, outgoing, incoming, qis);
    }

    reduce_accumulated_mask(mask, qis)
}

fn mask_fixture(owner: u32, ids: [Field; 3]) -> [Field; 8] {
    let mut outgoing = [0; 5];
    let mut incoming = [0; 5];
    let mut outgoing_commits = [0; 5];
    let mut incoming_commits = [0; 5];
    for peer in 0..5 {
        outgoing[peer] = (10 * owner + peer + 1) as Field;
        incoming[peer] = (10 * (peer + 1) + owner) as Field;
        outgoing_commits[peer] = compute_packed_prf_key_commitment(peer as Field, outgoing[peer]);
        incoming_commits[peer] =
            compute_packed_prf_key_commitment((owner - 1) as Field, incoming[peer]);
    }
    let ct0 = [Polynomial::new([7, 6, 5, 4, 3, 2, 1, 0])];
    let ct1 = [Polynomial::new([15, 14, 13, 12, 11, 10, 9, 8])];
    // Modulus bit of 65537 is 16, so this is the commitment decryption will open.
    let commitment = compute_ciphertext_commitment_checked::<8, 1, 16>(ct0, ct1);
    prf_decryption_mask::<8, 1, 5, 3, 17>(
        owner - 1,
        ids,
        outgoing,
        incoming,
        outgoing_commits,
        incoming_commits,
        commitment,
        [65537],
    )[0]
        .coefficients
}

#[test]
fn non_prefix_masks_are_distinct_and_cancel() {
    let ids: [Field; 3] = [1, 3, 5];
    let masks: [[Field; 8]; 3] = [
        mask_fixture(ids[0] as u32, ids),
        mask_fixture(ids[1] as u32, ids),
        mask_fixture(ids[2] as u32, ids),
    ];
    assert(masks[0] != masks[1]);
    assert(masks[1] != masks[2]);
    for coefficient in 0..8 {
        let sum = masks[0][coefficient] + masks[1][coefficient] + masks[2][coefficient];
        assert((sum == 0) | (sum == 65537) | (sum == 2 * 65537));
    }
}

#[test]
fn one_squeezed_element_splits_into_three_residues() {
    let q: Field = 65537;
    let qmod = ModU64::new(65537);
    // 3 + 5q + 7q^2. The same divisions are what evaluation stores.
    let x = 3 + 5 * q + 7 * q * q;
    let (quotient0, residue0) = qmod.quot_rem(x);
    let (quotient1, residue1) = qmod.quot_rem(quotient0);
    let residue2 = qmod.reduce_field(quotient1);
    assert(residue0 == 3);
    assert(residue1 == 5);
    assert(residue2 == 7);
    // q^3 + 4 keeps only the constant residue; the q^3 term is the discarded high part.
    let truncated = q * q * q + 4;
    let (high0, low0) = qmod.quot_rem(truncated);
    let (high1, low1) = qmod.quot_rem(high0);
    assert(low0 == 4);
    assert(low1 == 0);
    assert(qmod.reduce_field(high1) == 0);
}

#[test]
fn wide_modulus_quot_rem_matches_the_integer_split() {
    // This modulus is past the 2^50 hint threshold, so `quot_rem` returns the
    // witness quotient instead of dividing again.
    let q: Field = 576460752317792257;
    let qmod = ModU64::new(q as u64);
    let x = 3 + 5 * q + 7 * q * q;
    let (quotient0, residue0) = qmod.quot_rem(x);
    let (quotient1, residue1) = qmod.quot_rem(quotient0);
    let residue2 = qmod.reduce_field(quotient1);
    assert(residue0 == 3);
    assert(residue1 == 5);
    assert(residue2 == 7);
}

#[test]
fn insecure_sized_modulus_quot_rem_matches_the_integer_split() {
    // 134217089 is an insecure threshold modulus. It is below 2^50, so this
    // takes the byte path and still has to return the integer residues.
    let q: Field = 134217089;
    let qmod = ModU64::new(134217089);
    let x = 3 + 5 * q + 7 * q * q;
    let (quotient0, residue0) = qmod.quot_rem(x);
    let (quotient1, residue1) = qmod.quot_rem(quotient0);
    let residue2 = qmod.reduce_field(quotient1);
    assert(residue0 == 3);
    assert(residue1 == 5);
    assert(residue2 == 7);
}

fn tail_one_mask(owner: u32, ids: [Field; 3]) -> [Field; 4] {
    let mut outgoing = [0; 5];
    let mut incoming = [0; 5];
    let mut outgoing_commits = [0; 5];
    let mut incoming_commits = [0; 5];
    for peer in 0..5 {
        outgoing[peer] = (10 * owner + peer + 1) as Field;
        incoming[peer] = (10 * (peer + 1) + owner) as Field;
        outgoing_commits[peer] = compute_packed_prf_key_commitment(peer as Field, outgoing[peer]);
        incoming_commits[peer] =
            compute_packed_prf_key_commitment((owner - 1) as Field, incoming[peer]);
    }
    let ct0 = [Polynomial::new([3, 2, 1, 0])];
    let ct1 = [Polynomial::new([7, 6, 5, 4])];
    let commitment = compute_ciphertext_commitment_checked::<4, 1, 16>(ct0, ct1);
    prf_decryption_mask::<4, 1, 5, 3, 17>(
        owner - 1,
        ids,
        outgoing,
        incoming,
        outgoing_commits,
        incoming_commits,
        commitment,
        [65537],
    )[0]
        .coefficients
}

#[test]
fn tail_one_masks_are_distinct_and_cancel() {
    // N = 4 leaves a one-coefficient tail. N = 8192 leaves a two-coefficient tail.
    let ids: [Field; 3] = [1, 3, 5];
    let masks: [[Field; 4]; 3] = [
        tail_one_mask(ids[0] as u32, ids),
        tail_one_mask(ids[1] as u32, ids),
        tail_one_mask(ids[2] as u32, ids),
    ];
    assert(masks[0] != masks[1]);
    assert(masks[1] != masks[2]);
    for coefficient in 0..4 {
        let sum = masks[0][coefficient] + masks[1][coefficient] + masks[2][coefficient];
        assert((sum == 0) | (sum == 65537) | (sum == 2 * 65537));
    }
}

#[test(should_fail_with = "Party is outside the decryptor set")]
fn absent_owner_cannot_supply_a_peer_position() {
    let _ = mask_fixture(2, [1, 3, 5]);
}

#[test(should_fail_with = "Decryptor ids are not sorted")]
fn peer_selection_rejects_unsorted_ids() {
    let _ = mask_fixture(3, [1, 5, 3]);
}

#[test(should_fail_with = "Decryptor ids are not sorted")]
fn peer_selection_rejects_duplicate_ids() {
    let _ = mask_fixture(3, [1, 3, 3]);
}

#[test(should_fail_with = "Decryptor id is zero")]
fn peer_selection_rejects_zero_ids() {
    let _ = mask_fixture(3, [0, 3, 5]);
}

#[test(should_fail_with = "Decryptor id is out of range")]
fn peer_selection_rejects_out_of_range_ids() {
    let _ = mask_fixture(3, [1, 3, 6]);
}

fn residues_match_division<let B: u32>(q: u64, x: Field) {
    let qmod = ModU64::new(q);
    let (high_bound, low_bound) = limb_split_bounds(qmod);
    let (residue0, residue1, residue2) = split_full_group::<B>(qmod, x, high_bound, low_bound);
    let (quotient0, expected0) = qmod.quot_rem(x);
    let (quotient1, expected1) = qmod.quot_rem(quotient0);
    let expected2 = qmod.reduce_field(quotient1);
    assert(residue0 == expected0);
    assert(residue1 == expected1);
    assert(residue2 == expected2);
}

#[test]
fn evaluation_follows_the_supplied_limb_count() {
    let qis = [3, 65537, 134217089, 576460752317792257];
    let (high_bounds, low_bounds) = limb_bounds(qis);
    let squeezed = squeeze_key::<4, 4>(1, [2, 3]);
    // Bit lengths of the four moduli above: 2, 17, 27 (insecure-64), 60 (secure-8192).
    let polys = [
        fill_limb::<2, 4>(qis[0], squeezed_row::<4, 4>(squeezed, 0), high_bounds[0], low_bounds[0]),
        fill_limb::<17, 4>(
            qis[1],
            squeezed_row::<4, 4>(squeezed, 1),
            high_bounds[1],
            low_bounds[1],
        ),
        fill_limb::<27, 4>(
            qis[2],
            squeezed_row::<4, 4>(squeezed, 2),
            high_bounds[2],
            low_bounds[2],
        ),
        fill_limb::<60, 4>(
            qis[3],
            squeezed_row::<4, 4>(squeezed, 3),
            high_bounds[3],
            low_bounds[3],
        ),
    ];
    for row in 0..4 {
        for coefficient in 0..4 {
            assert((polys[row].coefficients[coefficient] as u128) < (qis[row] as u128));
        }
    }
}

#[test]
fn full_group_matches_successive_division_for_each_width() {
    let narrow: Field = 65537;
    let insecure: Field = 134217089;
    let secure: Field = 576460752317792257;
    residues_match_division::<17>(narrow as u64, 3 + 5 * narrow + 7 * narrow * narrow);
    residues_match_division::<27>(insecure as u64, 3 + 5 * insecure + 7 * insecure * insecure);
    residues_match_division::<60>(secure as u64, 3 + 5 * secure + 7 * secure * secure);
    // p-1 is the inclusive end of the high-quotient range.
    residues_match_division::<17>(narrow as u64, -1);
    residues_match_division::<27>(insecure as u64, -1);
    residues_match_division::<60>(secure as u64, -1);
}

#[test(should_fail)]
fn split_rejects_noncanonical_digit() {
    let q: Field = 65537;
    let qmod = ModU64::new(65537);
    let (high_bound, low_bound) = limb_split_bounds(qmod);
    constrain_three_residues::<17>(q, q, 0, q, 0, 0, high_bound, low_bound);
}

#[test(should_fail)]
fn split_rejects_carry_alias() {
    let q: Field = 65537;
    let qmod = ModU64::new(65537);
    let (high_bound, low_bound) = limb_split_bounds(qmod);
    let x = 3 + q * q;
    constrain_three_residues::<17>(q, x, 0, 3, q, 0, high_bound, low_bound);
}

#[test(should_fail)]
fn split_rejects_oversized_quotient() {
    let q: Field = 65537;
    let qmod = ModU64::new(65537);
    let (high_bound, low_bound) = limb_split_bounds(qmod);
    let x = (high_bound + 1) * q * q * q;
    constrain_three_residues::<17>(q, x, high_bound + 1, 0, 0, 0, high_bound, low_bound);
}

#[test(should_fail)]
fn split_rejects_wrapped_field_opening() {
    let q: Field = 65537;
    let qmod = ModU64::new(65537);
    let (high_bound, low_bound) = limb_split_bounds(qmod);
    // R+1 with h = H reconstructs p, which is the field element 0.
    let (quotient0, residue0) = qmod.quot_rem(low_bound + 1);
    let (quotient1, residue1) = qmod.quot_rem(quotient0);
    let residue2 = qmod.reduce_field(quotient1);
    constrain_three_residues::<17>(
        q,
        0,
        high_bound,
        residue0,
        residue1,
        residue2,
        high_bound,
        low_bound,
    );
}

#[test]
fn deferred_reduction_matches_per_peer_reduction() {
    let q: Field = 134217089;
    let qmod = ModU64::new(q as u64);
    let outgoing = [1, 100, q - 1];
    let incoming = [2, 7, 0];
    let mut stepwise = 0;
    let mut accumulated = 0;
    for i in 0..3 {
        stepwise = qmod.reduce_mod(stepwise + outgoing[i] + q - incoming[i]);
        accumulated = accumulated + outgoing[i] + q - incoming[i];
    }
    assert(reduce_accumulated_coefficient(qmod, accumulated) == stepwise);
}

fn mixed_limb_mask<let N: u32>(owner: u32, ids: [Field; 3]) -> [Polynomial<N>; 2] {
    let mut outgoing = [0; 5];
    let mut incoming = [0; 5];
    let mut outgoing_commits = [0; 5];
    let mut incoming_commits = [0; 5];
    for peer in 0..5 {
        outgoing[peer] = (10 * owner + peer + 1) as Field;
        incoming[peer] = (10 * (peer + 1) + owner) as Field;
        outgoing_commits[peer] = compute_packed_prf_key_commitment(peer as Field, outgoing[peer]);
        incoming_commits[peer] =
            compute_packed_prf_key_commitment((owner - 1) as Field, incoming[peer]);
    }
    let ct0 = [Polynomial::new([0; N]); 2];
    let ct1 = [Polynomial::new([0; N]); 2];
    let commitment = compute_ciphertext_commitment_checked::<N, 2, 16>(ct0, ct1);
    // 65537 is 17 bits. 134217089 is an insecure-64 modulus, 27 bits.
    prf_decryption_mask_two::<N, 5, 3, 17, 27>(
        owner - 1,
        ids,
        outgoing,
        incoming,
        outgoing_commits,
        incoming_commits,
        commitment,
        [65537, 134217089],
    )
}

#[test]
fn mixed_limb_tails_are_nonzero_and_cancel() {
    let ids: [Field; 3] = [1, 3, 5];
    let narrow: Field = 65537;
    let wide: Field = 134217089;
    let tail_two: [[Polynomial<8>; 2]; 3] = [
        mixed_limb_mask(ids[0] as u32, ids),
        mixed_limb_mask(ids[1] as u32, ids),
        mixed_limb_mask(ids[2] as u32, ids),
    ];
    let tail_one: [[Polynomial<4>; 2]; 3] = [
        mixed_limb_mask(ids[0] as u32, ids),
        mixed_limb_mask(ids[1] as u32, ids),
        mixed_limb_mask(ids[2] as u32, ids),
    ];
    assert(tail_two[0][0].coefficients != tail_two[1][0].coefficients);
    assert(tail_one[0][0].coefficients != tail_one[1][0].coefficients);
    let mut narrow_nonzero = false;
    let mut wide_nonzero = false;
    for coefficient in 0..8 {
        if tail_two[0][0].coefficients[coefficient] != 0 {
            narrow_nonzero = true;
        }
        if tail_two[0][1].coefficients[coefficient] != 0 {
            wide_nonzero = true;
        }
        for limb in 0..2 {
            let q = if limb == 0 { narrow } else { wide };
            let sum = tail_two[0][limb].coefficients[coefficient]
                + tail_two[1][limb].coefficients[coefficient]
                + tail_two[2][limb].coefficients[coefficient];
            assert((sum == 0) | (sum == q) | (sum == 2 * q));
        }
    }
    assert(narrow_nonzero);
    assert(wide_nonzero);
    for coefficient in 0..4 {
        for limb in 0..2 {
            let q = if limb == 0 { narrow } else { wide };
            let sum = tail_one[0][limb].coefficients[coefficient]
                + tail_one[1][limb].coefficients[coefficient]
                + tail_one[2][limb].coefficients[coefficient];
            assert((sum == 0) | (sum == q) | (sum == 2 * q));
        }
    }
}

fn zero_ciphertext_mask<let N: u32>(owner: u32, ids: [Field; 3]) -> [Polynomial<N>; 2] {
    let mut outgoing = [0; 5];
    let mut incoming = [0; 5];
    let mut outgoing_commits = [0; 5];
    let mut incoming_commits = [0; 5];
    for peer in 0..5 {
        outgoing[peer] = (10 * owner + peer + 1) as Field;
        incoming[peer] = (10 * (peer + 1) + owner) as Field;
        outgoing_commits[peer] = compute_packed_prf_key_commitment(peer as Field, outgoing[peer]);
        incoming_commits[peer] =
            compute_packed_prf_key_commitment((owner - 1) as Field, incoming[peer]);
    }
    let ct0 = [Polynomial::new([0; N]); 2];
    let ct1 = [Polynomial::new([0; N]); 2];
    // Centered width of max(65537, 134217089) is 26, the width the native commitment uses.
    let commitment = compute_ciphertext_commitment_checked::<N, 2, 26>(ct0, ct1);
    // 65537 is 17 bits. 134217089 is an insecure-64 modulus, 27 bits.
    prf_decryption_mask_two::<N, 5, 3, 17, 27>(
        owner - 1,
        ids,
        outgoing,
        incoming,
        outgoing_commits,
        incoming_commits,
        commitment,
        [65537, 134217089],
    )
}

#[test]
fn native_masks_match_for_both_tails() {
    let ids: [Field; 3] = [1, 3, 5];
    let tail_two = zero_ciphertext_mask::<8>(ids[0] as u32, ids);
    let tail_one = zero_ciphertext_mask::<16>(ids[0] as u32, ids);
    assert(tail_two[0].coefficients == [7412, 28446, 17326, 56383, 51908, 9857, 47608, 9856]);
    assert(
        tail_two[1].coefficients
            == [59089007, 10188786, 19792890, 84831172, 83697486, 28164971, 62327969, 44838048],
    );
    assert(
        tail_one[0].coefficients
            == [
                48718, 6878, 57133, 17990, 39729, 57523, 29682, 7705, 10869, 14453, 23457, 2980,
                19081, 56811, 9272, 16409,
            ],
    );
    assert(
        tail_one[1].coefficients
            == [
                115302108, 10993617, 14115167, 119191885, 23150975, 69758970, 60656832, 47568370,
                90572515, 45489300, 126981637, 110588325, 30204511, 68133202, 124128057, 13397114,
            ],
    );
}

#[test]
fn native_residue_preserves_centered_signs() {
    assert(native_residue(0, 97) == 0);
    assert(native_residue(48, 97) == 48);
    assert(native_residue(-1, 97) == 96);
    assert(native_residue(-48, 97) == 49);
}

#[test]
fn context_digest_binds_the_checked_ciphertext_commitment() {
    let qis: [Field; 3] = [576460752317792257, 576460752317399041, 576460752316776449];
    let mut ct0 = [Polynomial::new([0; 8]); 3];
    let mut ct1 = [Polynomial::new([0; 8]); 3];
    for row in 0..3 {
        let half = (qis[row] - 1) / 2;
        ct0[row] = Polynomial::new([-half, half, -1, 0, 1, -7, 11, 23]);
        ct1[row] = Polynomial::new([23, 11, -7, 1, 0, -1, half, -half]);
    }
    // Modulus bit of these limbs is 59, matching C6's checked ciphertext packing.
    let commitment = compute_ciphertext_commitment_checked::<8, 3, 59>(ct0, ct1);
    let digest = prf_context_digest::<8, 3, 3>([1, 3, 5], commitment);
    assert(digest == prf_context_digest::<8, 3, 3>([1, 3, 5], commitment));
    ct0[0].coefficients[0] += 1;
    let changed = compute_ciphertext_commitment_checked::<8, 3, 59>(ct0, ct1);
    assert(changed != commitment);
    assert(prf_context_digest::<8, 3, 3>([1, 3, 5], changed) != digest);
}
