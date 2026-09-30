// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Authorisation of a ballot by the owners of its slot: the check that a Safe makes, inside the
//! proof, so that the signatures stay private. A wallet is one owner, the slot, with threshold 1.
//!
//! The contract supplies two public inputs that the prover cannot change: the digest that the
//! owners sign, and the Keccak hash of the owners as 20-byte words, padded with the zero address to
//! `MAX_SAFE_OWNERS`, followed by the threshold as one byte, in two 16-byte halves. Only ECDSA owner
//! signatures over that digest count. The other Safe signature types (contract signatures, approved
//! hashes, `eth_sign`) need on-chain state or another digest, so a proof cannot check them.

use crate::ecdsa::{address_to_field, derive_address, digest_from_halves, validate_signature};
use keccak256::keccak256;

/// Returns true when the owners as 20-byte words, followed by the threshold as one byte, hash to
/// the committed value. The packing keeps 10 owners within two Keccak blocks.
fn owners_commitment_matches<let O: u32>(
    owners: [Field; O],
    threshold: u32,
    commitment_hi: Field,
    commitment_lo: Field,
) -> bool {
    let mut bytes = [0 as u8; O * 20 + 1];
    for i in 0..O {
        let owner: [u8; 20] = owners[i].to_be_bytes();
        for j in 0..20 {
            bytes[i * 20 + j] = owner[j];
        }
    }
    let threshold_byte: [u8; 1] = (threshold as Field).to_be_bytes();
    bytes[O * 20] = threshold_byte[0];

    keccak256(bytes, O * 20 + 1) == digest_from_halves(commitment_hi, commitment_lo)
}

/// Returns true when `threshold` distinct committed owners signed `hashed_message`.
///
/// The first `threshold` of the `S` signature slots are active, each a signature by the owner at
/// `owner_indices[i]`. Signers must be in strictly ascending address order, as a Safe requires,
/// which also stops one owner from counting twice. An inactive slot is not checked, but it must
/// hold a valid public key and an index below `O`. The threshold must be from 1 to `S`.
pub fn validate_safe_signatures<let S: u32, let O: u32>(
    hashed_message: [u8; 32],
    owners: [Field; O],
    threshold: u32,
    commitment_hi: Field,
    commitment_lo: Field,
    public_keys_x: [[u8; 32]; S],
    public_keys_y: [[u8; 32]; S],
    signatures: [[u8; 64]; S],
    owner_indices: [u32; S],
) -> bool {
    let mut valid = (threshold >= 1) & (threshold <= S);
    valid &= owners_commitment_matches(owners, threshold, commitment_hi, commitment_lo);

    let mut previous: Field = 0;
    for i in 0..S {
        let active = i < threshold;
        let signed = validate_signature(
            hashed_message,
            public_keys_x[i],
            public_keys_y[i],
            signatures[i],
        );
        let signer = address_to_field(derive_address(public_keys_x[i], public_keys_y[i]));
        let is_owner = owners[owner_indices[i]] == signer;
        let ascending = previous.lt(signer);

        valid &= !active | (signed & is_owner & ascending);
        if active {
            previous = signer;
        }
    }

    valid
}

// ================================================================================================
// Tests
// ================================================================================================
//
// The fixtures are real secp256k1 signatures. Four owners, sorted by address (private keys
// `keccak256("safe owner i")` for i = 0, 1, 2 and 4):
//   owner0 0x0dD9130977fBe72e9030dF1cd95Fbef5796AC5C0
//   owner1 0x1127c766a9808F9E0a15a2A56FcE79f2b5b5e8E9
//   owner2 0x3CaEf311dE49F3af5A74A7364E79A0350b8E723c
//   owner3 0x58201050f0dB7832Ef4A1Ab20EF40844a71F2433
// and one account that is not an owner:
//   outsider 0x6AB133Ce3481A06313b4e0B1bb810BCD670853a4
// Each signed DIGEST. The owner commitments pad the four owners to MAX_SAFE_OWNERS with the zero
// address, as `CRISPProgram` does.

use crate::constants::{MAX_SAFE_OWNERS, MAX_SAFE_SIGNERS};

global DIGEST: [u8; 32] = [
    76, 135, 189, 241, 169, 36, 3, 199, 216, 168, 245, 150, 27, 30, 6, 68, 76, 245, 191, 211, 252,
    152, 143, 56, 164, 105, 147, 200, 167, 133, 131, 194,
];
global OTHER_DIGEST: [u8; 32] = [
    218, 174, 189, 64, 247, 221, 120, 150, 21, 56, 81, 218, 187, 9, 195, 96, 39, 163, 160, 227, 102,
    168, 159, 151, 210, 148, 251, 46, 84, 25, 249, 252,
];

global OWNER0_X: [u8; 32] = [
    158, 203, 216, 75, 243, 188, 168, 109, 98, 234, 152, 25, 250, 66, 162, 152, 24, 58, 42, 255,
    181, 167, 251, 45, 107, 25, 227, 150, 111, 134, 10, 235,
];
global OWNER0_Y: [u8; 32] = [
    26, 157, 171, 131, 222, 175, 192, 182, 245, 188, 232, 73, 114, 176, 102, 140, 174, 221, 80, 222,
    35, 83, 69, 20, 76, 131, 151, 215, 243, 192, 148, 139,
];
global OWNER0_SIG: [u8; 64] = [
    109, 11, 30, 153, 9, 189, 233, 191, 125, 113, 106, 177, 106, 3, 221, 132, 139, 149, 72, 108, 51,
    112, 12, 159, 40, 46, 119, 70, 42, 251, 211, 98, 31, 65, 5, 239, 53, 204, 198, 194, 159, 174, 6,
    181, 123, 243, 79, 50, 48, 64, 250, 131, 38, 100, 112, 207, 157, 58, 91, 147, 37, 167, 193, 63,
];

global OWNER1_X: [u8; 32] = [
    74, 3, 149, 8, 179, 159, 136, 169, 176, 168, 62, 117, 224, 3, 114, 100, 194, 14, 11, 187, 187,
    152, 179, 118, 168, 57, 194, 144, 9, 196, 161, 19,
];
global OWNER1_Y: [u8; 32] = [
    244, 5, 238, 61, 231, 119, 131, 235, 123, 96, 101, 59, 137, 239, 123, 75, 210, 8, 122, 62, 42,
    107, 36, 174, 166, 221, 243, 70, 201, 126, 200, 116,
];
global OWNER1_SIG: [u8; 64] = [
    124, 180, 219, 204, 221, 105, 143, 82, 245, 92, 44, 124, 45, 177, 12, 202, 25, 188, 35, 185,
    121, 9, 162, 92, 161, 24, 144, 48, 168, 213, 79, 85, 100, 121, 210, 80, 21, 47, 151, 249, 252,
    162, 144, 39, 62, 142, 121, 70, 25, 20, 101, 2, 37, 56, 173, 201, 149, 129, 57, 122, 53, 174,
    192, 67,
];

global OWNER2_X: [u8; 32] = [
    24, 133, 79, 26, 194, 177, 123, 209, 179, 250, 93, 14, 98, 109, 28, 229, 87, 62, 56, 21, 132,
    220, 122, 191, 219, 83, 12, 163, 133, 30, 232, 155,
];
global OWNER2_Y: [u8; 32] = [
    153, 218, 165, 209, 64, 246, 111, 33, 8, 9, 161, 115, 176, 234, 44, 144, 224, 251, 172, 1, 74,
    19, 161, 152, 161, 139, 74, 37, 223, 30, 154, 241,
];
global OWNER2_SIG: [u8; 64] = [
    182, 54, 202, 118, 124, 243, 184, 130, 140, 176, 88, 84, 104, 66, 213, 169, 167, 250, 160, 32,
    104, 228, 0, 116, 176, 206, 190, 94, 188, 135, 114, 188, 100, 91, 62, 222, 16, 65, 102, 193,
    251, 3, 231, 122, 206, 33, 106, 130, 80, 98, 18, 229, 0, 63, 242, 36, 181, 212, 94, 113, 27,
    144, 178, 207,
];

global OWNER3_X: [u8; 32] = [
    222, 141, 175, 112, 45, 148, 85, 126, 255, 78, 72, 239, 142, 172, 217, 122, 206, 167, 76, 232,
    35, 219, 115, 96, 68, 222, 28, 6, 46, 237, 18, 149,
];
global OWNER3_Y: [u8; 32] = [
    194, 242, 80, 179, 243, 0, 255, 227, 133, 99, 232, 230, 88, 249, 64, 70, 196, 144, 200, 215, 98,
    179, 104, 11, 173, 15, 73, 37, 114, 231, 195, 123,
];
global OWNER3_SIG: [u8; 64] = [
    172, 162, 190, 111, 87, 167, 166, 221, 219, 217, 49, 131, 144, 181, 39, 114, 2, 81, 178, 116,
    249, 53, 234, 16, 238, 68, 56, 186, 101, 106, 143, 119, 8, 45, 145, 71, 208, 230, 75, 60, 102,
    48, 167, 38, 74, 182, 97, 124, 102, 144, 163, 80, 230, 76, 238, 135, 196, 212, 138, 156, 190,
    117, 21, 178,
];

global OUTSIDER_X: [u8; 32] = [
    246, 160, 175, 56, 39, 59, 80, 73, 196, 122, 145, 63, 248, 149, 206, 232, 155, 206, 230, 18, 24,
    239, 200, 108, 28, 175, 66, 216, 147, 81, 119, 179,
];
global OUTSIDER_Y: [u8; 32] = [
    23, 168, 230, 198, 93, 122, 52, 188, 170, 204, 169, 166, 243, 47, 137, 114, 145, 6, 81, 187,
    151, 32, 237, 26, 192, 243, 248, 40, 87, 206, 34, 181,
];
global OUTSIDER_SIG: [u8; 64] = [
    7, 79, 122, 83, 175, 201, 250, 253, 189, 138, 0, 61, 224, 78, 73, 21, 209, 34, 144, 81, 240,
    123, 239, 129, 242, 209, 98, 172, 175, 226, 160, 146, 110, 4, 103, 143, 193, 140, 230, 37, 209,
    250, 200, 160, 136, 52, 79, 37, 87, 220, 61, 120, 72, 11, 5, 5, 76, 101, 87, 215, 71, 29, 223,
    44,
];

// The owner commitments of the four owners, padded to MAX_SAFE_OWNERS. COMMIT_Tn has threshold n.
global COMMIT_T0: (Field, Field) =
    (0x002e33d5e9ce49155f7643ae1dc0f684, 0x36251217885075aaed200c712091c90b);
global COMMIT_T1: (Field, Field) =
    (0x87d622ff3d801a4c69ddc74ac80c8c43, 0x5f4871739508393e63afd2d9d94b4c59);
global COMMIT_T2: (Field, Field) =
    (0x552f5e6eb66ec9d5ffc0053430a9b926, 0x08d164983224ab8464904770a5c2572e);
global COMMIT_T4: (Field, Field) =
    (0xb032d5dab83e3ac480633acd9b8b23f0, 0x13536920010c51f3bb388812dd47fd6d);
global COMMIT_T5: (Field, Field) =
    (0x63afd2165460c0092ac9e6eb2ed4e45b, 0xa6805a324594cb35d5e29a1ab0cfb4a2);

fn test_owners() -> [Field; MAX_SAFE_OWNERS] {
    let mut owners = [0; MAX_SAFE_OWNERS];
    owners[0] = 0x0dD9130977fBe72e9030dF1cd95Fbef5796AC5C0;
    owners[1] = 0x1127c766a9808F9E0a15a2A56FcE79f2b5b5e8E9;
    owners[2] = 0x3CaEf311dE49F3af5A74A7364E79A0350b8E723c;
    owners[3] = 0x58201050f0dB7832Ef4A1Ab20EF40844a71F2433;
    owners
}

/// A signature slot: public key x, public key y, signature, owner index.
struct Slot {
    x: [u8; 32],
    y: [u8; 32],
    sig: [u8; 64],
    index: u32,
}

fn owner0() -> Slot {
    Slot { x: OWNER0_X, y: OWNER0_Y, sig: OWNER0_SIG, index: 0 }
}

fn owner1() -> Slot {
    Slot { x: OWNER1_X, y: OWNER1_Y, sig: OWNER1_SIG, index: 1 }
}

fn owner2() -> Slot {
    Slot { x: OWNER2_X, y: OWNER2_Y, sig: OWNER2_SIG, index: 2 }
}

fn owner3() -> Slot {
    Slot { x: OWNER3_X, y: OWNER3_Y, sig: OWNER3_SIG, index: 3 }
}

fn check(
    digest: [u8; 32],
    threshold: u32,
    commitment: (Field, Field),
    slots: [Slot; MAX_SAFE_SIGNERS],
) -> bool {
    let mut xs = [[0; 32]; MAX_SAFE_SIGNERS];
    let mut ys = [[0; 32]; MAX_SAFE_SIGNERS];
    let mut sigs = [[0; 64]; MAX_SAFE_SIGNERS];
    let mut indices = [0; MAX_SAFE_SIGNERS];
    for i in 0..MAX_SAFE_SIGNERS {
        xs[i] = slots[i].x;
        ys[i] = slots[i].y;
        sigs[i] = slots[i].sig;
        indices[i] = slots[i].index;
    }
    validate_safe_signatures(
        digest,
        test_owners(),
        threshold,
        commitment.0,
        commitment.1,
        xs,
        ys,
        sigs,
        indices,
    )
}

#[test]
fn test_one_of_four() {
    // The inactive slots repeat the active one. Their content is not checked.
    assert(
        check(
            DIGEST,
            1,
            COMMIT_T1,
            [owner1(), owner1(), owner1(), owner1()],
        ),
    );
}

#[test]
fn test_two_of_four_ignores_inactive_slots() {
    // An inactive slot holds a key that is not an owner, a signature that is not by that key, and
    // the index of an empty owner position.
    let junk = Slot { x: OUTSIDER_X, y: OUTSIDER_Y, sig: OWNER0_SIG, index: 6 };
    assert(check(DIGEST, 2, COMMIT_T2, [owner0(), owner2(), junk, junk]));
}

#[test]
fn test_four_of_four() {
    assert(
        check(
            DIGEST,
            4,
            COMMIT_T4,
            [owner0(), owner1(), owner2(), owner3()],
        ),
    );
}

// Each negative case below returns false instead of failing a constraint. The circuit asserts the
// result only on the vote branch, so a mask proof must still execute when no signature verifies.

/// The threshold is committed, so a prover cannot claim a smaller one than the Safe has.
#[test]
fn test_rejects_threshold_below_committed() {
    assert(
        !check(
            DIGEST,
            1,
            COMMIT_T2,
            [owner0(), owner0(), owner0(), owner0()],
        ),
    );
}

#[test]
fn test_rejects_descending_order() {
    assert(
        !check(
            DIGEST,
            2,
            COMMIT_T2,
            [owner1(), owner0(), owner0(), owner0()],
        ),
    );
}

#[test]
fn test_rejects_same_owner_twice() {
    assert(
        !check(
            DIGEST,
            2,
            COMMIT_T2,
            [owner1(), owner1(), owner1(), owner1()],
        ),
    );
}

#[test]
fn test_rejects_signer_not_an_owner() {
    let outsider = Slot { x: OUTSIDER_X, y: OUTSIDER_Y, sig: OUTSIDER_SIG, index: 2 };
    assert(
        !check(
            DIGEST,
            2,
            COMMIT_T2,
            [owner0(), outsider, outsider, outsider],
        ),
    );
}

#[test]
fn test_rejects_signature_over_other_digest() {
    assert(
        !check(
            OTHER_DIGEST,
            2,
            COMMIT_T2,
            [owner0(), owner1(), owner1(), owner1()],
        ),
    );
}

#[test]
fn test_rejects_wrong_owner_index() {
    let misplaced = Slot { x: OWNER1_X, y: OWNER1_Y, sig: OWNER1_SIG, index: 2 };
    assert(
        !check(
            DIGEST,
            2,
            COMMIT_T2,
            [owner0(), misplaced, misplaced, misplaced],
        ),
    );
}

/// Even with a matching commitment and valid slots.
#[test]
fn test_rejects_threshold_above_signer_cap() {
    assert(
        !check(
            DIGEST,
            5,
            COMMIT_T5,
            [owner0(), owner1(), owner2(), owner3()],
        ),
    );
}

#[test]
fn test_rejects_zero_threshold() {
    assert(
        !check(
            DIGEST,
            0,
            COMMIT_T0,
            [owner0(), owner1(), owner2(), owner3()],
        ),
    );
}
