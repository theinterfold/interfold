// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Helper functions for circuit construction and cryptographic operations.
use crate::math::polynomial::Polynomial;
use crate::math::safe::SafeSponge;

/// Compute hex-aligned packing parameters for a given `BIT`.
///
/// # Purpose
/// Returns `(nibble_bits, group)` for use by pack/flatten so layout stays consistent.
/// - `nibble_bits`: ceil (`BIT`) to the next multiple of 4 (nibble alignment).
///   - Examples: `BIT = 7 -> 8`, `BIT = 8 -> 8`, `BIT = 9 -> 12`, `BIT = 10 -> 12`, `BIT = 11 -> 12`,
///     `BIT=16 -> 16`, `BIT = 17 -> 20`.
/// - `group`: max number of encoded limbs that fit in one BN254 field element,
///            when each limb uses an extra 4 bits (see below).
///
/// # Rationale
/// - We align to nibbles so powers of two are hex-friendly and deterministic.
/// - We reserve one extra nibble (4 bits) per stored value to lift signed
///   coefficients into the non-negative range (e.g., store `v + 2^nibble_bits`),
///   which implies a radix of `2^(nibble_bits + 4)`.
///
/// # Safety
/// - Asserts `nibble_bits + 4 <= 254` to avoid mod-p wrap on BN254.
/// - Ensures at least one limb fits: `group >= 1`.
fn packing_layout<let BIT: u32>() -> (u32, u32) {
    // Ceil BIT up to the next multiple of 4 (nibble alignment).
    let nibble_bits = ((BIT + 3) / 4) * 4;

    // Each stored limb uses an extra nibble because negative coefficients
    // will be shifted to positive, so radix = 2^(nibble_bits+4).
    assert(nibble_bits + 4 <= 254);

    // Maximum limbs that fit in one BN254 element without wrap.
    let group = 254 / (nibble_bits + 4);
    assert(group >= 1);
    (nibble_bits, group)
}

/// Flatten `L` polynomials into a single linear stream of packed `Field` carriers.
///
/// ## What this does
/// - For each CRT limb `j` in `0..L`, it packs the coefficients of `poly[j]`
///   with `pack::<A, BIT>` and appends all resulting carriers to `inputs`.
/// - The packing layout (nibble-aligned width and `group` size) is taken from
///   `packing_layout::<BIT>()` and must match what `pack` uses.
///
/// ## Determinism & order
/// - Preserves a stable order: iterate `j = 0..L`, then for each `j` append
///   carriers in ascending chunk index `i = 0..num_chunks`.
/// - This ensures transcripts remain deterministic across runs.
///
/// ## Generics
/// - `A`: polynomial degree (number of coefficients per polynomial).
/// - `L`: number of CRT bases (polynomials).
/// - `BIT`: per-coefficient bit bound used by the packing layout (compile-time).
///
/// ## Returns
/// - The same `inputs` vector, extended with all carriers in deterministic order.
pub fn flatten<let A: u32, let L: u32, let BIT: u32>(
    mut inputs: [Field],
    poly: [Polynomial<A>; L],
) -> [Field] {
    for j in 0..L {
        // Pack its A coefficients into `num_chunks` carriers using the same BIT layout.
        let packed = pack::<A, BIT>(poly[j].coefficients);

        // Append carriers in-order to `inputs` to keep a stable transcript layout.
        for i in 0..packed.len() {
            inputs = inputs.push_back(packed[i]);
        }
    }

    // Return the extended input stream.
    inputs
}

/// Pack `A` values into a `[Field]` of carriers using the shared hex-aligned layout.
///
/// ## What this does
/// - Computes `(nibble_bits, group)` via `packing_layout::<BIT>()`.
/// - Encodes each value as a limb `digit = v + 2^nibble_bits` and concatenates
///   limbs in base `radix = 2^(nibble_bits + 4)` (one extra nibble of headroom).
/// - Packs up to `group` limbs per carrier (fits within BN254 254-bit capacity).
/// - Pads the last, partial carrier with `digit = 2^nibble_bits` to keep a stable layout.
///
/// ## Determinism & order
/// - Processes values in increasing index order and emits carriers in chunk order
///   (`chunk = 0..num_chunks`). Padding is deterministic.
///
/// ## Generics
/// - `A`: number of input values.
/// - `BIT`: per-value bit bound; rounded up to `nibble_bits` by `packing_layout`.
///
/// ## Preconditions / Notes
/// - Call with the raw coefficients whose magnitudes already satisfy the BIT bound
///   (as enforced by the upstream range checks); `pack` performs the signed -> unsigned
///   shift internally via `v + base`.
/// - `group >= 1` is enforced by `packing_layout::<BIT>()`.
/// - Padding with `digit = 2^nibble_bits` encodes `zero limb` consistently.
///
/// ## Returns
/// - A `[Field]` where each element is a concatenation of up to `group` limbs,
///   suitable for hashing or transcript I/O.
pub fn pack<let A: u32, let BIT: u32>(values: [Field; A]) -> [Field] {
    // Layout parameters: nibble-aligned width and limbs-per-carrier group size.
    let (nibble_bits, group) = packing_layout::<BIT>();

    let base = 2.pow_32(nibble_bits as Field); // 2^nibble_bits
    let radix = 2.pow_32((nibble_bits + 4) as Field); // 2^(nibble_bits + 4)

    // Number of chunks to emit: ceil(A / group).
    let num_chunks = (A + group - 1) / group;
    let mut out = [].as_vector();

    // Process in fixed-size chunks of `group` limbs.
    for chunk in 0..num_chunks {
        // How many real values go into this chunk.
        let remain = A - (chunk * group);
        let take = if remain < group { remain } else { group };

        // Build field element accumulator (big-endian concatenation in `radix`).
        let mut acc = 0;
        for i in 0..take {
            let v = values[chunk * group + i];
            acc = acc * radix + (v + base);
        }

        // Pad remaining limb slots with the canonical zero-limb `digit = base`.
        for _ in 0..(group - take) {
            acc = acc * radix + base;
        }

        out = out.push_back(acc);
    }
    out
}

/// Computes a cryptographic hash using the SAFE (Sponge API for Field Elements) protocol.
///
/// This is a convenience wrapper around the SAFE sponge API that handles the full
/// lifecycle: initialization, absorption, squeezing, and finalization. It's designed
/// for use in Fiat-Shamir challenge generation and commitment schemes within zero-knowledge circuits.
///
/// # Arguments
/// * `domain_separator` - A 64-byte domain separator used to differentiate between
///                        different protocol instances and prevent cross-protocol attacks.
/// * `inputs` - Vector of field elements to be absorbed into the sponge.
/// * `io_pattern` - A 2-element array encoding the I/O pattern:
///                 - `io_pattern[0]`: Encoded ABSORB operation (MSB=1, lower 31 bits = length)
///                 - `io_pattern[1]`: Encoded SQUEEZE operation (MSB=0, lower 31 bits = length)
///
/// # Returns
/// A vector of field elements squeezed from the sponge, with length determined by
/// the SQUEEZE operation in the IO pattern.
pub fn compute_safe(domain_separator: [u8; 64], inputs: [Field], io_pattern: [u32; 2]) -> [Field] {
    let mut sponge = SafeSponge::start(io_pattern, domain_separator);
    sponge.absorb(inputs);
    let digests = sponge.squeeze();
    sponge.finish();

    digests
}

#[test]
fn test_flatten() {
    // Create test polynomials
    let poly1 = Polynomial::new([1, 2, 3]); // degree 2
    let poly2 = Polynomial::new([4, -16, 6]); // degree 2
    let poly3 = Polynomial::new([-7, 8, 9]); // degree 2

    let polynomials = [poly1, poly2, poly3];

    // Initialize target array with zeros
    let mut inputs = [].as_vector();

    // Flatten the polynomials
    let result = flatten::<_, _, 4>(inputs, polynomials);

    // Verify the flattened coefficients are in the correct positions
    // Every value shifted 1 nibble incase of negative integers
    assert(result[0] == 0x11121310101010101010101010101010101010101010101010101010101010);
    assert(result[1] == 0x14001610101010101010101010101010101010101010101010101010101010); // -16 became 00 at  0x 14 00 16,
    assert(result[2] == 0x09181910101010101010101010101010101010101010101010101010101010); // -7 became 09 at 0x 09 18 19(16 - 7 = 9)
}

#[test]
fn test_flatten_big() {
    // Create test polynomials
    let poly1 = Polynomial::new([
        1791218451968394,
        21888242871839275222246405745257275088548364400416034343698198265248580087864,
        21888242871839275222246405745257275088548364400416034343698200542108324633466,
        5430119342984413,
        704811298945172,
        8901715723925099,
        21888242871839275222246405745257275088548364400416034343698203098124042812559,
        21888242871839275222246405745257275088548364400416034343698200215091693880034,
    ]);
    let poly2 = Polynomial::new([
        21888242871839275222246405745257275088548364400416034343698200314078269634250,
        21888242871839275222246405745257275088548364400416034343698200967285641915872,
        2909990636858607,
        7896103832076587,
        2078397209533893,
        21888242871839275222246405745257275088548364400416034343698199792421452734531,
        614400389245817,
        8290314119277588,
    ]);
    let poly3 = Polynomial::new([
        21888242871839275222246405745257275088548364400416034343698201373175279892906,
        21888242871839275222246405745257275088548364400416034343698201087241869723721,
        6768789983786188,
        635797784303388,
        7610153424227556,
        4633893206538324,
        2016269760615332,
        21888242871839275222246405745257275088548364400416034343698201007080554428142,
    ]);

    let polynomials = [poly1, poly2, poly3];

    // Initialize target array with zeros
    let mut inputs = [].as_vector();

    // Flatten the polynomials
    let result = flatten::<_, _, 54>(inputs, polynomials);

    // Verify the flattened coefficients are in the correct positions
    // Every value shifted 1 nibble incase of negative integers

    // For the first index of result operation goes like this,

    // First four index of poly1
    // 1791218451968394,
    // 21888242871839275222246405745257275088548364400416034343698198265248580087864,
    // 21888242871839275222246405745257275088548364400416034343698200542108324633466,
    // 5430119342984413,

    // base + 1791218451968394 = 0x1065d1a8b8b718a
    // base - 5921327228407753 = 0xeaf69591f3b037 (negative coefficient shifted)
    // base - 3644467483862151 = 0xf30d604a3a9b79 (negative coefficient shifted)
    // base + 5430119342984413 = 0x1134aaa2e86ccdd
    assert(result[0] == 0x1065d1a8b8b718a0eaf69591f3b0370f30d604a3a9b791134aaa2e86ccdd);
    assert(result[1] == 0x1028105ab1b789411fa010339db66b0fc220f1326bc8e0f1e3f4cc1e02e1);
    assert(result[2] == 0x0f23dfbe7cd76c90f4901299312ddf10a569efe35acef11c0d76f005412b);
    assert(result[3] == 0x107624a8f605dc50f0638a368960421022ecb3cf36b7911d73ff2c27ec14);
    assert(result[4] == 0x0f6013a24e1b9a90f4fd2c158a08481180c2dba8af4cc10242413515171c);
    assert(result[5] == 0x11b0964eb898ce411076805680b85410729c962da53a40f4b44412d0f6ed);
}

#[test]
fn test_flatten_small() {
    // Create test polynomials
    let poly1 = Polynomial::new([712345, 104857, 999999, 500001, 123, 654321, 77]);
    let poly2 = Polynomial::new([1, 524287, 888888, 23456, 34567, 765432, 0]);
    let poly3 = Polynomial::new([444444, 333333, 222222, 111111, 987654, 246810, 13579]);

    let polynomials = [poly1, poly2, poly3];

    // Initialize target array with zeros
    let mut inputs = [].as_vector();

    // Flatten the polynomials
    let result = flatten::<_, _, 20>(inputs, polynomials);

    assert(result[0] == 0x1ade991199991f423f17a12110007b19fbf110004d100000100000100000);
    assert(result[1] == 0x10000117ffff1d9038105ba01087071badf8100000100000100000100000);
    assert(result[2] == 0x16c81c15161513640e11b2071f120613c41a10350b100000100000100000);
}

#[test]
fn test_safe_hashing_with_safe_helper() {
    // Verifies basic hash functionality with a simple ABSORB(3) + SQUEEZE(1) pattern.
    let domain_separator = [
        0x41, 0x42, 0x43, 0x44, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0,
    ];
    let elements = [1, 2, 3].as_vector();

    // Pattern: ABSORB(3), SQUEEZE(1)
    let io_pattern = [0x80000003, 0x00000001];
    let digests1 = compute_safe(domain_separator, elements, io_pattern);

    assert(digests1.len() == 1);
    assert(digests1[0] != 0);

    // Test determinism
    let digests2 = compute_safe(domain_separator, elements, io_pattern);

    assert(digests2.len() == 1);
    assert(digests2[0] != 0);
    assert(digests2[0] == digests1[0]);
}

#[test]
fn test_pack() {
    // Test pack function directly with small values
    let values = [1, 2, 3, 4];
    let packed = pack::<4, 4>(values);

    // With BIT=4, nibble_bits=4, group should be floor(254/(4+4)) = 31
    // So all 4 values should fit in one carrier
    assert(packed.len() >= 1);

    // Test with negative values
    let values_neg = [-1, 2, -3, 4];
    let packed_neg = pack::<4, 4>(values_neg);
    assert(packed_neg.len() >= 1);
}

#[test]
fn test_pack_single_value() {
    // Test packing a single value
    let values = [42];
    let packed = pack::<1, 8>(values);
    assert(packed.len() == 1);
    assert(packed[0] != 0);
}

#[test]
fn test_pack_determinism() {
    // Test that packing is deterministic
    let values = [10, 20, 30];
    let packed1 = pack::<3, 8>(values);
    let packed2 = pack::<3, 8>(values);

    assert(packed1.len() == packed2.len());
    for i in 0..packed1.len() {
        assert(packed1[i] == packed2[i]);
    }
}
