// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Writes the constants and the `Prover.toml` files of the bid proof circuits in
//! `circuits/bid`.
//!
//! The statement: the SIMD plaintexts of the bid ciphertexts of `vickrey` or `vickrey-compact`
//! come from one bid `b < B`. The generator takes the plaintexts from `bid_slots`, the function
//! that `submit` encrypts with. It then encrypts and decrypts them under a throwaway key to read
//! the polynomial `m` that fhe.rs puts in the ciphertext, and writes
//! `k1 = reverse([Q · m]_t)` as `user_data_encryption` does.
//!
//! The generator checks its own output before it writes a file:
//! - the NTT of `m` equals the slot vector, through the map from NTT output to slot;
//! - that slot vector equals the layout `A · [b >= l] + B · [b > l]` for every slot;
//! - the public table reproduces `k1`;
//! - for the sparse strategy, every slot of the ring falls in a class that has the same value for
//!   every ciphertext of the design.

use auction_designs::designs::slot_level;
use auction_designs::encoding::{coefficients, inverse, simd, slot_points};
use auction_designs::{Design, Profile, Setup, Vickrey, VickreyCompact};
use clap::{Parser, ValueEnum};
use fhe::bfv::{BfvParameters, BfvParametersBuilder, Ciphertext, SecretKey};
use fhe_math::zq::primes::generate_prime;
use fhe_traits::{FheDecrypter, FheEncrypter};
use std::collections::HashMap;
use std::fmt::Display;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// The field prime of BN254 has 254 bits; every integer below 2^253 is below it.
const SAFE_BITS: u32 = 253;

#[derive(Clone, Copy, ValueEnum)]
enum ProfileArg {
    /// N = 16, t = 97. Not a real profile: it gives the small fixtures of the Noir tests.
    Tiny,
    Toy,
    /// N = 4096, t = 40961. Not a real profile: it is a size between `toy` and `demo`, for gate
    /// counts only, and it has no security.
    Mid,
    Demo,
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Variant {
    Vickrey,
    Compact,
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Strategy {
    /// A forward NTT of `k1` in the circuit.
    Ntt,
    /// `k1` as a combination of `B` public polynomials, for every one of the `N` coefficients.
    Table,
    /// `k1` has non-zero coefficients only at a few public positions. The circuit takes only those.
    Sparse,
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Case {
    Honest,
    /// `k1` encodes the bid `b + 1`, and the proof claims `b`.
    BidPlusOne,
    /// The first ciphertext is not a thermometer.
    NonThermometer,
    /// `vickrey` only: the second ciphertext encodes `b + 1`.
    MismatchedPair,
    /// The claimed bid is `B`; `k1` encodes `B - 1`.
    BidOutOfRange,
}

impl Case {
    const ALL: [Case; 5] = [
        Case::Honest,
        Case::BidPlusOne,
        Case::NonThermometer,
        Case::MismatchedPair,
        Case::BidOutOfRange,
    ];

    fn file(self) -> &'static str {
        match self {
            Case::Honest => "Prover.toml",
            Case::BidPlusOne => "Prover_bid-plus-one.toml",
            Case::NonThermometer => "Prover_non-thermometer.toml",
            Case::MismatchedPair => "Prover_mismatched-pair.toml",
            Case::BidOutOfRange => "Prover_bid-out-of-range.toml",
        }
    }
}

#[derive(Parser)]
#[command(about = "Write the constants and Prover.toml files of the bid proof circuits")]
struct Cli {
    #[arg(long, value_enum, default_value_t = ProfileArg::Toy)]
    params: ProfileArg,
    #[arg(long, default_value_t = 16)]
    bidders: usize,
    #[arg(long, default_value_t = 16)]
    levels: usize,
    #[arg(long, value_enum, default_value_t = Variant::Vickrey)]
    variant: Variant,
    #[arg(long, value_enum, default_value_t = Strategy::Ntt)]
    strategy: Strategy,
    /// The bid that the honest `Prover.toml` holds.
    #[arg(long, default_value_t = 5)]
    bid: u64,
    /// A circuit package: writes `src/constants.nr` and `Prover.toml` there.
    #[arg(long)]
    out_dir: Option<PathBuf>,
    /// Also write one `Prover_<case>.toml` for each tampered case.
    #[arg(long)]
    cases: bool,
    /// Write the fixture of the Noir tests of `bid_lib` (both strategies, all bids) to this file.
    #[arg(long)]
    fixture: Option<PathBuf>,
}

fn mul(a: u64, b: u64, t: u64) -> u64 {
    (u128::from(a) * u128::from(b) % u128::from(t)) as u64
}

fn pow(base: u64, mut exponent: u64, t: u64) -> u64 {
    let (mut result, mut base) = (1u64, base % t);
    while exponent > 0 {
        if exponent & 1 == 1 {
            result = mul(result, base, t);
        }
        base = mul(base, base, t);
        exponent >>= 1;
    }
    result
}

fn bit_reverse(index: usize, bits: u32) -> usize {
    index.reverse_bits() >> (usize::BITS - bits)
}

/// Bit length of `t^exponent`.
fn power_bits(t: u64, exponent: u32) -> u32 {
    // Little-endian limbs of 32 bits in u64 words: `limb · t + carry` fits 64 bits for t < 2^32.
    assert!(t < 1 << 32);
    let mut limbs = vec![1u64];
    for _ in 0..exponent {
        let mut carry = 0u64;
        for limb in limbs.iter_mut() {
            let value = *limb * t + carry;
            *limb = value & 0xFFFF_FFFF;
            carry = value >> 32;
        }
        while carry > 0 {
            limbs.push(carry & 0xFFFF_FFFF);
            carry >>= 32;
        }
    }
    32 * (limbs.len() as u32 - 1) + (64 - limbs[limbs.len() - 1].leading_zeros())
}

fn bit_length(value: u64) -> u32 {
    64 - value.leading_zeros()
}

/// The forward negacyclic NTT of Longa and Naehrig (Cooley-Tukey, twiddles in bit-reversed order).
/// Output `j` is `P(psi^(2 · brv(j) + 1))`.
fn ntt(values: &mut [u64], twiddles: &[u64], t: u64) {
    let n = values.len();
    let (mut m, mut half) = (1, n / 2);
    while m < n {
        for i in 0..m {
            let w = twiddles[m + i];
            let start = 2 * i * half;
            for j in start..start + half {
                let (u, v) = (values[j], mul(values[j + half], w, t));
                values[j] = (u + v) % t;
                values[j + half] = (u + t - v) % t;
            }
        }
        m *= 2;
        half /= 2;
    }
}

/// The inverse of [`ntt`]: Gentleman-Sande with the inverse twiddles, then the scale by `1/N`.
fn intt(values: &mut [u64], inverse_twiddles: &[u64], t: u64) {
    let n = values.len();
    let (mut step, mut m) = (1, n);
    while m > 1 {
        let half = m / 2;
        let mut start = 0;
        for i in 0..half {
            let w = inverse_twiddles[half + i];
            for j in start..start + step {
                let (u, v) = (values[j], values[j + step]);
                values[j] = (u + v) % t;
                values[j + step] = mul((u + t - v) % t, w, t);
            }
            start += 2 * step;
        }
        step *= 2;
        m = half;
    }
    let n_inverse = inverse(n as u64, t);
    for value in values.iter_mut() {
        *value = mul(*value, n_inverse, t);
    }
}

/// Parameters that are not a profile of the auction crate: 56-bit moduli, `depth + 2` of them as
/// for `Profile::Demo` at depth 3 and 4 (5 and 6). They have no security. `t` is a prime with
/// `t = 1 (mod 2N)`.
fn custom_params(degree: usize, plaintext: u64, depth: u32) -> Arc<BfvParameters> {
    let (count, bits) = (2 + depth as usize, 56usize);
    let mut upper = 1u64 << bits;
    let moduli: Vec<u64> = (0..count)
        .map(|_| {
            upper = generate_prime(bits, 2 * degree as u64, upper).expect("enough primes");
            upper
        })
        .collect();
    BfvParametersBuilder::new()
        .set_degree(degree)
        .set_plaintext_modulus(plaintext)
        .set_moduli(&moduli)
        .build_arc()
        .expect("valid custom parameters")
}

fn build_params(profile: ProfileArg, depth: u32) -> Arc<BfvParameters> {
    match profile {
        ProfileArg::Tiny => custom_params(16, 97, depth),
        ProfileArg::Mid => custom_params(4096, 40961, depth),
        ProfileArg::Toy => Profile::Toy.build(depth),
        ProfileArg::Demo => Profile::Demo.build(depth),
    }
}

impl Variant {
    fn depth(self) -> u32 {
        match self {
            Variant::Vickrey => Vickrey.depth(0),
            Variant::Compact => VickreyCompact.depth(0),
        }
    }

    fn check(self, setup: &Setup) {
        let result = match self {
            Variant::Vickrey => Vickrey.check(setup),
            Variant::Compact => VickreyCompact.check(setup),
        };
        result.unwrap_or_else(|error| panic!("invalid auction setup: {error}"));
    }

    /// The slot vectors that `submit` encrypts for `bid`, before the mask.
    fn bid_slots(self, setup: &Setup, bid: u64) -> Vec<Vec<u64>> {
        match self {
            Variant::Vickrey => Vickrey.bid_slots(setup, bid),
            Variant::Compact => VickreyCompact.bid_slots(setup, bid),
        }
    }

    /// `(A, B)` for each ciphertext: the slot value at level `l` is `A · [b >= l] + B · [b > l]`.
    fn weights(self) -> Vec<(i64, i64)> {
        match self {
            Variant::Vickrey => vec![(1, 0), (0, 1)],
            Variant::Compact => vec![(2, -1)],
        }
    }

    fn name(self) -> &'static str {
        match self {
            Variant::Vickrey => "vickrey",
            Variant::Compact => "vickrey-compact",
        }
    }
}

/// Everything that the circuits need for one auction shape.
struct Shape {
    setup: Setup,
    variant: Variant,
    degree: usize,
    log_degree: u32,
    t: u64,
    q_mod_t: u64,
    twiddles: Vec<u64>,
    inverse_twiddles: Vec<u64>,
    /// The slot of NTT output `j`.
    slot_of_output: Vec<usize>,
    /// The level of NTT output `j`; `levels` for a slot beyond the last copy.
    level_of: Vec<usize>,
    weights: Vec<(i64, i64)>,
}

fn signed_mod(value: i64, t: u64) -> u64 {
    value.rem_euclid(t as i64) as u64
}

impl Shape {
    fn new(cli: &Cli) -> Shape {
        let params = build_params(cli.params, cli.variant.depth());
        // The bid plaintexts do not depend on the tie priority.
        let setup = Setup::new(params, cli.bidders, cli.levels);
        cli.variant.check(&setup);
        let degree = setup.params.degree();
        let log_degree = degree.trailing_zeros();
        let t = setup.params.plaintext();
        let q_mod_t = setup
            .params
            .moduli()
            .iter()
            .fold(1u64, |acc, &modulus| mul(acc, modulus % t, t));
        assert_ne!(q_mod_t, 0, "Q must be invertible mod t");

        // Any slot point is a primitive 2N-th root. The NTT outputs are the powers
        // psi^(2 · brv(j) + 1), which are the slot points in another order.
        let points = slot_points(&setup.params);
        let psi = points[0];
        assert_eq!(pow(psi, degree as u64, t), t - 1, "psi is a primitive root");
        let psi_inverse = pow(psi, 2 * degree as u64 - 1, t);
        let twiddles: Vec<u64> = (0..degree)
            .map(|k| pow(psi, bit_reverse(k, log_degree) as u64, t))
            .collect();
        let inverse_twiddles: Vec<u64> = (0..degree)
            .map(|k| pow(psi_inverse, bit_reverse(k, log_degree) as u64, t))
            .collect();
        let slot_of_point: HashMap<u64, usize> = points
            .iter()
            .enumerate()
            .map(|(slot, &point)| (point, slot))
            .collect();
        let slot_of_output: Vec<usize> = (0..degree)
            .map(|j| {
                let point = pow(psi, 2 * bit_reverse(j, log_degree) as u64 + 1, t);
                *slot_of_point
                    .get(&point)
                    .expect("every NTT point is a slot point")
            })
            .collect();
        let level_of = slot_of_output
            .iter()
            .map(|&slot| slot_level(&setup, slot).unwrap_or(setup.levels))
            .collect();
        Shape {
            setup,
            variant: cli.variant,
            degree,
            log_degree,
            t,
            q_mod_t,
            twiddles,
            inverse_twiddles,
            slot_of_output,
            level_of,
            weights: cli.variant.weights(),
        }
    }

    /// The polynomial `m` that fhe.rs puts in a ciphertext of the SIMD plaintext `slots`: encrypt
    /// and decrypt under a throwaway key, and read the coefficients of the unencoded result.
    fn plaintext_polynomial(&self, slots: &[u64]) -> Vec<u64> {
        let mut rng = rand::rng();
        let key = SecretKey::random(&self.setup.params, &mut rng);
        let ciphertext: Ciphertext = key
            .try_encrypt(&simd(&self.setup.params, slots), &mut rng)
            .expect("encryption under a fresh key");
        coefficients(&key.try_decrypt(&ciphertext).expect("decryption"))
    }

    /// `k1 = reverse([Q · m]_t)`, as `user_data_encryption` computes it.
    fn k1(&self, m: &[u64]) -> Vec<u64> {
        m.iter()
            .rev()
            .map(|&coefficient| mul(coefficient, self.q_mod_t, self.t))
            .collect()
    }

    /// The slot value that the layout gives at `level` for a bid, ciphertext `ct`.
    fn expected(&self, ct: usize, bid: u64, level: usize) -> u64 {
        if level >= self.setup.levels {
            return 0;
        }
        let (a, b) = self.weights[ct];
        let at_least = i64::from(bid >= level as u64);
        let above = i64::from(bid > level as u64);
        signed_mod(a * at_least + b * above, self.t)
    }

    /// `k1` of each ciphertext for the slot vectors `slots`, after the checks on the NTT.
    fn k1_of_slots(&self, slots: &[Vec<u64>]) -> Vec<Vec<u64>> {
        slots
            .iter()
            .map(|slots| {
                let m = self.plaintext_polynomial(slots);
                let mut transformed = m.clone();
                ntt(&mut transformed, &self.twiddles, self.t);
                for (output, &value) in transformed.iter().enumerate() {
                    assert_eq!(
                        value, slots[self.slot_of_output[output]],
                        "NTT output {output} is not its slot"
                    );
                }
                self.k1(&m)
            })
            .collect()
    }

    /// The honest slots of `bid`, after the check against the layout of the design.
    fn honest_slots(&self, bid: u64) -> Vec<Vec<u64>> {
        let slots = self.variant.bid_slots(&self.setup, bid);
        for (ct, ct_slots) in slots.iter().enumerate() {
            for (slot, &value) in ct_slots.iter().enumerate() {
                let level = slot_level(&self.setup, slot).unwrap_or(self.setup.levels);
                assert_eq!(
                    value,
                    self.expected(ct, bid, level),
                    "slot {slot} of ciphertext {ct} breaks the layout"
                );
            }
        }
        slots
    }

    /// The claimed bid and the `k1` polynomials of a case.
    fn case(&self, case: Case, bid: u64) -> (u64, Vec<Vec<u64>>) {
        let levels = self.setup.levels as u64;
        assert!(bid < levels, "the honest bid is in 0..{levels}");
        let honest = |bid| self.k1_of_slots(&self.honest_slots(bid));
        match case {
            Case::Honest => (bid, honest(bid)),
            Case::BidPlusOne => {
                assert!(bid + 1 < levels, "bid + 1 must be below the levels");
                (bid, honest(bid + 1))
            }
            Case::BidOutOfRange => (levels, honest(levels - 1)),
            Case::MismatchedPair => {
                assert!(bid + 1 < levels, "bid + 1 must be below the levels");
                assert!(self.weights.len() == 2, "only vickrey has 2 ciphertexts");
                let (mut first, second) = (honest(bid), honest(bid + 1));
                first[1] = second[1].clone();
                (bid, first)
            }
            Case::NonThermometer => {
                let mut slots = self.honest_slots(bid);
                // A one above the bid, or a zero at level 0 for a bid above 0: a hole in the
                // thermometer.
                let (hole, value) = if bid + 2 < levels {
                    (bid as usize + 2, 1)
                } else {
                    assert!(bid >= 1, "no hole fits 1 or 2 levels");
                    (0, 0)
                };
                for (slot, entry) in slots[0].iter_mut().enumerate() {
                    if slot_level(&self.setup, slot) == Some(hole) {
                        *entry = value;
                    }
                }
                (bid, self.k1_of_slots(&slots))
            }
        }
    }

    /// `D[l] = reverse(Q · INTT(indicator of the slots of level l))` in the order of `k1`.
    fn table(&self) -> Vec<Vec<u64>> {
        (0..self.setup.levels)
            .map(|level| {
                let mut values: Vec<u64> = self
                    .level_of
                    .iter()
                    .map(|&l| u64::from(l == level))
                    .collect();
                intt(&mut values, &self.inverse_twiddles, self.t);
                self.k1(&values)
            })
            .collect()
    }

    /// `k1` from the table, for the claimed `bid`.
    fn table_k1(&self, table: &[Vec<u64>], ct: usize, bid: u64) -> Vec<u64> {
        (0..self.degree)
            .map(|i| {
                (0..self.setup.levels).fold(0u64, |acc, level| {
                    let weight = self.expected(ct, bid, level);
                    (acc + mul(weight, table[level][i], self.t)) % self.t
                })
            })
            .collect()
    }

    /// `(target_at, target_next)` of each ciphertext: `[Q · expected(l)]_t` is
    /// `target_at · ge[l] + target_next · ge[l + 1]` for `(ge[l], ge[l + 1])` in
    /// `{(0, 0), (1, 0), (1, 1)}`.
    fn targets(&self) -> Vec<(u64, i64)> {
        self.weights
            .iter()
            .map(|&(a, b)| {
                let at = mul(signed_mod(a, self.t), self.q_mod_t, self.t);
                let both = mul(signed_mod(a + b, self.t), self.q_mod_t, self.t);
                (at, both as i64 - at as i64)
            })
            .collect()
    }

    /// The `k1` positions where some level polynomial `D[l]` is non-zero, in ascending order. Every
    /// `k1` of the design is a combination of the `D[l]`, so it is zero elsewhere. (A plaintext
    /// polynomial is determined by its slots, so no other `k1` can have the layout either.)
    fn support(&self, table: &[Vec<u64>]) -> Vec<usize> {
        (0..self.degree)
            .filter(|&i| table.iter().any(|row| row[i] != 0))
            .collect()
    }

    /// The classes of slots that have the same weights on the support, with their level.
    ///
    /// `Q · m(alpha) = sum_j k1[position_j] · alpha^(N - 1 - position_j)`, so a slot gives the row
    /// `weights[j] = alpha^(N - 1 - position_j)`. Slots with the same row have the same value, so
    /// one check covers all of them. The generator asserts that no row belongs to 2 levels.
    /// Returns `(level, weights)` for each class, sorted by level.
    fn classes(&self, support: &[usize]) -> Vec<(usize, Vec<u64>)> {
        // A slot beyond the last copy holds 0, where the pattern of levels would give a bid value.
        // That breaks the period of the slots, and `k1` is dense.
        assert!(
            self.degree
                .is_multiple_of(self.setup.bidders * self.setup.levels),
            "the sparse strategy needs N = {} to be a multiple of bidders · levels = {}",
            self.degree,
            self.setup.bidders * self.setup.levels
        );
        let points = slot_points(&self.setup.params);
        let mut classes: HashMap<Vec<u64>, usize> = HashMap::new();
        for (slot, &point) in points.iter().enumerate() {
            let level = slot_level(&self.setup, slot).unwrap_or(self.setup.levels);
            let row: Vec<u64> = support
                .iter()
                .map(|&position| pow(point, (self.degree - 1 - position) as u64, self.t))
                .collect();
            let previous = classes.insert(row, level);
            assert!(
                previous.is_none_or(|previous| previous == level),
                "slots of levels {previous:?} and {level} have the same weights"
            );
        }
        let mut classes: Vec<(usize, Vec<u64>)> = classes
            .into_iter()
            .map(|(row, level)| (level, row))
            .collect();
        classes.sort();
        classes
    }

    fn sparse_quotient_bits(&self, support: usize) -> u32 {
        // x < S · (t - 1)^2 and the quotient of x - target is below S · t.
        bit_length(support as u64 * self.t)
    }

    fn ntt_quotient_bits(&self) -> u32 {
        // Values after L layers are below t^(L + 1), and the quotient is below t^L.
        assert!(
            power_bits(self.t, self.log_degree + 1) <= SAFE_BITS,
            "t^(L + 1) must stay below the field prime"
        );
        let bits = power_bits(self.t, self.log_degree);
        assert!(bits + bit_length(self.t) < SAFE_BITS, "t · 2^QBITS + t < p");
        bits
    }

    fn table_quotient_bits(&self) -> u32 {
        bit_length(2 * self.setup.levels as u64)
    }
}

/// An array literal, laid out as `nargo fmt` lays it out, so that generated files stay
/// `nargo fmt`-clean.
enum Node {
    Leaf(String),
    Array(Vec<Node>),
}

fn leaves<T: Display>(items: impl IntoIterator<Item = T>) -> Node {
    Node::Array(
        items
            .into_iter()
            .map(|item| Node::Leaf(item.to_string()))
            .collect(),
    )
}

fn rows<T: Display, R: IntoIterator<Item = T>>(rows: impl IntoIterator<Item = R>) -> Node {
    Node::Array(rows.into_iter().map(leaves).collect())
}

const WIDTH: usize = 100;

/// `head` columns are on the first line before the array, and `tail` after its last bracket.
fn render(node: &Node, indent: usize, head: usize, tail: usize) -> String {
    let Node::Array(items) = node else {
        let Node::Leaf(text) = node else {
            unreachable!()
        };
        return text.clone();
    };
    let pad = " ".repeat(indent);
    let inner = " ".repeat(indent + 4);
    if items.iter().all(|item| matches!(item, Node::Leaf(_))) {
        let texts: Vec<&str> = items
            .iter()
            .map(|item| match item {
                Node::Leaf(text) => text.as_str(),
                Node::Array(_) => unreachable!(),
            })
            .collect();
        let single = format!("[{}]", texts.join(", "));
        if head + single.len() + tail <= WIDTH {
            return single;
        }
        let mut out = String::from("[\n");
        let mut line = String::new();
        for text in texts {
            // Each item is followed by a comma; a line holds as many as fit the width.
            if !line.is_empty() && inner.len() + line.len() + 1 + text.len() + 1 > WIDTH {
                let _ = writeln!(out, "{inner}{line}");
                line.clear();
            }
            if !line.is_empty() {
                line.push(' ');
            }
            line.push_str(text);
            line.push(',');
        }
        let _ = writeln!(out, "{inner}{line}");
        let _ = write!(out, "{pad}]");
        return out;
    }
    let mut out = String::from("[\n");
    for item in items {
        let _ = writeln!(out, "{inner}{},", render(item, indent + 4, indent + 4, 1));
    }
    let _ = write!(out, "{pad}]");
    out
}

/// Lines of Noir at an indent, as `nargo fmt` formats them.
struct Emitter {
    indent: usize,
    out: String,
}

impl Emitter {
    fn doc(&mut self, text: &str) {
        let _ = writeln!(self.out, "{}/// {text}", " ".repeat(self.indent));
    }

    fn scalar(&mut self, name: &str, ty: &str, value: impl Display) {
        let _ = writeln!(
            self.out,
            "{}pub global {name}: {ty} = {value};",
            " ".repeat(self.indent)
        );
    }

    fn array(&mut self, name: &str, ty: &str, node: &Node) {
        let pad = " ".repeat(self.indent);
        let head = self.indent + format!("pub global {name}: {ty} = ").len();
        let rendered = render(node, self.indent, head, 1);
        // An array that fits on one line only after a break behind the `=` goes to the next line.
        let wrapped = render(node, self.indent + 4, self.indent + 4, 1);
        if rendered.contains('\n') && !wrapped.contains('\n') {
            let _ = writeln!(
                self.out,
                "{pad}pub global {name}: {ty} =\n{pad}    {wrapped};"
            );
        } else {
            let _ = writeln!(self.out, "{pad}pub global {name}: {ty} = {rendered};");
        }
    }
}

/// The constants of one strategy, indented by `indent` spaces.
fn constants(shape: &Shape, strategy: Strategy, indent: usize) -> String {
    let table = shape.table();
    let mut e = Emitter {
        indent,
        out: String::new(),
    };
    e.scalar("N", "u32", shape.degree);
    e.scalar("LOG_N", "u32", shape.log_degree);
    e.scalar("B", "u32", shape.setup.levels);
    e.scalar("CTS", "u32", shape.weights.len());
    e.scalar("PLAINTEXT_MODULUS", "Field", shape.t);
    e.scalar("Q_MOD_T", "Field", shape.q_mod_t);
    e.doc("Bit width of `t - 1`: the width that `user_data_encryption` uses for `k1`.");
    e.scalar("BIT_K", "u32", bit_length(shape.t - 1));
    match strategy {
        Strategy::Ntt => {
            e.scalar("QUOTIENT_BITS", "u32", shape.ntt_quotient_bits());
            let targets = shape.targets();
            e.array(
                "TARGET_AT",
                "[Field; CTS]",
                &leaves(targets.iter().map(|t| t.0)),
            );
            e.array(
                "TARGET_NEXT",
                "[Field; CTS]",
                &leaves(targets.iter().map(|t| t.1)),
            );
            e.doc("`psi^brv(k)` for a primitive 2N-th root `psi` mod `t`.");
            e.array("TWIDDLES", "[Field; N]", &leaves(shape.twiddles.iter()));
            e.doc("The level of the slot at each NTT output; `B` for a slot beyond the last copy.");
            e.array("LEVEL_OF", "[u32; N]", &leaves(shape.level_of.iter()));
        }
        Strategy::Table => {
            e.scalar("QUOTIENT_BITS", "u32", shape.table_quotient_bits());
            e.array(
                "COEF_AT",
                "[Field; CTS]",
                &leaves(shape.weights.iter().map(|w| w.0)),
            );
            e.array(
                "COEF_NEXT",
                "[Field; CTS]",
                &leaves(shape.weights.iter().map(|w| w.1)),
            );
            e.doc("`D[l] = reverse(Q · INTT(indicator of level l))`, in the order of `k1`.");
            e.array(
                "TABLE",
                "[[Field; N]; B]",
                &rows(table.iter().map(|row| row.iter())),
            );
        }
        Strategy::Sparse => {
            let support = shape.support(&table);
            let classes = shape.classes(&support);
            e.scalar("S", "u32", support.len());
            e.scalar("CLASSES", "u32", classes.len());
            e.scalar(
                "QUOTIENT_BITS",
                "u32",
                shape.sparse_quotient_bits(support.len()),
            );
            let targets = shape.targets();
            e.array(
                "TARGET_AT",
                "[Field; CTS]",
                &leaves(targets.iter().map(|t| t.0)),
            );
            e.array(
                "TARGET_NEXT",
                "[Field; CTS]",
                &leaves(targets.iter().map(|t| t.1)),
            );
            e.doc(
                "The positions in `k1` of the non-zero coefficients: all other coefficients are 0.",
            );
            e.array("POSITIONS", "[u32; S]", &leaves(support.iter()));
            e.doc("The level of each class of slots; `B` for slots beyond the last copy.");
            e.array(
                "CLASS_LEVEL",
                "[u32; CLASSES]",
                &leaves(classes.iter().map(|c| c.0)),
            );
            e.doc("`WEIGHTS[k][j] = alpha_k^(N - 1 - POSITIONS[j])` for the slot point `alpha_k` of class `k`.");
            e.array(
                "WEIGHTS",
                "[[Field; S]; CLASSES]",
                &rows(classes.iter().map(|c| c.1.iter())),
            );
        }
    }
    e.out
}

fn command_line(cli: &Cli) -> String {
    let value = |arg: &dyn ValueEnumName| arg.name();
    let mut command = format!(
        "cargo run --release --bin bid_circuit -- --params {} --bidders {} --levels {} --variant {} --strategy {} --bid {}",
        value(&cli.params),
        cli.bidders,
        cli.levels,
        value(&cli.variant),
        value(&cli.strategy),
        cli.bid
    );
    if let Some(dir) = &cli.out_dir {
        let _ = write!(command, " --out-dir {}", dir.display());
    }
    if let Some(path) = &cli.fixture {
        let _ = write!(command, " --fixture {}", path.display());
    }
    command
}

trait ValueEnumName {
    fn name(&self) -> String;
}

impl<T: ValueEnum> ValueEnumName for T {
    fn name(&self) -> String {
        self.to_possible_value()
            .expect("no skipped variants")
            .get_name()
            .to_string()
    }
}

fn header(cli: &Cli, what: &str) -> String {
    format!(
        "// SPDX-License-Identifier: LGPL-3.0-only\n//\n\
         // This file is provided WITHOUT ANY WARRANTY;\n\
         // without even the implied warranty of MERCHANTABILITY\n\
         // or FITNESS FOR A PARTICULAR PURPOSE.\n\n\
         // {what}\n\
         // GENERATED by examples/auction/src/bin/bid_circuit.rs. Do not edit it.\n\
         // Regenerate it from examples/auction with:\n\
         //   {}\n\n",
        command_line(cli)
    )
}

fn prover_toml(bid: u64, k1s: &[Vec<u64>]) -> String {
    let mut out = format!("b = \"{bid}\"\n");
    for k1 in k1s {
        out.push_str("\n[[k1s]]\ncoefficients = [");
        out.push_str(
            &k1.iter()
                .map(|c| format!("\"{c}\""))
                .collect::<Vec<_>>()
                .join(", "),
        );
        out.push_str("]\n");
    }
    out
}

/// `Prover.toml` of the sparse strategy: the coefficients of `k1` at the support positions.
fn prover_toml_sparse(bid: u64, k1s: &[Vec<u64>], support: &[usize]) -> String {
    let rows: Vec<String> = k1s
        .iter()
        .map(|k1| {
            for (i, &value) in k1.iter().enumerate() {
                assert!(
                    value == 0 || support.contains(&i),
                    "k1 is non-zero outside the support at {i}"
                );
            }
            let values: Vec<String> = support.iter().map(|&i| format!("\"{}\"", k1[i])).collect();
            format!("[{}]", values.join(", "))
        })
        .collect();
    format!("b = \"{bid}\"\nk1_support = [{}]\n", rows.join(", "))
}

fn write_file(path: &Path, content: &str) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("create the output directory");
    }
    fs::write(path, content).unwrap_or_else(|e| panic!("write {}: {e}", path.display()));
    println!("wrote {}", path.display());
}

fn k1_node(k1s: &[Vec<u64>]) -> Node {
    rows(k1s.iter().map(|k1| k1.iter()))
}

/// The fixture of the Noir tests: all strategies, `k1` of every bid, and the failing inputs.
fn fixture(cli: &Cli, shape: &Shape) -> String {
    let levels = shape.setup.levels;
    let cts = shape.weights.len();
    let degree = shape.degree;
    let mut out = header(cli, "Fixture of the tests of `bid_lib`.");
    for (name, strategy) in [
        ("ntt", Strategy::Ntt),
        ("table", Strategy::Table),
        ("sparse", Strategy::Sparse),
    ] {
        let _ = writeln!(out, "pub mod {name} {{");
        out.push_str(&constants(shape, strategy, 4));
        let _ = writeln!(out, "}}\n");
    }
    let mut e = Emitter {
        indent: 0,
        out: String::new(),
    };
    e.doc("`k1` of every ciphertext for the bids `0..B`: `K1_HONEST[bid][ct][i]`.");
    let all = Node::Array(
        (0..levels as u64)
            .map(|bid| k1_node(&shape.case(Case::Honest, bid).1))
            .collect(),
    );
    e.array(
        "K1_HONEST",
        &format!("[[[Field; {degree}]; {cts}]; {levels}]"),
        &all,
    );
    e.out.push('\n');
    for (name, case) in [
        ("K1_NON_THERMOMETER", Case::NonThermometer),
        ("K1_MISMATCHED_PAIR", Case::MismatchedPair),
    ] {
        if case == Case::MismatchedPair && cts != 2 {
            continue;
        }
        let (bid, k1s) = shape.case(case, cli.bid);
        e.doc(&format!("The claimed bid is {bid}."));
        e.array(name, &format!("[[Field; {degree}]; {cts}]"), &k1_node(&k1s));
        e.out.push('\n');
    }
    e.scalar("FIXTURE_BID", "Field", cli.bid);
    out.push_str(&e.out);
    out
}

fn main() {
    let cli = Cli::parse();
    let shape = Shape::new(&cli);
    let setup = &shape.setup;
    println!(
        "{}: N = {}, t = {}, Q mod t = {}, bidders = {}, levels = {}, ciphertexts = {}, {} copies",
        shape.variant.name(),
        shape.degree,
        shape.t,
        shape.q_mod_t,
        setup.bidders,
        setup.levels,
        shape.weights.len(),
        shape.degree / (setup.bidders * setup.levels),
    );

    // The public table must reproduce k1 of every real plaintext, whatever the strategy.
    let table = shape.table();
    let support = shape.support(&table);
    let columns = support.len();
    let entries: usize = table
        .iter()
        .map(|row| row.iter().filter(|&&v| v != 0).count())
        .sum();
    println!(
        "table: {entries} non-zero entries of {}, in {columns} of {} coefficients",
        table.len() * shape.degree,
        shape.degree
    );
    let classes = shape.classes(&support);
    println!(
        "sparse: {} classes of slots on {columns} positions",
        classes.len()
    );
    for bid in [0, cli.bid, setup.levels as u64 - 1] {
        let k1s = shape.k1_of_slots(&shape.honest_slots(bid));
        for (ct, k1) in k1s.iter().enumerate() {
            println!(
                "bid {bid}, ciphertext {ct}: {} non-zero coefficients in k1",
                k1.iter().filter(|&&v| v != 0).count()
            );
            // The sparse strategy: k1 is zero outside the support, and every class has its value.
            assert!(k1
                .iter()
                .enumerate()
                .all(|(i, &v)| v == 0 || support.contains(&i)));
            for (level, weights) in &classes {
                let value = support.iter().zip(weights).fold(0u64, |acc, (&i, &w)| {
                    (acc + mul(k1[i], w, shape.t)) % shape.t
                });
                let target = mul(shape.expected(ct, bid, *level), shape.q_mod_t, shape.t);
                assert_eq!(value, target, "class of level {level} breaks for bid {bid}");
            }
            assert_eq!(
                &shape.table_k1(&table, ct, bid),
                k1,
                "the table does not give k1 of bid {bid}, ciphertext {ct}"
            );
        }
    }

    if let Some(dir) = &cli.out_dir {
        let body = constants(&shape, cli.strategy, 0);
        write_file(
            &dir.join("src/constants.nr"),
            &format!(
                "{}{body}",
                header(&cli, "Constants of the bid proof circuit.")
            ),
        );
        let cases: &[Case] = if cli.cases {
            &Case::ALL
        } else {
            &[Case::Honest]
        };
        for &case in cases {
            if case == Case::MismatchedPair && shape.weights.len() != 2 {
                continue;
            }
            let (claimed, k1s) = shape.case(case, cli.bid);
            let content = match cli.strategy {
                Strategy::Sparse => prover_toml_sparse(claimed, &k1s, &support),
                _ => prover_toml(claimed, &k1s),
            };
            write_file(&dir.join(case.file()), &content);
        }
    }
    if let Some(path) = &cli.fixture {
        write_file(path, &fixture(&cli, &shape));
    }
}
