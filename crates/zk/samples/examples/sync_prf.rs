// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Standalone differential/size probe, outside circuit discovery. All keys are synthetic.

use e3_committee::CiphernodesCommitteeSize::{Micro, Minimum, Small};
use e3_fhe_params::BfvPreset;
use fhe::{
    bfv::{BfvParametersBuilder, Ciphertext},
    trbfv::{PartyPrfKeyTransport, PartyPrfKeys},
};
use fhe_math::rq::{Ntt, Poly};
use ndarray::Array2;
use std::{error::Error, fs, path::PathBuf};

type Result<T> = std::result::Result<T, Box<dyn Error>>;

fn main() -> Result<()> {
    let [case, dest]: [String; 2] = std::env::args()
        .skip(1)
        .collect::<Vec<_>>()
        .try_into()
        .map_err(|_| "usage: sync_prf CASE NEW_DIRECTORY")?;
    let vector = matches!(case.as_str(), "vector" | "vector-micro");
    let (params, committee) =
        match case.as_str() {
            "vector" | "vector-micro" => (
                BfvParametersBuilder::new()
                    .set_degree(8)
                    .set_plaintext_modulus(17)
                    .set_moduli(&[65537, 114689])
                    .build_arc()?,
                if case == "vector" { Minimum } else { Micro },
            ),
            "insecure-minimum" => (BfvPreset::InsecureThreshold64.build_pair()?.0, Minimum),
            "secure-minimum" => (BfvPreset::SecureThreshold8192.build_pair()?.0, Minimum),
            "secure-micro" => (BfvPreset::SecureThreshold8192.build_pair()?.0, Micro),
            "secure-small" => (BfvPreset::SecureThreshold8192.build_pair()?.0, Small),
            _ => return Err(
                "expected vector, vector-micro, insecure-minimum, secure-minimum, secure-micro, or secure-small"
                    .into(),
            ),
        };
    let values = committee.values();
    let peers = values.threshold;
    let d = params.degree();
    let qis = params.moduli();
    let l = qis.len();
    let dir = PathBuf::from(dest);
    fs::create_dir(&dir)?;
    fs::create_dir(dir.join("src"))?;
    let lib = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../circuits/lib")
        .canonicalize()?;
    fs::write(
        dir.join("Nargo.toml"),
        format!(
            "[package]\nname = \"sync_prf_probe\"\ntype = \"bin\"\nauthors = []\n\
             [dependencies]\nlib = {{ path = {lib:?} }}\n"
        ),
    )?;
    fs::write(
        dir.join("src/main.nr"),
        format!(
            "use lib::core::synchronized::prf::mask;\n\
             fn main(ids: [u32; {}], ct: [[[u64; {d}]; {l}]; 2], outgoing: [[u8; 32]; {peers}], \
             incoming: [[u8; 32]; {peers}], expected: pub [[u64; {d}]; {l}]) {{\n\
             assert(mask(ids, ct, {qis:?}, outgoing, incoming) == expected);\n}}\n",
            peers + 1
        ),
    )?;

    // The first small case reproduces fhe.rs's prf_power_basis_reference_vector.
    // Vary ciphertext and keys independently; repeated-byte keys alone cannot test endian order.
    let variations = if case == "vector" { 4 } else { 1 };
    for variation in 0..variations {
        let ids: Vec<_> = (0..=peers)
            .map(|i| if variation == 3 { i + 1 } else { 2 * i + 1 })
            .collect();
        let ctx = params.context_at_level(0)?;
        let ct = Ciphertext::new(
            (0..2)
                .map(|c| {
                    let mut poly = Poly::<Ntt>::zero(ctx);
                    poly.set_coefficients(Array2::from_shape_fn((l, d), |(r, j)| {
                        (c * 100 + r * 10 + j + 1 + usize::from(variation > 0 && c == 1 && j == 0))
                            as u64
                    }));
                    poly
                })
                .collect(),
            &params,
        )?;
        let power: Vec<_> = ct
            .iter()
            .map(|p| rows(p.clone().into_power_basis().coefficients()))
            .collect();
        let key = |i: usize, j: usize| -> [u8; 32] {
            let seed = (10 * i + j) as u8;
            std::array::from_fn(|b| {
                if case == "vector" && variation < 2 {
                    seed
                } else if case == "insecure-minimum" && b >= 8 {
                    0 // only the insecure DKG transport is width-limited
                } else {
                    seed.wrapping_add((b as u8).wrapping_mul(29))
                }
            })
        };
        let owners = if vector { &ids[..] } else { &ids[..1] };
        for &owner in owners {
            let keys = PartyPrfKeys::from_transport(PartyPrfKeyTransport::new(
                owner,
                values.n,
                (1..=values.n).map(|j| key(owner, j)).collect(),
                (1..=values.n).map(|j| key(j, owner)).collect(),
            )?)?;
            let expected = rows(keys.mask(&ids, &ct)?.coefficients());
            let others = || ids.iter().copied().filter(|&peer| peer != owner);
            let outgoing: Vec<_> = others().map(|j| key(owner, j)).collect();
            let incoming: Vec<_> = others().map(|j| key(j, owner)).collect();
            let name = if vector {
                format!("v{variation}-owner{owner}")
            } else {
                "Prover".into()
            };
            fs::write(
                dir.join(format!("{name}.toml")),
                format!(
                    "ids = {ids:?}\nct = {power:?}\noutgoing = {outgoing:?}\n\
                     incoming = {incoming:?}\nexpected = {expected:?}\n"
                ),
            )?;
        }
    }
    Ok(())
}

fn rows(matrix: ndarray::ArrayView2<'_, u64>) -> Vec<Vec<u64>> {
    matrix.outer_iter().map(|r| r.to_vec()).collect()
}
