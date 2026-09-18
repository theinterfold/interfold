// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

mod common;

use acir::{native_types::WitnessStack, FieldElement};
use common::fixtures_dir;
use e3_zk_prover::{input_map, CompiledCircuit, WitnessGenerator};

#[test]
fn test_witness_generation_from_fixture() {
    let fixtures = fixtures_dir();
    let circuit = CompiledCircuit::from_file(&fixtures.join("dummy.json")).unwrap();

    let witness_gen = WitnessGenerator::new();
    let inputs = input_map([("x", "5"), ("y", "3"), ("_sum", "8")]).unwrap();
    let witness = witness_gen.generate_witness(&circuit, inputs).unwrap();

    let stack = WitnessStack::<FieldElement>::deserialize(&witness).unwrap();
    assert_eq!(stack.length(), 1);
    let frame = stack.peek().unwrap();
    assert_eq!(frame.index, 0);

    let assignments = frame
        .witness
        .clone()
        .into_iter()
        .map(|(_, value)| value)
        .collect::<Vec<_>>();
    for expected in [5u128, 3, 8].map(FieldElement::from) {
        assert!(
            assignments.contains(&expected),
            "generated witness omitted assignment {expected}"
        );
    }
}
