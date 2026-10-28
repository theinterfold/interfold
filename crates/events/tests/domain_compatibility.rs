// SPDX-License-Identifier: LGPL-3.0-only

use e3_events::{Event, InterfoldEvent, InterfoldEventData, SignedProofPayload};

#[test]
fn baseline_signed_event_retains_encoding_signature_and_statement_identity() {
    // Encoded and signed at 26023af50 before moving circuit identity out of events.
    let encoded: String = include_str!("fixtures/signed-proof-v1.hex")
        .split_whitespace()
        .collect();
    let bytes = hex::decode(encoded).unwrap();
    let event: InterfoldEvent = bincode::deserialize(&bytes).unwrap();
    assert_eq!(bincode::serialize(&event).unwrap(), bytes);
    let InterfoldEventData::SignedProofFailed(data) = event.get_data() else {
        panic!("wrong baseline event variant")
    };
    let signed = &data.signed_payload;
    assert_eq!(
        signed.payload.proof.circuit,
        e3_zk_config::CircuitName::ThresholdShareDecryption
    );
    assert_eq!(signed.payload.e3_id, e3_events::E3id::new("2320", 11155111));
    assert_eq!(
        hex::encode(signed.payload.digest().unwrap()),
        "a885ff366fdda35b84b75a9b661f4d10af4a701ecbb1e891b8ff6eade0afbb53"
    );
    assert_eq!(
        hex::encode(signed.payload.statement_digest().unwrap()),
        "0031eaa67dedc62d62ded989f4f911ccca94a23d06602a76ae4beadfa2c279e5"
    );
    assert_eq!(signed.recover_address().unwrap(), data.faulting_node);
    let signer: alloy::signers::local::PrivateKeySigner =
        "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
            .parse()
            .unwrap();
    assert_eq!(
        SignedProofPayload::sign(signed.payload.clone(), &signer).unwrap(),
        *signed
    );
    let json = serde_json::to_value(signed).unwrap();
    assert_eq!(
        json["payload"]["proof"]["circuit"],
        "ThresholdShareDecryption"
    );
    assert_eq!(
        serde_json::from_value::<SignedProofPayload>(json).unwrap(),
        *signed
    );
    // These are aliases of the lower owner, not wrappers with a second encoding.
    let _: e3_committee::Committee = e3_events::Committee::new(vec![]);
    let _: e3_zk_config::CircuitVariant = e3_events::CircuitVariant::Evm;
}
