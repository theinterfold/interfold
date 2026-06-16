// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Slashing integration tests: off-chain proof signing + on-chain attestation-based slashing.
//!
//! ## What these tests prove
//!
//! ### Pure Rust (no Anvil)
//! 1. **ProofPayload signing**: `ProofPayload.digest()` produces the correct
//!    structured hash for off-chain proof signing (PROOF_PAYLOAD_TYPEHASH).
//! 2. **ECDSA roundtrip**: `sign_message_sync` → `recover_address` for ProofPayload.
//! 3. **Evidence encoding**: `encode_fault_evidence()` produces valid ABI-encoded
//!    data (retained for Lane B tests).
//! 4. **Vote typehash**: VOTE_TYPEHASH matches the Solidity constant.
//! 5. **Attestation evidence**: vote signatures are correctly constructed and
//!    ABI-encoded for `proposeSlash()`.
//!
//! ### On-chain integration (Anvil + Hardhat artifacts)
//! 6. **Valid attestation quorum** → slash executes successfully.
//! 7. **Insufficient attestations** → reverts `InsufficientAttestations`.
//! 8. **Voter not in committee** → reverts `VoterNotInCommittee`.
//! 9. **Invalid vote signature** → reverts `InvalidVoteSignature`.
//! 10. **Duplicate voter** → reverts `DuplicateVoter`.
//! 11. **Duplicate evidence replay** → reverts `DuplicateEvidence`.
//!
//! ## Prerequisites
//!
//! On-chain tests require:
//! - `anvil` on PATH (from Foundry)
//! - Compiled Hardhat artifacts: `cd packages/interfold-contracts && npx hardhat compile`
//!
//! Run with: `cargo test -p e3-zk-prover --test slashing_integration_tests`

mod common;

use alloy::{
    network::TransactionBuilder,
    primitives::{keccak256, Address, Bytes, FixedBytes, U256},
    providers::{Provider, ProviderBuilder},
    rpc::types::TransactionRequest,
    signers::{local::PrivateKeySigner, SignerSync},
    sol,
    sol_types::SolValue,
};
use common::find_anvil;
use e3_events::{
    encode_fault_evidence, CircuitName, E3id, Proof, ProofPayload, ProofType, SignedProofFailed,
    SignedProofPayload,
};
use e3_utils::utility_types::ArcBytes;
use std::path::PathBuf;

// ── Contract ABI definitions (bytecodes loaded from Hardhat artifacts at runtime) ──

sol! {
    #[sol(rpc)]
    contract SlashingManager {
        struct SlashPolicy {
            uint256 ticketPenalty;
            uint256 licensePenalty;
            bool requiresProof;
            address proofVerifier;
            bool banNode;
            uint256 appealWindow;
            bool enabled;
            bool affectsCommittee;
            uint8 failureReason;
        }

        function proposeSlash(uint256 e3Id, address operator, bytes calldata proof) external returns (uint256 proposalId);
        function getSlashPolicy(bytes32 reason) external view returns (SlashPolicy memory);
        function setSlashPolicy(bytes32 reason, SlashPolicy calldata policy) external;
        function setBondingRegistry(address newBondingRegistry) external;
        function setCiphernodeRegistry(address newCiphernodeRegistry) external;
        function setInterfold(address newInterfold) external;
        function totalProposals() external view returns (uint256);
        function isBanned(address node) external view returns (bool);

        error InsufficientAttestations();
        error DuplicateVoter();
        error VoterNotInCommittee();
        error InvalidVoteSignature();
        error InvalidProof();
        error DuplicateEvidence();
    }

    #[sol(rpc)]
    contract MockCiphernodeRegistry {
        function setCommitteeNodes(uint256 e3Id, address[] calldata nodes) external;
        function setThreshold(uint256 e3Id, uint32 m) external;
    }

}

// ── Helpers ──

/// No-op contract deployment bytecode.
///
/// Deploys a contract whose runtime is a single STOP opcode.
/// All calls to this contract succeed with empty return data, making it
/// suitable as a mock for any interface that only has void-returning functions
/// (e.g., IInterfold.onE3Failed).
const NOOP_DEPLOY_BYTECODE: &[u8] = &[
    0x60, 0x01, // PUSH1 0x01 (runtime size)
    0x60, 0x0c, // PUSH1 0x0c (offset of runtime in init code)
    0x60, 0x00, // PUSH1 0x00 (memory destination)
    0x39, //       CODECOPY
    0x60, 0x01, // PUSH1 0x01 (return size)
    0x60, 0x00, // PUSH1 0x00 (return offset)
    0xf3, //       RETURN
    0x00, //       -- runtime: STOP --
];

/// Mock contract that returns 32 zero bytes for any call.
///
/// EVM memory is zero-initialized, so `RETURN(0x00, 0x20)` returns 32 zero bytes.
/// Suitable as a mock for interfaces that return a single `uint256`
/// (e.g., `IBondingRegistry.slashTicketBalance` returns `uint256`).
const RETURNER_DEPLOY_BYTECODE: &[u8] = &[
    0x60, 0x05, // PUSH1 0x05 (runtime size)
    0x60, 0x0c, // PUSH1 0x0c (offset of runtime in init code)
    0x60, 0x00, // PUSH1 0x00 (memory destination)
    0x39, //       CODECOPY
    0x60, 0x05, // PUSH1 0x05 (return size)
    0x60, 0x00, // PUSH1 0x00 (return offset)
    0xf3, //       RETURN
    // -- runtime: return 32 zero bytes --
    0x60, 0x20, // PUSH1 0x20
    0x60, 0x00, // PUSH1 0x00
    0xf3, //       RETURN
];

fn contracts_artifacts_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../packages/interfold-contracts/artifacts/contracts")
}

fn read_artifact_bytecode(subpath: &str) -> Option<Vec<u8>> {
    let path = contracts_artifacts_dir().join(subpath);
    let json_str = std::fs::read_to_string(&path).ok()?;
    let json: serde_json::Value = serde_json::from_str(&json_str).ok()?;
    let hex_str = json["bytecode"].as_str()?;
    let clean = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    hex::decode(clean).ok()
}

/// Load contract bytecodes, returning None if any are missing.
fn load_slashing_artifacts() -> Option<(Vec<u8>, Vec<u8>)> {
    let sm = read_artifact_bytecode("slashing/SlashingManager.sol/SlashingManager.json")?;
    let mr = read_artifact_bytecode("test/MockCiphernodeRegistry.sol/MockCiphernodeRegistry.json")?;
    Some((sm, mr))
}

/// Deploy a contract on the connected provider.
/// `creation_bytecode` is the compiled init code; `constructor_args` is appended (ABI-encoded).
async fn deploy_contract(
    provider: &impl Provider,
    creation_bytecode: &[u8],
    constructor_args: &[u8],
) -> Address {
    let mut deploy_data = creation_bytecode.to_vec();
    deploy_data.extend_from_slice(constructor_args);
    let tx = TransactionRequest::default().with_deploy_code(Bytes::from(deploy_data));
    let receipt = provider
        .send_transaction(tx)
        .await
        .expect("failed to send deploy tx")
        .get_receipt()
        .await
        .expect("failed to get deploy receipt");
    receipt
        .contract_address
        .expect("deploy receipt missing contract address")
}

/// Create a test ProofPayload with the given parameters.
fn test_proof_payload(e3_id: u64, chain_id: u64) -> ProofPayload {
    ProofPayload {
        e3_id: E3id::new(e3_id.to_string(), chain_id),
        proof_type: ProofType::C0PkBfv,
        proof: Proof::new(
            CircuitName::PkBfv,
            ArcBytes::from_bytes(&[0xde, 0xad, 0xbe, 0xef]),
            // One 32-byte public input (padded zero)
            ArcBytes::from_bytes(&[0u8; 32]),
        ),
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Pure Rust tests — no Anvil or artifacts required
// ════════════════════════════════════════════════════════════════════════════

/// Verifies the typehash constant matches the keccak256 of the type string.
#[test]
fn test_proof_payload_typehash() {
    let expected: [u8; 32] = keccak256(
        "ProofPayload(uint256 chainId,uint256 e3Id,uint256 proofType,bytes zkProof,bytes publicSignals)",
    )
    .into();
    assert_eq!(
        ProofPayload::typehash(),
        expected,
        "typehash should match keccak256 of the type string"
    );
}

/// Verifies that digest() uses the structured typehash format with hashed dynamic fields.
#[test]
fn test_proof_payload_digest_matches_manual_computation() {
    let payload = test_proof_payload(1, 42);
    let digest = payload.digest().expect("digest should succeed");

    // Manually compute expected digest
    let typehash = keccak256(
        "ProofPayload(uint256 chainId,uint256 e3Id,uint256 proofType,bytes zkProof,bytes publicSignals)",
    );
    let expected_encoded = (
        typehash,
        U256::from(42u64),                   // chainId
        U256::from(1u64),                    // e3Id
        U256::from(0u8),                     // proofType (C0PkBfv = 0)
        keccak256([0xde, 0xad, 0xbe, 0xef]), // keccak256(zkProof)
        keccak256([0u8; 32]),                // keccak256(publicSignals)
    )
        .abi_encode();
    let expected_digest: [u8; 32] = keccak256(&expected_encoded).into();

    assert_eq!(
        digest, expected_digest,
        "digest should match manual computation"
    );
}

/// Verifies sign → recover roundtrip with the structured digest format.
#[test]
fn test_signing_roundtrip_with_structured_digest() {
    let signer: PrivateKeySigner =
        "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
            .parse()
            .unwrap();

    let payload = test_proof_payload(42, 31337);
    let signed = SignedProofPayload::sign(payload, &signer).expect("signing should succeed");
    let recovered = signed.recover_address().expect("recovery should succeed");

    assert_eq!(
        recovered,
        signer.address(),
        "recovered address should match signer"
    );
}

/// Verifies that different payloads produce different digests (no collisions).
#[test]
fn test_different_payloads_different_digests() {
    let p1 = test_proof_payload(1, 42);
    let p2 = test_proof_payload(2, 42); // different e3Id
    let mut p3 = test_proof_payload(1, 42);
    p3.proof_type = ProofType::C1PkGeneration; // different proofType

    let d1 = p1.digest().unwrap();
    let d2 = p2.digest().unwrap();
    let d3 = p3.digest().unwrap();

    assert_ne!(d1, d2, "different e3Ids should produce different digests");
    assert_ne!(
        d1, d3,
        "different proofTypes should produce different digests"
    );
}

/// Verifies that encode_fault_evidence() produces correctly structured ABI encoding.
#[test]
fn test_encode_fault_evidence_structure() {
    let signer: PrivateKeySigner =
        "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
            .parse()
            .unwrap();
    let verifier_addr: Address = "0x1234567890abcdef1234567890abcdef12345678"
        .parse()
        .unwrap();

    let payload = test_proof_payload(42, 31337);
    let signed = SignedProofPayload::sign(payload, &signer).expect("signing should succeed");

    let failed = SignedProofFailed {
        e3_id: E3id::new("42", 31337),
        faulting_node: signer.address(),
        proof_type: ProofType::C0PkBfv,
        signed_payload: signed.clone(),
    };

    let evidence = encode_fault_evidence(&failed, verifier_addr);

    // Decode and verify structure: (bytes, bytes32[], bytes, uint256, uint256, address)
    type EvidenceTuple = (Bytes, Vec<FixedBytes<32>>, Bytes, U256, U256, Address);
    let decoded = EvidenceTuple::abi_decode_params(&evidence).expect("evidence should ABI-decode");

    let (zk_proof, public_inputs, sig, chain_id, proof_type, verifier) = decoded;

    assert_eq!(&zk_proof[..], &[0xde, 0xad, 0xbe, 0xef], "zkProof mismatch");
    assert_eq!(public_inputs.len(), 1, "should have 1 public input");
    assert_eq!(
        public_inputs[0],
        FixedBytes::from([0u8; 32]),
        "public input value mismatch"
    );
    assert_eq!(&sig[..], &signed.signature[..], "signature bytes mismatch");
    assert_eq!(chain_id, U256::from(31337u64), "chainId mismatch");
    assert_eq!(proof_type, U256::from(0u8), "proofType mismatch");
    assert_eq!(verifier, verifier_addr, "verifier address mismatch");
}

/// Verifies that the digest format matches what Solidity would compute.
///
/// This is the critical cross-language test: if this passes, then:
/// `keccak256(abi.encode(PROOF_PAYLOAD_TYPEHASH, chainId, e3Id, proofType, keccak256(zkProof), keccak256(abi.encodePacked(publicInputs))))`
/// in Solidity produces the same bytes32 as `ProofPayload::digest()` in Rust.
#[test]
fn test_digest_matches_solidity_encoding() {
    let payload = test_proof_payload(42, 31337);
    let digest = payload.digest().expect("digest should succeed");

    // Simulate what Solidity does step by step:
    //
    // bytes32 messageHash = keccak256(abi.encode(
    //     PROOF_PAYLOAD_TYPEHASH,                              // bytes32
    //     chainId,                                              // uint256
    //     e3Id,                                                 // uint256
    //     proofType,                                            // uint256
    //     keccak256(zkProof),                                   // bytes32
    //     keccak256(abi.encodePacked(publicInputs))             // bytes32
    // ));
    //
    // For publicInputs = [bytes32(0)]:
    //   abi.encodePacked(publicInputs) = 0x0000...0000 (32 bytes)
    //   which is the same as the raw publicSignals bytes

    let typehash = keccak256(
        "ProofPayload(uint256 chainId,uint256 e3Id,uint256 proofType,bytes zkProof,bytes publicSignals)",
    );

    // abi.encode of all-static types: each word is 32 bytes, no offsets
    let mut solidity_encoded = Vec::with_capacity(192);
    solidity_encoded.extend_from_slice(typehash.as_ref()); // bytes32
    solidity_encoded.extend_from_slice(&U256::from(31337u64).to_be_bytes::<32>()); // uint256 chainId
    solidity_encoded.extend_from_slice(&U256::from(42u64).to_be_bytes::<32>()); // uint256 e3Id
    solidity_encoded.extend_from_slice(&U256::from(0u8).to_be_bytes::<32>()); // uint256 proofType
    solidity_encoded.extend_from_slice(keccak256([0xde, 0xad, 0xbe, 0xef]).as_ref()); // keccak256(zkProof)

    // For publicInputs = [bytes32(0)]:
    // Solidity: keccak256(abi.encodePacked(publicInputs)) = keccak256(bytes32(0))
    // Rust: keccak256(public_signals) = keccak256([0u8; 32])
    // These must be the same!
    let sol_public_inputs_hash = keccak256([0u8; 32]);
    solidity_encoded.extend_from_slice(sol_public_inputs_hash.as_ref()); // keccak256(publicSignals)

    let solidity_digest: [u8; 32] = keccak256(&solidity_encoded).into();

    assert_eq!(
        digest, solidity_digest,
        "Rust digest must exactly match Solidity messageHash reconstruction"
    );
}

// ════════════════════════════════════════════════════════════════════════════
// Attestation vote helpers — used by both pure Rust and on-chain tests
//
// The vote typehash / domain name / domain version are imported from
// `e3_events` so the test helper and the production `AccusationManager` actor
// always hash the SAME bytes. Adding a fourth source of truth here would
// reintroduce exactly the drift class this test layout exists to prevent.
// ════════════════════════════════════════════════════════════════════════════

use e3_events::{VOTE_DOMAIN_NAME, VOTE_DOMAIN_VERSION, VOTE_TYPEHASH_STR};

const VOTE_DOMAIN_TYPEHASH_STR: &str =
    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)";
/// Sentinel deadline matching Hardhat `ethers.MaxUint256` (no expiry in tests).
const VOTE_NO_EXPIRY: U256 = U256::MAX;

/// Lane A policy key: `keccak256(abi.encodePacked(proofType))` (must match `SlashingManager.proposeSlash`).
fn reason_for_proof_type(proof_type: u8) -> FixedBytes<32> {
    keccak256(U256::from(proof_type).abi_encode_packed())
}

/// Custom error selectors from `SlashingManager` (Anvil returns selector, not name).
fn err_has_selector(err: &str, selector: &str) -> bool {
    err.contains(selector) || err.contains(selector.trim_start_matches("0x"))
}

const SEL_INSUFFICIENT_ATTESTATIONS: &str = "0xe424f994";
const SEL_DUPLICATE_VOTER: &str = "0xcbceb64b";
const SEL_VOTER_NOT_IN_COMMITTEE: &str = "0x4ca81c26";
const SEL_INVALID_VOTE_SIGNATURE: &str = "0x64a283db";
const SEL_DUPLICATE_EVIDENCE: &str = "0x5be07e5e";

/// Compute `accusationId = keccak256(abi.encodePacked(chainId, e3Id, operator, proofType))`
/// matching `AccusationManager::accusation_id()` and `SlashingManager._verifyAttestationEvidence()`.
fn compute_accusation_id(
    chain_id: u64,
    e3_id: u64,
    operator: Address,
    proof_type: u8,
) -> FixedBytes<32> {
    keccak256(
        (
            U256::from(chain_id),
            U256::from(e3_id),
            operator,
            U256::from(proof_type),
        )
            .abi_encode_packed(),
    )
}

/// Compute the canonical EIP-712 vote domain separator.
fn compute_vote_domain_separator(chain_id: u64, verifying_contract: Address) -> FixedBytes<32> {
    let domain_typehash = keccak256(VOTE_DOMAIN_TYPEHASH_STR);
    let name_hash = keccak256(VOTE_DOMAIN_NAME.as_bytes());
    let version_hash = keccak256(VOTE_DOMAIN_VERSION.as_bytes());
    keccak256(
        (
            domain_typehash,
            name_hash,
            version_hash,
            U256::from(chain_id),
            verifying_contract,
        )
            .abi_encode(),
    )
}

/// Compute the canonical EIP-712 typed-data hash for a vote, matching
/// `AccusationManager::vote_digest()` and `SlashingManager._verifyVotes`.
fn compute_vote_digest(
    chain_id: u64,
    verifying_contract: Address,
    e3_id: u64,
    accusation_id: FixedBytes<32>,
    voter: Address,
    data_hash: FixedBytes<32>,
    deadline: U256,
) -> FixedBytes<32> {
    let typehash = keccak256(VOTE_TYPEHASH_STR);
    let struct_hash = keccak256(
        (
            typehash,
            U256::from(e3_id),
            accusation_id,
            voter,
            data_hash,
            deadline,
        )
            .abi_encode(),
    );
    let domain = compute_vote_domain_separator(chain_id, verifying_contract);
    let mut buf = Vec::with_capacity(2 + 32 + 32);
    buf.push(0x19);
    buf.push(0x01);
    buf.extend_from_slice(domain.as_ref());
    buf.extend_from_slice(struct_hash.as_ref());
    keccak256(&buf)
}

/// Sign a vote and return `(voter_address, signature_bytes)`. EIP-712 typed-data signature.
fn sign_vote(
    signer: &PrivateKeySigner,
    chain_id: u64,
    verifying_contract: Address,
    e3_id: u64,
    accusation_id: FixedBytes<32>,
    data_hash: FixedBytes<32>,
) -> (Address, Bytes) {
    sign_vote_with_deadline(
        signer,
        chain_id,
        verifying_contract,
        e3_id,
        accusation_id,
        data_hash,
        VOTE_NO_EXPIRY,
    )
}

fn sign_vote_with_deadline(
    signer: &PrivateKeySigner,
    chain_id: u64,
    verifying_contract: Address,
    e3_id: u64,
    accusation_id: FixedBytes<32>,
    data_hash: FixedBytes<32>,
    deadline: U256,
) -> (Address, Bytes) {
    let voter = signer.address();
    let digest = compute_vote_digest(
        chain_id,
        verifying_contract,
        e3_id,
        accusation_id,
        voter,
        data_hash,
        deadline,
    );
    // EIP-712: sign the typed-data hash directly (no EIP-191 wrapping).
    let sig = signer
        .sign_hash_sync(&digest)
        .expect("vote signing should succeed");
    (voter, Bytes::from(sig.as_bytes().to_vec()))
}

/// Encode attestation evidence for `proposeSlash()`.
///
/// Format: `abi.encode(uint256 proofType, address[] voters, bytes32[] dataHashes,
/// uint256 deadline, bytes[] signatures)`. Voters are sorted ascending by address.
fn encode_attestation_evidence(
    proof_type: u8,
    mut votes: Vec<(Address, FixedBytes<32>, Bytes)>,
    evidence: Bytes,
    deadline: U256,
) -> Bytes {
    votes.sort_by_key(|(addr, _, _)| *addr);

    let voters: Vec<Address> = votes.iter().map(|(a, _, _)| *a).collect();
    let data_hashes: Vec<FixedBytes<32>> = votes.iter().map(|(_, d, _)| *d).collect();
    let sigs: Vec<Bytes> = votes.iter().map(|(_, _, s)| s.clone()).collect();

    // `abi_encode_params` matches Solidity `abi.encode(a,b,...)`; `abi_encode` adds an extra
    // outer offset word that breaks `abi.decode(proof, (uint256))` in `proposeSlash`.
    (
        U256::from(proof_type),
        voters,
        data_hashes,
        evidence,
        deadline,
        sigs,
    )
        .abi_encode_params()
        .into()
}

// ════════════════════════════════════════════════════════════════════════════
// Pure Rust attestation tests — no Anvil required
// ════════════════════════════════════════════════════════════════════════════

/// Lane A reason key must match Hardhat `REASON_PT_0` / `keccak256(solidityPacked(uint256, 0))`.
#[test]
fn test_reason_for_proof_type_matches_solidity() {
    let expected: FixedBytes<32> =
        "0x290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e563"
            .parse()
            .unwrap();
    assert_eq!(reason_for_proof_type(0), expected);
}

/// Verifies the VOTE_TYPEHASH constant matches the keccak256 of the vote type string.
#[test]
fn test_vote_typehash() {
    let expected: [u8; 32] = keccak256(VOTE_TYPEHASH_STR).into();
    // Cross-check with the exact string the Solidity contract uses:
    let sol_str = "AccusationVote(uint256 e3Id,bytes32 accusationId,address voter,bytes32 dataHash,uint256 deadline)";
    let sol_hash: [u8; 32] = keccak256(sol_str).into();
    assert_eq!(
        expected, sol_hash,
        "VOTE_TYPEHASH must match the Solidity constant"
    );
}

/// Verifies vote digest computation matches the canonical EIP-712 typed-data hash.
#[test]
fn test_vote_digest_manual_computation() {
    let chain_id = 31337u64;
    let verifying_contract: Address = "0x9999999999999999999999999999999999999999"
        .parse()
        .unwrap();
    let e3_id = 42u64;
    let operator: Address = "0x1111111111111111111111111111111111111111"
        .parse()
        .unwrap();
    let voter: Address = "0x2222222222222222222222222222222222222222"
        .parse()
        .unwrap();
    let proof_type = 0u8; // C0PkBfv
    let data_hash = FixedBytes::from([0xab; 32]);

    let accusation_id = compute_accusation_id(chain_id, e3_id, operator, proof_type);
    let digest = compute_vote_digest(
        chain_id,
        verifying_contract,
        e3_id,
        accusation_id,
        voter,
        data_hash,
        VOTE_NO_EXPIRY,
    );

    // Manual EIP-712 computation
    let typehash = keccak256(VOTE_TYPEHASH_STR);
    let struct_hash: FixedBytes<32> = keccak256(
        (
            typehash,
            U256::from(e3_id),
            accusation_id,
            voter,
            data_hash,
            VOTE_NO_EXPIRY,
        )
            .abi_encode(),
    );
    let domain = compute_vote_domain_separator(chain_id, verifying_contract);
    let mut buf = Vec::with_capacity(2 + 32 + 32);
    buf.push(0x19);
    buf.push(0x01);
    buf.extend_from_slice(domain.as_ref());
    buf.extend_from_slice(struct_hash.as_ref());
    let expected: FixedBytes<32> = keccak256(&buf);

    assert_eq!(
        digest, expected,
        "vote digest should match canonical EIP-712 typed-data hash"
    );
}

/// Verifies vote sign/recover roundtrip (EIP-712, no EIP-191 wrapping).
#[test]
fn test_vote_signing_roundtrip() {
    let signer: PrivateKeySigner =
        "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
            .parse()
            .unwrap();
    let chain_id = 31337u64;
    let verifying_contract: Address = "0x9999999999999999999999999999999999999999"
        .parse()
        .unwrap();
    let e3_id = 42u64;
    let operator: Address = "0x1111111111111111111111111111111111111111"
        .parse()
        .unwrap();
    let proof_type = 0u8;
    let data_hash = FixedBytes::from([0xab; 32]);

    let accusation_id = compute_accusation_id(chain_id, e3_id, operator, proof_type);
    let (voter, sig_bytes) = sign_vote(
        &signer,
        chain_id,
        verifying_contract,
        e3_id,
        accusation_id,
        data_hash,
    );

    assert_eq!(
        voter,
        signer.address(),
        "voter should be the signer address"
    );

    // Verify recover (raw prehash, no EIP-191 wrapping)
    let digest = compute_vote_digest(
        chain_id,
        verifying_contract,
        e3_id,
        accusation_id,
        voter,
        data_hash,
        VOTE_NO_EXPIRY,
    );
    let sig =
        alloy::primitives::Signature::try_from(sig_bytes.as_ref()).expect("signature should parse");
    let recovered = sig
        .recover_address_from_prehash(&digest)
        .expect("recovery should succeed");
    assert_eq!(
        recovered,
        signer.address(),
        "recovered address should match signer"
    );
}

/// First ABI word of attestation evidence must be `proofType` (SlashingManager decodes only that).
#[test]
fn test_evidence_leading_word_is_proof_type() {
    let raw_evidence = Bytes::from(vec![0u8; 32]);
    let dh: FixedBytes<32> = keccak256(&raw_evidence);
    let evidence = encode_attestation_evidence(
        0,
        vec![
            (
                "0x1111111111111111111111111111111111111111"
                    .parse()
                    .unwrap(),
                dh,
                Bytes::from(vec![0u8; 65]),
            ),
            (
                "0x2222222222222222222222222222222222222222"
                    .parse()
                    .unwrap(),
                dh,
                Bytes::from(vec![0u8; 65]),
            ),
        ],
        raw_evidence,
        VOTE_NO_EXPIRY,
    );
    let leading = U256::from_be_slice(&evidence[..32]);
    assert_eq!(leading, U256::ZERO, "leading word must be proofType");
    let derived_reason: FixedBytes<32> = keccak256(leading.abi_encode_packed());
    assert_eq!(derived_reason, reason_for_proof_type(0));
}

/// Verifies attestation evidence encoding structure.
#[test]
fn test_attestation_evidence_encoding() {
    let signer1: PrivateKeySigner = PrivateKeySigner::random();
    let signer2: PrivateKeySigner = PrivateKeySigner::random();

    let chain_id = 31337u64;
    let verifying_contract: Address = "0x9999999999999999999999999999999999999999"
        .parse()
        .unwrap();
    let e3_id = 1u64;
    let operator: Address = "0x1111111111111111111111111111111111111111"
        .parse()
        .unwrap();
    let proof_type = 0u8;

    let accusation_id = compute_accusation_id(chain_id, e3_id, operator, proof_type);

    let raw_evidence = Bytes::from(vec![0xab; 32]);
    let data_hash: FixedBytes<32> = keccak256(&raw_evidence);
    let (voter1, sig1) = sign_vote(
        &signer1,
        chain_id,
        verifying_contract,
        e3_id,
        accusation_id,
        data_hash,
    );
    let (voter2, sig2) = sign_vote(
        &signer2,
        chain_id,
        verifying_contract,
        e3_id,
        accusation_id,
        data_hash,
    );

    let evidence = encode_attestation_evidence(
        proof_type,
        vec![(voter1, data_hash, sig1), (voter2, data_hash, sig2)],
        raw_evidence.clone(),
        VOTE_NO_EXPIRY,
    );

    // Decode and verify structure: (uint256, address[], bytes32[], bytes, uint256, bytes[])
    type AttestationTuple = (
        U256,
        Vec<Address>,
        Vec<FixedBytes<32>>,
        Bytes,
        U256,
        Vec<Bytes>,
    );
    let decoded =
        AttestationTuple::abi_decode_params(&evidence).expect("evidence should ABI-decode");

    let (dec_proof_type, dec_voters, dec_hashes, dec_evidence, dec_deadline, dec_sigs) = decoded;
    assert_eq!(dec_proof_type, U256::from(proof_type), "proofType mismatch");
    assert_eq!(dec_voters.len(), 2, "should have 2 voters");
    assert!(
        dec_voters[0] < dec_voters[1],
        "voters should be sorted ascending"
    );
    assert_eq!(dec_hashes.len(), 2, "should have 2 data hashes");
    assert_eq!(dec_evidence, raw_evidence, "evidence bytes mismatch");
    assert_eq!(dec_deadline, VOTE_NO_EXPIRY, "deadline mismatch");
    assert_eq!(dec_sigs.len(), 2, "should have 2 signatures");
    assert!(
        dec_hashes.iter().all(|h| *h == data_hash),
        "all voters must share the same dataHash"
    );
}

// ════════════════════════════════════════════════════════════════════════════
// On-chain integration tests — require Anvil + compiled Hardhat artifacts
// ════════════════════════════════════════════════════════════════════════════

/// Deploy SlashingManager and configure dependencies.
/// Returns (SlashingManager contract instance, admin address).
async fn deploy_and_configure(
    provider: &impl Provider,
    sm_bytecode: &[u8],
    mock_registry_addr: Address,
) -> (Address, Address) {
    let accounts = provider.get_accounts().await.unwrap();
    let admin = accounts[0];

    // Deploy noop for interfold (void functions)
    let noop_addr = deploy_contract(provider, NOOP_DEPLOY_BYTECODE, &[]).await;
    // Deploy returner for bondingRegistry (slashTicketBalance returns uint256)
    let returner_addr = deploy_contract(provider, RETURNER_DEPLOY_BYTECODE, &[]).await;

    // Deploy SlashingManager(initialDelay, admin) — use 0 delay for local tests
    let sm_args = (0u64, admin).abi_encode();
    let sm_addr = deploy_contract(provider, sm_bytecode, &sm_args).await;

    // Configure dependencies via admin functions
    let slashing_mgr = SlashingManager::new(sm_addr, provider);
    slashing_mgr
        .setBondingRegistry(returner_addr)
        .send()
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();
    slashing_mgr
        .setCiphernodeRegistry(mock_registry_addr)
        .send()
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();
    slashing_mgr
        .setInterfold(noop_addr)
        .send()
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();

    (sm_addr, admin)
}

/// **Lane A attestation flow**: 3 committee members vote on a fault, quorum
/// is reached (M=2), and the slash executes atomically.
///
/// Proves the complete Rust→Solidity attestation signing pipeline works:
/// vote_digest → sign_message_sync → abi.encode evidence → proposeSlash → _verifyAttestationEvidence
#[tokio::test]
async fn test_onchain_valid_attestation_executes_slash() {
    if !find_anvil().await {
        println!("skipping: anvil not found on PATH");
        return;
    }

    let (sm_bytecode, mr_bytecode) = match load_slashing_artifacts() {
        Some(artifacts) => artifacts,
        None => {
            println!(
                "skipping: contract artifacts not found \
                 (run `npx hardhat compile` in packages/interfold-contracts)"
            );
            return;
        }
    };

    let provider = ProviderBuilder::new().connect_anvil_with_wallet();
    let chain_id = provider.get_chain_id().await.unwrap();

    // Three committee member signers
    let voter_signer1 = PrivateKeySigner::random();
    let voter_signer2 = PrivateKeySigner::random();
    let voter_signer3 = PrivateKeySigner::random();

    let operator_addr: Address = "0x1111111111111111111111111111111111111111"
        .parse()
        .unwrap();

    // Deploy mock registry
    let mock_registry_addr = deploy_contract(&provider, &mr_bytecode, &[]).await;
    let mock_registry = MockCiphernodeRegistry::new(mock_registry_addr, &provider);

    // Deploy and configure SlashingManager
    let (sm_addr, _admin) = deploy_and_configure(&provider, &sm_bytecode, mock_registry_addr).await;
    let slashing_mgr = SlashingManager::new(sm_addr, &provider);

    let e3_id: u64 = 42;
    let proof_type = 0u8; // C0PkBfv
    let reason = reason_for_proof_type(proof_type);

    // Set slash policy (attestation-based: requiresProof=true, appealWindow=0)
    slashing_mgr
        .setSlashPolicy(
            reason,
            SlashingManager::SlashPolicy {
                ticketPenalty: U256::from(50_000_000u64),
                licensePenalty: U256::from(100_000_000_000_000_000_000u128),
                requiresProof: true,
                proofVerifier: Address::ZERO,
                banNode: false,
                appealWindow: U256::ZERO,
                enabled: true,
                affectsCommittee: false,
                failureReason: 0u8,
            },
        )
        .send()
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();

    let stored_policy = slashing_mgr
        .getSlashPolicy(reason)
        .call()
        .await
        .expect("getSlashPolicy should succeed");
    assert!(
        stored_policy.enabled,
        "slash policy must be enabled after setSlashPolicy"
    );
    assert!(
        stored_policy.requiresProof,
        "slash policy must be attestation-based (requiresProof)"
    );

    // Set committee: operator + 3 voters, threshold M=2 (operator must be a member)
    let committee = vec![
        operator_addr,
        voter_signer1.address(),
        voter_signer2.address(),
        voter_signer3.address(),
    ];
    mock_registry
        .setCommitteeNodes(U256::from(e3_id), committee)
        .send()
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();
    mock_registry
        .setThreshold(U256::from(e3_id), 2u32)
        .send()
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();

    // All 3 voters sign accusation votes
    let accusation_id = compute_accusation_id(chain_id, e3_id, operator_addr, proof_type);
    let raw_evidence = Bytes::from(vec![0xaa; 32]);
    let data_hash: FixedBytes<32> = keccak256(&raw_evidence);

    let (v1, s1) = sign_vote(
        &voter_signer1,
        chain_id,
        sm_addr,
        e3_id,
        accusation_id,
        data_hash,
    );
    let (v2, s2) = sign_vote(
        &voter_signer2,
        chain_id,
        sm_addr,
        e3_id,
        accusation_id,
        data_hash,
    );
    let (v3, s3) = sign_vote(
        &voter_signer3,
        chain_id,
        sm_addr,
        e3_id,
        accusation_id,
        data_hash,
    );

    let evidence = encode_attestation_evidence(
        proof_type,
        vec![
            (v1, data_hash, s1),
            (v2, data_hash, s2),
            (v3, data_hash, s3),
        ],
        raw_evidence,
        VOTE_NO_EXPIRY,
    );

    // Verify proposal count before
    let proposals_before = slashing_mgr
        .totalProposals()
        .call()
        .await
        .expect("totalProposals call failed");
    assert_eq!(
        proposals_before,
        U256::ZERO,
        "should have 0 proposals before"
    );

    // Submit slash — should succeed (3 valid votes, threshold M=2)
    let receipt = slashing_mgr
        .proposeSlash(U256::from(e3_id), operator_addr, evidence)
        .send()
        .await
        .expect("proposeSlash tx should not fail to send")
        .get_receipt()
        .await
        .expect("proposeSlash receipt should be obtainable");

    assert!(
        receipt.status(),
        "proposeSlash should succeed with valid attestation quorum"
    );

    // Verify proposal was created and executed
    let proposals_after = slashing_mgr
        .totalProposals()
        .call()
        .await
        .expect("totalProposals call failed");
    assert_eq!(
        proposals_after,
        U256::from(1u64),
        "should have 1 proposal after slash"
    );

    println!(
        "PASS: valid attestation quorum → slash executed — attestation signing pipeline verified"
    );
}

/// Tests that insufficient attestations (below threshold M) cause revert.
#[tokio::test]
async fn test_onchain_insufficient_attestations_reverts() {
    if !find_anvil().await {
        println!("skipping: anvil not found on PATH");
        return;
    }

    let (sm_bytecode, mr_bytecode) = match load_slashing_artifacts() {
        Some(artifacts) => artifacts,
        None => {
            println!("skipping: contract artifacts not found");
            return;
        }
    };

    let provider = ProviderBuilder::new().connect_anvil_with_wallet();
    let chain_id = provider.get_chain_id().await.unwrap();

    let voter_signer1 = PrivateKeySigner::random();
    let voter_signer2 = PrivateKeySigner::random();
    let voter_signer3 = PrivateKeySigner::random();

    let operator_addr: Address = "0x1111111111111111111111111111111111111111"
        .parse()
        .unwrap();

    let mock_registry_addr = deploy_contract(&provider, &mr_bytecode, &[]).await;
    let mock_registry = MockCiphernodeRegistry::new(mock_registry_addr, &provider);

    let (sm_addr, _admin) = deploy_and_configure(&provider, &sm_bytecode, mock_registry_addr).await;
    let slashing_mgr = SlashingManager::new(sm_addr, &provider);

    let e3_id: u64 = 42;
    let proof_type = 0u8;
    let reason = reason_for_proof_type(proof_type);

    slashing_mgr
        .setSlashPolicy(
            reason,
            SlashingManager::SlashPolicy {
                ticketPenalty: U256::from(50_000_000u64),
                licensePenalty: U256::from(100_000_000_000_000_000_000u128),
                requiresProof: true,
                proofVerifier: Address::ZERO,
                banNode: false,
                appealWindow: U256::ZERO,
                enabled: true,
                affectsCommittee: false,
                failureReason: 0u8,
            },
        )
        .send()
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();

    // Committee: operator + 3 voters, threshold M=2
    mock_registry
        .setCommitteeNodes(
            U256::from(e3_id),
            vec![
                operator_addr,
                voter_signer1.address(),
                voter_signer2.address(),
                voter_signer3.address(),
            ],
        )
        .send()
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();
    mock_registry
        .setThreshold(U256::from(e3_id), 2u32)
        .send()
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();

    // Only 1 vote (below threshold M=2)
    let accusation_id = compute_accusation_id(chain_id, e3_id, operator_addr, proof_type);
    let raw_evidence = Bytes::from(vec![0xbb; 32]);
    let data_hash: FixedBytes<32> = keccak256(&raw_evidence);

    let (v1, s1) = sign_vote(
        &voter_signer1,
        chain_id,
        sm_addr,
        e3_id,
        accusation_id,
        data_hash,
    );

    let evidence = encode_attestation_evidence(
        proof_type,
        vec![(v1, data_hash, s1)],
        raw_evidence,
        VOTE_NO_EXPIRY,
    );

    let result = slashing_mgr
        .proposeSlash(U256::from(e3_id), operator_addr, evidence)
        .call()
        .await;

    assert!(
        result.is_err(),
        "should revert because only 1 vote < threshold M=2"
    );

    let err_string = format!("{:?}", result.unwrap_err());
    assert!(
        err_has_selector(&err_string, SEL_INSUFFICIENT_ATTESTATIONS),
        "expected InsufficientAttestations revert, got: {err_string}"
    );

    println!("PASS: insufficient attestations correctly reverts");
}

/// Tests that a voter not in the committee causes revert.
#[tokio::test]
async fn test_onchain_voter_not_in_committee_reverts() {
    if !find_anvil().await {
        println!("skipping: anvil not found on PATH");
        return;
    }

    let (sm_bytecode, mr_bytecode) = match load_slashing_artifacts() {
        Some(artifacts) => artifacts,
        None => {
            println!("skipping: contract artifacts not found");
            return;
        }
    };

    let provider = ProviderBuilder::new().connect_anvil_with_wallet();
    let chain_id = provider.get_chain_id().await.unwrap();

    let committee_signer = PrivateKeySigner::random();
    let outsider_signer = PrivateKeySigner::random();

    let operator_addr: Address = "0x1111111111111111111111111111111111111111"
        .parse()
        .unwrap();

    let mock_registry_addr = deploy_contract(&provider, &mr_bytecode, &[]).await;
    let mock_registry = MockCiphernodeRegistry::new(mock_registry_addr, &provider);

    let (sm_addr, _admin) = deploy_and_configure(&provider, &sm_bytecode, mock_registry_addr).await;
    let slashing_mgr = SlashingManager::new(sm_addr, &provider);

    let e3_id: u64 = 42;
    let proof_type = 0u8;
    let reason = reason_for_proof_type(proof_type);

    slashing_mgr
        .setSlashPolicy(
            reason,
            SlashingManager::SlashPolicy {
                ticketPenalty: U256::from(50_000_000u64),
                licensePenalty: U256::from(100_000_000_000_000_000_000u128),
                requiresProof: true,
                proofVerifier: Address::ZERO,
                banNode: false,
                appealWindow: U256::ZERO,
                enabled: true,
                affectsCommittee: false,
                failureReason: 0u8,
            },
        )
        .send()
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();

    // Committee: operator + committee_signer (outsider is NOT a member)
    mock_registry
        .setCommitteeNodes(
            U256::from(e3_id),
            vec![operator_addr, committee_signer.address()],
        )
        .send()
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();
    mock_registry
        .setThreshold(U256::from(e3_id), 1u32)
        .send()
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();

    // Outsider signs a vote (valid signature, but not a committee member)
    let accusation_id = compute_accusation_id(chain_id, e3_id, operator_addr, proof_type);
    let raw_evidence = Bytes::from(vec![0xcc; 32]);
    let data_hash: FixedBytes<32> = keccak256(&raw_evidence);

    let (v_out, s_out) = sign_vote(
        &outsider_signer,
        chain_id,
        sm_addr,
        e3_id,
        accusation_id,
        data_hash,
    );

    let evidence = encode_attestation_evidence(
        proof_type,
        vec![(v_out, data_hash, s_out)],
        raw_evidence,
        VOTE_NO_EXPIRY,
    );

    let result = slashing_mgr
        .proposeSlash(U256::from(e3_id), operator_addr, evidence)
        .call()
        .await;

    assert!(
        result.is_err(),
        "should revert because voter is not a committee member"
    );

    let err_string = format!("{:?}", result.unwrap_err());
    assert!(
        err_has_selector(&err_string, SEL_VOTER_NOT_IN_COMMITTEE),
        "expected VoterNotInCommittee revert, got: {err_string}"
    );

    println!("PASS: non-committee voter correctly reverts — committee check verified");
}

/// Tests that an invalid vote signature (signed by wrong key) causes revert.
#[tokio::test]
async fn test_onchain_invalid_vote_signature_reverts() {
    if !find_anvil().await {
        println!("skipping: anvil not found on PATH");
        return;
    }

    let (sm_bytecode, mr_bytecode) = match load_slashing_artifacts() {
        Some(artifacts) => artifacts,
        None => {
            println!("skipping: contract artifacts not found");
            return;
        }
    };

    let provider = ProviderBuilder::new().connect_anvil_with_wallet();
    let chain_id = provider.get_chain_id().await.unwrap();

    let victim_signer = PrivateKeySigner::random();
    let impersonator_signer = PrivateKeySigner::random();

    let operator_addr: Address = "0x1111111111111111111111111111111111111111"
        .parse()
        .unwrap();

    let mock_registry_addr = deploy_contract(&provider, &mr_bytecode, &[]).await;
    let mock_registry = MockCiphernodeRegistry::new(mock_registry_addr, &provider);

    let (sm_addr, _admin) = deploy_and_configure(&provider, &sm_bytecode, mock_registry_addr).await;
    let slashing_mgr = SlashingManager::new(sm_addr, &provider);

    let e3_id: u64 = 42;
    let proof_type = 0u8;
    let reason = reason_for_proof_type(proof_type);

    slashing_mgr
        .setSlashPolicy(
            reason,
            SlashingManager::SlashPolicy {
                ticketPenalty: U256::from(50_000_000u64),
                licensePenalty: U256::from(100_000_000_000_000_000_000u128),
                requiresProof: true,
                proofVerifier: Address::ZERO,
                banNode: false,
                appealWindow: U256::ZERO,
                enabled: true,
                affectsCommittee: false,
                failureReason: 0u8,
            },
        )
        .send()
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();

    // operator + victim_signer are committee members
    mock_registry
        .setCommitteeNodes(
            U256::from(e3_id),
            vec![operator_addr, victim_signer.address()],
        )
        .send()
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();
    mock_registry
        .setThreshold(U256::from(e3_id), 1u32)
        .send()
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();

    // Impersonator signs the vote with their key, but we claim it's from victim_signer
    let accusation_id = compute_accusation_id(chain_id, e3_id, operator_addr, proof_type);
    let raw_evidence = Bytes::from(vec![0xdd; 32]);
    let data_hash: FixedBytes<32> = keccak256(&raw_evidence);

    // Sign using impersonator's key but construct the digest for victim_signer's address
    let digest = compute_vote_digest(
        chain_id,
        sm_addr,
        e3_id,
        accusation_id,
        victim_signer.address(),
        data_hash,
        VOTE_NO_EXPIRY,
    );
    let bad_sig = impersonator_signer
        .sign_hash_sync(&digest)
        .expect("signing should succeed");

    // Build evidence claiming the vote is from victim_signer but signed by impersonator
    let evidence: Bytes = (
        U256::from(proof_type),
        vec![victim_signer.address()],
        vec![data_hash],
        raw_evidence,
        VOTE_NO_EXPIRY,
        vec![Bytes::from(bad_sig.as_bytes().to_vec())],
    )
        .abi_encode_params()
        .into();

    let result = slashing_mgr
        .proposeSlash(U256::from(e3_id), operator_addr, evidence)
        .call()
        .await;

    assert!(
        result.is_err(),
        "should revert because signature doesn't match claimed voter"
    );

    let err_string = format!("{:?}", result.unwrap_err());
    assert!(
        err_has_selector(&err_string, SEL_INVALID_VOTE_SIGNATURE),
        "expected InvalidVoteSignature revert, got: {err_string}"
    );

    println!("PASS: invalid vote signature correctly reverts — signature verification verified");
}

/// Tests that duplicate voters (non-ascending order) cause revert.
///
/// The contract requires voters in strictly ascending address order to prevent
/// the same voter from being counted twice.
#[tokio::test]
async fn test_onchain_duplicate_voter_reverts() {
    if !find_anvil().await {
        println!("skipping: anvil not found on PATH");
        return;
    }

    let (sm_bytecode, mr_bytecode) = match load_slashing_artifacts() {
        Some(artifacts) => artifacts,
        None => {
            println!("skipping: contract artifacts not found");
            return;
        }
    };

    let provider = ProviderBuilder::new().connect_anvil_with_wallet();
    let chain_id = provider.get_chain_id().await.unwrap();

    let voter_signer = PrivateKeySigner::random();

    let operator_addr: Address = "0x1111111111111111111111111111111111111111"
        .parse()
        .unwrap();

    let mock_registry_addr = deploy_contract(&provider, &mr_bytecode, &[]).await;
    let mock_registry = MockCiphernodeRegistry::new(mock_registry_addr, &provider);

    let (sm_addr, _admin) = deploy_and_configure(&provider, &sm_bytecode, mock_registry_addr).await;
    let slashing_mgr = SlashingManager::new(sm_addr, &provider);

    let e3_id: u64 = 42;
    let proof_type = 0u8;
    let reason = reason_for_proof_type(proof_type);

    slashing_mgr
        .setSlashPolicy(
            reason,
            SlashingManager::SlashPolicy {
                ticketPenalty: U256::from(50_000_000u64),
                licensePenalty: U256::from(100_000_000_000_000_000_000u128),
                requiresProof: true,
                proofVerifier: Address::ZERO,
                banNode: false,
                appealWindow: U256::ZERO,
                enabled: true,
                affectsCommittee: false,
                failureReason: 0u8,
            },
        )
        .send()
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();

    mock_registry
        .setCommitteeNodes(
            U256::from(e3_id),
            vec![operator_addr, voter_signer.address()],
        )
        .send()
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();
    mock_registry
        .setThreshold(U256::from(e3_id), 1u32)
        .send()
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();

    // Create TWO votes from the same voter (duplicate addresses)
    let accusation_id = compute_accusation_id(chain_id, e3_id, operator_addr, proof_type);
    let raw_evidence = Bytes::from(vec![0xee; 32]);
    let data_hash: FixedBytes<32> = keccak256(&raw_evidence);

    let (voter, sig) = sign_vote(
        &voter_signer,
        chain_id,
        sm_addr,
        e3_id,
        accusation_id,
        data_hash,
    );

    // Submit evidence with duplicate voter entries (bypassing encode_attestation_evidence
    // which would deduplicate — construct manually to have same address appear twice)
    let evidence: Bytes = (
        U256::from(proof_type),
        vec![voter, voter],
        vec![data_hash, data_hash],
        raw_evidence,
        VOTE_NO_EXPIRY,
        vec![sig.clone(), sig],
    )
        .abi_encode_params()
        .into();

    let result = slashing_mgr
        .proposeSlash(U256::from(e3_id), operator_addr, evidence)
        .call()
        .await;

    assert!(
        result.is_err(),
        "should revert because of duplicate voter addresses"
    );

    let err_string = format!("{:?}", result.unwrap_err());
    assert!(
        err_has_selector(&err_string, SEL_DUPLICATE_VOTER),
        "expected DuplicateVoter revert, got: {err_string}"
    );

    println!("PASS: duplicate voter correctly reverts — sorted-order dedup verified");
}

/// Tests that replaying the same evidence causes revert.
#[tokio::test]
async fn test_onchain_duplicate_evidence_reverts() {
    if !find_anvil().await {
        println!("skipping: anvil not found on PATH");
        return;
    }

    let (sm_bytecode, mr_bytecode) = match load_slashing_artifacts() {
        Some(artifacts) => artifacts,
        None => {
            println!("skipping: contract artifacts not found");
            return;
        }
    };

    let provider = ProviderBuilder::new().connect_anvil_with_wallet();
    let chain_id = provider.get_chain_id().await.unwrap();

    let voter_signer1 = PrivateKeySigner::random();
    let voter_signer2 = PrivateKeySigner::random();

    let operator_addr: Address = "0x1111111111111111111111111111111111111111"
        .parse()
        .unwrap();

    let mock_registry_addr = deploy_contract(&provider, &mr_bytecode, &[]).await;
    let mock_registry = MockCiphernodeRegistry::new(mock_registry_addr, &provider);

    let (sm_addr, _admin) = deploy_and_configure(&provider, &sm_bytecode, mock_registry_addr).await;
    let slashing_mgr = SlashingManager::new(sm_addr, &provider);

    let e3_id: u64 = 42;
    let proof_type = 0u8;
    let reason = reason_for_proof_type(proof_type);

    slashing_mgr
        .setSlashPolicy(
            reason,
            SlashingManager::SlashPolicy {
                ticketPenalty: U256::from(50_000_000u64),
                licensePenalty: U256::from(100_000_000_000_000_000_000u128),
                requiresProof: true,
                proofVerifier: Address::ZERO,
                banNode: false,
                appealWindow: U256::ZERO,
                enabled: true,
                affectsCommittee: false,
                failureReason: 0u8,
            },
        )
        .send()
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();

    mock_registry
        .setCommitteeNodes(
            U256::from(e3_id),
            vec![
                operator_addr,
                voter_signer1.address(),
                voter_signer2.address(),
            ],
        )
        .send()
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();
    mock_registry
        .setThreshold(U256::from(e3_id), 2u32)
        .send()
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();

    let accusation_id = compute_accusation_id(chain_id, e3_id, operator_addr, proof_type);
    let raw_evidence = Bytes::from(vec![0xff; 32]);
    let data_hash: FixedBytes<32> = keccak256(&raw_evidence);

    let (v1, s1) = sign_vote(
        &voter_signer1,
        chain_id,
        sm_addr,
        e3_id,
        accusation_id,
        data_hash,
    );
    let (v2, s2) = sign_vote(
        &voter_signer2,
        chain_id,
        sm_addr,
        e3_id,
        accusation_id,
        data_hash,
    );

    let evidence = encode_attestation_evidence(
        proof_type,
        vec![(v1, data_hash, s1), (v2, data_hash, s2)],
        raw_evidence,
        VOTE_NO_EXPIRY,
    );

    // First submission should succeed
    slashing_mgr
        .proposeSlash(U256::from(e3_id), operator_addr, evidence.clone())
        .send()
        .await
        .expect("first proposeSlash should succeed")
        .get_receipt()
        .await
        .expect("first proposeSlash receipt should be obtainable");

    // Second submission with same evidence should revert
    let result = slashing_mgr
        .proposeSlash(U256::from(e3_id), operator_addr, evidence)
        .call()
        .await;

    assert!(
        result.is_err(),
        "should revert because the same evidence was already consumed"
    );

    let err_string = format!("{:?}", result.unwrap_err());
    assert!(
        err_has_selector(&err_string, SEL_DUPLICATE_EVIDENCE),
        "expected DuplicateEvidence revert, got: {err_string}"
    );

    println!("PASS: duplicate evidence correctly reverts — replay protection verified");
}

// ════════════════════════════════════════════════════════════════════════════
// End-to-end actor parity (Anvil)
//
// Drives the production `AccusationManager::vote_digest` and
// `e3_evm::encode_attestation_evidence` against a deployed `SlashingManager`
// on Anvil. Catches drift between off-chain signing/encoding and the
// on-chain decoder/recover that hand-rolled reference helpers cannot — if
// any of (typehash string, domain literal, field order, deadline binding)
// silently diverges, this test reverts on-chain.
// ════════════════════════════════════════════════════════════════════════════

/// The actor's `AccusationManager::vote_digest` + `e3_evm::encode_attestation_evidence`
/// must produce calldata that `SlashingManager._verifyAttestationEvidence`
/// accepts. This is the canonical "actor → Solidity" end-to-end test.
#[tokio::test]
async fn test_onchain_actor_signed_vote_accepted() {
    use e3_events::{AccusationOutcome, AccusationQuorumReached, AccusationVote, ProofType};
    use e3_evm::encode_attestation_evidence;
    use e3_slashing::AccusationManager;

    if !find_anvil().await {
        println!("skipping: anvil not found on PATH");
        return;
    }

    let (sm_bytecode, mr_bytecode) = match load_slashing_artifacts() {
        Some(artifacts) => artifacts,
        None => {
            println!(
                "skipping: contract artifacts not found \
                 (run `npx hardhat compile` in packages/interfold-contracts)"
            );
            return;
        }
    };

    let provider = ProviderBuilder::new().connect_anvil_with_wallet();
    let chain_id = provider.get_chain_id().await.unwrap();

    let voter1 = PrivateKeySigner::random();
    let voter2 = PrivateKeySigner::random();
    let voter3 = PrivateKeySigner::random();
    let operator_addr: Address = "0x4444444444444444444444444444444444444444"
        .parse()
        .unwrap();

    let mock_registry_addr = deploy_contract(&provider, &mr_bytecode, &[]).await;
    let mock_registry = MockCiphernodeRegistry::new(mock_registry_addr, &provider);
    let (sm_addr, _admin) = deploy_and_configure(&provider, &sm_bytecode, mock_registry_addr).await;
    let slashing_mgr = SlashingManager::new(sm_addr, &provider);

    let e3_id: u64 = 7;
    let proof_type = 0u8;
    let reason = reason_for_proof_type(proof_type);

    // Enable an attestation-based policy. `appealWindow = 0` keeps the
    // assertion focused on the verifier path (the slash auto-executes).
    slashing_mgr
        .setSlashPolicy(
            reason,
            SlashingManager::SlashPolicy {
                ticketPenalty: U256::from(50_000_000u64),
                licensePenalty: U256::from(100_000_000_000_000_000_000u128),
                requiresProof: true,
                proofVerifier: Address::ZERO,
                banNode: false,
                appealWindow: U256::ZERO,
                enabled: true,
                affectsCommittee: false,
                failureReason: 0u8,
            },
        )
        .send()
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();

    // Committee = operator + 3 voters; threshold M=2.
    let committee = vec![
        operator_addr,
        voter1.address(),
        voter2.address(),
        voter3.address(),
    ];
    mock_registry
        .setCommitteeNodes(U256::from(e3_id), committee)
        .send()
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();
    mock_registry
        .setThreshold(U256::from(e3_id), 2u32)
        .send()
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();

    // evidence bytes whose keccak256 becomes the data_hash voters sign
    let raw_evidence_bytes: Bytes = Bytes::from(vec![0xee; 32]);
    let data_hash: FixedBytes<32> = keccak256(&raw_evidence_bytes);

    // Pick a deadline far in the future so the on-chain check passes
    // regardless of Anvil's block.timestamp at submission time.
    let deadline: u64 = u64::MAX / 2;

    let accusation_id = compute_accusation_id(chain_id, e3_id, operator_addr, proof_type);

    // Build & sign three votes via the **production** code path:
    //   1. Construct `AccusationVote` exactly as the actor would.
    //   2. Compute the digest via the actor's `vote_digest`.
    //   3. Sign with `signer.sign_hash_sync` (same as `sign_vote_digest`).
    let make_actor_vote = |signer: &PrivateKeySigner| -> AccusationVote {
        let voter = signer.address();
        let mut vote = AccusationVote {
            e3_id: e3_events::E3id::new(e3_id.to_string(), chain_id),
            accusation_id: *accusation_id.as_ref(),
            voter,
            data_hash: *data_hash.as_ref(),
            deadline,
            signature: ArcBytes::default(),
        };
        let digest = AccusationManager::vote_digest(&vote, sm_addr);
        let sig = signer
            .sign_hash_sync(&FixedBytes::<32>::from(digest))
            .expect("vote sign");
        vote.signature = ArcBytes::from_bytes(&sig.as_bytes());
        vote
    };

    let votes_for = vec![
        make_actor_vote(&voter1),
        make_actor_vote(&voter2),
        make_actor_vote(&voter3),
    ];

    // Build the event the production writer consumes and encode via the
    // **production** encoder. If either side has drifted from Solidity,
    // `proposeSlash` will revert (InvalidVoteSignature, EquivocationDetected,
    // or ABI-decode failure).
    let quorum = AccusationQuorumReached {
        e3_id: e3_events::E3id::new(e3_id.to_string(), chain_id),
        accuser: voter1.address(),
        accused: operator_addr,
        proof_type: ProofType::C0PkBfv,
        votes_for,
        outcome: AccusationOutcome::AccusedFaulted,
        evidence: raw_evidence_bytes,
    };
    let evidence = encode_attestation_evidence(&quorum)
        .expect("encode_attestation_evidence must produce bytes for nonempty votes_for");

    // Submit. If anything in the actor → writer → Solidity chain disagrees,
    // this call reverts. The decoded Solidity error is far more informative
    // than a digest-mismatch assertion, which is the whole point of running
    // against the real contract.
    let receipt = slashing_mgr
        .proposeSlash(U256::from(e3_id), operator_addr, Bytes::from(evidence))
        .send()
        .await
        .expect("actor-signed proposeSlash must succeed (off-chain ↔ on-chain digest parity)")
        .get_receipt()
        .await
        .expect("proposeSlash receipt obtainable");
    assert!(
        receipt.status(),
        "actor-signed proposeSlash must land on chain — receipt status was false"
    );
    println!(
        "PASS: actor-signed AccusationVote accepted by Solidity verifier (tx={:?})",
        receipt.transaction_hash
    );
}
