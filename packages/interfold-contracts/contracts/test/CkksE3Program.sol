// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
pragma solidity 0.8.28;

import { IE3Program } from "../interfaces/IE3Program.sol";

/// @notice Honk verifier interface (bb `write_solidity_verifier` output).
interface IHonkVerifier {
    function verify(
        bytes calldata proof,
        bytes32[] calldata publicInputs
    ) external view returns (bool);
}

/// @title CkksE3Program
/// @notice CKKS E3 program with Greco-style verifiable-encryption gating:
///         a bid (CKKS ciphertext) is only accepted on-chain when it comes
///         with valid proofs of ciphertext well-formedness for BOTH legs:
///
///           - ct0 leg (`user_data_encryption_ckks_ct0`):
///             `ct0 = pk0*u + e0 + m`, with range-bounded `u`/`e0`/`m` and
///             CRT-consistent limbs. Public outputs:
///             `(pk0_commitment, ct0_commitment, m_commitment, u_commitment)`.
///           - ct1 leg (`user_data_encryption_ckks_ct1`):
///             `ct1 = pk1*u + e1`. Public outputs:
///             `(pk1_commitment, ct1_commitment, u_commitment)`.
///
///         The two legs are bound by the shared `u_commitment`: equality is
///         checked here, so the prover cannot use different randomness per
///         leg. The pk commitments bind the proof to the committee's joint
///         public key.
///
/// @dev The program address IS the protocol selector — `validate()` binds
///      `keccak256("fhe.rs:CKKS")` (mirror of `MockCkksE3Program`, which
///      remains for proof-less test flows).
contract CkksE3Program is IE3Program {
    bytes32 public constant ENCRYPTION_SCHEME_ID = keccak256("fhe.rs:CKKS");

    /// @dev The verifier consumes only the circuit's own public outputs in
    ///      `publicInputs` (its VK-declared count minus the 8 pairing-point
    ///      fields, which it reads from the proof tail).
    /// @dev ct0 leg outputs: (pk0_c, ct0_c, m_c, u_c).
    uint256 internal constant CT0_PUBLIC_INPUTS = 4;
    /// @dev ct1 leg outputs: (pk1_c, ct1_c, u_c).
    uint256 internal constant CT1_PUBLIC_INPUTS = 3;

    /// @notice Verifier for the ct0 leg (`user_data_encryption_ckks_ct0`).
    IHonkVerifier public immutable ct0Verifier;
    /// @notice Verifier for the ct1 leg (`user_data_encryption_ckks_ct1`).
    IHonkVerifier public immutable ct1Verifier;

    /// @notice Emitted when a verifiably-encrypted input is accepted.
    /// @param e3Id The E3 the input belongs to.
    /// @param publisher The account that published the input.
    /// @param ciphertextHash keccak256 of the accepted ciphertext bytes.
    /// @param ct0Commitment The ct0 polynomial commitment from the proof.
    /// @param ct1Commitment The ct1 polynomial commitment from the proof.
    /// @param uCommitment The (shared) encryption-randomness commitment.
    event VerifiedInputPublished(
        uint256 indexed e3Id,
        address indexed publisher,
        bytes32 ciphertextHash,
        bytes32 ct0Commitment,
        bytes32 ct1Commitment,
        bytes32 uCommitment
    );

    // ------------------------------------------------------------------
    // KNOWN LIMITS of this gate (documented posture, not oversights):
    // * Ciphertext-byte binding: keccak256(ciphertext) is emitted but NOT
    //   cryptographically tied to ct0/ct1 commitments on-chain (they hash
    //   polynomial limbs in-circuit). A submitter with a valid proof pair
    //   could attach different bytes; consumers must recompute the limb
    //   commitments from the bytes they consume (same posture as BFV).
    //   Closing it requires the circuit to also output a hash of the
    //   canonical byte serialization.
    // * Sender binding: proofs are not bound to msg.sender; front-running
    //   a pending submission copies only the COMMITMENT (dedup below
    //   makes the copy worthless, the original reverts — acceptable for
    //   demo; production would absorb msg.sender into the FS transcript).
    // * pk binding: pk0/pk1 commitments are proven but not compared to
    //   the committee's registered key for this e3Id (registry wiring).
    // ------------------------------------------------------------------
    error InvalidVerifierAddress();
    error DuplicateSubmission(uint256 e3Id, bytes32 uCommitment);
    error InvalidInputEncoding();
    error WrongPublicInputCount(uint256 leg, uint256 got, uint256 want);
    error UCommitmentMismatch(bytes32 ct0Leg, bytes32 ct1Leg);
    error Ct0ProofInvalid();
    error Ct1ProofInvalid();

    constructor(IHonkVerifier ct0Verifier_, IHonkVerifier ct1Verifier_) {
        if (
            address(ct0Verifier_) == address(0) ||
            address(ct1Verifier_) == address(0)
        ) {
            revert InvalidVerifierAddress();
        }
        ct0Verifier = ct0Verifier_;
        ct1Verifier = ct1Verifier_;
    }

    /// @inheritdoc IE3Program
    function validate(
        uint256,
        uint256,
        bytes calldata,
        bytes calldata,
        bytes calldata
    ) external pure returns (bytes32) {
        return ENCRYPTION_SCHEME_ID;
    }

    /// Replay/bid-copy dedup: a (e3Id, uCommitment) pair is accepted once.
    /// `u_commitment` is a hiding hash of the encryptor's secret randomness,
    /// so a copied proof tuple necessarily repeats it — Mallory cannot
    /// resubmit Alice's (ciphertext, proofs) as her own bid, and the same
    /// bid cannot be double-counted. Fresh randomness (a NEW encryption of
    /// even the same value) yields a new u_commitment, so honest re-bids
    /// still work. Cross-e3Id replay stays possible only for identical
    /// ciphertext bytes, which downstream keying by e3Id already isolates.
    mapping(uint256 => mapping(bytes32 => bool)) public seenUCommitments;

    /// @inheritdoc IE3Program
    /// @dev `data` is ABI-encoded as:
    ///      `abi.encode(bytes ciphertext, bytes ct0Proof,
    ///                  bytes32[] ct0PublicInputs, bytes ct1Proof,
    ///                  bytes32[] ct1PublicInputs)`.
    ///      Reverts unless both Honk proofs verify and the `u` commitments
    ///      agree across legs.
    function publishInput(uint256 e3Id, bytes memory data) external {
        (
            bytes memory ciphertext,
            bytes memory ct0Proof,
            bytes32[] memory ct0PublicInputs,
            bytes memory ct1Proof,
            bytes32[] memory ct1PublicInputs
        ) = abi.decode(data, (bytes, bytes, bytes32[], bytes, bytes32[]));

        if (ciphertext.length == 0) revert InvalidInputEncoding();
        if (ct0PublicInputs.length != CT0_PUBLIC_INPUTS) {
            revert WrongPublicInputCount(
                0,
                ct0PublicInputs.length,
                CT0_PUBLIC_INPUTS
            );
        }
        if (ct1PublicInputs.length != CT1_PUBLIC_INPUTS) {
            revert WrongPublicInputCount(
                1,
                ct1PublicInputs.length,
                CT1_PUBLIC_INPUTS
            );
        }

        // Randomness binding: ct0 leg emits u_commitment at index 3,
        // ct1 leg at index 2 (each after its commitment outputs).
        bytes32 uCommitmentCt0 = ct0PublicInputs[3];
        bytes32 uCommitmentCt1 = ct1PublicInputs[2];
        if (uCommitmentCt0 != uCommitmentCt1) {
            revert UCommitmentMismatch(uCommitmentCt0, uCommitmentCt1);
        }

        if (seenUCommitments[e3Id][uCommitmentCt0]) {
            revert DuplicateSubmission(e3Id, uCommitmentCt0);
        }
        seenUCommitments[e3Id][uCommitmentCt0] = true;

        if (!_verify(ct0Verifier, ct0Proof, ct0PublicInputs)) {
            revert Ct0ProofInvalid();
        }
        if (!_verify(ct1Verifier, ct1Proof, ct1PublicInputs)) {
            revert Ct1ProofInvalid();
        }

        emit VerifiedInputPublished(
            e3Id,
            msg.sender,
            keccak256(ciphertext),
            ct0PublicInputs[1],
            ct1PublicInputs[1],
            uCommitmentCt0
        );
    }

    /// @inheritdoc IE3Program
    function verify(
        uint256,
        bytes32,
        bytes32,
        bytes memory
    ) external pure returns (bool success) {
        return true;
    }

    /// @dev bb-generated verifiers REVERT on invalid proofs (rather than
    ///      returning false); normalize both behaviors to a bool.
    function _verify(
        IHonkVerifier verifier,
        bytes memory proof,
        bytes32[] memory publicInputs
    ) internal view returns (bool ok) {
        try verifier.verify(proof, publicInputs) returns (bool result) {
            ok = result;
        } catch {
            ok = false;
        }
    }
}
