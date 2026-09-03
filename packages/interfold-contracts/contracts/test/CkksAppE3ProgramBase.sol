// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
pragma solidity 0.8.28;

import { IE3Program } from "../interfaces/IE3Program.sol";
import { IHonkVerifier } from "./CkksE3Program.sol";

/// @title CkksAppE3ProgramBase
/// @notice Shared gate for CKKS E3 programs whose submissions carry THREE
///         Honk proofs bound by commitments:
///
///           - ct0 leg (`user_data_encryption_ckks_ct0_psN`):
///             outputs `(pk0_c, ct0_c, m_commitment, u_commitment)`.
///           - ct1 leg (`user_data_encryption_ckks_ct1_psN`):
///             outputs `(pk1_c, ct1_c, u_commitment)`.
///           - app leg (`ckks_<app>_validity_psN`): takes the SAME message
///             polynomial as private input, recomputes `m_commitment`, and
///             proves the application predicate. Its public inputs are
///             `[app-specific public inputs..., m_commitment]`.
///
///         Bindings checked here: `u_commitment` equal across ct0/ct1
///         (randomness), `m_commitment` equal across ct0/app (message).
///         A `(e3Id, u_commitment)` pair is accepted once.
///
/// @dev The KNOWN LIMITS of `CkksE3Program` (ciphertext-byte binding, pk
///      binding to the committee key) apply unchanged. Sender binding is
///      app-specific: the auction leg carries the bidder address as a
///      public input the gate equates to `msg.sender`.
abstract contract CkksAppE3ProgramBase is IE3Program {
    bytes32 public constant ENCRYPTION_SCHEME_ID = keccak256("fhe.rs:CKKS");

    uint256 internal constant CT0_PUBLIC_INPUTS = 4;
    uint256 internal constant CT1_PUBLIC_INPUTS = 3;
    /// @dev Index of `m_commitment` / `u_commitment` in the ct0 outputs.
    uint256 internal constant CT0_M_INDEX = 2;
    uint256 internal constant CT0_U_INDEX = 3;
    uint256 internal constant CT1_U_INDEX = 2;

    IHonkVerifier public immutable ct0Verifier;
    IHonkVerifier public immutable ct1Verifier;
    IHonkVerifier public immutable appVerifier;

    /// @notice A submission accepted by all three legs.
    struct Submission {
        address publisher;
        bytes32 ciphertextHash;
        bytes32 ct0Commitment;
        bytes32 ct1Commitment;
        bytes32 mCommitment;
        bytes32 uCommitment;
    }

    /// @notice Accepted submissions per E3, in publication order.
    mapping(uint256 => Submission[]) internal _submissions;
    /// @notice Replay/bid-copy dedup (see `CkksE3Program`).
    mapping(uint256 => mapping(bytes32 => bool)) public seenUCommitments;

    event VerifiedInputPublished(
        uint256 indexed e3Id,
        address indexed publisher,
        bytes32 ciphertextHash,
        bytes32 ct0Commitment,
        bytes32 ct1Commitment,
        bytes32 mCommitment,
        bytes32 uCommitment
    );

    error InvalidVerifierAddress();
    error DuplicateSubmission(uint256 e3Id, bytes32 uCommitment);
    error InvalidInputEncoding();
    error WrongPublicInputCount(uint256 leg, uint256 got, uint256 want);
    error UCommitmentMismatch(bytes32 ct0Leg, bytes32 ct1Leg);
    error MCommitmentMismatch(bytes32 ct0Leg, bytes32 appLeg);
    error Ct0ProofInvalid();
    error Ct1ProofInvalid();
    error AppProofInvalid();

    constructor(
        IHonkVerifier ct0Verifier_,
        IHonkVerifier ct1Verifier_,
        IHonkVerifier appVerifier_
    ) {
        if (
            address(ct0Verifier_) == address(0) ||
            address(ct1Verifier_) == address(0) ||
            address(appVerifier_) == address(0)
        ) {
            revert InvalidVerifierAddress();
        }
        ct0Verifier = ct0Verifier_;
        ct1Verifier = ct1Verifier_;
        appVerifier = appVerifier_;
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

    /// @inheritdoc IE3Program
    function verify(
        uint256,
        bytes32,
        bytes32,
        bytes memory
    ) external pure returns (bool success) {
        return true;
    }

    /// @notice Number of accepted submissions for `e3Id`.
    function submissionCount(uint256 e3Id) external view returns (uint256) {
        return _submissions[e3Id].length;
    }

    /// @notice Accepted submission `index` of `e3Id`.
    function submissionAt(
        uint256 e3Id,
        uint256 index
    ) external view returns (Submission memory) {
        return _submissions[e3Id][index];
    }

    /// @dev Number of app-leg public inputs (app-specific values + the
    ///      trailing `m_commitment`).
    function _appPublicInputCount() internal pure virtual returns (uint256);

    /// @dev App-specific checks on the app leg's public inputs (everything
    ///      but the trailing `m_commitment`). Must revert on failure.
    function _checkAppPublicInputs(
        uint256 e3Id,
        bytes32[] memory appPublicInputs
    ) internal view virtual;

    /// @dev Shared three-leg gate. `data` is ABI-encoded as
    ///      `abi.encode(bytes ciphertext, bytes ct0Proof, bytes32[] ct0Pub,
    ///                  bytes ct1Proof, bytes32[] ct1Pub,
    ///                  bytes appProof, bytes32[] appPub)`.
    function _publishThreeLegInput(uint256 e3Id, bytes memory data) internal {
        (
            bytes memory ciphertext,
            bytes memory ct0Proof,
            bytes32[] memory ct0Pub,
            bytes memory ct1Proof,
            bytes32[] memory ct1Pub,
            bytes memory appProof,
            bytes32[] memory appPub
        ) = abi.decode(
                data,
                (bytes, bytes, bytes32[], bytes, bytes32[], bytes, bytes32[])
            );

        if (ciphertext.length == 0) revert InvalidInputEncoding();
        if (ct0Pub.length != CT0_PUBLIC_INPUTS) {
            revert WrongPublicInputCount(0, ct0Pub.length, CT0_PUBLIC_INPUTS);
        }
        if (ct1Pub.length != CT1_PUBLIC_INPUTS) {
            revert WrongPublicInputCount(1, ct1Pub.length, CT1_PUBLIC_INPUTS);
        }
        uint256 appCount = _appPublicInputCount();
        if (appPub.length != appCount) {
            revert WrongPublicInputCount(2, appPub.length, appCount);
        }

        bytes32 uCommitment = ct0Pub[CT0_U_INDEX];
        if (uCommitment != ct1Pub[CT1_U_INDEX]) {
            revert UCommitmentMismatch(uCommitment, ct1Pub[CT1_U_INDEX]);
        }
        bytes32 mCommitment = ct0Pub[CT0_M_INDEX];
        bytes32 appM = appPub[appCount - 1];
        if (mCommitment != appM) {
            revert MCommitmentMismatch(mCommitment, appM);
        }

        _checkAppPublicInputs(e3Id, appPub);

        if (seenUCommitments[e3Id][uCommitment]) {
            revert DuplicateSubmission(e3Id, uCommitment);
        }
        seenUCommitments[e3Id][uCommitment] = true;

        if (!_verify(ct0Verifier, ct0Proof, ct0Pub)) revert Ct0ProofInvalid();
        if (!_verify(ct1Verifier, ct1Proof, ct1Pub)) revert Ct1ProofInvalid();
        if (!_verify(appVerifier, appProof, appPub)) revert AppProofInvalid();

        bytes32 ciphertextHash = keccak256(ciphertext);
        _submissions[e3Id].push(
            Submission({
                publisher: msg.sender,
                ciphertextHash: ciphertextHash,
                ct0Commitment: ct0Pub[1],
                ct1Commitment: ct1Pub[1],
                mCommitment: mCommitment,
                uCommitment: uCommitment
            })
        );

        emit VerifiedInputPublished(
            e3Id,
            msg.sender,
            ciphertextHash,
            ct0Pub[1],
            ct1Pub[1],
            mCommitment,
            uCommitment
        );
    }

    /// @dev bb-generated verifiers REVERT on invalid proofs; normalize.
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
