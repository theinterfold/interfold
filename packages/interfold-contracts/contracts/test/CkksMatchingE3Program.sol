// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
pragma solidity 0.8.28;

import { IE3Program } from "../interfaces/IE3Program.sol";
import { IHonkVerifier } from "./CkksE3Program.sol";

/// @title CkksMatchingE3Program
/// @notice Private matching (CKKS ParamSet 5): exactly TWO parties per
///         round, A (slot 0, `forward` layout) and B (slot 1, `reversed`
///         layout), each submitting TWO coefficient-encoded ciphertexts
///         proven in FIVE legs: Greco ct0 + ct1 for the VECTOR ciphertext,
///         Greco ct0 + ct1 for the MASK ciphertext, and the
///         `ckks_matching_validity_ps5` proof that
///           * the vector message is the `forward` (role 0) / `reversed`
///             (role 1) coefficient encoding of 16 fixed-point entries with
///             `|v_j| <= 1`, every other coefficient 0;
///           * the mask message carries 128 integers in `[0, 1024)` on
///             coefficients `1..=128`, every other coefficient 0.
///
///         Validity-leg public inputs (5 words):
///         `[role, address, index, m_commitment_vec, m_commitment_mask]`.
///
///         Bindings the chain enforces:
///           * `address == msg.sender`;
///           * `index` == the sender's registered slot, and `role == index`
///             (slot 0 is A / forward, slot 1 is B / reversed);
///           * `m_commitment_vec` == the vector ct0 leg's `m_commitment`,
///             `m_commitment_mask` == the mask ct0 leg's; each ct0/ct1 pair
///             shares its `u_commitment`; both `u_commitment`s are new for
///             the E3 (dedup), and one submission per sender.
///
///         The network computes `relin(forward(a) * reversed(b)) + mask_a
///         + mask_b` (one ciphertext x ciphertext product under the
///         committee's level-0 relin key) and the committee opens the first
///         64 coefficients; coefficient 0 is `-<a, b>` (the app negates),
///         the rest are mask-dominated cross terms. The score is public to
///         both parties; neither vector is ever opened.
contract CkksMatchingE3Program is IE3Program {
    bytes32 public constant ENCRYPTION_SCHEME_ID = keccak256("fhe.rs:CKKS");

    uint256 internal constant CT0_PUBLIC_INPUTS = 4;
    uint256 internal constant CT1_PUBLIC_INPUTS = 3;
    uint256 internal constant CT0_M_INDEX = 2;
    uint256 internal constant CT0_U_INDEX = 3;
    uint256 internal constant CT1_U_INDEX = 2;
    /// @dev `[role, address, index, m_c_vec, m_c_mask]`.
    uint256 public constant APP_PUBLIC_INPUTS = 5;
    uint256 internal constant APP_ROLE = 0;
    uint256 internal constant APP_ADDRESS = 1;
    uint256 internal constant APP_INDEX = 2;
    uint256 internal constant APP_M_VEC = 3;
    uint256 internal constant APP_M_MASK = 4;
    /// @notice Exactly two parties per round.
    uint256 public constant PARTIES = 2;
    /// @notice The opened output is the first 64 coefficients as `int128`
    ///         words (`e3_trckks::program::COEFFICIENT_OUTPUT_COUNT`).
    uint256 public constant OUTPUT_COEFFICIENTS = 64;
    uint256 public constant OUTPUT_BYTES = OUTPUT_COEFFICIENTS * 16;

    IHonkVerifier public immutable ct0Verifier;
    IHonkVerifier public immutable ct1Verifier;
    IHonkVerifier public immutable appVerifier;
    /// @notice Round opener allowed to register rounds.
    address public immutable owner;

    /// @notice One accepted submission.
    struct Submission {
        address party;
        uint256 index;
        bytes32 vectorCiphertextHash;
        bytes32 maskCiphertextHash;
        bytes32 mCommitmentVec;
        bytes32 mCommitmentMask;
        bytes32 uCommitmentVec;
        bytes32 uCommitmentMask;
    }

    /// @dev Both Greco legs of ONE ciphertext.
    struct GrecoPair {
        bytes ciphertext;
        bytes ct0Proof;
        bytes32[] ct0Pub;
        bytes ct1Proof;
        bytes32[] ct1Pub;
    }

    /// @dev The five-leg submission envelope, ABI-decoded from
    ///      `publishInput`'s `data` as a single nested tuple:
    ///      `abi.encode(MatchingSubmission)` — NOT a flat field list. Each
    ///      `GrecoPair` is its own dynamic tuple with head/tail offsets;
    ///      encoders must spell out
    ///      `tuple((bytes,bytes,bytes32[],bytes,bytes32[]),
    ///             (bytes,bytes,bytes32[],bytes,bytes32[]),
    ///             bytes,bytes32[])`
    ///      (see `test/CkksMatchingE3Program.spec.ts::encodeFiveLegInput`).
    struct MatchingSubmission {
        GrecoPair vector;
        GrecoPair mask;
        bytes appProof;
        bytes32[] appPub;
    }

    /// @notice Registered party list per E3 (`[A, B]`; slot index = position).
    mapping(uint256 => address[]) internal _parties;
    /// @notice `index + 1` of a registered party (0 = not registered).
    mapping(uint256 => mapping(address => uint256)) public partySlot;
    mapping(uint256 => Submission[]) internal _submissions;
    mapping(uint256 => mapping(bytes32 => bool)) public seenUCommitments;
    mapping(uint256 => mapping(address => bool)) public hasSubmitted;

    event RoundRegistered(uint256 indexed e3Id, address partyA, address partyB);
    event SubmissionPublished(
        uint256 indexed e3Id,
        address indexed party,
        uint256 index,
        bytes32 vectorCiphertextHash,
        bytes32 maskCiphertextHash,
        bytes32 mCommitmentVec,
        bytes32 mCommitmentMask
    );

    error InvalidVerifierAddress();
    error NotOwner();
    error RoundAlreadyRegistered(uint256 e3Id);
    error RoundNotRegistered(uint256 e3Id);
    error WrongPartyCount(uint256 got, uint256 want);
    error DuplicateParty(address party);
    error InvalidParty();
    error InvalidInputEncoding();
    error WrongPublicInputCount(uint256 leg, uint256 got, uint256 want);
    error UCommitmentMismatch(uint256 ciphertext, bytes32 ct0Leg, bytes32 ct1Leg);
    error MCommitmentMismatch(uint256 ciphertext, bytes32 ct0Leg, bytes32 appLeg);
    error DuplicateSubmission(uint256 e3Id, bytes32 uCommitment);
    error AlreadySubmitted(uint256 e3Id, address party);
    error WrongSender(address proven, address sender);
    error NotRegistered(uint256 e3Id, address party);
    error WrongIndex(uint256 got, uint256 want);
    error WrongRole(uint256 got, uint256 want);
    error Ct0ProofInvalid(uint256 ciphertext);
    error Ct1ProofInvalid(uint256 ciphertext);
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
        owner = msg.sender;
    }

    /// @notice Registers a round once: the two parties, `parties[0]` = A
    ///         (forward), `parties[1]` = B (reversed).
    function registerRound(uint256 e3Id, address[] calldata parties) external {
        if (msg.sender != owner) revert NotOwner();
        if (_parties[e3Id].length != 0) revert RoundAlreadyRegistered(e3Id);
        if (parties.length != PARTIES) revert WrongPartyCount(parties.length, PARTIES);
        for (uint256 i = 0; i < parties.length; i++) {
            if (parties[i] == address(0)) revert InvalidParty();
            if (partySlot[e3Id][parties[i]] != 0) revert DuplicateParty(parties[i]);
            partySlot[e3Id][parties[i]] = i + 1;
            _parties[e3Id].push(parties[i]);
        }
        emit RoundRegistered(e3Id, parties[0], parties[1]);
    }

    /// @inheritdoc IE3Program
    /// @dev `data` is the ABI encoding of [`MatchingSubmission`]. Each helper
    ///      below verifies ONE Greco pair or the validity leg and returns
    ///      only what the cross-leg binding needs, keeping the frame small.
    function publishInput(uint256 e3Id, bytes memory data) external {
        MatchingSubmission memory sub = abi.decode(data, (MatchingSubmission));
        if (sub.appPub.length != APP_PUBLIC_INPUTS) {
            revert WrongPublicInputCount(4, sub.appPub.length, APP_PUBLIC_INPUTS);
        }

        // Cross-leg bindings + policy checks (cheap) before any Honk verify.
        bytes32 uV = _checkGrecoPair(0, sub.vector, sub.appPub[APP_M_VEC]);
        bytes32 uM = _checkGrecoPair(1, sub.mask, sub.appPub[APP_M_MASK]);
        uint256 index = _checkAppPublicInputs(e3Id, sub.appPub);
        _markSubmitted(e3Id, uV, uM);

        // The five proofs.
        _verifyGrecoPair(0, sub.vector);
        _verifyGrecoPair(1, sub.mask);
        if (!_verify(appVerifier, sub.appProof, sub.appPub)) revert AppProofInvalid();

        _record(e3Id, index, sub, uV, uM);
    }

    /// @dev One submission per sender, every `u_commitment` new for the E3.
    function _markSubmitted(uint256 e3Id, bytes32 uV, bytes32 uM) internal {
        if (hasSubmitted[e3Id][msg.sender]) revert AlreadySubmitted(e3Id, msg.sender);
        if (seenUCommitments[e3Id][uV]) revert DuplicateSubmission(e3Id, uV);
        if (seenUCommitments[e3Id][uM] || uV == uM) {
            revert DuplicateSubmission(e3Id, uM);
        }
        hasSubmitted[e3Id][msg.sender] = true;
        seenUCommitments[e3Id][uV] = true;
        seenUCommitments[e3Id][uM] = true;
    }

    function _record(
        uint256 e3Id,
        uint256 index,
        MatchingSubmission memory sub,
        bytes32 uV,
        bytes32 uM
    ) internal {
        bytes32 hashV = keccak256(sub.vector.ciphertext);
        bytes32 hashM = keccak256(sub.mask.ciphertext);
        _submissions[e3Id].push(
            Submission({
                party: msg.sender,
                index: index,
                vectorCiphertextHash: hashV,
                maskCiphertextHash: hashM,
                mCommitmentVec: sub.appPub[APP_M_VEC],
                mCommitmentMask: sub.appPub[APP_M_MASK],
                uCommitmentVec: uV,
                uCommitmentMask: uM
            })
        );
        emit SubmissionPublished(
            e3Id,
            msg.sender,
            index,
            hashV,
            hashM,
            sub.appPub[APP_M_VEC],
            sub.appPub[APP_M_MASK]
        );
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
    /// @dev Called by `Interfold.publishCiphertextOutput` with the proof
    ///      bytes; the ciphertext itself is verified by the registered
    ///      ciphertext verifier (mock on the dev stack). Nothing about the
    ///      ciphertext is checkable here without decoding it.
    function verify(
        uint256,
        bytes32,
        bytes32,
        bytes memory
    ) external pure returns (bool success) {
        return true;
    }

    /// @notice Shape check of the OPENED output the committee publishes:
    ///         exactly `OUTPUT_COEFFICIENTS` big-endian `int128` words
    ///         (`e3_trckks::program::encode_fixed_point_output` at 4
    ///         decimals). Callers (the coordination server) run it before
    ///         decoding the score.
    function verifyOutput(bytes calldata plaintextOutput) external pure returns (bool) {
        return plaintextOutput.length == OUTPUT_BYTES;
    }

    function parties(uint256 e3Id) external view returns (address[] memory) {
        return _parties[e3Id];
    }

    function submissionCount(uint256 e3Id) external view returns (uint256) {
        return _submissions[e3Id].length;
    }

    function submissionAt(
        uint256 e3Id,
        uint256 i
    ) external view returns (Submission memory) {
        return _submissions[e3Id][i];
    }

    /// @dev Shape + bindings of one Greco pair: shared `u_commitment`, and
    ///      the ct0 leg's `m_commitment` equal to the validity leg's word.
    function _checkGrecoPair(
        uint256 which,
        GrecoPair memory pair,
        bytes32 appM
    ) internal pure returns (bytes32 uCommitment) {
        if (pair.ciphertext.length == 0) revert InvalidInputEncoding();
        if (pair.ct0Pub.length != CT0_PUBLIC_INPUTS) {
            revert WrongPublicInputCount(2 * which, pair.ct0Pub.length, CT0_PUBLIC_INPUTS);
        }
        if (pair.ct1Pub.length != CT1_PUBLIC_INPUTS) {
            revert WrongPublicInputCount(2 * which + 1, pair.ct1Pub.length, CT1_PUBLIC_INPUTS);
        }
        uCommitment = pair.ct0Pub[CT0_U_INDEX];
        if (uCommitment != pair.ct1Pub[CT1_U_INDEX]) {
            revert UCommitmentMismatch(which, uCommitment, pair.ct1Pub[CT1_U_INDEX]);
        }
        if (pair.ct0Pub[CT0_M_INDEX] != appM) {
            revert MCommitmentMismatch(which, pair.ct0Pub[CT0_M_INDEX], appM);
        }
    }

    /// @dev The two Honk proofs of one Greco pair.
    function _verifyGrecoPair(uint256 which, GrecoPair memory pair) internal view {
        if (!_verify(ct0Verifier, pair.ct0Proof, pair.ct0Pub)) revert Ct0ProofInvalid(which);
        if (!_verify(ct1Verifier, pair.ct1Proof, pair.ct1Pub)) revert Ct1ProofInvalid(which);
    }

    /// @dev `address == msg.sender`, `index` == the sender's registered slot,
    ///      `role == index`.
    function _checkAppPublicInputs(
        uint256 e3Id,
        bytes32[] memory appPub
    ) internal view returns (uint256 index) {
        if (_parties[e3Id].length == 0) revert RoundNotRegistered(e3Id);
        {
            // `address` is a free field element in the circuit, so the
            // whole 256-bit word must equal the sender (no high bits).
            uint256 word = uint256(appPub[APP_ADDRESS]);
            address proven = address(uint160(word));
            if (word >> 160 != 0 || proven != msg.sender) {
                revert WrongSender(proven, msg.sender);
            }
        }
        uint256 slot = partySlot[e3Id][msg.sender];
        if (slot == 0) revert NotRegistered(e3Id, msg.sender);
        index = uint256(appPub[APP_INDEX]);
        if (index != slot - 1) revert WrongIndex(index, slot - 1);
        uint256 role = uint256(appPub[APP_ROLE]);
        if (role != index) revert WrongRole(role, index);
    }

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
