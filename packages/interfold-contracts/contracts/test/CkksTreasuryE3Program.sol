// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
pragma solidity 0.8.28;

import { IE3Program } from "../interfaces/IE3Program.sol";
import { IHonkVerifier } from "./CkksE3Program.sol";

/// @title CkksTreasuryE3Program
/// @notice Private treasury-risk aggregation (CKKS ParamSet 5). n DAOs each
///         hold a private exposure vector `x` over 4 public assets
///         (cap-normalised, `x_a in [0, 1]`); the round publishes PUBLIC
///         risk weights `w[4]`. A DAO's submission is THREE COEFFICIENT-
///         encoded ciphertexts proven in SEVEN legs: Greco ct0 + ct1 for
///         each of `forward(x)`, `reversed(w o x)` and `mask(m)`, and the
///         `ckks_treasury_validity_ps5` proof that
///           * the forward message is `x_a` on coefficient `a + 1` with
///             `0 <= x_a <= 1`, every other coefficient 0;
///           * the reversed message is `w_a * x_a` on coefficient `N-a-1`
///             under the round's REGISTERED weights, every other 0;
///           * the mask message is an integer in `[0, 1024)` on
///             coefficients `1..=128`, every other 0 (coefficient 0 — the
///             result — is never masked).
///
///         Validity-leg public inputs (9 words):
///         `[w_0..w_3, address, index, m_commitment_fwd, m_commitment_rev, m_commitment_mask]`.
///
///         Bindings the chain enforces:
///           * `address == msg.sender` (the DAO submits from its own key);
///           * `index` == the sender's position in the round's registered
///             DAO list;
///           * `[w_0..w_3]` == the round's registered weights;
///           * each `m_commitment` == its ct0 leg's `m_commitment`; each
///             ct0/ct1 pair shares its `u_commitment`; all three
///             `u_commitment`s are new for the E3 (dedup), and one
///             submission per sender.
///
///         The network sums `F = sum f_i`, `R = sum r_i`, `M = sum m_i`
///         and opens `relin(F * R) + M`; coefficient 0 of the output is
///         `-sum_a w_a (sum_i x_{i,a})^2` — the weighted concentration risk
///         of the COMBINED book. No single book, and not even the aggregate
///         book, is ever opened: only the one scalar (the app negates).
contract CkksTreasuryE3Program is IE3Program {
    bytes32 public constant ENCRYPTION_SCHEME_ID = keccak256("fhe.rs:CKKS");

    uint256 internal constant CT0_PUBLIC_INPUTS = 4;
    uint256 internal constant CT1_PUBLIC_INPUTS = 3;
    uint256 internal constant CT0_M_INDEX = 2;
    uint256 internal constant CT0_U_INDEX = 3;
    uint256 internal constant CT1_U_INDEX = 2;
    /// @dev `[w_0..w_3, address, index, m_c_fwd, m_c_rev, m_c_mask]`.
    uint256 public constant APP_PUBLIC_INPUTS = 9;
    uint256 public constant ASSETS = 4;
    uint256 internal constant APP_WEIGHTS = 0;
    uint256 internal constant APP_ADDRESS = 4;
    uint256 internal constant APP_INDEX = 5;
    uint256 internal constant APP_M_FWD = 6;
    uint256 internal constant APP_M_REV = 7;
    uint256 internal constant APP_M_MASK = 8;
    /// @notice The opened output: the first 64 coefficients at 4 decimals
    ///         as big-endian `int128` words (`e3_trckks::program`).
    uint256 public constant OUTPUT_WORDS = 64;
    uint256 public constant OUTPUT_DECIMALS = 4;

    IHonkVerifier public immutable ct0Verifier;
    IHonkVerifier public immutable ct1Verifier;
    IHonkVerifier public immutable appVerifier;
    /// @notice Round opener allowed to register rounds.
    address public immutable owner;

    /// @notice One accepted submission.
    struct Submission {
        address dao;
        uint256 index;
        bytes32 forwardCiphertextHash;
        bytes32 reversedCiphertextHash;
        bytes32 maskCiphertextHash;
        bytes32 mCommitmentFwd;
        bytes32 mCommitmentRev;
        bytes32 mCommitmentMask;
        bytes32 uCommitmentFwd;
        bytes32 uCommitmentRev;
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

    /// @dev The seven-leg envelope, ABI-decoded from `publishInput`'s
    ///      `data` as a single nested tuple: `abi.encode(TreasurySubmission)`
    ///      — NOT a flat field list. Each `GrecoPair` is its own dynamic
    ///      tuple with head/tail offsets; encoders must spell out
    ///      `tuple((bytes,bytes,bytes32[],bytes,bytes32[]),
    ///             (bytes,bytes,bytes32[],bytes,bytes32[]),
    ///             (bytes,bytes,bytes32[],bytes,bytes32[]),
    ///             bytes,bytes32[])`
    ///      (see `test/CkksTreasuryE3Program.spec.ts::encodeSevenLegInput`).
    struct TreasurySubmission {
        GrecoPair forward;
        GrecoPair reversed;
        GrecoPair mask;
        bytes appProof;
        bytes32[] appPub;
    }

    /// @notice Whether a round is registered per E3.
    mapping(uint256 => bool) public roundRegistered;
    /// @notice The round's public risk weights (x 2^16, negatives as `p - |w|`).
    mapping(uint256 => bytes32[ASSETS]) internal _weights;
    /// @notice Registered DAO list per E3 (slot index = position).
    mapping(uint256 => address[]) internal _daos;
    /// @notice `index + 1` of a registered DAO (0 = not registered).
    mapping(uint256 => mapping(address => uint256)) public daoSlot;
    mapping(uint256 => Submission[]) internal _submissions;
    mapping(uint256 => mapping(bytes32 => bool)) public seenUCommitments;
    mapping(uint256 => mapping(address => bool)) public hasSubmitted;

    event RoundRegistered(uint256 indexed e3Id, bytes32[ASSETS] weights, uint256 daos);
    event SubmissionPublished(
        uint256 indexed e3Id,
        address indexed dao,
        uint256 index,
        bytes32 forwardCiphertextHash,
        bytes32 reversedCiphertextHash,
        bytes32 maskCiphertextHash,
        bytes32 mCommitmentFwd,
        bytes32 mCommitmentRev,
        bytes32 mCommitmentMask
    );

    error InvalidVerifierAddress();
    error NotOwner();
    error RoundAlreadyRegistered(uint256 e3Id);
    error RoundNotRegistered(uint256 e3Id);
    error NoDaos();
    error DuplicateDao(address dao);
    error InvalidInputEncoding();
    error WrongPublicInputCount(uint256 leg, uint256 got, uint256 want);
    error UCommitmentMismatch(uint256 ciphertext, bytes32 ct0Leg, bytes32 ct1Leg);
    error MCommitmentMismatch(uint256 ciphertext, bytes32 ct0Leg, bytes32 appLeg);
    error DuplicateSubmission(uint256 e3Id, bytes32 uCommitment);
    error AlreadySubmitted(uint256 e3Id, address dao);
    error WrongSender(address proven, address sender);
    error NotRegistered(uint256 e3Id, address dao);
    error WrongIndex(uint256 got, uint256 want);
    error WrongWeights(uint256 word, bytes32 got, bytes32 want);
    error Ct0ProofInvalid(uint256 ciphertext);
    error Ct1ProofInvalid(uint256 ciphertext);
    error AppProofInvalid();
    error InvalidOutputLength(uint256 got);

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

    /// @notice Registers a round once: the public risk weights (x 2^16,
    ///         negatives as `p - |w|`) and the DAO list (slot `i` = `daos[i]`).
    function registerRound(
        uint256 e3Id,
        bytes32[ASSETS] calldata weights,
        address[] calldata daos
    ) external {
        if (msg.sender != owner) revert NotOwner();
        if (roundRegistered[e3Id]) revert RoundAlreadyRegistered(e3Id);
        if (daos.length == 0) revert NoDaos();
        roundRegistered[e3Id] = true;
        _weights[e3Id] = weights;
        for (uint256 i = 0; i < daos.length; i++) {
            if (daoSlot[e3Id][daos[i]] != 0) revert DuplicateDao(daos[i]);
            daoSlot[e3Id][daos[i]] = i + 1;
            _daos[e3Id].push(daos[i]);
        }
        emit RoundRegistered(e3Id, weights, daos.length);
    }

    /// @inheritdoc IE3Program
    /// @dev `data` is the ABI encoding of [`TreasurySubmission`]. Each
    ///      helper below verifies ONE Greco pair or the validity leg and
    ///      returns only what the cross-leg binding needs.
    function publishInput(uint256 e3Id, bytes memory data) external {
        TreasurySubmission memory sub = abi.decode(data, (TreasurySubmission));
        if (sub.appPub.length != APP_PUBLIC_INPUTS) {
            revert WrongPublicInputCount(6, sub.appPub.length, APP_PUBLIC_INPUTS);
        }

        // Cross-leg bindings + policy checks (cheap) before any Honk verify.
        bytes32 uF = _checkGrecoPair(0, sub.forward, sub.appPub[APP_M_FWD]);
        bytes32 uR = _checkGrecoPair(1, sub.reversed, sub.appPub[APP_M_REV]);
        bytes32 uM = _checkGrecoPair(2, sub.mask, sub.appPub[APP_M_MASK]);
        uint256 index = _checkAppPublicInputs(e3Id, sub.appPub);
        _markSubmitted(e3Id, uF, uR, uM);

        // The seven proofs.
        _verifyGrecoPair(0, sub.forward);
        _verifyGrecoPair(1, sub.reversed);
        _verifyGrecoPair(2, sub.mask);
        if (!_verify(appVerifier, sub.appProof, sub.appPub)) revert AppProofInvalid();

        _record(e3Id, index, sub, uF, uR, uM);
    }

    /// @dev One submission per sender, every `u_commitment` new for the E3.
    function _markSubmitted(uint256 e3Id, bytes32 uF, bytes32 uR, bytes32 uM) internal {
        if (hasSubmitted[e3Id][msg.sender]) revert AlreadySubmitted(e3Id, msg.sender);
        if (seenUCommitments[e3Id][uF]) revert DuplicateSubmission(e3Id, uF);
        if (seenUCommitments[e3Id][uR] || uR == uF) revert DuplicateSubmission(e3Id, uR);
        if (seenUCommitments[e3Id][uM] || uM == uF || uM == uR) {
            revert DuplicateSubmission(e3Id, uM);
        }
        hasSubmitted[e3Id][msg.sender] = true;
        seenUCommitments[e3Id][uF] = true;
        seenUCommitments[e3Id][uR] = true;
        seenUCommitments[e3Id][uM] = true;
    }

    function _record(
        uint256 e3Id,
        uint256 index,
        TreasurySubmission memory sub,
        bytes32 uF,
        bytes32 uR,
        bytes32 uM
    ) internal {
        bytes32 hashF = keccak256(sub.forward.ciphertext);
        bytes32 hashR = keccak256(sub.reversed.ciphertext);
        bytes32 hashM = keccak256(sub.mask.ciphertext);
        _submissions[e3Id].push(
            Submission({
                dao: msg.sender,
                index: index,
                forwardCiphertextHash: hashF,
                reversedCiphertextHash: hashR,
                maskCiphertextHash: hashM,
                mCommitmentFwd: sub.appPub[APP_M_FWD],
                mCommitmentRev: sub.appPub[APP_M_REV],
                mCommitmentMask: sub.appPub[APP_M_MASK],
                uCommitmentFwd: uF,
                uCommitmentRev: uR,
                uCommitmentMask: uM
            })
        );
        emit SubmissionPublished(
            e3Id,
            msg.sender,
            index,
            hashF,
            hashR,
            hashM,
            sub.appPub[APP_M_FWD],
            sub.appPub[APP_M_REV],
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
    /// @dev Called by `InterfoldLifecycle` at CIPHERTEXT-output publish with
    ///      the ciphertext verifier's proof (the dev stack's mock), not with
    ///      the plaintext — the plaintext layout is checked by
    ///      [`decodeOutput`] / [`riskFromOutput`] once
    ///      `PlaintextOutputPublished` lands.
    function verify(
        uint256,
        bytes32,
        bytes32,
        bytes memory
    ) external pure returns (bool success) {
        return true;
    }

    /// @notice Decodes the opened plaintext: exactly `OUTPUT_WORDS`
    ///         big-endian `int128` words (the first 64 coefficients at
    ///         `OUTPUT_DECIMALS` decimals — `e3_trckks::program`). Reverts
    ///         on any other length: that is not this program's output.
    function decodeOutput(
        bytes memory plaintextOutput
    ) public pure returns (int128[OUTPUT_WORDS] memory words) {
        if (plaintextOutput.length != OUTPUT_WORDS * 16) revert InvalidOutputLength(plaintextOutput.length);
        for (uint256 i = 0; i < OUTPUT_WORDS; i++) {
            uint128 raw;
            for (uint256 b = 0; b < 16; b++) {
                raw = (raw << 8) | uint128(uint8(plaintextOutput[16 * i + b]));
            }
            words[i] = int128(raw);
        }
    }

    /// @notice The weighted concentration risk of the combined book, scaled
    ///         by `10^OUTPUT_DECIMALS`: `-coefficient_0` (the `t^N == -1`
    ///         wrap of `forward(x) * reversed(w o x)`).
    function riskFromOutput(bytes memory plaintextOutput) external pure returns (int128) {
        return -decodeOutput(plaintextOutput)[0];
    }

    function weights(uint256 e3Id) external view returns (bytes32[ASSETS] memory) {
        return _weights[e3Id];
    }

    function daos(uint256 e3Id) external view returns (address[] memory) {
        return _daos[e3Id];
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

    function _checkAppPublicInputs(
        uint256 e3Id,
        bytes32[] memory appPub
    ) internal view returns (uint256 index) {
        if (!roundRegistered[e3Id]) revert RoundNotRegistered(e3Id);
        {
            // `address` is a free field element in the circuit, so the
            // whole 256-bit word must equal the sender (no high bits).
            uint256 word = uint256(appPub[APP_ADDRESS]);
            address proven = address(uint160(word));
            if (word >> 160 != 0 || proven != msg.sender) {
                revert WrongSender(proven, msg.sender);
            }
        }
        {
            uint256 slot = daoSlot[e3Id][msg.sender];
            if (slot == 0) revert NotRegistered(e3Id, msg.sender);
            index = uint256(appPub[APP_INDEX]);
            if (index != slot - 1) revert WrongIndex(index, slot - 1);
        }
        bytes32[ASSETS] storage w = _weights[e3Id];
        for (uint256 a = 0; a < ASSETS; a++) {
            if (appPub[APP_WEIGHTS + a] != w[a]) {
                revert WrongWeights(APP_WEIGHTS + a, appPub[APP_WEIGHTS + a], w[a]);
            }
        }
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
