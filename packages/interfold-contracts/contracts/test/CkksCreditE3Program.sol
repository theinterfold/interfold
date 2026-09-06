// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
pragma solidity 0.8.28;

import { IE3Program } from "../interfaces/IE3Program.sol";
import { IHonkVerifier } from "./CkksE3Program.sol";

/// @title CkksCreditE3Program
/// @notice Private credit scoring v2 (CKKS ParamSet 4). An application is
///         TWO ciphertexts proven in FIVE legs: Greco ct0 + ct1 for the
///         LOGIT ciphertext, Greco ct0 + ct1 for the MASK ciphertext, and
///         the `ckks_credit_validity_ps4` proof that
///           * the logit message is the slot-`index` encoding of
///             `<w, x>/cap + b` under the round's REGISTERED model over
///             features `x_j in [0, cap]` whose leaf
///             `poseidon([address, x_0, .., x_7])` is under the round's
///             issuer root, every other slot 0;
///           * the mask message is the slot-`index` encoding of a value in
///             `[0, 1024)`, every other slot 0.
///
///         Validity-leg public inputs (15 words):
///         `[cap, address, merkle_root, index, w_0..w_7, bias, m_commitment_z, m_commitment_m]`.
///
///         Bindings the chain enforces:
///           * `address == msg.sender` (the applicant holds the attested address);
///           * `index` == the sender's position in the round's registered
///             applicant list (the round opener registers `[address]` with
///             the root, so slot assignment is public and unique);
///           * `[cap, w_0..w_7, bias]` == the round's registered model;
///           * `m_commitment_z` == the logit ct0 leg's `m_commitment`,
///             `m_commitment_m` == the mask ct0 leg's; each ct0/ct1 pair
///             shares its `u_commitment`; both `u_commitment`s are new for
///             the E3 (dedup), and one application per sender.
///
///         The network computes `sigma(z_i) + m_i` in slot `i` (two
///         ciphertext x ciphertext products under the committee's relin
///         keys); only applicant `i` (holding `m_i`) reads `sigma(z_i)`.
///         Scores are NOT decoded on-chain: the program records the two
///         ciphertext hashes and relays the opened output.
contract CkksCreditE3Program is IE3Program {
    bytes32 public constant ENCRYPTION_SCHEME_ID = keccak256("fhe.rs:CKKS");

    uint256 internal constant CT0_PUBLIC_INPUTS = 4;
    uint256 internal constant CT1_PUBLIC_INPUTS = 3;
    uint256 internal constant CT0_M_INDEX = 2;
    uint256 internal constant CT0_U_INDEX = 3;
    uint256 internal constant CT1_U_INDEX = 2;
    /// @dev `[cap, address, merkle_root, index, w_0..w_7, bias, m_c_z, m_c_m]`.
    uint256 public constant APP_PUBLIC_INPUTS = 15;
    uint256 public constant FEATURES = 8;
    uint256 internal constant APP_CAP = 0;
    uint256 internal constant APP_ADDRESS = 1;
    uint256 internal constant APP_ROOT = 2;
    uint256 internal constant APP_INDEX = 3;
    uint256 internal constant APP_WEIGHTS = 4;
    uint256 internal constant APP_BIAS = 12;
    uint256 internal constant APP_M_Z = 13;
    uint256 internal constant APP_M_M = 14;

    IHonkVerifier public immutable ct0Verifier;
    IHonkVerifier public immutable ct1Verifier;
    IHonkVerifier public immutable appVerifier;
    /// @notice Round opener allowed to register rounds.
    address public immutable owner;

    /// @notice A round's public model in the circuit's fixed point
    ///         (weights and bias x 2^16, negatives as `p - |w|`).
    struct Model {
        uint256 cap;
        bytes32[FEATURES] weights;
        bytes32 bias;
    }

    /// @notice One accepted application.
    struct Application {
        address applicant;
        uint256 index;
        bytes32 logitCiphertextHash;
        bytes32 maskCiphertextHash;
        bytes32 mCommitmentZ;
        bytes32 mCommitmentM;
        bytes32 uCommitmentZ;
        bytes32 uCommitmentM;
    }

    /// @dev Both Greco legs of ONE ciphertext.
    struct GrecoPair {
        bytes ciphertext;
        bytes ct0Proof;
        bytes32[] ct0Pub;
        bytes ct1Proof;
        bytes32[] ct1Pub;
    }

    /// @dev The five-leg application envelope, ABI-decoded from
    ///      `publishInput`'s `data` as a single nested tuple:
    ///      `abi.encode(CreditApplication)` — NOT a flat field list. Each
    ///      `GrecoPair` is its own dynamic tuple with head/tail offsets;
    ///      encoders must spell out
    ///      `tuple((bytes,bytes,bytes32[],bytes,bytes32[]),
    ///             (bytes,bytes,bytes32[],bytes,bytes32[]),
    ///             bytes,bytes32[])`
    ///      (see `test/CkksCreditE3Program.spec.ts::encodeFiveLegInput`).
    struct CreditApplication {
        GrecoPair logit;
        GrecoPair mask;
        bytes appProof;
        bytes32[] appPub;
    }

    /// @notice Issuer feature-snapshot Merkle root per E3 (0 = not registered).
    mapping(uint256 => bytes32) public issuerRoots;
    mapping(uint256 => Model) internal _models;
    /// @notice Registered applicant list per E3 (slot index = position).
    mapping(uint256 => address[]) internal _applicants;
    /// @notice `index + 1` of a registered applicant (0 = not registered).
    mapping(uint256 => mapping(address => uint256)) public applicantSlot;
    mapping(uint256 => Application[]) internal _applications;
    mapping(uint256 => mapping(bytes32 => bool)) public seenUCommitments;
    mapping(uint256 => mapping(address => bool)) public hasApplied;

    event RoundRegistered(
        uint256 indexed e3Id,
        bytes32 root,
        uint256 cap,
        uint256 applicants
    );
    event ApplicationPublished(
        uint256 indexed e3Id,
        address indexed applicant,
        uint256 index,
        bytes32 logitCiphertextHash,
        bytes32 maskCiphertextHash,
        bytes32 mCommitmentZ,
        bytes32 mCommitmentM
    );

    error InvalidVerifierAddress();
    error NotOwner();
    error InvalidRoot();
    error InvalidCap();
    error RoundAlreadyRegistered(uint256 e3Id);
    error RoundNotRegistered(uint256 e3Id);
    error NoApplicants();
    error DuplicateApplicant(address applicant);
    error InvalidInputEncoding();
    error WrongPublicInputCount(uint256 leg, uint256 got, uint256 want);
    error UCommitmentMismatch(uint256 ciphertext, bytes32 ct0Leg, bytes32 ct1Leg);
    error MCommitmentMismatch(uint256 ciphertext, bytes32 ct0Leg, bytes32 appLeg);
    error DuplicateSubmission(uint256 e3Id, bytes32 uCommitment);
    error AlreadyApplied(uint256 e3Id, address applicant);
    error WrongRoot(bytes32 got, bytes32 want);
    error WrongCap(uint256 got, uint256 want);
    error WrongSender(address proven, address sender);
    error NotRegistered(uint256 e3Id, address applicant);
    error WrongIndex(uint256 got, uint256 want);
    error WrongModel(uint256 word, bytes32 got, bytes32 want);
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

    /// @notice Registers a round once: the issuer root, the public model
    ///         and the applicant list (slot `i` = `applicants[i]`).
    function registerRound(
        uint256 e3Id,
        bytes32 root,
        Model calldata model,
        address[] calldata applicants
    ) external {
        if (msg.sender != owner) revert NotOwner();
        if (root == bytes32(0)) revert InvalidRoot();
        if (model.cap == 0 || model.cap >= (1 << 32)) revert InvalidCap();
        if (issuerRoots[e3Id] != bytes32(0)) revert RoundAlreadyRegistered(e3Id);
        if (applicants.length == 0) revert NoApplicants();
        issuerRoots[e3Id] = root;
        _models[e3Id] = model;
        for (uint256 i = 0; i < applicants.length; i++) {
            if (applicantSlot[e3Id][applicants[i]] != 0) {
                revert DuplicateApplicant(applicants[i]);
            }
            applicantSlot[e3Id][applicants[i]] = i + 1;
            _applicants[e3Id].push(applicants[i]);
        }
        emit RoundRegistered(e3Id, root, model.cap, applicants.length);
    }

    /// @inheritdoc IE3Program
    /// @dev `data` is the ABI encoding of [`CreditApplication`] (see it
    ///      for the flat field list). Each helper below verifies ONE
    ///      Greco pair or the validity leg and returns only what the
    ///      cross-leg binding needs, keeping the frame small.
    function publishInput(uint256 e3Id, bytes memory data) external {
        CreditApplication memory app = abi.decode(data, (CreditApplication));
        if (app.appPub.length != APP_PUBLIC_INPUTS) {
            revert WrongPublicInputCount(4, app.appPub.length, APP_PUBLIC_INPUTS);
        }

        // Cross-leg bindings + policy checks (cheap) before any Honk verify.
        bytes32 uZ = _checkGrecoPair(0, app.logit, app.appPub[APP_M_Z]);
        bytes32 uM = _checkGrecoPair(1, app.mask, app.appPub[APP_M_M]);
        uint256 index = _checkAppPublicInputs(e3Id, app.appPub);
        _markSubmitted(e3Id, uZ, uM);

        // The five proofs.
        _verifyGrecoPair(0, app.logit);
        _verifyGrecoPair(1, app.mask);
        if (!_verify(appVerifier, app.appProof, app.appPub)) revert AppProofInvalid();

        _record(e3Id, index, app, uZ, uM);
    }

    /// @dev One application per sender, every `u_commitment` new for the E3.
    function _markSubmitted(uint256 e3Id, bytes32 uZ, bytes32 uM) internal {
        if (hasApplied[e3Id][msg.sender]) revert AlreadyApplied(e3Id, msg.sender);
        if (seenUCommitments[e3Id][uZ]) revert DuplicateSubmission(e3Id, uZ);
        if (seenUCommitments[e3Id][uM] || uZ == uM) {
            revert DuplicateSubmission(e3Id, uM);
        }
        hasApplied[e3Id][msg.sender] = true;
        seenUCommitments[e3Id][uZ] = true;
        seenUCommitments[e3Id][uM] = true;
    }

    function _record(
        uint256 e3Id,
        uint256 index,
        CreditApplication memory app,
        bytes32 uZ,
        bytes32 uM
    ) internal {
        bytes32 hashZ = keccak256(app.logit.ciphertext);
        bytes32 hashM = keccak256(app.mask.ciphertext);
        _applications[e3Id].push(
            Application({
                applicant: msg.sender,
                index: index,
                logitCiphertextHash: hashZ,
                maskCiphertextHash: hashM,
                mCommitmentZ: app.appPub[APP_M_Z],
                mCommitmentM: app.appPub[APP_M_M],
                uCommitmentZ: uZ,
                uCommitmentM: uM
            })
        );
        emit ApplicationPublished(
            e3Id,
            msg.sender,
            index,
            hashZ,
            hashM,
            app.appPub[APP_M_Z],
            app.appPub[APP_M_M]
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
    function verify(
        uint256,
        bytes32,
        bytes32,
        bytes memory
    ) external pure returns (bool success) {
        return true;
    }

    function model(uint256 e3Id) external view returns (Model memory) {
        return _models[e3Id];
    }

    function applicants(uint256 e3Id) external view returns (address[] memory) {
        return _applicants[e3Id];
    }

    function applicationCount(uint256 e3Id) external view returns (uint256) {
        return _applications[e3Id].length;
    }

    function applicationAt(
        uint256 e3Id,
        uint256 i
    ) external view returns (Application memory) {
        return _applications[e3Id][i];
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
        bytes32 root = issuerRoots[e3Id];
        if (root == bytes32(0)) revert RoundNotRegistered(e3Id);
        if (appPub[APP_ROOT] != root) revert WrongRoot(appPub[APP_ROOT], root);
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
            uint256 slot = applicantSlot[e3Id][msg.sender];
            if (slot == 0) revert NotRegistered(e3Id, msg.sender);
            index = uint256(appPub[APP_INDEX]);
            if (index != slot - 1) revert WrongIndex(index, slot - 1);
        }
        _checkModel(e3Id, appPub);
    }

    /// @dev `[cap, w_0..w_7, bias]` of the proof against the stored round
    ///      model, one storage word at a time.
    function _checkModel(uint256 e3Id, bytes32[] memory appPub) internal view {
        Model storage m = _models[e3Id];
        if (uint256(appPub[APP_CAP]) != m.cap) {
            revert WrongCap(uint256(appPub[APP_CAP]), m.cap);
        }
        for (uint256 j = 0; j < FEATURES; j++) {
            if (appPub[APP_WEIGHTS + j] != m.weights[j]) {
                revert WrongModel(APP_WEIGHTS + j, appPub[APP_WEIGHTS + j], m.weights[j]);
            }
        }
        if (appPub[APP_BIAS] != m.bias) {
            revert WrongModel(APP_BIAS, appPub[APP_BIAS], m.bias);
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
