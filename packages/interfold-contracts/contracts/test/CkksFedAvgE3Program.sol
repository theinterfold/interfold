// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
pragma solidity 0.8.28;

import { IE3Program } from "../interfaces/IE3Program.sol";
import { IHonkVerifier } from "./CkksE3Program.sol";

/// @title CkksFedAvgE3Program
/// @notice Private federated averaging (CKKS ParamSet 5). One client update
///         is TWO ciphertexts proven in FIVE legs: Greco ct0 + ct1 for the
///         GRADIENT ciphertext, Greco ct0 + ct1 for the COUNT ciphertext,
///         and the `ckks_fedavg_validity_ps5` proof that
///           * the gradient message is `gradient_block(g)`: entries
///             `g_j in [-1, 1]` on coefficients `1..=D`, the `1.0` marker on
///             coefficient `D + 1`, zero elsewhere, with
///             `sum_j g_j^2 <= normBound` (the round's poisoning bound);
///           * the count message is `constant(n)`: the client's PRIVATE
///             sample count `1 <= n < 1024` on coefficient 0, zero elsewhere.
///
///         Validity-leg public inputs (5 words):
///         `[norm_bound, address, index, m_commitment_grad, m_commitment_count]`.
///
///         Bindings the chain enforces:
///           * `address == msg.sender` (the client signs its own update);
///           * `index` == the sender's position in the round's registered
///             client list;
///           * `norm_bound` == the round's registered bound;
///           * `m_commitment_grad` == the gradient ct0 leg's `m_commitment`,
///             `m_commitment_count` == the count ct0 leg's; each ct0/ct1
///             pair shares its `u_commitment`; both `u_commitment`s are new
///             for the E3 (dedup), and one update per sender.
///
///         The network computes `sum_i n_i * G_i` (one ct x ct product per
///         client under the committee's level-0 relin key) and opens ONE
///         ciphertext: coefficient `j + 1` = `sum_i n_i g_{i,j}`, coefficient
///         `D + 1` = `sum_i n_i`. The sample-weighted mean is the ratio.
///         Neither any client's update nor its sample count is revealed;
///         the aggregate IS public (the usual FedAvg leakage), which is why
///         the round carries a public minimum client count the coordination
///         server enforces before evaluating.
contract CkksFedAvgE3Program is IE3Program {
    bytes32 public constant ENCRYPTION_SCHEME_ID = keccak256("fhe.rs:CKKS");

    uint256 internal constant CT0_PUBLIC_INPUTS = 4;
    uint256 internal constant CT1_PUBLIC_INPUTS = 3;
    uint256 internal constant CT0_M_INDEX = 2;
    uint256 internal constant CT0_U_INDEX = 3;
    uint256 internal constant CT1_U_INDEX = 2;
    /// @dev `[norm_bound, address, index, m_c_grad, m_c_count]`.
    uint256 public constant APP_PUBLIC_INPUTS = 5;
    uint256 internal constant APP_NORM_BOUND = 0;
    uint256 internal constant APP_ADDRESS = 1;
    uint256 internal constant APP_INDEX = 2;
    uint256 internal constant APP_M_GRAD = 3;
    uint256 internal constant APP_M_COUNT = 4;
    /// @notice Model-update dimension compiled into the validity circuit.
    uint256 public constant D = 8;
    /// @notice `norm_bound` is `B * 2^32` and must fit the circuit's 40-bit window.
    uint256 public constant NORM_BOUND_BITS = 40;
    /// @notice Opened output: the first 64 coefficients as big-endian `int128`
    ///         words at `OUTPUT_DECIMALS` decimals (`e3_trckks::program`).
    uint256 public constant OUTPUT_WORDS = 64;
    uint256 public constant OUTPUT_DECIMALS = 4;

    IHonkVerifier public immutable ct0Verifier;
    IHonkVerifier public immutable ct1Verifier;
    IHonkVerifier public immutable appVerifier;
    /// @notice Round opener allowed to register rounds.
    address public immutable owner;

    /// @notice One accepted update.
    struct Submission {
        address client;
        uint256 index;
        bytes32 gradientCiphertextHash;
        bytes32 countCiphertextHash;
        bytes32 mCommitmentGrad;
        bytes32 mCommitmentCount;
        bytes32 uCommitmentGrad;
        bytes32 uCommitmentCount;
    }

    /// @dev Both Greco legs of ONE ciphertext.
    struct GrecoPair {
        bytes ciphertext;
        bytes ct0Proof;
        bytes32[] ct0Pub;
        bytes ct1Proof;
        bytes32[] ct1Pub;
    }

    /// @dev The five-leg update envelope, ABI-decoded from `publishInput`'s
    ///      `data` as a single nested tuple: `abi.encode(Update)` — NOT a
    ///      flat field list. Each `GrecoPair` is its own dynamic tuple with
    ///      head/tail offsets; encoders must spell out
    ///      `tuple((bytes,bytes,bytes32[],bytes,bytes32[]),
    ///             (bytes,bytes,bytes32[],bytes,bytes32[]),
    ///             bytes,bytes32[])`
    ///      (see `test/CkksFedAvgE3Program.spec.ts::encodeFiveLegInput`).
    struct Update {
        GrecoPair gradient;
        GrecoPair count;
        bytes appProof;
        bytes32[] appPub;
    }

    /// @notice A round's public parameters.
    struct Round {
        /// `B * 2^32`: the squared-norm bound every update proves against.
        uint256 normBound;
        /// Minimum accepted updates before the server evaluates (public).
        uint256 minClients;
        bool registered;
    }

    mapping(uint256 => Round) internal _rounds;
    /// @notice Registered client list per E3 (slot index = position).
    mapping(uint256 => address[]) internal _clients;
    /// @notice `index + 1` of a registered client (0 = not registered).
    mapping(uint256 => mapping(address => uint256)) public clientSlot;
    mapping(uint256 => Submission[]) internal _submissions;
    mapping(uint256 => mapping(bytes32 => bool)) public seenUCommitments;
    mapping(uint256 => mapping(address => bool)) public hasSubmitted;

    event RoundRegistered(
        uint256 indexed e3Id,
        uint256 normBound,
        uint256 minClients,
        uint256 clients
    );
    event UpdatePublished(
        uint256 indexed e3Id,
        address indexed client,
        uint256 index,
        bytes32 gradientCiphertextHash,
        bytes32 countCiphertextHash,
        bytes32 mCommitmentGrad,
        bytes32 mCommitmentCount
    );

    error InvalidVerifierAddress();
    error NotOwner();
    error InvalidNormBound();
    error InvalidMinClients(uint256 minClients, uint256 clients);
    error RoundAlreadyRegistered(uint256 e3Id);
    error RoundNotRegistered(uint256 e3Id);
    error NoClients();
    error DuplicateClient(address client);
    error InvalidInputEncoding();
    error WrongPublicInputCount(uint256 leg, uint256 got, uint256 want);
    error UCommitmentMismatch(uint256 ciphertext, bytes32 ct0Leg, bytes32 ct1Leg);
    error MCommitmentMismatch(uint256 ciphertext, bytes32 ct0Leg, bytes32 appLeg);
    error DuplicateSubmission(uint256 e3Id, bytes32 uCommitment);
    error AlreadySubmitted(uint256 e3Id, address client);
    error WrongNormBound(uint256 got, uint256 want);
    error WrongSender(address proven, address sender);
    error NotRegistered(uint256 e3Id, address client);
    error WrongIndex(uint256 got, uint256 want);
    error Ct0ProofInvalid(uint256 ciphertext);
    error Ct1ProofInvalid(uint256 ciphertext);
    error AppProofInvalid();
    error InvalidOutputLength(uint256 length);
    error ZeroTotalCount();

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

    /// @notice Registers a round once: the squared-norm bound (`B * 2^32`),
    ///         the public minimum client count and the client list
    ///         (slot `i` = `clients[i]`).
    function registerRound(
        uint256 e3Id,
        uint256 normBound,
        uint256 minClients,
        address[] calldata clientList
    ) external {
        if (msg.sender != owner) revert NotOwner();
        if (normBound == 0 || normBound >= (1 << NORM_BOUND_BITS)) revert InvalidNormBound();
        if (_rounds[e3Id].registered) revert RoundAlreadyRegistered(e3Id);
        if (clientList.length == 0) revert NoClients();
        if (minClients == 0 || minClients > clientList.length) {
            revert InvalidMinClients(minClients, clientList.length);
        }
        _rounds[e3Id] = Round({ normBound: normBound, minClients: minClients, registered: true });
        for (uint256 i = 0; i < clientList.length; i++) {
            if (clientSlot[e3Id][clientList[i]] != 0) revert DuplicateClient(clientList[i]);
            clientSlot[e3Id][clientList[i]] = i + 1;
            _clients[e3Id].push(clientList[i]);
        }
        emit RoundRegistered(e3Id, normBound, minClients, clientList.length);
    }

    /// @inheritdoc IE3Program
    /// @dev `data` is the ABI encoding of [`Update`]. Each helper below
    ///      verifies ONE Greco pair or the validity leg and returns only what
    ///      the cross-leg binding needs, keeping the frame small.
    function publishInput(uint256 e3Id, bytes memory data) external {
        Update memory upd = abi.decode(data, (Update));
        if (upd.appPub.length != APP_PUBLIC_INPUTS) {
            revert WrongPublicInputCount(4, upd.appPub.length, APP_PUBLIC_INPUTS);
        }

        // Cross-leg bindings + policy checks (cheap) before any Honk verify.
        bytes32 uG = _checkGrecoPair(0, upd.gradient, upd.appPub[APP_M_GRAD]);
        bytes32 uC = _checkGrecoPair(1, upd.count, upd.appPub[APP_M_COUNT]);
        uint256 index = _checkAppPublicInputs(e3Id, upd.appPub);
        _markSubmitted(e3Id, uG, uC);

        // The five proofs.
        _verifyGrecoPair(0, upd.gradient);
        _verifyGrecoPair(1, upd.count);
        if (!_verify(appVerifier, upd.appProof, upd.appPub)) revert AppProofInvalid();

        _record(e3Id, index, upd, uG, uC);
    }

    /// @dev One update per sender, every `u_commitment` new for the E3.
    function _markSubmitted(uint256 e3Id, bytes32 uG, bytes32 uC) internal {
        if (hasSubmitted[e3Id][msg.sender]) revert AlreadySubmitted(e3Id, msg.sender);
        if (seenUCommitments[e3Id][uG]) revert DuplicateSubmission(e3Id, uG);
        if (seenUCommitments[e3Id][uC] || uG == uC) revert DuplicateSubmission(e3Id, uC);
        hasSubmitted[e3Id][msg.sender] = true;
        seenUCommitments[e3Id][uG] = true;
        seenUCommitments[e3Id][uC] = true;
    }

    function _record(
        uint256 e3Id,
        uint256 index,
        Update memory upd,
        bytes32 uG,
        bytes32 uC
    ) internal {
        bytes32 hashG = keccak256(upd.gradient.ciphertext);
        bytes32 hashC = keccak256(upd.count.ciphertext);
        _submissions[e3Id].push(
            Submission({
                client: msg.sender,
                index: index,
                gradientCiphertextHash: hashG,
                countCiphertextHash: hashC,
                mCommitmentGrad: upd.appPub[APP_M_GRAD],
                mCommitmentCount: upd.appPub[APP_M_COUNT],
                uCommitmentGrad: uG,
                uCommitmentCount: uC
            })
        );
        emit UpdatePublished(
            e3Id,
            msg.sender,
            index,
            hashG,
            hashC,
            upd.appPub[APP_M_GRAD],
            upd.appPub[APP_M_COUNT]
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
    /// @dev Called by Interfold with the keccak of the ciphertext output; the
    ///      dev stack's ciphertext verifier is the mock. The opened plaintext
    ///      is checked by `decodeOutput` / `meanFromOutput` (64 int128 words).
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

    /// @notice The sample-weighted mean update and the total sample count
    ///         from the opened plaintext: `mean[j] = words[j+1] / words[D+1]`
    ///         scaled by `10^OUTPUT_DECIMALS` (integer division toward zero);
    ///         `totalCount = words[D+1] / 10^OUTPUT_DECIMALS` rounded.
    function meanFromOutput(
        bytes memory plaintextOutput
    ) external pure returns (int128[D] memory mean, int128 totalCount) {
        int128[OUTPUT_WORDS] memory words = decodeOutput(plaintextOutput);
        int128 total = words[D + 1];
        if (total <= 0) revert ZeroTotalCount();
        int128 scale = int128(int256(10 ** OUTPUT_DECIMALS));
        for (uint256 j = 0; j < D; j++) {
            mean[j] = (words[j + 1] * scale) / total;
        }
        totalCount = (total + scale / 2) / scale;
    }

    function round(uint256 e3Id) external view returns (Round memory) {
        return _rounds[e3Id];
    }

    function clients(uint256 e3Id) external view returns (address[] memory) {
        return _clients[e3Id];
    }

    function submissionCount(uint256 e3Id) external view returns (uint256) {
        return _submissions[e3Id].length;
    }

    function submissionAt(uint256 e3Id, uint256 i) external view returns (Submission memory) {
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
        Round storage r = _rounds[e3Id];
        if (!r.registered) revert RoundNotRegistered(e3Id);
        if (uint256(appPub[APP_NORM_BOUND]) != r.normBound) {
            revert WrongNormBound(uint256(appPub[APP_NORM_BOUND]), r.normBound);
        }
        {
            // `address` is a free field element in the circuit, so the
            // whole 256-bit word must equal the sender (no high bits).
            uint256 word = uint256(appPub[APP_ADDRESS]);
            address proven = address(uint160(word));
            if (word >> 160 != 0 || proven != msg.sender) revert WrongSender(proven, msg.sender);
        }
        uint256 slot = clientSlot[e3Id][msg.sender];
        if (slot == 0) revert NotRegistered(e3Id, msg.sender);
        index = uint256(appPub[APP_INDEX]);
        if (index != slot - 1) revert WrongIndex(index, slot - 1);
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
