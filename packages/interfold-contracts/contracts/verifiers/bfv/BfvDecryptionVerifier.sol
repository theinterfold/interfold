// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
pragma solidity 0.8.28;

import { IDecryptionVerifier } from "../../interfaces/IDecryptionVerifier.sol";
import { ICircuitVerifier } from "../../interfaces/ICircuitVerifier.sol";
import { ICiphernodeRegistry } from "../../interfaces/ICiphernodeRegistry.sol";
import { CommitteeHashLib } from "../../lib/CommitteeHashLib.sol";

/**
 * @title BfvDecryptionVerifier
 * @notice Verifies the DecryptionAggregator (EVM) proof produced by the
 *         recursive aggregation pipeline (C6 folds + C7/decrypted_shares
 *         verified internally) and binds it to the full on-chain call context.
 * @dev Used when the Interfold is configured with encryptionSchemeId
 *      keccak256("fhe.rs:BFV"). Constructor `threshold` must match the
 *      compiled DecryptionAggregator circuit `T` (`lib::configs::default::T`).
 *
 *      Expected `publicInputs` layout for DecryptionAggregator EVM outputs:
 *        [0]                = expectedC6FoldKeyHash  (complete VK-tree anchor)
 *        [1]                = expectedC7KeyHash      (VK anchor)
 *        [2]                = committee_hash_hi
 *        [3]                = committee_hash_lo
 *        [4]                = decryption_domain_hi
 *        [5]                = decryption_domain_lo
 *        [6]                = ciphertext_commitment
 *        [7]                = aggregate recursive VK key hash
 *        [8 .. 8+3*(T+1))  = party_ids, expected_sk, expected_esm columns
 *        [last 50]          = plaintext message coefficients (50 u64 LE)
 *        Total: expectedPublicInputsLen = 7 + 1 + 3*(T+1) + 50.
 *
 *      The two VK-hash slots are checked against contract immutables set at
 *      construction; this anchors the recursive aggregation trust and
 *      prevents a malicious aggregator from substituting a forged sub-VK.
 *
 *      The `party_ids`/`expected_sk`/`expected_esm` columns are cross-checked
 *      against `ciphernodeRegistry.getDkgAnchors(e3Id)` (`_verifyDkgAnchors`):
 *      the circuit only proves a decryption share is internally consistent
 *      with some self-declared commitment, so this binds that commitment to
 *      the address-signed DKG output actually recorded for this E3.
 *
 *      Each secret-bearing C6 proof commits to the same domain limbs. C6Fold
 *      preserves them, and DecryptionAggregator exposes them here, so an
 *      aggregator cannot re-label an existing proof for another E3.
 *
 *      The domain prevents cross-context replay, the SAFE ciphertext commitment
 *      binds the final proof to the stored circuit-compatible commitment, and
 *      the DKG anchors bind the proof's secret-bearing commitments to the
 *      authenticated DKG output.
 */
contract BfvDecryptionVerifier is IDecryptionVerifier {
    error InvalidCircuitVerifier(address verifier);
    error InvalidVerificationKeyHash();
    error NonCanonicalPublicInput(uint256 index);
    error MessageCoefficientOutOfRange(uint256 index);

    uint256 internal constant BN254_SCALAR_MODULUS =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    /// @dev Message is always the last 50 public inputs (50 uint64 coeffs = 400 bytes plaintext).
    uint256 internal constant MESSAGE_COEFFS_COUNT = 50;

    /// @dev `decryption_aggregator` return tail: `1 + 3*(T+1) + MESSAGE_COEFFS_COUNT` fields.
    uint256 internal constant DEC_RETURN_PREFIX_LEN = 1;

    /// @dev `decryption_aggregator` return columns after the leading key hash
    ///      (party_ids, expected_sk, expected_esm).
    uint256 internal constant DEC_RETURN_COLUMN_COUNT = 3;

    /// @dev `publicInputs` index for `committee_hash_hi` (after sub-circuit key hashes).
    uint256 internal constant COMMITTEE_HASH_HI_IDX = 2;

    /// @dev `publicInputs` index for `committee_hash_lo`.
    uint256 internal constant COMMITTEE_HASH_LO_IDX = 3;

    /// @dev Public input indices for the E3 decryption-domain limbs.
    uint256 internal constant DECRYPTION_DOMAIN_HI_IDX = 4;
    uint256 internal constant DECRYPTION_DOMAIN_LO_IDX = 5;
    uint256 internal constant CIPHERTEXT_COMMITMENT_IDX = 6;

    /// @notice BFV threshold `T`; must match the compiled DecryptionAggregator circuit.
    uint256 public immutable override threshold;

    /// @dev `7 + DEC_RETURN_PREFIX_LEN + DEC_RETURN_COLUMN_COUNT*(T+1) + MESSAGE_COEFFS_COUNT`.
    uint256 internal immutable expectedPublicInputsLen;

    /// @dev `publicInputs` start index of the `party_ids[T+1]` column.
    ///      Circuit-side `party_ids` are 1-indexed Shamir x-coordinates
    ///      (1..N_PARTIES); the registry's `dkgPartyIds` are 0-indexed
    ///      sortition slots, so comparisons subtract 1 (see `_verifyDkgAnchors`).
    uint256 internal immutable partyIdColOffset;

    /// @dev `publicInputs` start index of the `expected_sk[T+1]` column.
    uint256 internal immutable skColOffset;

    /// @dev `publicInputs` start index of the `expected_esm[T+1]` column.
    uint256 internal immutable esmColOffset;

    /// @notice Underlying Honk verifier for the DecryptionAggregator circuit.
    ICircuitVerifier public immutable circuitVerifier;

    /// @notice Registry holding the per-E3 DKG anchors (`dkgPartyIds`,
    ///         `dkgSkAggCommits`, `dkgEsmAggCommits`) that the proof's
    ///         `party_ids`/`expected_sk`/`expected_esm` outputs must match.
    ICiphernodeRegistry public immutable ciphernodeRegistry;

    /// @notice SAFE commitment to the C6 fold, genesis, and leaf VKs.
    ///         Expected at `publicInputs[0]`. The builder writes
    ///         `c6_fold.vk_tree_hash` from the complete artifact pair.
    bytes32 public immutable expectedC6FoldKeyHash;

    /// @notice Barretenberg hash of the C7 non-ZK recursive VK.
    ///         Expected at `publicInputs[1]` from `decrypted_shares_aggregation.vk_hash`.
    bytes32 public immutable expectedC7KeyHash;

    constructor(
        address _circuitVerifier,
        address _ciphernodeRegistry,
        bytes32 _expectedC6FoldKeyHash,
        bytes32 _expectedC7KeyHash,
        uint256 _threshold
    ) {
        require(_threshold > 0, "BfvDecryptionVerifier: threshold=0");
        if (_circuitVerifier.code.length == 0) {
            revert InvalidCircuitVerifier(_circuitVerifier);
        }
        if (
            _expectedC6FoldKeyHash == bytes32(0) ||
            _expectedC7KeyHash == bytes32(0)
        ) revert InvalidVerificationKeyHash();
        threshold = _threshold;
        expectedPublicInputsLen =
            7 +
            DEC_RETURN_PREFIX_LEN +
            (DEC_RETURN_COLUMN_COUNT * (_threshold + 1)) +
            MESSAGE_COEFFS_COUNT;

        partyIdColOffset = 7 + DEC_RETURN_PREFIX_LEN;
        skColOffset = partyIdColOffset + (_threshold + 1);
        esmColOffset = skColOffset + (_threshold + 1);

        circuitVerifier = ICircuitVerifier(_circuitVerifier);
        ciphernodeRegistry = ICiphernodeRegistry(_ciphernodeRegistry);
        expectedC6FoldKeyHash = _expectedC6FoldKeyHash;
        expectedC7KeyHash = _expectedC7KeyHash;
    }

    /// @inheritdoc IDecryptionVerifier
    function verify(
        uint256 e3Id,
        bytes32 decryptionDomain,
        bytes32 plaintextOutputHash,
        bytes32 committeeHash,
        bytes32 ciphertextCommitment,
        bytes calldata proof
    ) external view override returns (bool) {
        (bytes memory rawProof, bytes32[] memory publicInputs) = abi.decode(
            proof,
            (bytes, bytes32[])
        );

        if (publicInputs.length != expectedPublicInputsLen) {
            revert InvalidPublicInputsLength();
        }
        _validatePublicInputs(publicInputs);

        // Anchor recursive-aggregation trust to immutable VK hashes.
        if (publicInputs[0] != expectedC6FoldKeyHash) {
            revert VkHashMismatch();
        }
        if (publicInputs[1] != expectedC7KeyHash) {
            revert VkHashMismatch();
        }

        // Bind to the on-chain committee hash (hi/lo split per Noir field convention).
        if (
            publicInputs[COMMITTEE_HASH_HI_IDX] !=
            CommitteeHashLib.hi(committeeHash)
        ) {
            revert DomainBindingMismatch();
        }
        if (
            publicInputs[COMMITTEE_HASH_LO_IDX] !=
            CommitteeHashLib.lo(committeeHash)
        ) {
            revert DomainBindingMismatch();
        }
        if (
            publicInputs[DECRYPTION_DOMAIN_HI_IDX] !=
            CommitteeHashLib.hi(decryptionDomain)
        ) {
            revert DomainBindingMismatch();
        }
        if (
            publicInputs[DECRYPTION_DOMAIN_LO_IDX] !=
            CommitteeHashLib.lo(decryptionDomain)
        ) {
            revert DomainBindingMismatch();
        }

        if (publicInputs[CIPHERTEXT_COMMITMENT_IDX] != ciphertextCommitment) {
            revert CiphertextCommitmentMismatch();
        }

        // Plaintext hash check: 50-coefficient plaintext must hash to the claimed value.
        if (!_verifyPlaintextHash(publicInputs, plaintextOutputHash)) {
            revert PlaintextHashMismatch();
        }

        // Cross-phase binding: the proof's per-party sk/esm commitments must match
        // the DKG anchors this registry recorded (address-signed) for this E3.
        _verifyDkgAnchors(e3Id, publicInputs);

        // Bubble up as a revert instead of a silent `false`.
        if (!circuitVerifier.verify(rawProof, publicInputs)) {
            revert InvalidProof();
        }
        return true;
    }

    function _validatePublicInputs(
        bytes32[] memory publicInputs
    ) internal view {
        uint256 messageOffset = expectedPublicInputsLen - MESSAGE_COEFFS_COUNT;
        for (uint256 i = 0; i < publicInputs.length; ++i) {
            uint256 value = uint256(publicInputs[i]);
            if (value >= BN254_SCALAR_MODULUS) {
                revert NonCanonicalPublicInput(i);
            }
            if (i >= messageOffset && value > type(uint64).max) {
                revert MessageCoefficientOutOfRange(i);
            }
        }
    }

    function _verifyPlaintextHash(
        bytes32[] memory publicInputs,
        bytes32 expected
    ) internal view returns (bool) {
        uint256 offset = expectedPublicInputsLen - MESSAGE_COEFFS_COUNT;
        bytes memory plaintext = new bytes(MESSAGE_COEFFS_COUNT * 8);
        for (uint256 i = 0; i < MESSAGE_COEFFS_COUNT; i++) {
            uint64 coeff = uint64(uint256(publicInputs[offset + i]));
            for (uint256 j = 0; j < 8; j++) {
                plaintext[i * 8 + j] = bytes1(uint8(coeff >> (j * 8)));
            }
        }
        return keccak256(plaintext) == expected;
    }

    /// @dev Binds the proof's `party_ids`/`expected_sk`/`expected_esm` outputs to the
    ///      registry's stored DKG anchors for this E3, closing the gap where the circuit
    ///      only proves internal self-consistency ("I know a share matching some claimed
    ///      commitment") without tying that commitment to the address-signed DKG output.
    ///
    ///      Index note: circuit `party_ids` are 1-indexed Shamir x-coordinates
    ///      (1..N_PARTIES); `getDkgAnchors` returns the registry's 0-indexed sortition
    ///      `party_id` (matching `topNodes`/`canonicalCommitteeNodeAt`). Subtract 1
    ///      before comparing.
    function _verifyDkgAnchors(
        uint256 e3Id,
        bytes32[] memory publicInputs
    ) internal view {
        (
            uint256[] memory dkgPartyIds,
            bytes32[] memory dkgSkAggCommits,
            bytes32[] memory dkgEsmAggCommits
        ) = ciphernodeRegistry.getDkgAnchors(e3Id);

        for (uint256 i = 0; i < threshold + 1; i++) {
            uint256 circuitPartyId = uint256(
                publicInputs[partyIdColOffset + i]
            );
            uint256 registryPartyId = circuitPartyId - 1;

            uint256 matchedIdx = type(uint256).max;
            for (uint256 j = 0; j < dkgPartyIds.length; j++) {
                if (dkgPartyIds[j] == registryPartyId) {
                    matchedIdx = j;
                    break;
                }
            }
            if (matchedIdx == type(uint256).max) {
                revert DkgAnchorNotFound();
            }

            if (
                publicInputs[skColOffset + i] != dkgSkAggCommits[matchedIdx] ||
                publicInputs[esmColOffset + i] != dkgEsmAggCommits[matchedIdx]
            ) {
                revert DkgAnchorMismatch();
            }
        }
    }
}
