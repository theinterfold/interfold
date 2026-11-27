// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity 0.8.28;

import { IDecryptionVerifier } from "../../interfaces/IDecryptionVerifier.sol";
import { ICircuitVerifier } from "../../interfaces/ICircuitVerifier.sol";
import { ICiphernodeRegistry } from "../../interfaces/ICiphernodeRegistry.sol";
import {
    ISynchronizedDkgPublication
} from "../../interfaces/ISynchronizedDkgPublication.sol";
import { BfvProtocol } from "../../lib/BfvProtocol.sol";
import { CommitteeHashLib } from "../../lib/CommitteeHashLib.sol";

/// @notice Direct C6/C7 verifier for the disabled synchronized Minimum definition.
/// @dev The lifecycle supplies request-bound call arguments. The fixed registry supplies
/// the independently published v1 setup. Synchronized owner IDs are zero-based in both.
contract SynchronizedDecryptionVerifier is IDecryptionVerifier {
    error InvalidConfiguration();
    error InvalidSynchronizedAuthority();
    error NonCanonicalPublicInput(uint256 index);
    error MessageCoefficientOutOfRange(uint256 index);

    uint256 private constant SCALAR_MODULUS =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;
    uint256 private constant H = BfvProtocol.MINIMUM_H;
    uint256 public constant override threshold = BfvProtocol.MINIMUM_T;
    // setup[2], owner, roster[H], domain[2], SK, bundle, ct, d, c0.
    uint256 private constant ROW = 10 + H;
    uint256 private constant MESSAGE = 2 + (threshold + 1) * ROW;

    ICircuitVerifier public immutable CIRCUIT_VERIFIER;
    ISynchronizedDkgPublication public immutable REGISTRY;
    bytes32 public immutable CRYPTO_CONFIG_ID;
    bytes32 public immutable C6_KEY_HASH;
    bytes32 public immutable C7_KEY_HASH;

    constructor(address honk, address registry, bytes32 configId) {
        (bytes32 c6, bytes32 c7) = BfvProtocol.synchronizedMinimumChildKeys(
            configId
        );
        if (
            honk.code.length == 0 ||
            registry.code.length == 0 ||
            c6 == 0 ||
            c7 == 0
        ) revert InvalidConfiguration();
        CIRCUIT_VERIFIER = ICircuitVerifier(honk);
        REGISTRY = ISynchronizedDkgPublication(registry);
        CRYPTO_CONFIG_ID = configId;
        C6_KEY_HASH = c6;
        C7_KEY_HASH = c7;
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
        (bytes memory raw, bytes32[] memory fields) = abi.decode(
            proof,
            (bytes, bytes32[])
        );
        if (fields.length != MESSAGE + BfvProtocol.MESSAGE_COEFFS_COUNT)
            revert InvalidPublicInputsLength();
        for (uint256 i; i < MESSAGE; ++i) {
            if (uint256(fields[i]) >= SCALAR_MODULUS)
                revert NonCanonicalPublicInput(i);
        }
        if (fields[0] != C6_KEY_HASH || fields[1] != C7_KEY_HASH)
            revert VkHashMismatch();
        ISynchronizedDkgPublication.Authority memory a = REGISTRY
            .getSynchronizedDkgAuthority(e3Id);
        if (
            a.version != 1 ||
            a.cryptoConfigId != CRYPTO_CONFIG_ID ||
            a.partyIds.length != H ||
            a.skAggCommits.length != H ||
            a.keyBundleCommits.length != H
        ) revert InvalidSynchronizedAuthority();
        if (
            ICiphernodeRegistry(address(REGISTRY)).getCommitteeHash(e3Id) !=
            committeeHash
        ) revert DomainBindingMismatch();
        for (uint256 i; i <= threshold; ++i) {
            uint256 p = 2 + i * ROW;
            if (
                fields[p] != CommitteeHashLib.hi(a.setupBinding) ||
                fields[p + 1] != CommitteeHashLib.lo(a.setupBinding) ||
                fields[p + 3 + H] != CommitteeHashLib.hi(decryptionDomain) ||
                fields[p + 4 + H] != CommitteeHashLib.lo(decryptionDomain)
            ) revert DomainBindingMismatch();
            if (
                uint256(fields[p + 2]) != a.partyIds[i] ||
                fields[p + 5 + H] != a.skAggCommits[i] ||
                fields[p + 6 + H] != a.keyBundleCommits[i]
            ) revert DkgAnchorMismatch();
            for (uint256 j; j < H; ++j) {
                if (uint256(fields[p + 3 + j]) != a.partyIds[j])
                    revert DkgAnchorMismatch();
            }
            if (fields[p + 7 + H] != ciphertextCommitment)
                revert CiphertextCommitmentMismatch();
        }
        bytes memory plaintext = new bytes(BfvProtocol.PLAINTEXT_BYTE_LEN);
        for (uint256 i; i < BfvProtocol.MESSAGE_COEFFS_COUNT; ++i) {
            uint256 coeff = uint256(fields[MESSAGE + i]);
            if (coeff > type(uint64).max)
                revert MessageCoefficientOutOfRange(MESSAGE + i);
            for (uint256 j; j < BfvProtocol.MESSAGE_COEFF_BYTE_LEN; ++j) {
                plaintext[i * BfvProtocol.MESSAGE_COEFF_BYTE_LEN + j] = bytes1(
                    uint8(coeff >> (8 * j))
                );
            }
        }
        if (keccak256(plaintext) != plaintextOutputHash)
            revert PlaintextHashMismatch();
        if (!CIRCUIT_VERIFIER.verify(raw, fields)) revert InvalidProof();
        return true;
    }
}
