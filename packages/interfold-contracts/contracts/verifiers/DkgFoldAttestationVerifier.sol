// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

pragma solidity 0.8.28;

import { E3 } from "../interfaces/IE3.sol";
import { ICiphernodeRegistry } from "../interfaces/ICiphernodeRegistry.sol";
import {
    IDkgFoldAttestationVerifier
} from "../interfaces/IDkgFoldAttestationVerifier.sol";
import { ActiveCryptoConfig } from "../lib/ActiveCryptoConfig.sol";
import { BfvPkV2Layout } from "../lib/BfvPkV2Layout.sol";
import { DkgFoldAttestationLib } from "../lib/DkgFoldAttestationLib.sol";

/**
 * @title DkgFoldAttestationVerifier
 * @notice Stateless verifier for DKG fold attestations at committee publication.
 */
contract DkgFoldAttestationVerifier is IDkgFoldAttestationVerifier {
    struct BundleData {
        bytes32[] publicInputs;
        DkgFoldAttestationLib.Attestation[] attestations;
        DkgFoldAttestationLib.PartySlotBinding[] bindings;
        uint256 h;
        /// @dev Index of the first party ID: 2 for the trBFV `dkg_aggregator` (after the
        ///      nodes-fold and C5 key hashes), 1 for `dkg_aggregator_v2` (after the nodes-fold
        ///      key hash only).
        uint256 partyIdOffset;
        /// @dev Offset of the SK aggregate commitments after the `h` party IDs: 5 for the trBFV
        ///      `dkg_aggregator`, 21 for `dkg_aggregator_v2`, whose prefix also carries the
        ///      legacy VK binding and the C2 chunk hashes.
        uint256 commitmentOffset;
    }

    /// @inheritdoc IDkgFoldAttestationVerifier
    function verify(
        address registry,
        uint256 chainId,
        uint256 e3Id,
        bytes calldata proof,
        bytes calldata dkgAttestationBundle
    )
        external
        view
        returns (
            uint256[] memory partyIds,
            bytes32[] memory skAggCommits,
            bytes32[] memory esmAggCommits
        )
    {
        BundleData memory data = _loadBundle(
            registry,
            e3Id,
            proof,
            dkgAttestationBundle
        );
        return _fillAnchors(registry, chainId, e3Id, data);
    }

    function _loadBundle(
        address registry,
        uint256 e3Id,
        bytes calldata proof,
        bytes calldata dkgAttestationBundle
    ) private view returns (BundleData memory data) {
        try this.decodeProofPublicInputs(proof) returns (
            bytes32[] memory publicInputs
        ) {
            data.publicInputs = publicInputs;
        } catch {
            revert ICiphernodeRegistry.InvalidFoldAttestation();
        }
        (data.h, data.partyIdOffset, data.commitmentOffset) = _honestPartyCount(
            registry,
            e3Id,
            data.publicInputs
        );
        // Defense in depth: require the public-inputs `partyId` slots
        // (`publicInputs[partyIdOffset..partyIdOffset+h]`) to be strictly
        // ascending. The zk circuit already enforces this, but rejecting
        // duplicates here prevents two bindings from resolving to the same slot
        // in `_partySlot` (which would silently overwrite each other in
        // `partyIdsOut` etc.).
        for (uint256 k = 1; k < data.h; k++) {
            require(
                uint256(data.publicInputs[data.partyIdOffset + k]) >
                    uint256(data.publicInputs[data.partyIdOffset + k - 1]),
                ICiphernodeRegistry.InvalidFoldAttestation()
            );
        }
        try this.decodeAttestationBundle(dkgAttestationBundle) returns (
            DkgFoldAttestationLib.Attestation[] memory attestations,
            DkgFoldAttestationLib.PartySlotBinding[] memory bindings
        ) {
            data.attestations = attestations;
            data.bindings = bindings;
        } catch {
            revert ICiphernodeRegistry.InvalidFoldAttestation();
        }
        if (
            data.attestations.length != data.bindings.length ||
            data.bindings.length != data.h
        ) {
            revert ICiphernodeRegistry.AttestationBindingCountMismatch();
        }
    }

    /// @notice Exposed only for guarded decode in `_loadBundle`.
    function decodeProofPublicInputs(
        bytes calldata proof
    ) external pure returns (bytes32[] memory publicInputs) {
        (, publicInputs) = abi.decode(proof, (bytes, bytes32[]));
    }

    /// @notice Exposed only for guarded decode in `_loadBundle`.
    function decodeAttestationBundle(
        bytes calldata dkgAttestationBundle
    )
        external
        pure
        returns (
            DkgFoldAttestationLib.Attestation[] memory attestations,
            DkgFoldAttestationLib.PartySlotBinding[] memory bindings
        )
    {
        (attestations, bindings) = abi.decode(
            dkgAttestationBundle,
            (
                DkgFoldAttestationLib.Attestation[],
                DkgFoldAttestationLib.PartySlotBinding[]
            )
        );
    }

    function _fillAnchors(
        address registry,
        uint256 chainId,
        uint256 e3Id,
        BundleData memory data
    )
        private
        view
        returns (
            uint256[] memory partyIdsOut,
            bytes32[] memory skAggOut,
            bytes32[] memory esmAggOut
        )
    {
        partyIdsOut = new uint256[](data.h);
        skAggOut = new bytes32[](data.h);
        esmAggOut = new bytes32[](data.h);

        for (uint256 i = 0; i < data.h; i++) {
            _applyBinding(
                registry,
                chainId,
                e3Id,
                data,
                i,
                partyIdsOut,
                skAggOut,
                esmAggOut
            );
        }
    }

    function _applyBinding(
        address registry,
        uint256 chainId,
        uint256 e3Id,
        BundleData memory data,
        uint256 i,
        uint256[] memory partyIdsOut,
        bytes32[] memory skAggOut,
        bytes32[] memory esmAggOut
    ) private view {
        if (i > 0) {
            require(
                data.bindings[i].partyId > data.bindings[i - 1].partyId,
                ICiphernodeRegistry.InvalidFoldAttestation()
            );
            require(
                data.attestations[i].partyId > data.attestations[i - 1].partyId,
                ICiphernodeRegistry.InvalidFoldAttestation()
            );
        }

        (uint256 slot, bytes32 sk, bytes32 esm) = _verifyBinding(
            registry,
            chainId,
            e3Id,
            data,
            data.bindings[i],
            data.attestations[i]
        );

        partyIdsOut[slot] = data.bindings[i].partyId;
        skAggOut[slot] = sk;
        esmAggOut[slot] = esm;
    }

    /// @dev The E3's parameter set selects the statement: `dkg_aggregator_v2` on the l-BFV sets,
    ///      `dkg_aggregator` otherwise. The PK verifier has already checked the statement against
    ///      the committee.
    function _honestPartyCount(
        address registry,
        uint256 e3Id,
        bytes32[] memory publicInputs
    )
        private
        view
        returns (uint256 h, uint256 partyIdOffset, uint256 commitmentOffset)
    {
        E3 memory e3 = ICiphernodeRegistry(registry).interfold().getE3(e3Id);
        if (BfvPkV2Layout.isLbfvParamSet(e3.paramSet)) {
            (, uint32 honest, ) = ActiveCryptoConfig.committeeParams(
                uint8(e3.committeeSize)
            );
            require(
                publicInputs.length ==
                    BfvPkV2Layout.publicInputsLength(
                        honest,
                        BfvPkV2Layout.rowCount(e3.paramSet)
                    ),
                ICiphernodeRegistry.InvalidFoldAttestation()
            );
            return (
                honest,
                BfvPkV2Layout.PARTY_ID_START,
                BfvPkV2Layout.COMMITMENT_OFFSET
            );
        }
        // trBFV `dkg_aggregator`: 3*h + 6 public inputs.
        require(
            publicInputs.length >= 6 && (publicInputs.length - 6) % 3 == 0,
            ICiphernodeRegistry.InvalidFoldAttestation()
        );
        h = (publicInputs.length - 6) / 3;
        partyIdOffset = 2;
        commitmentOffset = 5;
        // Defense in depth: the BFV pk-verifier already rejects `h == 0`, but
        // a zero-honest-party proof would otherwise pass this verifier with no
        // attestations to check and write empty anchors to the registry.
        require(h > 0, ICiphernodeRegistry.InvalidFoldAttestation());
    }

    function _verifyBinding(
        address registry,
        uint256 chainId,
        uint256 e3Id,
        BundleData memory data,
        DkgFoldAttestationLib.PartySlotBinding memory binding,
        DkgFoldAttestationLib.Attestation memory att
    ) private view returns (uint256 slot, bytes32 skCommit, bytes32 esmCommit) {
        // Canonical-slot binding: `binding.node` must equal the canonical
        // operator at index `partyId` of the finalized committee — i.e.
        // `canonicalCommitteeNodeAt(e3Id, partyId)`, which returns
        // `topNodes[partyId]` in address-ascending order. `partyId` is the
        // canonical sortition slot id, so this rejects any binding pointing
        // to an operator who is not the canonical occupant of that slot,
        // even one who is otherwise an active committee member. Combined
        // with the EIP-712 `ecrecover` check below, the attestation is
        // bound to *both* the right address and the right canonical slot.
        require(
            ICiphernodeRegistry(registry).canonicalCommitteeNodeAt(
                e3Id,
                binding.partyId
            ) == binding.node,
            ICiphernodeRegistry.InvalidFoldAttestation()
        );
        require(
            ICiphernodeRegistry(registry).isCommitteeMemberActive(
                e3Id,
                binding.node
            ),
            ICiphernodeRegistry.InvalidFoldAttestation()
        );

        require(
            att.partyId == binding.partyId,
            ICiphernodeRegistry.InvalidFoldAttestation()
        );

        address signer = DkgFoldAttestationLib.recoverSigner(
            chainId,
            address(this),
            registry,
            e3Id,
            att
        );
        require(
            signer == binding.node,
            ICiphernodeRegistry.InvalidFoldAttestation()
        );

        uint256 skOffset = data.commitmentOffset + data.h;
        uint256 esmOffset = data.commitmentOffset + (2 * data.h);

        slot = _partySlot(
            data.publicInputs,
            data.partyIdOffset,
            data.h,
            binding.partyId
        );

        require(
            data.publicInputs[skOffset + slot] == att.skAggCommit &&
                data.publicInputs[esmOffset + slot] == att.esmAggCommit,
            ICiphernodeRegistry.InvalidFoldAttestation()
        );

        return (slot, att.skAggCommit, att.esmAggCommit);
    }

    function _partySlot(
        bytes32[] memory publicInputs,
        uint256 partyIdOffset,
        uint256 h,
        uint256 partyId
    ) private pure returns (uint256 slot) {
        for (uint256 k = 0; k < h; k++) {
            if (uint256(publicInputs[partyIdOffset + k]) == partyId) {
                return k;
            }
        }
        revert ICiphernodeRegistry.PartyIdNotInProof();
    }
}
