// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
pragma solidity 0.8.28;

import { Math } from "@openzeppelin/contracts/utils/math/Math.sol";
import { SafeCast } from "@openzeppelin/contracts/utils/math/SafeCast.sol";
import { IIdentityVerifier } from "../interfaces/IIdentityVerifier.sol";
import {
    IZKPassportHelper,
    IZKPassportVerifier
} from "../interfaces/IZKPassportVerifier.sol";

/// @notice Verifies a bond-owner credential with a ZKPassport proof of a chip document: a passport,
///         national ID card or residence permit (ICAO 9303).
/// @dev Trusts the issuing governments' signing keys and ZKPassport's verifier, helper,
///      certificate registry and OPRF key, which ZKPassport's admin keys can change without delay.
///      The identifier belongs to one document, not to one person: a person with two documents
///      gets two identifiers, and a renewed document gets a new identifier.
///      The domain, scope, identifier type and OPRF key are fixed per deployment. A change to any
///      of them changes every identifier, so it needs a new registry or a migration. A new
///      ZKPassport version needs a new deployment, because the public-input layout belongs to the
///      version.
contract ZKPassportIdentityVerifier is IIdentityVerifier {
    /// @dev Index of the proof date (seconds) in ZKPassport's public inputs.
    uint256 internal constant PROOF_DATE_INDEX = 2;
    /// @dev In the pinned version, the public inputs end with
    ///      [nullifier type, scoped nullifier, OPRF key hash].
    uint256 internal constant NULLIFIER_TYPE_OFFSET_FROM_END = 3;
    uint256 internal constant OPRF_KEY_HASH_OFFSET_FROM_END = 1;
    /// @dev ZKPassport's `NullifierType`: 0 is non-salted, 1 is salted (OPRF). The mock and
    ///      no-identifier types are never accepted.
    uint8 internal constant SALTED = 1;
    string internal constant IDENTITY_TAG = "interfold.identity.zkpassport.v1";

    error InvalidRootVerifier(address rootVerifier);
    error InvalidConfiguration();
    error UnsupportedVersion(bytes32 version);
    error InvalidProof();
    error UnexpectedNullifierType(uint256 nullifierType);
    error UnexpectedOPRFKey(bytes32 oprfKeyHash);
    error MissingIdentifier();
    error WrongBinding(address senderAddress, uint256 chainId);
    error ExpiryNotProven(uint256 validUntil);
    error FaceMatchMissing();

    IZKPassportVerifier public immutable ROOT_VERIFIER;
    /// @notice The only ZKPassport verifier version that this deployment accepts.
    bytes32 public immutable VERSION;
    /// @notice The accepted identifier type: 0 non-salted, 1 salted.
    uint8 public immutable NULLIFIER_TYPE;
    /// @notice The OPRF key hash that a proof must carry: ZKPassport's key for salted proofs, zero
    ///         for non-salted proofs.
    bytes32 public immutable OPRF_KEY_HASH;
    bool public immutable FACE_MATCH_REQUIRED;
    /// @notice The maximum age, in seconds, of a proof at verification.
    uint256 public immutable PROOF_VALIDITY;
    /// @notice The longest credential, in seconds after the proof date.
    uint48 public immutable MAX_VALIDITY;
    bytes32 public immutable IDENTITY_NAMESPACE;
    string public domain;
    string public scope;

    constructor(
        address _rootVerifier,
        bytes32 _version,
        string memory _domain,
        string memory _scope,
        uint8 _nullifierType,
        bytes32 _oprfKeyHash,
        bool _faceMatchRequired,
        uint256 _proofValidity,
        uint48 _maxValidity
    ) {
        if (_rootVerifier.code.length == 0) {
            revert InvalidRootVerifier(_rootVerifier);
        }
        if (
            _version == bytes32(0) ||
            bytes(_domain).length == 0 ||
            bytes(_scope).length == 0 ||
            _nullifierType > SALTED ||
            (_nullifierType == SALTED) != (_oprfKeyHash != bytes32(0)) ||
            _proofValidity == 0 ||
            _maxValidity == 0
        ) revert InvalidConfiguration();
        ROOT_VERIFIER = IZKPassportVerifier(_rootVerifier);
        VERSION = _version;
        domain = _domain;
        scope = _scope;
        NULLIFIER_TYPE = _nullifierType;
        OPRF_KEY_HASH = _oprfKeyHash;
        FACE_MATCH_REQUIRED = _faceMatchRequired;
        PROOF_VALIDITY = _proofValidity;
        MAX_VALIDITY = _maxValidity;
        IDENTITY_NAMESPACE = keccak256(
            abi.encode(IDENTITY_TAG, _domain, _scope)
        );
    }

    /// @inheritdoc IIdentityVerifier
    /// @dev Evidence is abi.encode(IZKPassportVerifier.ProofVerificationParams, uint256 validUntil).
    ///      `validUntil` is the lower bound of the proof's expiry-date check: the document is valid
    ///      at least until then. The credential ends at `validUntil`, or `MAX_VALIDITY` after the
    ///      proof date if that is earlier.
    function verify(
        address owner,
        bytes calldata evidence
    ) external override returns (bytes32 identityId, uint48 expiresAt) {
        (
            IZKPassportVerifier.ProofVerificationParams memory params,
            uint256 validUntil
        ) = abi.decode(
                evidence,
                (IZKPassportVerifier.ProofVerificationParams, uint256)
            );
        (bytes32 uniqueIdentifier, IZKPassportHelper helper) = _verifyProof(
            params
        );
        _checkCommittedInputs(
            helper,
            params.committedInputs,
            owner,
            validUntil
        );
        uint256 proofDate = uint256(
            params.proofVerificationData.publicInputs[PROOF_DATE_INDEX]
        );
        expiresAt = SafeCast.toUint48(
            Math.min(validUntil, proofDate + MAX_VALIDITY)
        );
        identityId = keccak256(
            abi.encode(IDENTITY_NAMESPACE, uniqueIdentifier)
        );
    }

    /// @dev Verifies the proof under the fixed service configuration, and returns the document's
    ///      identifier and ZKPassport's helper for the proof's committed inputs.
    function _verifyProof(
        IZKPassportVerifier.ProofVerificationParams memory params
    ) internal returns (bytes32 uniqueIdentifier, IZKPassportHelper helper) {
        if (params.version != VERSION) {
            revert UnsupportedVersion(params.version);
        }
        // ZKPassport checks the domain, scope, validity window and dev mode that the caller
        // passes, so the fixed values replace the caller's.
        params.serviceConfig = IZKPassportVerifier.ServiceConfig(
            PROOF_VALIDITY,
            domain,
            scope,
            false
        );
        bool verified;
        (verified, uniqueIdentifier, helper) = ROOT_VERIFIER.verify(params);
        if (!verified) revert InvalidProof();

        bytes32[] memory publicInputs = params
            .proofVerificationData
            .publicInputs;
        uint256 proofNullifierType = uint256(
            publicInputs[publicInputs.length - NULLIFIER_TYPE_OFFSET_FROM_END]
        );
        // Salted and non-salted identifiers of one document differ, so accepting both would let
        // one document register two owners.
        if (proofNullifierType != NULLIFIER_TYPE) {
            revert UnexpectedNullifierType(proofNullifierType);
        }
        // A salted identifier depends on the OPRF key, so a second key would give one document a
        // second identifier.
        bytes32 proofOprfKeyHash = publicInputs[
            publicInputs.length - OPRF_KEY_HASH_OFFSET_FROM_END
        ];
        if (proofOprfKeyHash != OPRF_KEY_HASH) {
            revert UnexpectedOPRFKey(proofOprfKeyHash);
        }
        if (uniqueIdentifier == bytes32(0)) revert MissingIdentifier();
    }

    /// @dev Checks the owner and chain binding, the expiry bound and, when required, strict
    ///      FaceMatch in the proof's committed inputs.
    function _checkCommittedInputs(
        IZKPassportHelper helper,
        bytes memory committedInputs,
        address owner,
        uint256 validUntil
    ) internal view {
        IZKPassportVerifier.BoundData memory bound = helper.getBoundData(
            committedInputs
        );
        if (bound.senderAddress != owner || bound.chainId != block.chainid) {
            revert WrongBinding(bound.senderAddress, bound.chainId);
        }
        if (!helper.isExpiryDateAfterOrEqual(validUntil, committedInputs)) {
            revert ExpiryNotProven(validUntil);
        }
        if (
            FACE_MATCH_REQUIRED &&
            !helper.isFaceMatchVerified(
                IZKPassportVerifier.FaceMatchMode.STRICT,
                IZKPassportVerifier.OS.ANY,
                committedInputs
            )
        ) revert FaceMatchMissing();
    }
}
