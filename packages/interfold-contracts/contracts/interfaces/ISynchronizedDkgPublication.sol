// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity 0.8.28;

/// @notice View of an existing request-frozen field; does not change the legacy IInterfold ERC-165 ID.
interface ISynchronizedDkgRequestContext {
    function e3CryptoConfigIds(uint256 e3Id) external view returns (bytes32);
}

/// @notice Versioned synchronized DKG authority, separate from SS fold/ESM anchors.
interface ISynchronizedDkgPublication {
    struct Publication {
        bytes32 pkCommitment;
        bytes32 dealerBatch;
        uint256[] partyIds;
        bytes proof;
        /// One signature for each selected recipient, in canonical party-id order.
        bytes[] signatures;
    }

    struct Authority {
        uint8 version;
        address verifier;
        bytes32 cryptoConfigId;
        bytes32 setupBinding;
        bytes32 dealerBatch;
        bytes32 pkCommitment;
        uint256[] partyIds;
        bytes32[] thresholdPkCommits;
        bytes32[] skAggCommits;
        bytes32[] keyBundleCommits;
    }

    event SynchronizedDkgAuthorityPublished(
        uint256 indexed e3Id,
        Authority authority
    );

    error InvalidSynchronizedDkgPublication();
    error SynchronizedDkgPublicationRequired();

    function publishSynchronizedCommittee(
        uint256 e3Id,
        Publication calldata publication
    ) external;

    /// @notice Version zero means no synchronized publication; SS anchors are never returned here.
    function getSynchronizedDkgAuthority(
        uint256 e3Id
    ) external view returns (Authority memory authority);
}

/// @notice Request-frozen synchronized verifier. Never an IPkVerifier/SS fallback.
interface ISynchronizedDkgPublicationVerifier {
    // Match the immutable getter ABI.
    // solhint-disable-next-line func-name-mixedcase
    function INTERFOLD() external view returns (address);
    // solhint-disable-next-line func-name-mixedcase
    function CRYPTO_CONFIG_ID() external view returns (bytes32);
    // solhint-disable-next-line func-name-mixedcase
    function N() external view returns (uint256);
    // solhint-disable-next-line func-name-mixedcase
    function H() external view returns (uint256);

    function setupBinding(
        uint256 e3Id,
        address[] calldata committee
    ) external view returns (bytes32);

    function verify(
        uint256 e3Id,
        address[] calldata committee,
        uint256[] calldata dealers,
        bytes32 pkCommitment,
        bytes32 dealerBatch,
        bytes calldata proof
    )
        external
        view
        returns (
            bytes32[] memory sk,
            bytes32[] memory bundles,
            bytes32[] memory thresholdKeys
        );
}
