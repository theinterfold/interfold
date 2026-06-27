// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
pragma solidity 0.8.28;

/**
 * @title ICCA
 * @notice Minimal, version-agnostic interfaces for the Uniswap Continuous
 *         Clearing Auction (CCA) factory + auction instance.
 *
 * @dev    The on-chain CCA contracts are NOT deployed from this repository.
 *         These are thin call/predict interfaces against the canonical Uniswap
 *         factories already deployed on mainnet/L2s. There are two live ABIs:
 *
 *         - v1.1.0 (0xCCccCcCAE7503Cac057829BF2811De42E16e0bD5, Mainnet/Unichain/Base)
 *           uses {initializeDistribution} / {getAuctionAddress}. The auction
 *           CREATE2 init code is `abi.encode(token, uint128(amount), params)`.
 *
 *         - v2.0.0 (0x00cCa200BF124dBfA848937c553864f4B4CE0632) uses {create} /
 *           {getAddress}. Its auction CREATE2 init code additionally encodes the
 *           factory's immutable protocol-fee-controller address.
 *
 *         Both share the same {AuctionParameters} field order. The deployer
 *         contract picks the correct entrypoint at runtime via a config flag,
 *         so a single audited factory supports either Uniswap version.
 */

/// @notice Auction configuration, abi-encoded into `configData`.
/// @dev    `token` and `totalSupply` are passed as separate factory arguments,
///         NOT part of this struct. Field order MUST match the deployed Uniswap
///         `AuctionParameters` exactly, or `abi.decode` on the factory reverts /
///         produces a different CREATE2 address.
struct AuctionParameters {
    /// @notice Token to raise funds in. Use address(0) for native ETH.
    address currency;
    /// @notice Recipient of unsold/leftover tokens at auction end.
    address tokensRecipient;
    /// @notice Recipient of all raised funds.
    address fundsRecipient;
    /// @notice Block at which the first auction step starts.
    uint64 startBlock;
    /// @notice Block at which the auction finishes.
    uint64 endBlock;
    /// @notice Block at which tokens can be claimed (must be >= endBlock).
    uint64 claimBlock;
    /// @notice Fixed price granularity.
    uint256 tickSpacing;
    /// @notice Optional hook called before a bid (e.g. Predicate/KYC). 0 = none.
    address validationHook;
    /// @notice Starting floor price for the auction.
    uint256 floorPrice;
    /// @notice Currency that must be raised for the auction to graduate.
    uint128 requiredCurrencyRaised;
    /// @notice Packed bytes describing the token issuance schedule (steps).
    bytes auctionStepsData;
}

/// @title ICCAFactoryV1
/// @notice Uniswap CCA factory v1.1.0 entrypoints.
interface ICCAFactoryV1 {
    /// @notice Deploys a new auction instance via CREATE2.
    /// @param token The token being sold (FOLD).
    /// @param amount The sale supply (must fit in uint128).
    /// @param configData abi.encode(AuctionParameters).
    /// @param salt User salt; the factory combines it with msg.sender.
    /// @return distributionContract The deployed auction address.
    function initializeDistribution(
        address token,
        uint256 amount,
        bytes calldata configData,
        bytes32 salt
    ) external returns (address distributionContract);

    /// @notice Predicts the auction address for the given inputs and caller.
    /// @dev `sender` MUST equal the address that will call
    ///      {initializeDistribution}, or the prediction will not match.
    function getAuctionAddress(
        address token,
        uint256 amount,
        bytes calldata configData,
        bytes32 salt,
        address sender
    ) external view returns (address);
}

/// @title ICCAFactoryV2
/// @notice Uniswap CCA factory v2.0.0 entrypoints.
interface ICCAFactoryV2 {
    /// @notice Deploys a new auction instance via CREATE2 (v2 naming).
    function create(
        address token,
        uint256 amount,
        bytes calldata configData,
        bytes32 salt
    ) external returns (address distributor);

    /// @notice Predicts the auction address (v2 naming).
    /// @dev `sender` MUST equal the address that will call {create}.
    function getAddress(
        address token,
        uint256 amount,
        bytes calldata configData,
        bytes32 salt,
        address sender
    ) external view returns (address);

    /// @notice The protocol fee controller baked into every auction's init code.
    function protocolFeeController() external view returns (address);
}

/// @title ICCAAuction
/// @notice The subset of the deployed CCA auction instance the deployer reads
///         from and pokes during funding. Common to v1.1.0 and v2.0.0.
interface ICCAAuction {
    /// @notice Notifies the auction that its sale tokens have been transferred
    ///         in. Must be called once after the sale supply is funded.
    function onTokensReceived() external;

    /// @notice The token being sold.
    function token() external view returns (address);

    /// @notice The sale supply.
    function totalSupply() external view returns (uint128);

    /// @notice The recipient of unsold tokens.
    function tokensRecipient() external view returns (address);

    /// @notice The recipient of raised funds.
    function fundsRecipient() external view returns (address);

    /// @notice The currency being raised.
    function currency() external view returns (address);

    /// @notice First auction block.
    function startBlock() external view returns (uint64);

    /// @notice Final auction block.
    function endBlock() external view returns (uint64);

    /// @notice Claim block.
    function claimBlock() external view returns (uint64);
}
