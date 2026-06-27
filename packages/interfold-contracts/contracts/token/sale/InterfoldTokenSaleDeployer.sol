// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
pragma solidity 0.8.28;

import {
    ICCAFactoryV1,
    ICCAFactoryV2,
    ICCAAuction
} from "../../interfaces/external/ICCA.sol";

/// @notice The minimal slice of {InterfoldToken} the deployer needs.
interface IFoldToken {
    function mint(address recipient, uint256 amount, bytes32 label) external;

    function transferOwnership(address newOwner) external;

    function owner() external view returns (address);

    // solhint-disable-next-line func-name-mixedcase
    function CLAIM_SOURCE() external view returns (address);
}

/**
 * @title InterfoldTokenSaleDeployer
 * @notice Safe-owned, operator-run deployment factory for the FOLD token
 *         sale via a Uniswap Continuous Clearing Auction (CCA).
 *
 * @dev    PURPOSE & THREAT MODEL
 *
 *         For legal reasons FOLD must be deployed from a specific jurisdiction.
 *         The pattern here lets an "operator" wallet (the gas payer) press the
 *         button, while the Interfold Foundation Safe remains the sole protocol
 *         authority:
 *
 *           - {protocolAdmin} is set explicitly at construction. The operator
 *             may deploy THIS contract, but the script/config must pass the
 *             Foundation Safe as protocolAdmin.
 *           - FOLD is deployed with `initialOwner = address(this)` so the
 *             factory can fund the sale, then ownership is handed to the Safe.
 *             FOLD is {Ownable2Step}: the Safe must call {acceptOwnership} to
 *             finalize, which atomically moves every role to the Safe.
 *
 *         CIRCULAR-DEPENDENCY SOLUTION
 *
 *         FOLD's constructor needs the CCA auction address (`CLAIM_SOURCE`,
 *         immutable), and the CCA needs FOLD's address. This is resolved with
 *         deterministic prediction, verified atomically on-chain:
 *
 *           1. Off-chain: predict FOLD's address from this factory's next nonce
 *              (plain CREATE) and bake it into `configData`/the CCA prediction.
 *           2. Off-chain: predict the CCA address from the Uniswap factory using
 *              `sender = address(this)` (this contract calls the CCA factory).
 *           3. Off-chain: bake the predicted CCA address into FOLD's init code
 *              as `claimSource`.
 *           4. On-chain: this contract CREATEs FOLD, creates the auction, and
 *              REQUIRES `fold.CLAIM_SOURCE() == auction`. That single equality
 *              catches any nonce/prediction/sender mismatch and reverts the whole
 *              transaction, so a wrong prediction can never half-deploy.
 *
 *         SUPPORTED UNISWAP VERSIONS
 *
 *         {SaleConfig.ccaUseV2} selects the entrypoint: v1.1.0 uses
 *         {ICCAFactoryV1.initializeDistribution}; v2.0.0 uses
 *         {ICCAFactoryV2.create}. The off-chain predictor must mirror the same
 *         version, since their CREATE2 init code differs.
 */
contract InterfoldTokenSaleDeployer {
    // ─────────────────────────────────────────────────────────────────────────
    // Types
    // ─────────────────────────────────────────────────────────────────────────

    /// @param ccaFactory The deployed Uniswap CCA factory address.
    /// @param ccaUseV2 When true, call the v2 `create`/`getAddress` ABI; when
    ///        false, the v1.1.0 `initializeDistribution`/`getAuctionAddress` ABI.
    /// @param saleAmount FOLD sale supply minted to the auction (must fit uint128).
    /// @param ccaSalt Salt forwarded to the Uniswap factory.
    /// @param ccaConfigData abi.encode(AuctionParameters) for the auction.
    /// @param saleLabel Label recorded on the FOLD mint event.
    /// @param foldInitCodeHash keccak256 of the FOLD creation code + constructor
    ///        args (with claimSource = predicted auction). Binds the exact token
    ///        bytecode/params into the one-use config hash.
    struct SaleConfig {
        address ccaFactory;
        bool ccaUseV2;
        uint256 saleAmount;
        bytes32 ccaSalt;
        bytes ccaConfigData;
        bytes32 saleLabel;
        bytes32 foldInitCodeHash;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Errors
    // ─────────────────────────────────────────────────────────────────────────

    error ZeroAddress();
    error ConfigAlreadyUsed(bytes32 configHash);
    error FoldInitCodeMismatch();
    error FoldDeployFailed();
    error SaleAmountTooLarge();
    error AuctionMismatch(address expected, address actual);
    error FoldOwnershipNotRetained(address owner);
    error AuctionTokenMismatch(address expected, address actual);

    // ─────────────────────────────────────────────────────────────────────────
    // Constants & immutables
    // ─────────────────────────────────────────────────────────────────────────

    /// @notice The Safe that becomes FOLD owner/admin.
    /// @dev Passed at construction so an EOA can deploy the factory while the
    ///      Foundation Safe remains the only admin address.
    ///      Kept camelCase as a deliberate, documented external API name.
    // solhint-disable-next-line immutable-vars-naming
    address public immutable protocolAdmin;

    // ─────────────────────────────────────────────────────────────────────────
    // Storage
    // ─────────────────────────────────────────────────────────────────────────

    /// @notice Replay guard: each config can be deployed exactly once.
    mapping(bytes32 configHash => bool used) public usedConfigHashes;

    // ─────────────────────────────────────────────────────────────────────────
    // Events
    // ─────────────────────────────────────────────────────────────────────────

    /// @notice Emitted once a sale is fully deployed and funded.
    event SaleDeployed(
        bytes32 indexed configHash,
        address indexed fold,
        address indexed auction,
        uint256 saleAmount,
        address operator
    );

    // ─────────────────────────────────────────────────────────────────────────
    // Constructor
    // ─────────────────────────────────────────────────────────────────────────

    constructor(address protocolAdmin_) {
        if (protocolAdmin_ == address(0)) revert ZeroAddress();
        protocolAdmin = protocolAdmin_;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Deployment
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * @notice Deploys FOLD + the CCA auction and funds the sale, all in one
     *         transaction. Callable by the operator wallet.
     *
     * @param config        The deployment parameters.
     * @param foldInitCode  The full FOLD creation code + abi-encoded constructor
     *                       args. Its keccak256 must equal
     *                       `config.foldInitCodeHash`.
     * @return fold    The deployed FOLD token address.
     * @return auction The deployed CCA auction address (== FOLD `CLAIM_SOURCE`).
     */
    function deploySale(
        SaleConfig calldata config,
        bytes calldata foldInitCode
    ) external returns (address fold, address auction) {
        // 1. Verify config integrity and replay guard.
        bytes32 configHash = _checkConfig(config, foldInitCode);

        // 2. Deploy FOLD via plain CREATE (address fixed by this factory's nonce,
        //    matching the off-chain prediction baked into the CCA config).
        fold = _create(foldInitCode);
        // The factory must be FOLD's owner so it can mint the sale supply.
        if (IFoldToken(fold).owner() != address(this)) {
            revert FoldOwnershipNotRetained(IFoldToken(fold).owner());
        }

        // 3. Create the CCA auction through the deployed Uniswap factory.
        //    `sender` in the prediction was address(this); here we ARE the
        //    caller, so the address matches by construction.
        auction = _createAuction(config, fold);

        // 4. Atomic correctness gate: the auction we just created MUST be the
        //    one baked into FOLD as the immutable claim source. This single
        //    check fails the whole tx on any prediction/nonce/sender mismatch.
        address claimSource = IFoldToken(fold).CLAIM_SOURCE();
        if (auction != claimSource) {
            revert AuctionMismatch(claimSource, auction);
        }
        if (ICCAAuction(auction).token() != fold) {
            revert AuctionTokenMismatch(fold, ICCAAuction(auction).token());
        }

        // 5. Fund the sale: mint the sale supply to the auction and notify it.
        IFoldToken(fold).mint(auction, config.saleAmount, config.saleLabel);
        ICCAAuction(auction).onTokensReceived();

        // 6. Hand FOLD ownership to the Safe. FOLD is Ownable2Step, so this is a
        //    pending transfer; the Safe must call acceptOwnership() to finalize,
        //    which atomically moves every role to the Safe. Until then the
        //    factory retains the roles but exposes no further minting path.
        IFoldToken(fold).transferOwnership(protocolAdmin);

        emit SaleDeployed(
            configHash,
            fold,
            auction,
            config.saleAmount,
            msg.sender
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Views
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * @notice Deterministic hash used to identify a deployment config.
     * @dev Domain-separated by chain id and this contract's address so the
     *      replay guard is scoped to this deployer instance. `ccaConfigData` is
     *      hashed (not embedded) to keep the preimage fixed-size.
     */
    function hashConfig(
        SaleConfig calldata config
    ) public view returns (bytes32) {
        return
            keccak256(
                abi.encode(
                    block.chainid,
                    address(this),
                    config.ccaFactory,
                    config.ccaUseV2,
                    config.saleAmount,
                    config.ccaSalt,
                    keccak256(config.ccaConfigData),
                    config.saleLabel,
                    config.foldInitCodeHash
                )
            );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Internal
    // ─────────────────────────────────────────────────────────────────────────

    /// @dev Validates the FOLD init code hash and the replay guard. Marks the
    ///      config used. Returns the config hash.
    function _checkConfig(
        SaleConfig calldata config,
        bytes calldata foldInitCode
    ) internal returns (bytes32 configHash) {
        if (config.ccaFactory == address(0)) revert ZeroAddress();
        if (config.saleAmount > type(uint128).max) revert SaleAmountTooLarge();
        if (keccak256(foldInitCode) != config.foldInitCodeHash) {
            revert FoldInitCodeMismatch();
        }

        configHash = hashConfig(config);
        if (usedConfigHashes[configHash]) revert ConfigAlreadyUsed(configHash);
        usedConfigHashes[configHash] = true;
    }

    /// @dev Dispatches to the correct Uniswap CCA factory ABI for the version.
    function _createAuction(
        SaleConfig calldata config,
        address fold
    ) internal returns (address auction) {
        if (config.ccaUseV2) {
            auction = ICCAFactoryV2(config.ccaFactory).create(
                fold,
                config.saleAmount,
                config.ccaConfigData,
                config.ccaSalt
            );
        } else {
            auction = ICCAFactoryV1(config.ccaFactory).initializeDistribution(
                fold,
                config.saleAmount,
                config.ccaConfigData,
                config.ccaSalt
            );
        }
    }

    /// @dev Deploys `initCode` with plain CREATE and returns the new address.
    function _create(bytes calldata initCode) internal returns (address addr) {
        bytes memory code = initCode;
        // solhint-disable-next-line no-inline-assembly
        assembly ("memory-safe") {
            addr := create(0, add(code, 0x20), mload(code))
        }
        if (addr == address(0)) revert FoldDeployFailed();
    }
}
