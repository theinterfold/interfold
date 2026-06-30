// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity 0.8.28;

import { ICCAFactory, ICCAAuction } from "../../interfaces/external/ICCA.sol";

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
 * @notice Operator-callable sale deployment factory. The Safe passed as
 *         `protocolAdmin` becomes the FOLD owner; the caller only pays gas.
 * @dev FOLD and the CCA auction depend on each other's addresses. The deploy
 *      script predicts both addresses, this contract checks the prediction
 *      on-chain, and the whole transaction reverts on any mismatch.
 */
contract InterfoldTokenSaleDeployer {
    /// @param ccaFactory The deployed Uniswap CCA factory address.
    /// @param saleAmount FOLD sale supply minted to the auction (must fit uint128).
    /// @param ccaSalt Salt forwarded to the Uniswap factory.
    /// @param ccaConfigData abi.encode(AuctionParameters) for the auction.
    /// @param saleLabel Label recorded on the FOLD mint event.
    /// @param foldInitCodeHash keccak256 of the FOLD creation code + constructor
    ///        args (with claimSource = predicted auction). Binds the exact token
    ///        bytecode/params into the one-use config hash.
    struct SaleConfig {
        address ccaFactory;
        uint256 saleAmount;
        bytes32 ccaSalt;
        bytes ccaConfigData;
        bytes32 saleLabel;
        bytes32 foldInitCodeHash;
    }

    error ZeroAddress();
    error ConfigAlreadyUsed(bytes32 configHash);
    error FoldInitCodeMismatch();
    error FoldDeployFailed();
    error SaleAmountTooLarge();
    error AuctionMismatch(address expected, address actual);
    error FoldOwnershipNotRetained(address owner);
    error AuctionTokenMismatch(address expected, address actual);

    /// @notice The Safe that becomes FOLD owner/admin.
    // solhint-disable-next-line immutable-vars-naming
    address public immutable protocolAdmin;

    /// @notice Replay guard: each config can be deployed exactly once.
    mapping(bytes32 configHash => bool used) public usedConfigHashes;

    /// @notice Emitted once a sale is fully deployed and funded.
    event SaleDeployed(
        bytes32 indexed configHash,
        address indexed fold,
        address indexed auction,
        uint256 saleAmount,
        address operator
    );

    constructor(address protocolAdmin_) {
        if (protocolAdmin_ == address(0)) revert ZeroAddress();
        protocolAdmin = protocolAdmin_;
    }

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
        bytes32 configHash = _checkConfig(config, foldInitCode);

        fold = _create(foldInitCode);
        if (IFoldToken(fold).owner() != address(this)) {
            revert FoldOwnershipNotRetained(IFoldToken(fold).owner());
        }

        auction = _createAuction(config, fold);

        address claimSource = IFoldToken(fold).CLAIM_SOURCE();
        if (auction != claimSource) {
            revert AuctionMismatch(claimSource, auction);
        }
        if (ICCAAuction(auction).token() != fold) {
            revert AuctionTokenMismatch(fold, ICCAAuction(auction).token());
        }

        IFoldToken(fold).mint(auction, config.saleAmount, config.saleLabel);
        ICCAAuction(auction).onTokensReceived();

        IFoldToken(fold).transferOwnership(protocolAdmin);

        emit SaleDeployed(
            configHash,
            fold,
            auction,
            config.saleAmount,
            msg.sender
        );
    }

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
                    config.saleAmount,
                    config.ccaSalt,
                    keccak256(config.ccaConfigData),
                    config.saleLabel,
                    config.foldInitCodeHash
                )
            );
    }

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

    /// @dev Deploys the auction through the Uniswap CCA v2 factory.
    function _createAuction(
        SaleConfig calldata config,
        address fold
    ) internal returns (address auction) {
        auction = ICCAFactory(config.ccaFactory).create(
            fold,
            config.saleAmount,
            config.ccaConfigData,
            config.ccaSalt
        );
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
