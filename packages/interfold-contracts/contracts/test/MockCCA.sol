// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
pragma solidity 0.8.28;

import { AuctionParameters } from "../interfaces/external/ICCA.sol";

// address(1) sentinel meaning "use the caller (sender)".
address constant MSG_SENDER_SENTINEL = address(1);

interface IERC20Like {
    function balanceOf(address) external view returns (uint256);

    function transfer(address to, uint256 amount) external returns (bool);
}

/// @notice Shared auction state + hooks for the mock auctions.
abstract contract MockCCAAuctionBase {
    address public immutable token;
    uint128 public immutable totalSupply;
    address public immutable currency;
    address public immutable tokensRecipient;
    address public immutable fundsRecipient;
    uint64 public immutable startBlock;
    uint64 public immutable endBlock;
    uint64 public immutable claimBlock;
    address public immutable validationHook;

    bool public tokensReceived;
    uint256 public received;
    uint256 public totalCurrencyRaised;
    mapping(address bidder => uint256 amount) public bids;
    mapping(address bidder => bool claimed) public claimed;

    error TokensAlreadyReceived();
    error InvalidTokenAmountReceived();
    error NativeEthOnly();
    error AuctionNotStarted();
    error AuctionEnded();
    error ClaimNotOpen();
    error NothingToClaim();
    error AlreadyClaimed();

    event TokensReceivedEvent(uint256 amount);
    event Bid(address indexed bidder, uint256 amount);
    event Claimed(address indexed bidder, uint256 amount);

    constructor(
        address _token,
        uint128 _totalSupply,
        AuctionParameters memory _params
    ) {
        token = _token;
        totalSupply = _totalSupply;
        currency = _params.currency;
        tokensRecipient = _params.tokensRecipient;
        fundsRecipient = _params.fundsRecipient;
        startBlock = _params.startBlock;
        endBlock = _params.endBlock;
        claimBlock = _params.claimBlock;
        validationHook = _params.validationHook;
    }

    /// @notice Notifies the auction its sale tokens have landed.
    function onTokensReceived() external {
        if (tokensReceived) revert TokensAlreadyReceived();
        uint256 bal = IERC20Like(token).balanceOf(address(this));
        if (bal < totalSupply) revert InvalidTokenAmountReceived();
        tokensReceived = true;
        received = bal;
        emit TokensReceivedEvent(bal);
    }

    /// @notice Minimal ETH bid path for Sepolia/local deployment rehearsals.
    /// @dev The real Uniswap CCA handles pricing. This mock distributes the
    ///      funded sale supply pro-rata by ETH contributed so tests can verify
    ///      claims and FOLD claim locks without a frontend.
    function bid() external payable {
        if (currency != address(0)) revert NativeEthOnly();
        if (block.number < startBlock) revert AuctionNotStarted();
        if (block.number > endBlock) revert AuctionEnded();
        if (msg.value == 0) revert NothingToClaim();

        bids[msg.sender] += msg.value;
        totalCurrencyRaised += msg.value;
        emit Bid(msg.sender, msg.value);
    }

    function claim() external returns (uint256 amount) {
        if (block.number < claimBlock) revert ClaimNotOpen();
        if (claimed[msg.sender]) revert AlreadyClaimed();

        uint256 bidAmount = bids[msg.sender];
        if (bidAmount == 0 || totalCurrencyRaised == 0) {
            revert NothingToClaim();
        }

        claimed[msg.sender] = true;
        amount = (uint256(totalSupply) * bidAmount) / totalCurrencyRaised;
        if (amount == 0) revert NothingToClaim();
        require(IERC20Like(token).transfer(msg.sender, amount), "transfer");
        emit Claimed(msg.sender, amount);
    }
}

/// @notice Mock CCA v2.0.0 auction: 4 constructor args (fee controller in init
///         code), matching the real v2.0.0 CREATE2 init-code preimage.
contract MockCCAAuction is MockCCAAuctionBase {
    address public immutable protocolFeeController;

    constructor(
        address _token,
        uint128 _totalSupply,
        AuctionParameters memory _params,
        address _protocolFeeController
    ) MockCCAAuctionBase(_token, _totalSupply, _params) {
        protocolFeeController = _protocolFeeController;
    }
}

/// @notice Mock of the Uniswap CCA v2 factory.
/// @dev CREATE2 derivation matches the real contracts exactly:
///        salt        = keccak256(abi.encode(sender, userSalt))
///        initCode    = type(MockCCAAuction).creationCode ++
///                      abi.encode(token, uint128(amount), params, feeController)
///      Because the deployer predicts off-chain against the *real* auction
///      bytecode, tests must predict against THIS contract's bytecode instead;
///      the prediction helper accepts a creation-code override for that.
contract MockCCAFactory {
    address public immutable protocolFeeController;

    event AuctionCreated(
        address indexed auction,
        address indexed token,
        uint256 amount,
        bytes configData
    );

    error InvalidTokenAmount(uint256 amount);

    constructor(address _protocolFeeController) {
        protocolFeeController = _protocolFeeController;
    }

    function create(
        address token,
        uint256 amount,
        bytes calldata configData,
        bytes32 salt
    ) external returns (address auction) {
        return _create(token, amount, configData, salt, msg.sender);
    }

    function getAddress(
        address token,
        uint256 amount,
        bytes calldata configData,
        bytes32 salt,
        address sender
    ) external view returns (address) {
        return _predict(token, amount, configData, salt, sender);
    }

    // ── Shared ───────────────────────────────────────────────────────────────

    function _resolveParams(
        bytes calldata configData,
        address sender
    ) internal pure returns (AuctionParameters memory params) {
        params = abi.decode(configData, (AuctionParameters));
        if (params.tokensRecipient == MSG_SENDER_SENTINEL) {
            params.tokensRecipient = sender;
        }
        if (params.fundsRecipient == MSG_SENDER_SENTINEL) {
            params.fundsRecipient = sender;
        }
    }

    function _initCode(
        address token,
        uint256 amount,
        AuctionParameters memory params
    ) internal view returns (bytes memory) {
        return
            abi.encodePacked(
                type(MockCCAAuction).creationCode,
                abi.encode(
                    token,
                    uint128(amount),
                    params,
                    protocolFeeController
                )
            );
    }

    function _create(
        address token,
        uint256 amount,
        bytes calldata configData,
        bytes32 salt,
        address sender
    ) internal returns (address auction) {
        if (amount > type(uint128).max) revert InvalidTokenAmount(amount);
        AuctionParameters memory params = _resolveParams(configData, sender);
        bytes32 create2Salt = keccak256(abi.encode(sender, salt));
        bytes memory initCode = _initCode(token, amount, params);
        // solhint-disable-next-line no-inline-assembly
        assembly ("memory-safe") {
            auction := create2(
                0,
                add(initCode, 0x20),
                mload(initCode),
                create2Salt
            )
        }
        require(auction != address(0), "CCA: CREATE2 failed");
        emit AuctionCreated(
            auction,
            token,
            uint128(amount),
            abi.encode(params)
        );
    }

    function _predict(
        address token,
        uint256 amount,
        bytes calldata configData,
        bytes32 salt,
        address sender
    ) internal view returns (address) {
        if (amount > type(uint128).max) revert InvalidTokenAmount(amount);
        AuctionParameters memory params = _resolveParams(configData, sender);
        bytes32 create2Salt = keccak256(abi.encode(sender, salt));
        bytes32 initCodeHash = keccak256(_initCode(token, amount, params));
        return
            address(
                uint160(
                    uint256(
                        keccak256(
                            abi.encodePacked(
                                bytes1(0xff),
                                address(this),
                                create2Salt,
                                initCodeHash
                            )
                        )
                    )
                )
            );
    }
}
