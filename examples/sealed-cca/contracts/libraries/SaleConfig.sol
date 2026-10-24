// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
pragma solidity 0.8.28;

import { IERC20Metadata } from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";

/// @dev The most price steps of a sale. The demand curve of the output has this many slots.
uint8 constant SALE_LEVELS = 16;

/// @notice The configuration of one sale, from the request's `customParams`.
struct Sale {
  uint8 revealMode;
  uint8 levels;
  /// @dev The E3 requester. It deposited the supply and gets the proceeds.
  address creator;
  string title;
  address saleToken;
  address paymentToken;
  uint256 supply;
  uint256 escrow;
  address gate;
  /// @dev `10^decimals` of the sale token: the base units of one whole sale token.
  uint256 saleUnit;
  /// @dev The price of each step: payment-token base units per `saleUnit` sale-token base units.
  /// The public getter omits arrays; read the prices with `salePrices`.
  uint256[SALE_LEVELS] prices;
}

/// @title Decoder and checker of the parameters of a sale.
/// @notice An external library, because the program is near the size limit of a contract.
library SaleConfig {
  uint8 public constant MIN_LEVELS = 2;
  uint256 public constant MAX_TITLE_BYTES = 80;
  /// @notice The largest supply, escrow and price. It keeps every product of the clearing below 2^256.
  uint256 public constant MAX_AMOUNT = 2 ** 112;
  uint8 public constant MAX_SALE_DECIMALS = 30;
  uint8 public constant REVEAL_DEMAND_CURVE = 0;

  error RevealModeUnsupported(uint8 revealMode);
  error InvalidTitle();
  error InvalidPrices();
  error InvalidLevels();
  error InvalidGate();
  error GateConfigWithoutGate();
  error InvalidToken();
  error InvalidAmount();

  /// @dev What `decode` reads from `customParams`.
  struct Params {
    uint8 revealMode;
    uint8 levels;
    uint256[SALE_LEVELS] prices;
    address saleToken;
    uint256 supply;
    address paymentToken;
    uint256 escrow;
    string title;
    address gate;
    bytes gateConfig;
  }

  /// @notice Decodes and checks `abi.encode(uint8 revealMode, uint8 levels, uint256[16] prices, address
  /// saleToken, uint256 supply, address paymentToken, uint256 escrow, string title, address gate, bytes
  /// gateConfig)`. The creator of the returned sale is not set.
  function decode(bytes calldata customParams) public view returns (Sale memory s, bytes memory gateConfig) {
    // The flat `abi.encode(a, b, ...)` of the parameters is the encoding of one struct without its
    // head offset: add the offset word, and decode the struct.
    Params memory p = abi.decode(bytes.concat(bytes32(uint256(32)), customParams), (Params));
    s.revealMode = p.revealMode;
    s.levels = p.levels;
    s.prices = p.prices;
    s.saleToken = p.saleToken;
    s.supply = p.supply;
    s.paymentToken = p.paymentToken;
    s.escrow = p.escrow;
    s.title = p.title;
    s.gate = p.gate;
    gateConfig = p.gateConfig;
    _check(s, gateConfig);
    uint8 decimals = IERC20Metadata(s.saleToken).decimals();
    if (decimals > MAX_SALE_DECIMALS) revert InvalidToken();
    s.saleUnit = 10 ** uint256(decimals);
  }

  function _check(Sale memory s, bytes memory gateConfig) private view {
    if (s.revealMode != REVEAL_DEMAND_CURVE) revert RevealModeUnsupported(s.revealMode);
    if (s.levels < MIN_LEVELS || s.levels > SALE_LEVELS) revert InvalidLevels();
    if (s.prices[0] == 0) revert InvalidPrices();
    for (uint256 level = 1; level < s.levels; level++) {
      if (s.prices[level] <= s.prices[level - 1]) revert InvalidPrices();
    }
    // The steps the creator did not choose are empty, so the stored list is canonical.
    for (uint256 level = s.levels; level < SALE_LEVELS; level++) {
      if (s.prices[level] != 0) revert InvalidPrices();
    }
    if (s.prices[s.levels - 1] > MAX_AMOUNT) revert InvalidPrices();
    if (s.supply == 0 || s.supply > MAX_AMOUNT || s.escrow == 0 || s.escrow > MAX_AMOUNT) revert InvalidAmount();
    if (s.saleToken.code.length == 0 || s.paymentToken.code.length == 0 || s.saleToken == s.paymentToken) revert InvalidToken();
    uint256 titleBytes = bytes(s.title).length;
    if (titleBytes == 0 || titleBytes > MAX_TITLE_BYTES) revert InvalidTitle();
    if (s.gate == address(0)) {
      if (gateConfig.length != 0) revert GateConfigWithoutGate();
    } else if (s.gate.code.length == 0) {
      revert InvalidGate();
    }
  }
}
