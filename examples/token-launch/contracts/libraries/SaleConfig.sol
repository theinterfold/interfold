// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
pragma solidity 0.8.28;

import { IERC20Metadata } from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";
import { ITokenLaunch } from "../interfaces/ITokenLaunch.sol";

/// @dev The price steps of the slot layout. A sale uses `levels` of them.
uint8 constant SALE_LEVELS = 16;
/// @dev The escrow tiers of a sale.
uint8 constant SALE_TIERS = 4;

/// @notice The configuration of a sale, from the `customParams` of the request of round 1.
struct Sale {
  /// @dev The requester of round 1. It deposited the supply and gets the proceeds.
  address creator;
  uint8 levels;
  address saleToken;
  address paymentToken;
  uint256 supply;
  /// @dev Payment-token base units of one budget unit.
  uint256 budgetUnit;
  /// @dev `10^decimals` of the sale token: the base units of one whole sale token.
  uint256 saleUnit;
  /// @dev The escrow tiers in budget units, ascending, trailing zeros unused.
  uint16[SALE_TIERS] tiers;
  /// @dev The price of each step: payment-token base units per `saleUnit` sale-token base units.
  uint256[SALE_LEVELS] prices;
  string title;
}

/// @title Decoder and checker of the parameters of a sale (role 1).
/// @notice An external library, because the program is near the size limit of a contract.
library SaleConfig {
  uint8 public constant MIN_LEVELS = 8;
  uint256 public constant MAX_TITLE_BYTES = 80;
  /// @notice The largest supply, budget unit and price. It keeps every product of the clearing below 2^256.
  uint256 public constant MAX_AMOUNT = 2 ** 112;
  uint16 public constant MAX_BUDGET_UNITS = 4095;
  uint8 public constant MAX_SALE_DECIMALS = 30;

  /// @dev What `decode` reads from the body. A struct with a dynamic member is encoded with one more offset
  /// word than the flat `abi.encode` of its members, which `decode` adds.
  struct Params {
    uint8 levels;
    uint256[SALE_LEVELS] prices;
    address saleToken;
    uint256 supply;
    address paymentToken;
    uint256 budgetUnit;
    uint16[SALE_TIERS] tiers;
    string title;
  }

  /// @notice Decodes and checks `abi.encode(uint8 levels, uint256[16] prices, address saleToken, uint256 supply,
  /// address paymentToken, uint256 budgetUnit, uint16[4] tiers, string title)`, stores the sale and emits
  /// `SaleCreated`. Storing here keeps the copy code out of `TokenLaunchProgram`.
  function create(Sale storage s, uint256 saleId, address creator, bytes memory body) public {
    Params memory p = abi.decode(bytes.concat(bytes32(uint256(32)), body), (Params));
    _check(p);
    uint8 decimals = IERC20Metadata(p.saleToken).decimals();
    if (decimals > MAX_SALE_DECIMALS) revert ITokenLaunch.InvalidToken();
    s.creator = creator;
    s.levels = p.levels;
    s.saleToken = p.saleToken;
    s.paymentToken = p.paymentToken;
    s.supply = p.supply;
    s.budgetUnit = p.budgetUnit;
    s.saleUnit = 10 ** uint256(decimals);
    s.tiers = p.tiers;
    s.prices = p.prices;
    s.title = p.title;
    emit ITokenLaunch.SaleCreated(
      saleId,
      creator,
      p.levels,
      p.prices,
      p.saleToken,
      p.paymentToken,
      p.supply,
      p.budgetUnit,
      p.tiers,
      p.title
    );
  }

  function _check(Params memory s) private view {
    if (s.levels < MIN_LEVELS || s.levels > SALE_LEVELS) revert ITokenLaunch.InvalidLevels();
    if (s.prices[0] == 0) revert ITokenLaunch.InvalidPrices();
    for (uint256 level = 1; level < s.levels; level++) {
      if (s.prices[level] <= s.prices[level - 1]) revert ITokenLaunch.InvalidPrices();
    }
    // The steps the creator did not choose are empty, so the stored list is canonical.
    for (uint256 level = s.levels; level < SALE_LEVELS; level++) {
      if (s.prices[level] != 0) revert ITokenLaunch.InvalidPrices();
    }
    if (s.prices[s.levels - 1] > MAX_AMOUNT) revert ITokenLaunch.InvalidPrices();
    // Tiers: strictly increasing and at most 4095 units, then only zeros.
    if (s.tiers[0] == 0) revert ITokenLaunch.InvalidTiers();
    bool unused;
    for (uint256 t = 0; t < SALE_TIERS; t++) {
      uint16 tier = s.tiers[t];
      if (tier == 0) {
        unused = true;
      } else if (unused || tier > MAX_BUDGET_UNITS || (t > 0 && tier <= s.tiers[t - 1])) {
        revert ITokenLaunch.InvalidTiers();
      }
    }
    if (s.supply == 0 || s.supply > MAX_AMOUNT || s.budgetUnit == 0 || s.budgetUnit > MAX_AMOUNT) revert ITokenLaunch.InvalidAmount();
    if (s.saleToken.code.length == 0 || s.paymentToken.code.length == 0 || s.saleToken == s.paymentToken)
      revert ITokenLaunch.InvalidToken();
    uint256 titleBytes = bytes(s.title).length;
    if (titleBytes == 0 || titleBytes > MAX_TITLE_BYTES) revert ITokenLaunch.InvalidTitle();
  }
}
