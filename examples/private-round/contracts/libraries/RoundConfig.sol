// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
pragma solidity 0.8.28;

import { IERC20Metadata } from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";

/// @dev The most price steps of a round. The price lanes of the output have this many slots.
uint8 constant ROUND_LEVELS = 16;

/// @notice The configuration of one round, from the request's `customParams`.
/// @dev The order of the members is the order of the return values of `PrivateRoundProgram.sale`.
/// The prices come last: the public getter of the mapping leaves out arrays.
struct Round {
  uint8 levels;
  /// @dev The E3 requester. It deposited the supply and gets the proceeds.
  address creator;
  string title;
  address saleToken;
  address paymentToken;
  /// @dev The sale-token base units of one lot: what each bidder buys.
  uint256 lot;
  uint8 lots;
  uint8 reserveStep;
  uint8 minLots;
  /// @dev `lot * lots`: the sale tokens that the creator deposits.
  uint256 supply;
  /// @dev What every bidder escrows once: the price of one lot at the highest step, rounded up.
  uint256 escrow;
  address gate;
  /// @dev `10^decimals` of the sale token: the base units of one whole sale token.
  uint256 saleUnit;
  /// @dev The price of each step: payment-token base units per `saleUnit` sale-token base units.
  /// Read the prices with `salePrices`.
  uint256[ROUND_LEVELS] prices;
}

/// @title Decoder and checker of the parameters of a private round.
/// @notice An external library, because the program is near the size limit of a contract.
library RoundConfig {
  uint8 public constant MIN_LEVELS = 2;
  uint8 public constant MAX_LOTS = 12;
  uint256 public constant MAX_TITLE_BYTES = 80;
  /// @notice The largest price and supply. It keeps every product of the settlement below 2^256.
  uint256 public constant MAX_AMOUNT = 2 ** 112;
  uint8 public constant MAX_SALE_DECIMALS = 30;

  error InvalidLevels();
  error InvalidPrices();
  error InvalidLots();
  error InvalidReserve();
  error InvalidAmount();
  error InvalidTitle();
  error InvalidToken();
  error InvalidGate();
  error GateConfigWithoutGate();

  /// @notice A round was requested. `PrivateRoundProgram` declares the same event: this copy lets the
  /// library emit it from the program's address, which keeps the program smaller.
  event SaleCreated(
    uint256 indexed e3Id,
    address indexed creator,
    uint8 levels,
    uint256[ROUND_LEVELS] prices,
    address saleToken,
    address paymentToken,
    uint256 lot,
    uint8 lots,
    uint8 reserveStep,
    uint8 minLots,
    uint256 escrow,
    string title,
    address gate
  );

  /// @dev What `decode` reads from `customParams`.
  struct Params {
    uint8 levels;
    uint256[ROUND_LEVELS] prices;
    address saleToken;
    uint256 lot;
    uint8 lots;
    uint8 reserveStep;
    uint8 minLots;
    address paymentToken;
    string title;
    address gate;
    bytes gateConfig;
  }

  /// @notice Decodes and checks `abi.encode(uint8 levels, uint256[16] prices, address saleToken,
  /// uint256 lot, uint8 lots, uint8 reserveStep, uint8 minLots, address paymentToken, string title,
  /// address gate, bytes gateConfig)`, derives the supply, the escrow and the sale unit, and writes the
  /// round to `s`. The storage write is here, to keep the program below the contract size limit.
  /// @return gateConfig The gate configuration, for the gate.
  function init(Round storage s, uint256 e3Id, bytes calldata customParams, address creator) public returns (bytes memory gateConfig) {
    // The flat `abi.encode(a, b, ...)` of the parameters is the encoding of one struct without its
    // head offset: add the offset word, and decode the struct.
    Params memory p = abi.decode(bytes.concat(bytes32(uint256(32)), customParams), (Params));
    _check(p);
    uint8 decimals = IERC20Metadata(p.saleToken).decimals();
    if (decimals > MAX_SALE_DECIMALS) revert InvalidToken();
    s.levels = p.levels;
    s.creator = creator;
    s.prices = p.prices;
    s.saleToken = p.saleToken;
    s.lot = p.lot;
    s.lots = p.lots;
    s.reserveStep = p.reserveStep;
    s.minLots = p.minLots;
    s.paymentToken = p.paymentToken;
    s.title = p.title;
    s.gate = p.gate;
    gateConfig = p.gateConfig;
    s.saleUnit = 10 ** uint256(decimals);
    s.supply = p.lot * p.lots;
    s.escrow = (p.lot * p.prices[p.levels - 1] + s.saleUnit - 1) / s.saleUnit;
    _emitSaleCreated(s, e3Id);
  }

  function _emitSaleCreated(Round storage s, uint256 e3Id) private {
    emit SaleCreated(
      e3Id,
      s.creator,
      s.levels,
      s.prices,
      s.saleToken,
      s.paymentToken,
      s.lot,
      s.lots,
      s.reserveStep,
      s.minLots,
      s.escrow,
      s.title,
      s.gate
    );
  }

  function _check(Params memory p) private view {
    if (p.levels < MIN_LEVELS || p.levels > ROUND_LEVELS) revert InvalidLevels();
    if (p.prices[0] == 0) revert InvalidPrices();
    for (uint256 level = 1; level < p.levels; level++) {
      if (p.prices[level] <= p.prices[level - 1]) revert InvalidPrices();
    }
    // The steps the creator did not choose are empty, so the stored list is canonical.
    for (uint256 level = p.levels; level < ROUND_LEVELS; level++) {
      if (p.prices[level] != 0) revert InvalidPrices();
    }
    if (p.prices[p.levels - 1] > MAX_AMOUNT) revert InvalidPrices();
    if (p.lots == 0 || p.lots > MAX_LOTS || p.minLots == 0 || p.minLots > p.lots) revert InvalidLots();
    if (p.reserveStep >= p.levels) revert InvalidReserve();
    if (p.lot == 0 || p.lot > MAX_AMOUNT || p.lot * p.lots > MAX_AMOUNT) revert InvalidAmount();
    if (p.saleToken.code.length == 0 || p.paymentToken.code.length == 0 || p.saleToken == p.paymentToken) revert InvalidToken();
    uint256 titleBytes = bytes(p.title).length;
    if (titleBytes == 0 || titleBytes > MAX_TITLE_BYTES) revert InvalidTitle();
    if (p.gate == address(0)) {
      if (p.gateConfig.length != 0) revert GateConfigWithoutGate();
    } else if (p.gate.code.length == 0) {
      revert InvalidGate();
    }
  }
}
