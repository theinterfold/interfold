// SPDX-License-Identifier: LGPL-3.0-only
import { ethers as ethersLib } from "ethers";

export const ZERO = ethersLib.ZeroAddress;
export const MSG_SENDER_SENTINEL =
  "0x0000000000000000000000000000000000000001";
export const DAY = 24n * 60n * 60n;
export const FORTY_DAYS = 40n * DAY;
export const FOUR_YEARS = 4n * 365n * DAY;
export const DEFAULT_SALE_AMOUNT = ethersLib.parseEther("1000").toString();
export const CCA_VERSION = "v2.0.0";
export const CCA_FACTORY_ADDRESS =
  "0x00cCa200BF124dBfA848937c553864f4B4CE0632";

export const AUCTION_PARAMETERS_TUPLE =
  "tuple(" +
  "address currency," +
  "address tokensRecipient," +
  "address fundsRecipient," +
  "uint64 startBlock," +
  "uint64 endBlock," +
  "uint64 claimBlock," +
  "uint256 tickSpacing," +
  "address validationHook," +
  "uint256 floorPrice," +
  "uint128 requiredCurrencyRaised," +
  "bytes auctionStepsData" +
  ")";

export const CCA_FACTORY_ABI = [
  "function create(address token,uint256 amount,bytes configData,bytes32 salt) returns (address)",
  "function getAddress(address token,uint256 amount,bytes configData,bytes32 salt,address sender) view returns (address)",
  "function protocolFeeController() view returns (address)",
];

export const CCA_AUCTION_ABI = [
  "function token() view returns (address)",
  "function totalSupply() view returns (uint128)",
  "function tokensRecipient() view returns (address)",
  "function fundsRecipient() view returns (address)",
  "function currency() view returns (address)",
  "function startBlock() view returns (uint64)",
  "function endBlock() view returns (uint64)",
  "function claimBlock() view returns (uint64)",
  "function validationHook() view returns (address)",
  "event TokensReceived(uint128 totalSupply)",
  "function tokensReceived() view returns (bool)",
  "function isGraduated() view returns (bool)",
  "function currencyRaised() view returns (uint256)",
  "function checkpoint() returns (tuple(uint256 clearingPrice,uint224 currencyRaisedAtClearingPriceQ96X7,uint256 cumulativeMpsPerPrice,uint24 cumulativeMps,uint64 prev,uint64 next))",
  "function bids(uint256 bidId) view returns (tuple(uint64 startBlock,uint24 startCumulativeMps,uint64 exitedBlock,uint256 maxPrice,address owner,uint256 amountQ96,uint256 tokensFilled))",
  "function submitBid(uint256 maxPrice,uint128 amount,address owner,bytes hookData) payable returns (uint256 bidId)",
  "function exitBid(uint256 bidId)",
  "function exitPartiallyFilledBid(uint256 bidId,uint64 lastFullyFilledCheckpointBlock,uint64 outbidBlock)",
  "function claimTokens(uint256 bidId)",
  "event BidSubmitted(uint256 indexed id,address indexed owner,uint256 price,uint256 amount)",
  "function bid() payable",
  "function claim() returns (uint256)",
];

export const PREDICATE_VALIDATION_HOOK_ABI = [
  "function auction() view returns (address)",
  "function owner() view returns (address)",
  "function getRegistry() view returns (address)",
  "function getPolicyID() view returns (string)",
  "function requireSenderIsOwner() view returns (bool)",
  "function setAuction(address auction)",
];

export const abi = ethersLib.AbiCoder.defaultAbiCoder();

