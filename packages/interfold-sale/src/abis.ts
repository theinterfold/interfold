// SPDX-License-Identifier: LGPL-3.0-only

export const AUCTION_ABI = [
  'function token() view returns (address)',
  'function totalSupply() view returns (uint128)',
  'function currency() view returns (address)',
  'function startBlock() view returns (uint64)',
  'function endBlock() view returns (uint64)',
  'function claimBlock() view returns (uint64)',
  'function tokensReceived() view returns (bool)',
  'function isGraduated() view returns (bool)',
  'function currencyRaised() view returns (uint256)',
  'function checkpoint() returns (tuple(uint256 clearingPrice,uint224 currencyRaisedAtClearingPriceQ96X7,uint256 cumulativeMpsPerPrice,uint24 cumulativeMps,uint64 prev,uint64 next))',
  'function bids(uint256 bidId) view returns (tuple(uint64 startBlock,uint24 startCumulativeMps,uint64 exitedBlock,uint256 maxPrice,address owner,uint256 amountQ96,uint256 tokensFilled))',
  'function submitBid(uint256 maxPrice,uint128 amount,address owner,bytes hookData) payable returns (uint256 bidId)',
  'function exitBid(uint256 bidId)',
  'function exitPartiallyFilledBid(uint256 bidId,uint64 lastFullyFilledCheckpointBlock,uint64 outbidBlock)',
  'function claimTokens(uint256 bidId)',
  'event BidSubmitted(uint256 indexed id,address indexed owner,uint256 price,uint256 amount)',
  'function bid() payable',
  'function claim() returns (uint256)',
] as const

export const FOLD_ABI = [
  'function balanceOf(address account) view returns (uint256)',
  'function totalSupply() view returns (uint256)',
  'function lockCount(address account) view returns (uint256)',
  'function queuedLockCount(address account) view returns (uint256)',
  'function locks(address account,uint256 index) view returns (bytes32 policyId,uint256 amount)',
  'function queuedLocks(address account,uint256 index) view returns (bytes32 policyId,uint256 amount)',
  'function lockedBalanceOf(address account) view returns (uint256)',
  'function transferableBalanceOf(address account) view returns (uint256)',
  'function owner() view returns (address)',
  'function pendingOwner() view returns (address)',
  'function tgeTimestamp() view returns (uint64)',
  'function phase() view returns (uint8)',
  'function hasRole(bytes32 role,address account) view returns (bool)',
  'function createLockPolicy(bytes32 policyId,tuple(uint64 holdUntil,tuple(uint8 anchor,uint64 start,uint64 cliffDuration,uint64 vestDuration) unlock) policy)',
  'function linkClaim(address account,uint256 amount,bytes32 policyId)',
  'function mintAllocations(tuple(address recipient,uint256 amount,bytes32 policyId,bytes32 label)[] allocations)',
  'function setTransferWhitelisted(address account,bool whitelisted)',
  'function setClaimLockExempt(address account,bool exempt)',
  'function acceptOwnership()',
  'function tge()',
  'event AllocationMinted(address indexed recipient,uint256 amount,bytes32 indexed policyId,bytes32 indexed label)',
  'event PolicyDefined(bytes32 indexed policyId,tuple(uint64 holdUntil,tuple(uint8 anchor,uint64 start,uint64 cliffDuration,uint64 vestDuration) unlock) policy)',
  'event TransferWhitelistUpdated(address indexed account,bool whitelisted)',
  'event ClaimLockExemptUpdated(address indexed account,bool exempt)',
  'event ActiveLockUpdated(address indexed account,bytes32 indexed policyId,uint256 amount)',
  'event QueuedLockUpdated(address indexed account,bytes32 indexed policyId,uint256 amount)',
  'event ActiveLockRelinked(address indexed account,bytes32 indexed fromPolicyId,bytes32 indexed toPolicyId,uint256 amount)',
  'event TgeTriggered(uint64 timestamp)',
] as const

export const BONDING_ABI = ['function totalBonded(address account) view returns (uint256)'] as const

export const ERC20_ABI = [
  'function decimals() view returns (uint8)',
  'function symbol() view returns (string)',
  'function balanceOf(address account) view returns (uint256)',
  'function allowance(address owner,address spender) view returns (uint256)',
  'function approve(address spender,uint256 amount) returns (bool)',
] as const
