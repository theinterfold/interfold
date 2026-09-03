// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

// On-chain leg: the `CkksAppE3ProgramBase` three-leg envelope and the sender-bound submission.
// Like CRISP's `submitVoteDirectly`, the bid is sent FROM THE BIDDER'S WALLET — the auction leg's
// `address` public input must equal `msg.sender`, so nobody (not the server) can relay it. The
// ciphertext travels in calldata; the server indexes `VerifiedInputPublished` and fetches the
// bytes from the transaction (CRISP's InputPublished model — no side upload).

import { decodeAbiParameters, encodeAbiParameters, parseAbi, parseAbiParameters } from 'viem'
import type { Address, Hex, PublicClient, WalletClient } from 'viem'

import type { BidSubmission } from './types'

export const THREE_LEG_ENVELOPE = parseAbiParameters('bytes, bytes, bytes32[], bytes, bytes32[], bytes, bytes32[]')

export const AUCTION_PROGRAM_ABI = parseAbi([
  'function publishInput(uint256 e3Id, bytes data)',
  'function setBalanceRoot(uint256 e3Id, bytes32 root)',
  'function balanceRoots(uint256 e3Id) view returns (bytes32)',
  'function bidCap() view returns (uint256)',
  'function submissionCount(uint256 e3Id) view returns (uint256)',
  'function seenUCommitments(uint256 e3Id, bytes32 u) view returns (bool)',
  'event VerifiedInputPublished(uint256 indexed e3Id, address indexed publisher, bytes32 ciphertextHash, bytes32 ct0Commitment, bytes32 ct1Commitment, bytes32 mCommitment, bytes32 uCommitment)',
  'event BalanceRootSet(uint256 indexed e3Id, bytes32 root)',
  'error DuplicateSubmission(uint256 e3Id, bytes32 uCommitment)',
  'error WrongSender(address proven, address sender)',
  'error WrongRoot(bytes32 got, bytes32 want)',
  'error WrongCap(uint256 got, uint256 want)',
  'error RootNotSet(uint256 e3Id)',
  'error UCommitmentMismatch(bytes32 ct0Leg, bytes32 ct1Leg)',
  'error MCommitmentMismatch(bytes32 ct0Leg, bytes32 appLeg)',
  'error Ct0ProofInvalid()',
  'error Ct1ProofInvalid()',
  'error AppProofInvalid()',
])

/** Three Honk verifies ≈ 3M gas; the envelope itself is ~200 KB of calldata. */
export const PUBLISH_GAS_LIMIT = 29_000_000n

export const encodeBidEnvelope = (s: BidSubmission): Hex =>
  encodeAbiParameters(THREE_LEG_ENVELOPE, [
    s.ciphertext,
    s.ct0.proof,
    s.ct0.publicInputs,
    s.ct1.proof,
    s.ct1.publicInputs,
    s.app.proof,
    s.app.publicInputs,
  ])

/** Recovers the ciphertext bytes from a `publishInput(uint256,bytes)` calldata (what the server does). */
export const decodeCiphertextFromCalldata = (input: Hex): Hex => {
  const args = decodeAbiParameters(parseAbiParameters('uint256, bytes'), `0x${input.slice(10)}`)
  const [ciphertext] = decodeAbiParameters(THREE_LEG_ENVELOPE, args[1])
  return ciphertext
}

export interface PublishResult {
  hash: Hex
  gasUsed: bigint
  blockNumber: bigint
}

/**
 * Simulate then send `publishInput` from the connected wallet. A contract refusal (over-balance
 * forgery, replay, wrong sender) surfaces as a decoded custom error from the simulation instead of
 * a mined revert.
 */
export const publishBid = async (
  walletClient: WalletClient,
  publicClient: PublicClient,
  program: Address,
  e3Id: bigint,
  submission: BidSubmission,
): Promise<PublishResult> => {
  const account = walletClient.account
  if (!account) throw new Error('wallet has no account')
  const data = encodeBidEnvelope(submission)
  const { request } = await publicClient.simulateContract({
    account,
    address: program,
    abi: AUCTION_PROGRAM_ABI,
    functionName: 'publishInput',
    args: [e3Id, data],
    gas: PUBLISH_GAS_LIMIT,
  })
  const hash = await walletClient.writeContract(request)
  const receipt = await publicClient.waitForTransactionReceipt({ hash })
  if (receipt.status !== 'success') throw new Error(`bid transaction reverted: ${hash}`)
  return { hash, gasUsed: receipt.gasUsed, blockNumber: receipt.blockNumber }
}
