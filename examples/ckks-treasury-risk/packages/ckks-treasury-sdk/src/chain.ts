// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

// On-chain leg: the `CkksTreasuryE3Program` SEVEN-leg envelope and the sender-bound submission.
// Like CRISP's `submitVoteDirectly`, the submission is sent FROM THE DAO'S WALLET — the validity
// leg's `address` public input must equal `msg.sender`, so nobody (not the server) can relay it.
// All three ciphertexts travel in calldata; the server indexes `SubmissionPublished` and fetches
// the bytes from the transaction (CRISP's InputPublished model — no side upload).

import { decodeAbiParameters, encodeAbiParameters, parseAbi, parseAbiParameters } from 'viem'
import type { Address, Hex, PublicClient, WalletClient } from 'viem'

import type { TreasurySubmission } from './types'

/**
 * `CkksTreasuryE3Program.TreasurySubmission` — a single NESTED tuple, not a flat field list:
 * each `GrecoPair` is its own dynamic tuple with head/tail offsets, so
 * `abi.decode(data, (TreasurySubmission))` only accepts this shape. Pinned against the
 * contract by `test/CkksTreasuryE3Program.spec.ts`.
 */
export const SEVEN_LEG_ENVELOPE = parseAbiParameters(
  '((bytes, bytes, bytes32[], bytes, bytes32[]), (bytes, bytes, bytes32[], bytes, bytes32[]), (bytes, bytes, bytes32[], bytes, bytes32[]), bytes, bytes32[])',
)

export const TREASURY_PROGRAM_ABI = parseAbi([
  'function publishInput(uint256 e3Id, bytes data)',
  'function registerRound(uint256 e3Id, bytes32[4] weights, address[] daos)',
  'function weights(uint256 e3Id) view returns (bytes32[4])',
  'function daos(uint256 e3Id) view returns (address[])',
  'function daoSlot(uint256 e3Id, address dao) view returns (uint256)',
  'function submissionCount(uint256 e3Id) view returns (uint256)',
  'function hasSubmitted(uint256 e3Id, address dao) view returns (bool)',
  'function seenUCommitments(uint256 e3Id, bytes32 u) view returns (bool)',
  'function riskFromOutput(bytes plaintextOutput) pure returns (int128)',
  'event SubmissionPublished(uint256 indexed e3Id, address indexed dao, uint256 index, bytes32 forwardCiphertextHash, bytes32 reversedCiphertextHash, bytes32 maskCiphertextHash, bytes32 mCommitmentFwd, bytes32 mCommitmentRev, bytes32 mCommitmentMask)',
  'event RoundRegistered(uint256 indexed e3Id, bytes32[4] weights, uint256 daos)',
  'error InvalidVerifierAddress()',
  'error NotOwner()',
  'error RoundAlreadyRegistered(uint256 e3Id)',
  'error RoundNotRegistered(uint256 e3Id)',
  'error NoDaos()',
  'error DuplicateDao(address dao)',
  'error InvalidInputEncoding()',
  'error WrongPublicInputCount(uint256 leg, uint256 got, uint256 want)',
  'error UCommitmentMismatch(uint256 ciphertext, bytes32 ct0Leg, bytes32 ct1Leg)',
  'error MCommitmentMismatch(uint256 ciphertext, bytes32 ct0Leg, bytes32 appLeg)',
  'error DuplicateSubmission(uint256 e3Id, bytes32 uCommitment)',
  'error AlreadySubmitted(uint256 e3Id, address dao)',
  'error WrongSender(address proven, address sender)',
  'error NotRegistered(uint256 e3Id, address dao)',
  'error WrongIndex(uint256 got, uint256 want)',
  'error WrongWeights(uint256 word, bytes32 got, bytes32 want)',
  'error Ct0ProofInvalid(uint256 ciphertext)',
  'error Ct1ProofInvalid(uint256 ciphertext)',
  'error AppProofInvalid()',
  'error InvalidOutputLength(uint256 got)',
])

/** Seven Honk verifies measure 20,037,798 gas (hardhat spec, 105,600-byte calldata). */
export const PUBLISH_GAS_LIMIT = 29_000_000n

export const encodeSubmissionEnvelope = (s: TreasurySubmission): Hex =>
  encodeAbiParameters(SEVEN_LEG_ENVELOPE, [
    [
      [s.ciphertextFwd, s.ct0F.proof, s.ct0F.publicInputs, s.ct1F.proof, s.ct1F.publicInputs],
      [s.ciphertextRev, s.ct0R.proof, s.ct0R.publicInputs, s.ct1R.proof, s.ct1R.publicInputs],
      [s.ciphertextMask, s.ct0M.proof, s.ct0M.publicInputs, s.ct1M.proof, s.ct1M.publicInputs],
      s.app.proof,
      s.app.publicInputs,
    ],
  ])

/** Recovers all three ciphertexts from a `publishInput(uint256,bytes)` calldata (what the server does). */
export const decodeCiphertextsFromCalldata = (input: Hex): { forward: Hex; reversed: Hex; mask: Hex } => {
  const args = decodeAbiParameters(parseAbiParameters('uint256, bytes'), `0x${input.slice(10)}`)
  const decoded = decodeAbiParameters(SEVEN_LEG_ENVELOPE, args[1])
  return { forward: decoded[0][0][0], reversed: decoded[0][1][0], mask: decoded[0][2][0] }
}

export interface PublishResult {
  hash: Hex
  gasUsed: bigint
  blockNumber: bigint
}

/**
 * Simulate then send `publishInput` from the connected wallet. A contract refusal (wrong weights,
 * wrong slot, replay, wrong sender) surfaces as a decoded custom error from the simulation
 * instead of a mined revert.
 */
export const publishSubmission = async (
  walletClient: WalletClient,
  publicClient: PublicClient,
  program: Address,
  e3Id: bigint,
  submission: TreasurySubmission,
): Promise<PublishResult> => {
  const account = walletClient.account
  if (!account) throw new Error('wallet has no account')
  const data = encodeSubmissionEnvelope(submission)
  const { request } = await publicClient.simulateContract({
    account,
    address: program,
    abi: TREASURY_PROGRAM_ABI,
    functionName: 'publishInput',
    args: [e3Id, data],
    gas: PUBLISH_GAS_LIMIT,
  })
  const hash = await walletClient.writeContract(request)
  const receipt = await publicClient.waitForTransactionReceipt({ hash })
  if (receipt.status !== 'success') throw new Error(`submission transaction reverted: ${hash}`)
  return { hash, gasUsed: receipt.gasUsed, blockNumber: receipt.blockNumber }
}
