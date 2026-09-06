// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

// On-chain leg: the `CkksFedAvgE3Program` FIVE-leg envelope and the sender-bound submission.
// Like CRISP's `submitVoteDirectly`, the update is sent FROM THE CLIENT'S WALLET — the validity
// leg's `address` public input must equal `msg.sender`, so nobody (not the server) can relay it.
// Both ciphertexts travel in calldata; the server indexes `UpdatePublished` and fetches the bytes
// from the transaction (CRISP's InputPublished model — no side upload).

import { decodeAbiParameters, encodeAbiParameters, parseAbi, parseAbiParameters } from 'viem'
import type { Address, Hex, PublicClient, WalletClient } from 'viem'

import type { UpdateSubmission } from './types'

/**
 * `CkksFedAvgE3Program.Update` — a single NESTED tuple, not a flat field list: each `GrecoPair`
 * is its own dynamic tuple with head/tail offsets, so `abi.decode(data, (Update))` only accepts
 * this shape. Pinned against the contract by `test/CkksFedAvgE3Program.spec.ts`.
 */
export const FIVE_LEG_ENVELOPE = parseAbiParameters(
  '((bytes, bytes, bytes32[], bytes, bytes32[]), (bytes, bytes, bytes32[], bytes, bytes32[]), bytes, bytes32[])',
)

export const FEDAVG_PROGRAM_ABI = parseAbi([
  'struct Round { uint256 normBound; uint256 minClients; bool registered; }',
  'function publishInput(uint256 e3Id, bytes data)',
  'function registerRound(uint256 e3Id, uint256 normBound, uint256 minClients, address[] clientList)',
  'function round(uint256 e3Id) view returns (Round)',
  'function clients(uint256 e3Id) view returns (address[])',
  'function clientSlot(uint256 e3Id, address client) view returns (uint256)',
  'function submissionCount(uint256 e3Id) view returns (uint256)',
  'function hasSubmitted(uint256 e3Id, address client) view returns (bool)',
  'function seenUCommitments(uint256 e3Id, bytes32 u) view returns (bool)',
  'function meanFromOutput(bytes plaintextOutput) pure returns (int128[8] mean, int128 totalCount)',
  'event UpdatePublished(uint256 indexed e3Id, address indexed client, uint256 index, bytes32 gradientCiphertextHash, bytes32 countCiphertextHash, bytes32 mCommitmentGrad, bytes32 mCommitmentCount)',
  'event RoundRegistered(uint256 indexed e3Id, uint256 normBound, uint256 minClients, uint256 clients)',
  'error InvalidVerifierAddress()',
  'error NotOwner()',
  'error InvalidNormBound()',
  'error InvalidMinClients(uint256 minClients, uint256 clients)',
  'error RoundAlreadyRegistered(uint256 e3Id)',
  'error RoundNotRegistered(uint256 e3Id)',
  'error NoClients()',
  'error DuplicateClient(address client)',
  'error InvalidInputEncoding()',
  'error WrongPublicInputCount(uint256 leg, uint256 got, uint256 want)',
  'error UCommitmentMismatch(uint256 ciphertext, bytes32 ct0Leg, bytes32 ct1Leg)',
  'error MCommitmentMismatch(uint256 ciphertext, bytes32 ct0Leg, bytes32 appLeg)',
  'error DuplicateSubmission(uint256 e3Id, bytes32 uCommitment)',
  'error AlreadySubmitted(uint256 e3Id, address client)',
  'error WrongNormBound(uint256 got, uint256 want)',
  'error WrongSender(address proven, address sender)',
  'error NotRegistered(uint256 e3Id, address client)',
  'error WrongIndex(uint256 got, uint256 want)',
  'error Ct0ProofInvalid(uint256 ciphertext)',
  'error Ct1ProofInvalid(uint256 ciphertext)',
  'error AppProofInvalid()',
  'error InvalidOutputLength(uint256 length)',
  'error ZeroTotalCount()',
])

/** Five Honk verifies ≈ 5M gas; the envelope itself is ~350 KB of calldata. */
export const PUBLISH_GAS_LIMIT = 29_000_000n

export const encodeUpdateEnvelope = (s: UpdateSubmission): Hex =>
  encodeAbiParameters(FIVE_LEG_ENVELOPE, [
    [
      [s.ciphertextG, s.ct0G.proof, s.ct0G.publicInputs, s.ct1G.proof, s.ct1G.publicInputs],
      [s.ciphertextC, s.ct0C.proof, s.ct0C.publicInputs, s.ct1C.proof, s.ct1C.publicInputs],
      s.app.proof,
      s.app.publicInputs,
    ],
  ])

/** Recovers both ciphertexts from a `publishInput(uint256,bytes)` calldata (what the server does). */
export const decodeCiphertextsFromCalldata = (input: Hex): { gradient: Hex; count: Hex } => {
  const args = decodeAbiParameters(parseAbiParameters('uint256, bytes'), `0x${input.slice(10)}`)
  const decoded = decodeAbiParameters(FIVE_LEG_ENVELOPE, args[1])
  return { gradient: decoded[0][0][0], count: decoded[0][1][0] }
}

export interface PublishResult {
  hash: Hex
  gasUsed: bigint
  blockNumber: bigint
}

/**
 * Simulate then send `publishInput` from the connected wallet. A contract refusal (wrong bound,
 * wrong slot, replay, wrong sender) surfaces as a decoded custom error from the simulation
 * instead of a mined revert.
 */
export const publishUpdate = async (
  walletClient: WalletClient,
  publicClient: PublicClient,
  program: Address,
  e3Id: bigint,
  submission: UpdateSubmission,
): Promise<PublishResult> => {
  const account = walletClient.account
  if (!account) throw new Error('wallet has no account')
  const data = encodeUpdateEnvelope(submission)
  const { request } = await publicClient.simulateContract({
    account,
    address: program,
    abi: FEDAVG_PROGRAM_ABI,
    functionName: 'publishInput',
    args: [e3Id, data],
    gas: PUBLISH_GAS_LIMIT,
  })
  const hash = await walletClient.writeContract(request)
  const receipt = await publicClient.waitForTransactionReceipt({ hash })
  if (receipt.status !== 'success') throw new Error(`update transaction reverted: ${hash}`)
  return { hash, gasUsed: receipt.gasUsed, blockNumber: receipt.blockNumber }
}
