// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

// On-chain leg: the `CkksCreditE3Program` FIVE-leg envelope and the sender-bound submission.
// Like CRISP's `submitVoteDirectly`, the application is sent FROM THE APPLICANT'S WALLET — the
// credit leg's `address` public input must equal `msg.sender`, so nobody (not the server) can relay
// it. Both ciphertexts travel in calldata; the server indexes `ApplicationPublished` and fetches
// the bytes from the transaction (CRISP's InputPublished model — no side upload).

import { decodeAbiParameters, encodeAbiParameters, parseAbi, parseAbiParameters } from 'viem'
import type { Address, Hex, PublicClient, WalletClient } from 'viem'

import type { ApplicationSubmission } from './types'

/**
 * `CkksCreditE3Program.CreditApplication` — a single NESTED tuple, not a flat
 * field list: each `GrecoPair` is its own dynamic tuple with head/tail
 * offsets, so `abi.decode(data, (CreditApplication))` only accepts this shape.
 * Pinned against the contract by `test/CkksCreditE3Program.spec.ts`.
 */
export const FIVE_LEG_ENVELOPE = parseAbiParameters(
  '((bytes, bytes, bytes32[], bytes, bytes32[]), (bytes, bytes, bytes32[], bytes, bytes32[]), bytes, bytes32[])',
)

export const CREDIT_PROGRAM_ABI = parseAbi([
  'struct Model { uint256 cap; bytes32[8] weights; bytes32 bias; }',
  'function publishInput(uint256 e3Id, bytes data)',
  'function registerRound(uint256 e3Id, bytes32 root, Model model, address[] applicants)',
  'function issuerRoots(uint256 e3Id) view returns (bytes32)',
  'function model(uint256 e3Id) view returns (Model)',
  'function applicants(uint256 e3Id) view returns (address[])',
  'function applicantSlot(uint256 e3Id, address applicant) view returns (uint256)',
  'function applicationCount(uint256 e3Id) view returns (uint256)',
  'function hasApplied(uint256 e3Id, address applicant) view returns (bool)',
  'function seenUCommitments(uint256 e3Id, bytes32 u) view returns (bool)',
  'event ApplicationPublished(uint256 indexed e3Id, address indexed applicant, uint256 index, bytes32 logitCiphertextHash, bytes32 maskCiphertextHash, bytes32 mCommitmentZ, bytes32 mCommitmentM)',
  'event RoundRegistered(uint256 indexed e3Id, bytes32 root, uint256 cap, uint256 applicants)',
  'error RoundAlreadyRegistered(uint256 e3Id)',
  'error RoundNotRegistered(uint256 e3Id)',
  'error InvalidRoot()',
  'error InvalidCap()',
  'error NotOwner()',
  'error NoApplicants()',
  'error DuplicateApplicant(address applicant)',
  'error DuplicateSubmission(uint256 e3Id, bytes32 uCommitment)',
  'error AlreadyApplied(uint256 e3Id, address applicant)',
  'error WrongSender(address proven, address sender)',
  'error WrongRoot(bytes32 got, bytes32 want)',
  'error WrongCap(uint256 got, uint256 want)',
  'error NotRegistered(uint256 e3Id, address applicant)',
  'error WrongIndex(uint256 got, uint256 want)',
  'error WrongModel(uint256 word, bytes32 got, bytes32 want)',
  'error UCommitmentMismatch(uint256 ciphertext, bytes32 ct0Leg, bytes32 ct1Leg)',
  'error MCommitmentMismatch(uint256 ciphertext, bytes32 ct0Leg, bytes32 appLeg)',
  'error Ct0ProofInvalid(uint256 ciphertext)',
  'error Ct1ProofInvalid(uint256 ciphertext)',
  'error AppProofInvalid()',
])

/** Five Honk verifies ≈ 5M gas; the envelope itself is ~350 KB of calldata. */
export const PUBLISH_GAS_LIMIT = 29_000_000n

export const encodeApplicationEnvelope = (s: ApplicationSubmission): Hex =>
  encodeAbiParameters(FIVE_LEG_ENVELOPE, [
    [
      [s.ciphertextZ, s.ct0Z.proof, s.ct0Z.publicInputs, s.ct1Z.proof, s.ct1Z.publicInputs],
      [s.ciphertextM, s.ct0M.proof, s.ct0M.publicInputs, s.ct1M.proof, s.ct1M.publicInputs],
      s.app.proof,
      s.app.publicInputs,
    ],
  ])

/** Recovers both ciphertexts from a `publishInput(uint256,bytes)` calldata (what the server does). */
export const decodeCiphertextsFromCalldata = (input: Hex): { logit: Hex; mask: Hex } => {
  const args = decodeAbiParameters(parseAbiParameters('uint256, bytes'), `0x${input.slice(10)}`)
  const decoded = decodeAbiParameters(FIVE_LEG_ENVELOPE, args[1])
  return { logit: decoded[0][0][0], mask: decoded[0][1][0] }
}

export interface PublishResult {
  hash: Hex
  gasUsed: bigint
  blockNumber: bigint
}

/**
 * Simulate then send `publishInput` from the connected wallet. A contract refusal (wrong root,
 * wrong model, wrong slot, replay, wrong sender) surfaces as a decoded custom error from the
 * simulation instead of a mined revert.
 */
export const publishApplication = async (
  walletClient: WalletClient,
  publicClient: PublicClient,
  program: Address,
  e3Id: bigint,
  submission: ApplicationSubmission,
): Promise<PublishResult> => {
  const account = walletClient.account
  if (!account) throw new Error('wallet has no account')
  const data = encodeApplicationEnvelope(submission)
  const { request } = await publicClient.simulateContract({
    account,
    address: program,
    abi: CREDIT_PROGRAM_ABI,
    functionName: 'publishInput',
    args: [e3Id, data],
    gas: PUBLISH_GAS_LIMIT,
  })
  const hash = await walletClient.writeContract(request)
  const receipt = await publicClient.waitForTransactionReceipt({ hash })
  if (receipt.status !== 'success') throw new Error(`application transaction reverted: ${hash}`)
  return { hash, gasUsed: receipt.gasUsed, blockNumber: receipt.blockNumber }
}
