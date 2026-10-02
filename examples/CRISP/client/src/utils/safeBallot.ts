// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { MAX_SAFE_OWNERS, MAX_SAFE_SIGNERS } from '@crisp-e3/sdk'
import { getAddress, hashTypedData, parseAbi } from 'viem'
import type { Address, Hex, PublicClient } from 'viem'
import { ballotTypedData } from '@/utils/ballotDigest'

/**
 * What the owners of a Safe need to sign one ballot: enough to rebuild the digest themselves.
 *
 * It travels only in the fragment of a link (`#/safe-sign/…`), which a browser never sends to a
 * server. So neither the CRISP server nor the web host learns that a Safe collects signatures, which
 * would mark the later input as a vote.
 */
export type SafeSignRequest = {
  chainId: number
  crispProgram: Address
  e3Id: string
  safe: Address
  ctCommitment: Hex
  owners: Address[]
  /** The owners that sign with a key. A contract owner signs in its own app, which can publish the message. */
  keyOwners: Address[]
  threshold: number
  /** The option the coordinator encrypted. The co-signers cannot check it against the ciphertext. */
  choice: string
}

/** What the coordinator reads about a Safe before it prepares a ballot for it. */
export type SafeSlot = Pick<SafeSignRequest, 'safe' | 'owners' | 'keyOwners' | 'threshold'>

const SAFE_ABI = parseAbi(['function getOwners() view returns (address[])', 'function getThreshold() view returns (uint256)'])
const CRISP_SAFE_ABI = parseAbi(['function isSafe(address account) view returns (bool)'])

/** The link a co-signer opens: the app's own page, with the request in the fragment. */
export const signRequestLink = (request: SafeSignRequest): string => {
  const base64 = btoa(String.fromCharCode(...new TextEncoder().encode(JSON.stringify(request))))
  const base64Url = base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
  return `${window.location.origin}${window.location.pathname}#/safe-sign/${base64Url}`
}

/**
 * Parse the signing request of a link, the text after `#/safe-sign/`.
 *
 * @throws When the text holds no well-formed request.
 */
export const parseSignRequest = (encoded: string): SafeSignRequest => {
  try {
    const bytes = Uint8Array.from(atob(encoded.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0))
    const r = JSON.parse(new TextDecoder().decode(bytes))
    const request: SafeSignRequest = {
      chainId: r.chainId,
      crispProgram: getAddress(r.crispProgram),
      e3Id: r.e3Id,
      safe: getAddress(r.safe),
      ctCommitment: r.ctCommitment,
      owners: r.owners.map((owner: string) => getAddress(owner)),
      keyOwners: r.keyOwners.map((owner: string) => getAddress(owner)),
      threshold: r.threshold,
      choice: String(r.choice),
    }
    // Hashing the typed data also checks the round and the ciphertext commitment.
    safeBallotTypedData(request)
    if (!Number.isSafeInteger(request.chainId) || !Number.isInteger(request.threshold)) throw new Error()
    if (request.keyOwners.some((owner) => !request.owners.includes(owner))) throw new Error()
    return request
  } catch {
    throw new Error('This link holds no valid Safe signing request. Ask the coordinator for the link again.')
  }
}

/**
 * The typed data each owner signs: the Safe's EIP-712 `SafeMessage` over the CRISP ballot digest.
 *
 * Built from the request alone, with no network access. Its hash is the `digest` that
 * `CRISPProgram.ballotAuthorization` returns for the Safe, and the Safe's own `isValidSignature`
 * accepts the signature.
 *
 * @param request The signing request.
 * @returns The typed data for `signTypedData`, and its hash.
 */
export const safeBallotTypedData = (request: SafeSignRequest) => {
  const ballotDigest = hashTypedData({
    ...ballotTypedData(request.chainId, request.crispProgram),
    message: { e3Id: BigInt(request.e3Id), slot: request.safe, ciphertextCommitment: request.ctCommitment },
  })
  const typedData = {
    domain: { chainId: request.chainId, verifyingContract: request.safe },
    types: { SafeMessage: [{ name: 'message', type: 'bytes' }] },
    primaryType: 'SafeMessage',
    // `abi.encode(bytes32)` is the 32 bytes of the digest itself.
    message: { message: ballotDigest },
  } as const
  return { typedData, digest: hashTypedData(typedData) }
}

/** Code that EIP-7702 installs on an account: a delegation. The account keeps its private key. */
const EIP7702_DELEGATION_PREFIX = '0xef0100'

/**
 * Read a Safe's owners and threshold, after a check that the CRISP program accepts it as a Safe.
 *
 * @throws When the program does not accept the Safe, the Safe is above the ballot caps, or fewer
 * than `threshold` owners sign with a private key.
 */
export const readSafeSlot = async (client: PublicClient, crispProgram: Address, safe: Address): Promise<SafeSlot> => {
  if (!(await client.readContract({ address: crispProgram, abi: CRISP_SAFE_ABI, functionName: 'isSafe', args: [safe] }))) {
    throw new Error('This address is not a Safe that this CRISP deployment accepts (Safe 1.3.0, 1.4.1 or 1.5.0).')
  }
  const [rawOwners, rawThreshold] = await Promise.all([
    client.readContract({ address: safe, abi: SAFE_ABI, functionName: 'getOwners' }),
    client.readContract({ address: safe, abi: SAFE_ABI, functionName: 'getThreshold' }),
  ])
  const owners = rawOwners.map((owner) => getAddress(owner))
  const threshold = Number(rawThreshold)
  if (owners.length > MAX_SAFE_OWNERS || threshold > MAX_SAFE_SIGNERS) {
    throw new Error(
      `This Safe has ${owners.length} owners and a threshold of ${threshold}. A ballot supports at most ${MAX_SAFE_OWNERS} owners and a threshold of ${MAX_SAFE_SIGNERS}.`,
    )
  }
  const codes = await Promise.all(owners.map((owner) => client.getCode({ address: owner })))
  const keyOwners = owners.filter((_, i) => !codes[i] || codes[i] === '0x' || codes[i].toLowerCase().startsWith(EIP7702_DELEGATION_PREFIX))
  if (keyOwners.length < threshold) {
    throw new Error(
      `Only ${keyOwners.length} owners of this Safe sign with a private key, and the ballot needs ${threshold}. Owners that are contracts, such as nested Safes, cannot sign a ballot.`,
    )
  }
  return { safe, owners, keyOwners, threshold }
}
