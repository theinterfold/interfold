// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { MAX_SAFE_OWNERS, MAX_SAFE_SIGNERS } from '@crisp-e3/sdk'
import { getAddress, hashTypedData, isAddress, isHex, parseAbi } from 'viem'
import type { Address, Hex, PublicClient } from 'viem'
import { ballotTypedData } from '@/utils/ballotDigest'

/**
 * What the owners of a Safe need to sign one ballot: enough to rebuild the digest themselves.
 *
 * It travels only in the fragment of a link (`#/safe-sign/…`, a route of the app's hash router).
 * A browser never sends the fragment to a server, and the page it loads is the one every visitor
 * loads, so neither the CRISP server nor the web host learns that a Safe is collecting
 * signatures. That matters: a mask needs no signatures, so a signing session tied to a later
 * input would mark it as a vote.
 */
export type SafeSignRequest = {
  chainId: number
  crispProgram: Address
  e3Id: string
  safe: Address
  ctCommitment: Hex
  owners: Address[]
  /**
   * The owners that sign with a private key: accounts with no code, or with an EIP-7702
   * delegation. Only these may sign. An owner that is a contract, such as a nested Safe, would
   * sign through its own app, which can publish the message.
   */
  keyOwners: Address[]
  threshold: number
  /** The option the coordinator encrypted. The co-signers cannot check it against the ciphertext. */
  choice: string
}

/** The hash-router path of the co-signer page. */
export const SAFE_SIGN_ROUTE = '/safe-sign'

const SAFE_ABI = parseAbi(['function getOwners() view returns (address[])', 'function getThreshold() view returns (uint256)'])
const CRISP_SAFE_ABI = parseAbi(['function isSafe(address account) view returns (bool)'])

const toBase64Url = (text: string) =>
  btoa(String.fromCharCode(...new TextEncoder().encode(text)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '')
const fromBase64Url = (encoded: string) =>
  new TextDecoder().decode(Uint8Array.from(atob(encoded.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0)))

/** The link a co-signer opens: the app's own page, with the request in the fragment. */
export const signRequestLink = (request: SafeSignRequest): string =>
  `${window.location.origin}${window.location.pathname}#${SAFE_SIGN_ROUTE}/${toBase64Url(JSON.stringify(request))}`

/**
 * Parse and check a signing request.
 *
 * @param encoded The request as the link carries it, after `#/safe-sign/`.
 * @returns The request.
 * @throws When the text does not hold a well-formed request.
 */
export const parseSignRequest = (encoded: string): SafeSignRequest => {
  let value: unknown
  try {
    value = JSON.parse(fromBase64Url(encoded))
  } catch {
    throw new Error('This link holds no readable Safe signing request. Ask for the link again.')
  }
  if (typeof value !== 'object' || value === null) throw new Error('The signing request is not an object.')
  const r = value as Record<string, unknown>

  const address = (field: unknown, name: string): Address => {
    if (typeof field !== 'string' || !isAddress(field)) throw new Error(`The signing request has an invalid ${name}.`)
    return getAddress(field)
  }
  if (typeof r.chainId !== 'number' || !Number.isSafeInteger(r.chainId)) throw new Error('The signing request has an invalid chain.')
  if (typeof r.e3Id !== 'string' || !/^\d+$/.test(r.e3Id)) throw new Error('The signing request has an invalid round.')
  if (typeof r.ctCommitment !== 'string' || !isHex(r.ctCommitment) || r.ctCommitment.length !== 66) {
    throw new Error('The signing request has an invalid ciphertext commitment.')
  }
  if (!Array.isArray(r.owners) || r.owners.length === 0 || r.owners.length > MAX_SAFE_OWNERS) {
    throw new Error('The signing request has an invalid owner list.')
  }
  const owners = r.owners.map((owner, i) => address(owner, `owner ${i + 1}`))
  if (!Array.isArray(r.keyOwners)) throw new Error('The signing request has no list of owners that can sign.')
  const keyOwners = r.keyOwners.map((owner, i) => address(owner, `signing owner ${i + 1}`))
  if (keyOwners.some((owner) => !owners.includes(owner))) throw new Error('The signing request names a signer that is not an owner.')
  if (typeof r.threshold !== 'number' || !Number.isInteger(r.threshold) || r.threshold < 1 || r.threshold > MAX_SAFE_SIGNERS) {
    throw new Error('The signing request has an invalid threshold.')
  }
  if (typeof r.choice !== 'string' || r.choice.length > 200) throw new Error('The signing request has an invalid choice.')

  return {
    chainId: r.chainId,
    crispProgram: address(r.crispProgram, 'CRISP program'),
    e3Id: r.e3Id,
    safe: address(r.safe, 'Safe'),
    ctCommitment: r.ctCommitment as Hex,
    owners,
    keyOwners,
    threshold: r.threshold,
    choice: r.choice,
  }
}

/**
 * The typed data each owner signs: the Safe's EIP-712 `SafeMessage` over the CRISP ballot digest.
 *
 * Built entirely from the request, with no network access, so a co-signer checks what they sign
 * without a request that a server could log. Its hash is what `CRISPProgram.ballotAuthorization`
 * returns as `digest` for the Safe, and the Safe's own `isValidSignature` accepts the signature.
 *
 * @param request The signing request.
 * @returns The typed data for `signTypedData`, and its hash.
 */
export const safeBallotTypedData = (request: SafeSignRequest) => {
  const ballot = ballotTypedData(request.chainId, request.crispProgram)
  const ballotDigest = hashTypedData({
    ...ballot,
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

/** What the coordinator reads about a Safe before it prepares a ballot for it. */
export type SafeSlot = { address: Address; owners: Address[]; keyOwners: Address[]; threshold: number }

/** Code that EIP-7702 installs on an account: a delegation. The account keeps its private key. */
const EIP7702_DELEGATION_PREFIX = '0xef0100'

/**
 * Read a Safe's owners and threshold, and check that the CRISP program accepts it as a Safe.
 *
 * @param client The public client.
 * @param crispProgram The CRISP program of the round.
 * @param safe The Safe address.
 * @returns The Safe's owners, the owners that sign with a private key, and the threshold.
 * @throws When the program does not accept the address as a Safe, the Safe is above the caps, or
 * fewer than `threshold` owners sign with a private key.
 */
export const readSafeSlot = async (client: PublicClient, crispProgram: Address, safe: Address): Promise<SafeSlot> => {
  const accepted = await client.readContract({ address: crispProgram, abi: CRISP_SAFE_ABI, functionName: 'isSafe', args: [safe] })
  if (!accepted) throw new Error('This address is not a Safe that this CRISP deployment accepts (Safe 1.3.0 or 1.4.1).')

  const [rawOwners, threshold] = await Promise.all([
    client.readContract({ address: safe, abi: SAFE_ABI, functionName: 'getOwners' }),
    client.readContract({ address: safe, abi: SAFE_ABI, functionName: 'getThreshold' }),
  ])
  if (rawOwners.length > MAX_SAFE_OWNERS || threshold > BigInt(MAX_SAFE_SIGNERS)) {
    throw new Error(
      `This Safe has ${rawOwners.length} owners and a threshold of ${threshold}. A ballot supports at most ${MAX_SAFE_OWNERS} owners and a threshold of ${MAX_SAFE_SIGNERS}.`,
    )
  }
  const owners = rawOwners.map((owner) => getAddress(owner))
  const codes = await Promise.all(owners.map((owner) => client.getCode({ address: owner })))
  const keyOwners = owners.filter((_, i) => {
    const code = codes[i]
    return !code || code === '0x' || code.toLowerCase().startsWith(EIP7702_DELEGATION_PREFIX)
  })
  if (keyOwners.length < Number(threshold)) {
    throw new Error(
      `Only ${keyOwners.length} owners of this Safe sign with a private key, and the ballot needs ${threshold}. Owners that are contracts, such as nested Safes, cannot sign a ballot.`,
    )
  }
  return { address: getAddress(safe), owners, keyOwners, threshold: Number(threshold) }
}
