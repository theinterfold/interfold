// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
// Bond-owner identity behind the operator guide: the governance policy, the owner's credential, and
// the evidence that OwnerIdentityRegistry.register takes for a ZKPassport proof.
//
// The policy has no view. The bonding registry emits IdentityPolicyUpdated(timepoint, registry,
// required), and the latest log is the current policy. The verifier's fixed settings (domain, scope,
// ZKPassport version, identifier type) are read from the verifier itself, so the page follows the
// deployment. Before a deployment, the page can still make a proof with the planned settings
// (PREVIEW_SERVICE) and offer it as a download.

import { encodeAbiParameters, encodeFunctionData, getAbiItem, type Address, type Hex } from 'viem'
import type { RequestSuccess, SolidityVerifierParameters } from '@zkpassport/sdk'
import {
  CONTRACTS,
  IDENTITY_DEPLOY_BLOCK,
  bondingRegistryAbi,
  ownerIdentityRegistryAbi,
  publicClient,
  zkPassportIdentityVerifierAbi,
  zkPassportRootVerifierAbi,
} from './chain'
import { getLogsChunked } from './e3'

export type ProofResult = RequestSuccess['proofs'][number]

const ZERO_ADDRESS = '0x0000000000000000000000000000000000000000'

/** `BondOwnerCapacityLib.IDENTITY_CAPACITY_WINDOW`. Windows start at multiples of it from Unix time zero. */
export const CAPACITY_WINDOW = 30n * 86_400n

/**
 * The verifier settings for a proof before governance deploys a verifier. The domain and scope are part
 * of every identifier, so the deployment must use the same values.
 */
export const PREVIEW_SERVICE = {
  domain: 'dashboard.theinterfold.com',
  scope: 'interfold-bond-owner',
  proofValidity: 7n * 86_400n,
  maxValidity: 365n * 86_400n,
} as const

const IDENTITY_POLICY_UPDATED = getAbiItem({ abi: bondingRegistryAbi, name: 'IdentityPolicyUpdated' })
const PROOF_VERIFICATION_PARAMS = getAbiItem({ abi: zkPassportRootVerifierAbi, name: 'verify' }).inputs[0]

export type IdentityPolicy = {
  registry: Address
  required: boolean
  /** Timestamp from which the policy applies. */
  timepoint: bigint
}

/** The settings that the deployed ZKPassportIdentityVerifier fixes for every proof. */
export type VerifierConfig = {
  address: Address
  domain: string
  scope: string
  /** The one ZKPassport version that the verifier accepts. */
  version: Hex
  /** 0 non-salted, 1 salted. */
  nullifierType: number
  oprfKeyHash: Hex
  faceMatchRequired: boolean
  /** Maximum proof age, in seconds, when the registration is mined. */
  proofValidity: bigint
  /** Longest credential, in seconds after the proof date. */
  maxValidity: bigint
}

export type OwnerAccount = {
  /** Latest block timestamp. */
  now: bigint
  /** A contract owner (a Safe) registers through its own transaction. */
  isContract: boolean
  /** The owner's credential, or null when the network has no identity registry. */
  identity: { identityId: Hex; expiresAt: bigint; verifiedNow: boolean } | null
}

/** The current identity policy: the latest IdentityPolicyUpdated log, or null before the first. */
export async function fetchIdentityPolicy(): Promise<IdentityPolicy | null> {
  const head = await publicClient.getBlockNumber()
  const logs = await getLogsChunked<any>(
    { address: CONTRACTS.BondingRegistry, event: IDENTITY_POLICY_UPDATED },
    IDENTITY_DEPLOY_BLOCK,
    head,
  )
  const latest = logs[logs.length - 1]
  if (!latest) return null
  return { registry: latest.args.registry, required: latest.args.required, timepoint: BigInt(latest.args.timepoint) }
}

export async function fetchVerifierConfig(registry: Address): Promise<VerifierConfig> {
  const address = (await (publicClient.readContract as any)({
    address: registry,
    abi: ownerIdentityRegistryAbi,
    functionName: 'verifier',
  })) as Address
  if (address === ZERO_ADDRESS) throw new Error('The identity registry has no verifier yet.')
  const read = (functionName: string) => (publicClient.readContract as any)({ address, abi: zkPassportIdentityVerifierAbi, functionName })
  const [domain, scope, version, nullifierType, oprfKeyHash, faceMatchRequired, proofValidity, maxValidity] = await Promise.all([
    read('domain'),
    read('scope'),
    read('VERSION'),
    read('NULLIFIER_TYPE'),
    read('OPRF_KEY_HASH'),
    read('FACE_MATCH_REQUIRED'),
    read('PROOF_VALIDITY'),
    read('MAX_VALIDITY'),
  ])
  return {
    address,
    domain,
    scope,
    version,
    nullifierType: Number(nullifierType),
    oprfKeyHash,
    faceMatchRequired,
    proofValidity: BigInt(proofValidity),
    maxValidity: BigInt(maxValidity),
  }
}

export async function fetchOwnerAccount(owner: Address, registry: Address | null): Promise<OwnerAccount> {
  const block = await publicClient.getBlock()
  const read = (functionName: string, args: readonly unknown[]) =>
    (publicClient.readContract as any)({ address: registry, abi: ownerIdentityRegistryAbi, functionName, args })
  const [code, identity] = await Promise.all([
    publicClient.getCode({ address: owner }),
    registry
      ? Promise.all([read('identityOf', [owner]), read('isVerifiedAt', [owner, block.timestamp])]).then(
          ([[identityId, expiresAt], verifiedNow]: [[Hex, number | bigint], boolean]) => ({
            identityId,
            expiresAt: BigInt(expiresAt),
            verifiedNow,
          }),
        )
      : Promise.resolve(null),
  ])
  return { now: block.timestamp, isContract: Boolean(code && code !== '0x'), identity }
}

/** The last second of the capacity window that contains `timestamp` (`BondOwnerCapacityLib._windowEnd`). */
export function capacityWindowEnd(timestamp: bigint): bigint {
  return (timestamp / CAPACITY_WINDOW + 1n) * CAPACITY_WINDOW - 1n
}

/** The ZKPassport chain name that binds a proof to `chainId`, or null where ZKPassport has no verifier. */
export function boundChainName(chainId: number): 'ethereum' | 'ethereum_sepolia' | null {
  if (chainId === 1) return 'ethereum'
  if (chainId === 11_155_111) return 'ethereum_sepolia'
  return null
}

/** The outer EVM proof: the one proof that the verifier checks. */
export function outerEvmProof(proofs: readonly ProofResult[]): ProofResult | null {
  return proofs.find((proof) => proof.name?.startsWith('outer_evm')) ?? null
}

/**
 * The lower bound of the proof's expiry-date check. The evidence must carry exactly this value as
 * `validUntil`, because the verifier asks ZKPassport's helper to confirm the committed bound.
 */
export function expiryLowerBound(proofs: readonly ProofResult[]): bigint | null {
  for (const proof of proofs) {
    const committed = proof.committedInputs?.compare_expiry_evm as { minDateTimestamp?: number } | undefined
    if (committed?.minDateTimestamp !== undefined) return BigInt(committed.minDateTimestamp)
  }
  return null
}

/** The values that the verifier reads from the proof's public inputs. */
export function proofFacts(params: SolidityVerifierParameters): {
  proofDate: bigint
  nullifierType: number
  scopedNullifier: Hex
  oprfKeyHash: Hex
} {
  const inputs = params.proofVerificationData.publicInputs
  return {
    proofDate: BigInt(inputs[2]),
    nullifierType: Number(BigInt(inputs[inputs.length - 3])),
    scopedNullifier: inputs[inputs.length - 2] as Hex,
    oprfKeyHash: inputs[inputs.length - 1] as Hex,
  }
}

/** The credential end that the verifier sets: `validUntil`, or `maxValidity` after the proof date if earlier. */
export function credentialEnd(validUntil: bigint, proofDate: bigint, maxValidity: bigint): bigint {
  const capped = proofDate + maxValidity
  return validUntil < capped ? validUntil : capped
}

/** `abi.encode(ProofVerificationParams, validUntil)`, the evidence of ZKPassportIdentityVerifier. */
export function encodeEvidence(params: SolidityVerifierParameters, validUntil: bigint): Hex {
  return encodeAbiParameters(
    [PROOF_VERIFICATION_PARAMS, { type: 'uint256' }],
    [
      {
        version: params.version as Hex,
        proofVerificationData: {
          vkeyHash: params.proofVerificationData.vkeyHash as Hex,
          proof: params.proofVerificationData.proof as Hex,
          publicInputs: params.proofVerificationData.publicInputs as Hex[],
        },
        committedInputs: params.committedInputs as Hex,
        serviceConfig: {
          validityPeriodInSeconds: BigInt(params.serviceConfig.validityPeriodInSeconds),
          domain: params.serviceConfig.domain,
          scope: params.serviceConfig.scope,
          devMode: params.serviceConfig.devMode,
        },
      },
      validUntil,
    ],
  )
}

/** A Safe Transaction Builder batch that registers the proof from the Safe that it binds. */
export function safeRegistrationBatch(registry: Address, safe: Address, chainId: number, evidence: Hex, createdAt: number) {
  return {
    version: '1.0',
    chainId: String(chainId),
    createdAt,
    meta: {
      name: 'Interfold bond-owner identity',
      description: 'OwnerIdentityRegistry.register for this Safe. Execute it before the proof expires.',
      createdFromSafeAddress: safe,
    },
    transactions: [
      {
        to: registry,
        value: '0',
        data: encodeFunctionData({ abi: ownerIdentityRegistryAbi, functionName: 'register', args: [evidence] }),
      },
    ],
  }
}

/** The credential line of the identity panel. */
export function identityStatusText(account: OwnerAccount): string {
  const identity = account.identity
  if (!identity || identity.expiresAt === 0n) return 'Not verified'
  return identity.verifiedNow ? `Verified until ${fmtDay(identity.expiresAt)}` : `Expired on ${fmtDay(identity.expiresAt)}`
}

export function fmtDay(ts: bigint): string {
  return new Date(Number(ts) * 1000).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric', timeZone: 'UTC' })
}

/** A Unix timestamp as the value of a date field: YYYY-MM-DD in UTC. */
export function dateInput(ts: bigint): string {
  return new Date(Number(ts) * 1000).toISOString().slice(0, 10)
}

/** A YYYY-MM-DD date field as the Unix timestamp of its UTC midnight, or null. */
export function parseDateInput(value: string): bigint | null {
  const match = /^(\d{4})-(\d{2})-(\d{2})$/.exec(value.trim())
  if (!match) return null
  const ms = Date.UTC(Number(match[1]), Number(match[2]) - 1, Number(match[3]))
  const day = new Date(ms)
  // Reject dates that roll over, such as 2026-02-31.
  if (day.getUTCMonth() !== Number(match[2]) - 1 || day.getUTCDate() !== Number(match[3])) return null
  return BigInt(ms / 1000)
}

/** Everything that a registration or a test needs to replay one proof, as the page downloads it. */
export type ProofBundle = {
  kind: 'interfold.identity.zkpassport-proof'
  chainId: number
  owner: Address
  domain: string
  scope: string
  faceMatch: boolean
  /** Unix seconds. */
  validUntil: string
  proofDate: string
  nullifierType: number
  oprfKeyHash: Hex
  version: Hex
  params: SolidityVerifierParameters
  evidence: Hex
  proofs: ProofResult[]
  result: RequestSuccess['result']
}

export function buildProofBundle({
  success,
  params,
  owner,
  chainId,
  faceMatch,
}: {
  success: RequestSuccess
  params: SolidityVerifierParameters
  owner: Address
  chainId: number
  faceMatch: boolean
}): ProofBundle {
  const validUntil = expiryLowerBound(success.proofs)
  if (validUntil === null) throw new Error('The proof has no expiry-date check.')
  const facts = proofFacts(params)
  return {
    kind: 'interfold.identity.zkpassport-proof',
    chainId,
    owner,
    domain: params.serviceConfig.domain,
    scope: params.serviceConfig.scope,
    faceMatch,
    validUntil: validUntil.toString(),
    proofDate: facts.proofDate.toString(),
    nullifierType: facts.nullifierType,
    oprfKeyHash: facts.oprfKeyHash,
    version: params.version as Hex,
    params,
    evidence: encodeEvidence(params, validUntil),
    proofs: success.proofs,
    result: success.result,
  }
}
