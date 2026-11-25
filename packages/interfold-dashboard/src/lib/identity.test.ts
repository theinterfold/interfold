// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import assert from 'node:assert/strict'
import test from 'node:test'
import {
  decodeAbiParameters,
  decodeFunctionData,
  encodeAbiParameters,
  getAbiItem,
  keccak256,
  pad,
  toHex,
  type Address,
  type Hex,
} from 'viem'
import type { RequestSuccess, SolidityVerifierParameters } from '@zkpassport/sdk'
import { zkPassportVersion } from '@interfold/contracts/zkpassport'
import { bondingRegistryAbi, identityRegisterAbi, ownerIdentityRegistryAbi, zkPassportRootVerifierAbi } from './chain'
import {
  boundChainName,
  buildProofBundle,
  encodeEvidence,
  expiryLowerBound,
  isContractCode,
  outerEvmProof,
  registrationDeadline,
  safeRegistrationBatch,
  type ProofResult,
  IDENTITY_STORAGE_SLOT,
  proofBinding,
  readIdentityPolicy,
} from './identity'

const OWNER = '0x2222222222222222222222222222222222222222' as Address
const REGISTRY = '0x5555555555555555555555555555555555555555' as Address
const word = (value: bigint): Hex => pad(toHex(value), { size: 32 })
const PROOF_DATE = 1_790_000_000n
const VALID_UNTIL = 1_830_000_000n

function verifierParams(): SolidityVerifierParameters {
  return {
    version: zkPassportVersion(0, 20, 0),
    proofVerificationData: {
      vkeyHash: word(7n),
      proof: '0x1234',
      // The verifier reads the proof date at index 2 and ends with
      // [nullifier type, scoped nullifier, OPRF key hash].
      publicInputs: [word(1n), word(2n), word(PROOF_DATE), word(9n), word(0n), word(0xabcdefn), word(0n)],
    },
    committedInputs: '0xbeef',
    serviceConfig: {
      validityPeriodInSeconds: 604_800,
      domain: 'dashboard.theinterfold.com',
      scope: 'interfold-bond-owner',
      devMode: false,
    },
  }
}

function proofs(): ProofResult[] {
  return [
    { name: 'sig_check_dsc', proof: '0x01' },
    { name: 'compare_expiry_evm', committedInputs: { compare_expiry_evm: { minDateTimestamp: Number(VALID_UNTIL), maxDateTimestamp: 0 } } },
    { name: 'outer_evm_count_5', proof: '0x02', version: '0.21.1' },
  ]
}

test('a proof binds to the ZKPassport name of the dashboard chain', () => {
  assert.equal(boundChainName(1), 'ethereum')
  assert.equal(boundChainName(11_155_111), 'ethereum_sepolia')
  assert.equal(boundChainName(8453), null)
})

test('the evidence carries the outer proof and the committed expiry bound', () => {
  assert.equal(outerEvmProof(proofs())?.name, 'outer_evm_count_5')
  assert.equal(outerEvmProof(proofs().slice(0, 2)), null)
  assert.equal(expiryLowerBound(proofs()), VALID_UNTIL)
  assert.equal(expiryLowerBound([{ name: 'outer_evm' }]), null)
})

test('from ZKPassport 0.23.0 only chip proofs pass, and a version the verifier does not know fails', () => {
  const params = verifierParams()
  const version023 = zkPassportVersion(0, 23, 0)
  const chip = {
    ...params,
    version: version023,
    proofVerificationData: {
      ...params.proofVerificationData,
      publicInputs: [...params.proofVerificationData.publicInputs, word(100n)],
    },
  }
  const success = { proofs: proofs(), result: {} } as RequestSuccess
  assert.equal(buildProofBundle({ success, params: chip, owner: OWNER, chainId: 1, faceMatch: true }).version, version023)
  for (const method of [101n, 200n, 201n]) {
    const other = {
      ...chip,
      proofVerificationData: {
        ...chip.proofVerificationData,
        publicInputs: [...params.proofVerificationData.publicInputs, word(method)],
      },
    }
    assert.throws(
      () => buildProofBundle({ success, params: other, owner: OWNER, chainId: 1, faceMatch: true }),
      /did not read the document's chip/,
    )
  }
  assert.throws(
    () =>
      buildProofBundle({ success, params: { ...chip, version: zkPassportVersion(0, 24, 0) }, owner: OWNER, chainId: 1, faceMatch: true }),
    /does not read ZKPassport version/,
  )
})

test('the evidence decodes as the verifier decodes it', () => {
  const params = verifierParams()
  const evidence = encodeEvidence(params, VALID_UNTIL)
  const tuple = getAbiItem({ abi: zkPassportRootVerifierAbi, name: 'verify' }).inputs[0]
  const [decoded, validUntil] = decodeAbiParameters([tuple, { type: 'uint256' }], evidence) as [any, bigint]
  assert.equal(validUntil, VALID_UNTIL)
  assert.equal(decoded.version, params.version)
  assert.equal(decoded.proofVerificationData.proof, '0x1234')
  assert.deepEqual(decoded.proofVerificationData.publicInputs, params.proofVerificationData.publicInputs)
  assert.equal(decoded.committedInputs, '0xbeef')
  assert.equal(decoded.serviceConfig.domain, 'dashboard.theinterfold.com')
  assert.equal(decoded.serviceConfig.validityPeriodInSeconds, 604_800n)
})

test('a Safe batch registers the evidence from the bound Safe', () => {
  const evidence = encodeEvidence(verifierParams(), VALID_UNTIL)
  const batch = safeRegistrationBatch(REGISTRY, OWNER, 1, evidence, 1_700_000_000_000)
  assert.equal(batch.chainId, '1')
  assert.equal(batch.meta.createdFromSafeAddress, OWNER)
  assert.equal(batch.transactions.length, 1)
  assert.equal(batch.transactions[0].to, REGISTRY)
  assert.equal(batch.transactions[0].value, '0')
  const call = decodeFunctionData({ abi: ownerIdentityRegistryAbi, data: batch.transactions[0].data })
  assert.equal(call.functionName, 'register')
  assert.deepEqual(call.args, [evidence])

  // With a registered operator, the same batch counts the owner in this window.
  const bonding = '0x6666666666666666666666666666666666666666' as Address
  const operator = '0x7777777777777777777777777777777777777777' as Address
  const counted = safeRegistrationBatch(REGISTRY, OWNER, 1, evidence, 1_700_000_000_000, { bondingRegistry: bonding, operator })
  assert.equal(counted.transactions.length, 2)
  assert.deepEqual(counted.transactions[0], batch.transactions[0])
  assert.equal(counted.transactions[1].to, bonding)
  const refresh = decodeFunctionData({ abi: bondingRegistryAbi, data: counted.transactions[1].data })
  assert.equal(refresh.functionName, 'refreshOperatorStatus')
  assert.deepEqual(refresh.args, [operator])
})

test('the downloaded bundle describes the proof that it carries', () => {
  const success = { proofs: proofs(), result: {} } as RequestSuccess
  const bundle = buildProofBundle({ success, params: verifierParams(), owner: OWNER, chainId: 1, faceMatch: true })
  assert.equal(bundle.owner, OWNER)
  assert.equal(bundle.chainId, 1)
  assert.equal(bundle.validUntil, VALID_UNTIL.toString())
  assert.equal(bundle.proofDate, PROOF_DATE.toString())
  assert.equal(bundle.domain, 'dashboard.theinterfold.com')
  assert.equal(bundle.scope, 'interfold-bond-owner')
  assert.equal(bundle.evidence, encodeEvidence(verifierParams(), VALID_UNTIL))
  assert.doesNotThrow(() => JSON.stringify(bundle))

  assert.throws(
    () =>
      buildProofBundle({
        success: { proofs: [], result: {} } as RequestSuccess,
        params: verifierParams(),
        owner: OWNER,
        chainId: 1,
        faceMatch: true,
      }),
    /no expiry-date check/,
  )
})

test('an EIP-7702 account registers itself; a contract wallet goes through its own transaction', () => {
  assert.equal(isContractCode(undefined), false)
  assert.equal(isContractCode('0x'), false)
  assert.equal(isContractCode(`0xef0100${'ab'.repeat(20)}`), false)
  assert.equal(isContractCode(`0xEF0100${'AB'.repeat(20)}`), false)
  assert.equal(isContractCode('0x6080604052'), true)
  assert.equal(isContractCode(`0xef0100${'ab'.repeat(21)}`), true)
})

test('a proof registers until it is too old or its credential ends', () => {
  assert.equal(registrationDeadline(1_000n, 600n, 5_000n), 1_600n)
  assert.equal(registrationDeadline(1_000n, 600n, 1_200n), 1_200n)
})

test('the policy comes from the bonding registry storage', async () => {
  const registry = '0x4444444444444444444444444444444444444444' as Address
  const slots = (versions: bigint, version: bigint, policy: bigint) => {
    const checkpoints = BigInt(keccak256(word(IDENTITY_STORAGE_SLOT)))
    const policySlot = keccak256(encodeAbiParameters([{ type: 'uint256' }, { type: 'uint256' }], [version, IDENTITY_STORAGE_SLOT + 1n]))
    const values = new Map<string, bigint>([
      [word(IDENTITY_STORAGE_SLOT), versions],
      [word(checkpoints + versions - 1n), (version << 48n) | 1_700n],
      [policySlot, policy],
    ])
    return async (slot: Hex) => values.get(slot) ?? 0n
  }
  // The second version requires the registry: `required` sits in the byte above the address.
  assert.deepEqual(await readIdentityPolicy(slots(2n, 2n, (1n << 160n) | BigInt(registry))), {
    registry,
    required: true,
    timepoint: 1_700n,
  })
  assert.deepEqual(await readIdentityPolicy(slots(1n, 1n, BigInt(registry))), { registry, required: false, timepoint: 1_700n })
  // A policy that clears the registry turns the gate off, and before the first policy there is none.
  assert.equal(await readIdentityPolicy(slots(3n, 3n, 0n)), null)
  assert.equal(await readIdentityPolicy(async () => 0n), null)
})

test('the binding check reads the owner and chain from the proof', () => {
  const proofs = [
    { name: 'compare_expiry_evm', committedInputs: { compare_expiry_evm: { minDateTimestamp: 1, maxDateTimestamp: 0 } } },
    { name: 'outer_evm_count_6', proof: '0x02', committedInputs: { bind_evm: { data: { user_address: OWNER, chain: 'ethereum' } } } },
  ] as unknown as ProofResult[]
  assert.deepEqual(proofBinding(proofs), { owner: OWNER, chain: 'ethereum' })
  assert.equal(proofBinding(proofs.slice(0, 1)), null)
})

test('a registration that the verifier rejects shows the error name', () => {
  const errors = identityRegisterAbi.filter((item) => item.type === 'error').map((item) => item.name)
  assert.ok(errors.includes('WrongBinding'))
  assert.ok(errors.includes('IdentityInUse'))
})
