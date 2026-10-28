// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import assert from 'node:assert/strict'
import test from 'node:test'
import { decodeAbiParameters, decodeFunctionData, getAbiItem, pad, toHex, type Address, type Hex } from 'viem'
import type { RequestSuccess, SolidityVerifierParameters } from '@zkpassport/sdk'
import { ownerIdentityRegistryAbi, zkPassportRootVerifierAbi } from './chain'
import {
  CAPACITY_WINDOW,
  boundChainName,
  buildProofBundle,
  capacityWindowEnd,
  credentialEnd,
  encodeEvidence,
  expiryLowerBound,
  outerEvmProof,
  proofFacts,
  safeRegistrationBatch,
  type ProofResult,
} from './identity'

const OWNER = '0x2222222222222222222222222222222222222222' as Address
const REGISTRY = '0x5555555555555555555555555555555555555555' as Address
const word = (value: bigint): Hex => pad(toHex(value), { size: 32 })
const PROOF_DATE = 1_790_000_000n
const VALID_UNTIL = 1_830_000_000n

function verifierParams(): SolidityVerifierParameters {
  return {
    version: word(0x14_00_00n << 224n),
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

test('capacity windows end at the same second as BondOwnerCapacityLib', () => {
  const start = CAPACITY_WINDOW * 680n
  assert.equal(capacityWindowEnd(start), start + CAPACITY_WINDOW - 1n)
  assert.equal(capacityWindowEnd(start + CAPACITY_WINDOW - 1n), start + CAPACITY_WINDOW - 1n)
  assert.equal(capacityWindowEnd(start + CAPACITY_WINDOW), start + 2n * CAPACITY_WINDOW - 1n)
})

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

  const facts = proofFacts(verifierParams())
  assert.deepEqual(facts, { proofDate: PROOF_DATE, nullifierType: 0, scopedNullifier: word(0xabcdefn), oprfKeyHash: word(0n) })
  assert.equal(credentialEnd(VALID_UNTIL, PROOF_DATE, 365n * 86_400n), PROOF_DATE + 365n * 86_400n)
  assert.equal(credentialEnd(PROOF_DATE + 10n, PROOF_DATE, 365n * 86_400n), PROOF_DATE + 10n)
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
