// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { createHash } from 'node:crypto'
import {
  type Hex,
  decodeAbiParameters,
  decodeEventLog,
  encodeAbiParameters,
  encodeEventTopics,
  hashTypedData,
  keccak256,
  parseAbiParameters,
  toHex,
  verifyTypedData,
} from 'viem'
import { privateKeyToAccount } from 'viem/accounts'
import { describe, expect, it } from 'vitest'
import {
  CONFIG_DOMAIN,
  OFFER_TYPES,
  SNARK_SCALAR_FIELD,
  configLeaf,
  encodeNegotiationParams,
  encodeOfferInput,
  inputLeaf,
  negotiationProgramAbi,
  offerInputsHash,
  offerTypedData,
} from './negotiation'

const SELLER = '0x1111111111111111111111111111111111111111'
const BUYER = '0x2222222222222222222222222222222222222222'
const PROGRAM = '0x3333333333333333333333333333333333333333'
const ciphertexts: Hex[] = ['0xaa01', '0xbb0202', '0xcc030303']
const commitments: Hex[] = [`0x${'11'.repeat(32)}`, `0x${'22'.repeat(32)}`, `0x${'33'.repeat(32)}`]

describe('encodeNegotiationParams', () => {
  it('encodes the six parameters of the contract', () => {
    const data = encodeNegotiationParams({ seller: SELLER, buyer: BUYER, levels: 16, minPrice: 100n, stepPrice: 25n, title: 'A used bike' })
    const [seller, buyer, levels, minPrice, stepPrice, title] = decodeAbiParameters(
      parseAbiParameters('address seller, address buyer, uint8 levels, uint256 minPrice, uint256 stepPrice, string title'),
      data,
    )
    expect([seller, buyer, levels, minPrice, stepPrice, title]).toEqual([SELLER, BUYER, 16, 100n, 25n, 'A used bike'])
  })
})

describe('encodeOfferInput', () => {
  it('encodes the data of publishInput, with an empty signature for a direct offer', () => {
    const data = encodeOfferInput({ party: SELLER, ciphertexts, commitments, proof: '0x01' })
    const decoded = decodeAbiParameters(
      parseAbiParameters('address party, bytes[] ciphertexts, bytes32[] commitments, bytes proof, bytes signature'),
      data,
    )
    expect(decoded[0]).toBe(SELLER)
    expect(decoded[1]).toEqual(ciphertexts)
    expect(decoded[2]).toEqual(commitments)
    expect(decoded[3]).toBe('0x01')
    expect(decoded[4]).toBe('0x')
  })

  it('carries the signature of a relayed offer', () => {
    const data = encodeOfferInput({ party: BUYER, ciphertexts, commitments, proof: '0x01', signature: '0xabcd' })
    const [, , , , signature] = decodeAbiParameters(
      parseAbiParameters('address party, bytes[] ciphertexts, bytes32[] commitments, bytes proof, bytes signature'),
      data,
    )
    expect(signature).toBe('0xabcd')
  })

  it('rejects a wrong number of ciphertexts or commitments', () => {
    expect(() => encodeOfferInput({ party: SELLER, ciphertexts: ciphertexts.slice(0, 2), commitments, proof: '0x01' })).toThrow(
      /3 ciphertexts/,
    )
    expect(() => encodeOfferInput({ party: SELLER, ciphertexts, commitments: commitments.slice(0, 2), proof: '0x01' })).toThrow(
      /3 commitments/,
    )
  })
})

describe('offerInputsHash', () => {
  it('hashes the commitments and the hashes of the ciphertexts, as the contract does', () => {
    const encoded = encodeAbiParameters(parseAbiParameters('bytes32[], bytes32, bytes32, bytes32'), [
      commitments,
      keccak256(ciphertexts[0]),
      keccak256(ciphertexts[1]),
      keccak256(ciphertexts[2]),
    ])
    expect(offerInputsHash(commitments, ciphertexts)).toBe(keccak256(encoded))
  })

  it('changes when a commitment or a ciphertext changes, or when they swap', () => {
    const base = offerInputsHash(commitments, ciphertexts)
    expect(offerInputsHash([commitments[1], commitments[0], commitments[2]], ciphertexts)).not.toBe(base)
    expect(offerInputsHash(commitments, [ciphertexts[1], ciphertexts[0], ciphertexts[2]])).not.toBe(base)
    expect(offerInputsHash(commitments, [ciphertexts[0], ciphertexts[1], '0xcc030304'])).not.toBe(base)
  })

  it('rejects a wrong number of ciphertexts or commitments', () => {
    expect(() => offerInputsHash(commitments, ciphertexts.slice(0, 2))).toThrow()
    expect(() => offerInputsHash([...commitments, commitments[0]], ciphertexts)).toThrow()
  })
})

describe('offerTypedData', () => {
  const account = privateKeyToAccount(`0x${'ab'.repeat(32)}`)

  it('has the domain and the type of the contract', () => {
    const typed = offerTypedData(31337, PROGRAM, 7n, account.address, offerInputsHash(commitments, ciphertexts))
    expect(typed.domain).toEqual({ name: 'NegotiationProgram', version: '1', chainId: 31337n, verifyingContract: PROGRAM })
    expect(typed.types).toBe(OFFER_TYPES)
    expect(typed.primaryType).toBe('Offer')
    expect(OFFER_TYPES.Offer.map((field) => `${field.type} ${field.name}`)).toEqual(['uint256 e3Id', 'address party', 'bytes32 inputsHash'])
  })

  it('gives a signature that recovers the party and binds every field', async () => {
    const inputsHash = offerInputsHash(commitments, ciphertexts)
    const typed = offerTypedData(31337, PROGRAM, 7n, account.address, inputsHash)
    const signature = await account.signTypedData(typed)
    expect(await verifyTypedData({ ...typed, address: account.address, signature })).toBe(true)
    const other = offerTypedData(31337, PROGRAM, 8n, account.address, inputsHash)
    expect(await verifyTypedData({ ...other, address: account.address, signature })).toBe(false)
    expect(hashTypedData(other)).not.toBe(hashTypedData(typed))
  })
})

describe('input leaves', () => {
  it('has the configuration leaf keccak256(domain) mod BN254', () => {
    expect(configLeaf()).toBe(BigInt(keccak256(toHex(CONFIG_DOMAIN))) % SNARK_SCALAR_FIELD)
    expect(configLeaf()).toBeLessThan(SNARK_SCALAR_FIELD)
  })

  it('hashes ciphertext hash, commitment, party and uint40(role * 256 + index) with sha256', () => {
    const leaf = inputLeaf({ ciphertext: ciphertexts[2], commitment: commitments[2], party: BUYER, role: 1, index: 2 })
    const bytes = Buffer.concat([
      Buffer.from(keccak256(ciphertexts[2]).slice(2), 'hex'),
      Buffer.from(commitments[2].slice(2), 'hex'),
      Buffer.from(BUYER.slice(2), 'hex'),
      Buffer.from('0000000102', 'hex'),
    ])
    expect(bytes.length).toBe(32 + 32 + 20 + 5)
    expect(leaf).toBe(BigInt(`0x${createHash('sha256').update(bytes).digest('hex')}`) % SNARK_SCALAR_FIELD)
  })

  it('separates the roles and the indexes', () => {
    const leaves = new Set<bigint>()
    for (const role of [0, 1]) {
      for (const index of [0, 1, 2]) {
        leaves.add(inputLeaf({ ciphertext: ciphertexts[0], commitment: commitments[0], party: SELLER, role, index }))
      }
    }
    expect(leaves.size).toBe(6)
  })

  it('rejects a role or an index out of range', () => {
    const base = { ciphertext: ciphertexts[0], commitment: commitments[0], party: SELLER } as const
    expect(() => inputLeaf({ ...base, role: 2, index: 0 })).toThrow()
    expect(() => inputLeaf({ ...base, role: 0, index: 3 })).toThrow()
    expect(() => inputLeaf({ ...base, role: 0, index: -1 })).toThrow()
  })
})

describe('negotiationProgramAbi', () => {
  it('has the events, the views and the entry points of the specification', () => {
    const names = negotiationProgramAbi.map((item) => `${item.type}:${'name' in item ? item.name : ''}`)
    for (const expected of [
      'event:NegotiationCreated',
      'event:OfferSubmitted',
      'event:Settled',
      'function:negotiation',
      'function:offerSubmitted',
      'function:outcome',
      'function:publishInput',
      'function:settle',
    ]) {
      expect(names).toContain(expected)
    }
  })

  it('decodes an OfferSubmitted log', () => {
    const topics = encodeEventTopics({ abi: negotiationProgramAbi, eventName: 'OfferSubmitted', args: { e3Id: 7n, party: SELLER } })
    const data = encodeAbiParameters(parseAbiParameters('uint8 role, uint256 firstLeaf, bytes[] ciphertexts, bytes32[] commitments'), [
      0,
      1n,
      ciphertexts,
      commitments,
    ])
    const log = decodeEventLog({ abi: negotiationProgramAbi, topics: topics as [Hex, ...Hex[]], data })
    expect(log.eventName).toBe('OfferSubmitted')
    expect(log.args).toEqual({ e3Id: 7n, party: SELLER, role: 0, firstLeaf: 1n, ciphertexts, commitments })
  })
})
