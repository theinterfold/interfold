// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { expect } from 'chai'
import { createHash } from 'crypto'
import { deployCRISPProgram, ethers } from './utils'
import type { CRISPProgram } from '../types'

const SNARK_SCALAR_FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617n

/// The same vector is asserted by `the_leaf_matches_the_contract_vector` in
/// `program/tests/input_leaf.rs`. If either side changes, both tests fail.
const VECTOR = {
  ciphertext: '0x' + Buffer.from(Array.from({ length: 64 }, (_, i) => i)).toString('hex'),
  commitment: '0x' + 'ab'.repeat(32),
  slot: '0x' + 'cd'.repeat(20),
  parentIndexPlusOne: 0,
  leaf: 2902394196295929744342726349634404286327629052839628262482747965753261350412n,
}

/// The input tree leaf binds the published ciphertext bytes to the commitment the Noir proof
/// constrained.
///
/// The proof never sees the serialized bytes, so without this binding a submitter can publish a
/// valid commitment beside unrelated bytes. The Secure Process then cannot reproduce the on-chain
/// root and the round is lost. Binding both lets it detect the mismatch and exclude that one input.
///
/// The Secure Process rebuilds this leaf in Rust. A divergence of a single byte between the two
/// implementations makes every root mismatch, and nothing else in the system would catch it —
/// which is what these tests exist for.
describe('CRISPProgram input leaf', function () {
  this.timeout(120000)

  let crispProgram: CRISPProgram

  before(async () => {
    crispProgram = await deployCRISPProgram()
  })

  function expectedLeaf(ciphertext: string, commitment: string, slot: string, parentIndexPlusOne: number): bigint {
    const parent = Buffer.alloc(5)
    parent.writeUIntBE(parentIndexPlusOne, 0, 5)

    const inner = Buffer.from(ethers.getBytes(ethers.keccak256(ciphertext)))
    const outer = createHash('sha256')
      .update(inner)
      .update(Buffer.from(commitment.slice(2), 'hex'))
      .update(Buffer.from(slot.slice(2), 'hex'))
      .update(parent)
      .digest()
    return BigInt('0x' + outer.toString('hex')) % SNARK_SCALAR_FIELD
  }

  it('matches the shared cross-language vector', async () => {
    const leaf = await crispProgram.inputLeaf(
      ethers.keccak256(VECTOR.ciphertext),
      VECTOR.commitment,
      VECTOR.slot,
      VECTOR.parentIndexPlusOne,
    )
    expect(leaf).to.equal(VECTOR.leaf)
  })

  it('is sha256(keccak256(bytes) || commitment || slot || parent) reduced into the scalar field', async () => {
    const leaf = await crispProgram.inputLeaf(
      ethers.keccak256(VECTOR.ciphertext),
      VECTOR.commitment,
      VECTOR.slot,
      VECTOR.parentIndexPlusOne,
    )
    expect(leaf).to.equal(expectedLeaf(VECTOR.ciphertext, VECTOR.commitment, VECTOR.slot, VECTOR.parentIndexPlusOne))
  })

  it('always produces a leaf the Poseidon tree accepts', async () => {
    // A leaf at or above the field order is rejected by LazyIMT, so the reduction is not optional.
    for (let i = 0; i < 8; i += 1) {
      const ciphertext = ethers.hexlify(ethers.randomBytes(96))
      const commitment = ethers.hexlify(ethers.randomBytes(32))
      const leaf = await crispProgram.inputLeaf(ethers.keccak256(ciphertext), commitment, ethers.hexlify(ethers.randomBytes(20)), i)
      expect(leaf).to.be.lessThan(SNARK_SCALAR_FIELD)
    }
  })

  it('changes when the ciphertext bytes change', async () => {
    // This is the property the whole fix rests on: swapping the bytes beside a valid commitment
    // must be visible.
    const a = await crispProgram.inputLeaf(ethers.keccak256(VECTOR.ciphertext), VECTOR.commitment, VECTOR.slot, 0)
    const b = await crispProgram.inputLeaf(ethers.keccak256(VECTOR.ciphertext.replace(/0f/, '1f')), VECTOR.commitment, VECTOR.slot, 0)
    expect(a).to.not.equal(b)
  })

  it('changes when the commitment changes', async () => {
    const ciphertextHash = ethers.keccak256(VECTOR.ciphertext)
    const a = await crispProgram.inputLeaf(ciphertextHash, VECTOR.commitment, VECTOR.slot, 0)
    const b = await crispProgram.inputLeaf(ciphertextHash, '0x' + 'ef'.repeat(32), VECTOR.slot, 0)
    expect(a).to.not.equal(b)
  })

  it('does not let the two fields be traded off against each other', async () => {
    // Both fields have a fixed 32-byte width, so their boundary cannot be shifted.
    const a = await crispProgram.inputLeaf('0x' + 'aa'.repeat(32), '0x' + '11'.repeat(32), VECTOR.slot, 0)
    const b = await crispProgram.inputLeaf('0x' + '11'.repeat(32), '0x' + 'aa'.repeat(32), VECTOR.slot, 0)
    expect(a).to.not.equal(b)
  })

  it('accepts an empty ciphertext without reverting', async () => {
    const leaf = await crispProgram.inputLeaf(ethers.keccak256('0x'), VECTOR.commitment, VECTOR.slot, 0)
    expect(leaf).to.equal(expectedLeaf('0x', VECTOR.commitment, VECTOR.slot, 0))
  })

  it('changes when the slot changes', async () => {
    // The tree is append-only and the Secure Process groups entries by slot, so a prover must not
    // be able to move an entry to a different slot.
    const ciphertextHash = ethers.keccak256(VECTOR.ciphertext)
    const a = await crispProgram.inputLeaf(ciphertextHash, VECTOR.commitment, VECTOR.slot, 0)
    const b = await crispProgram.inputLeaf(ciphertextHash, VECTOR.commitment, '0x' + '01'.repeat(20), 0)
    expect(a).to.not.equal(b)
  })

  it('changes when the parent changes', async () => {
    // The Secure Process walks each slot's chain by the parent, so an unbound parent would let a
    // prover re-point entries and change which one holds the slot.
    const ciphertextHash = ethers.keccak256(VECTOR.ciphertext)
    const a = await crispProgram.inputLeaf(ciphertextHash, VECTOR.commitment, VECTOR.slot, 0)
    const b = await crispProgram.inputLeaf(ciphertextHash, VECTOR.commitment, VECTOR.slot, 1)
    expect(a).to.not.equal(b)
    expect(b).to.equal(expectedLeaf(VECTOR.ciphertext, VECTOR.commitment, VECTOR.slot, 1))
  })
})
