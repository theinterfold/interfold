// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { expect, describe, it } from 'vitest'
import { bytesToHex } from 'viem'
import { extractSignatureComponents, generateMerkleProof, generateMerkleTree, hashLeaf } from '../src/utils'
import { SLOT_ADDRESS } from './constants'
import { generateTestLeaves } from './helpers'
import { MASK_SIGNATURE } from '../src/constants'

describe('Utils', () => {
  describe('hashLeaf', () => {
    it('Should return a bigint hash of the two values', () => {
      const leaf = hashLeaf('0x1234567890123456789012345678901234567890', 1000n)

      expect(typeof leaf).toBe('bigint')
      expect(leaf).toBe(5744770974032406598001112375731623179326875761382288642755141437508907349272n)
    })
  })

  describe('generateMerkleTree', () => {
    it('matches the known root for an odd number of leaves', () => {
      const tree = generateMerkleTree([1n, 2n, 3n])
      expect(tree.root).toBe(13816780880028945690020260331303642730075999758909899334839547418969502592169n)
    })
  })

  describe('generateMerkleProof', () => {
    const address = SLOT_ADDRESS
    const balance = 100n

    it('Should generate a valid merkle proof for a leaf', () => {
      const leaves = generateTestLeaves([{ address, balance }])
      const tree = generateMerkleTree(leaves)

      const proof = generateMerkleProof(balance, address, leaves)
      expect(proof.leaf).toBe(hashLeaf(address, balance))

      expect(proof.length).toBe(3)
      const unpaddedProof = {
        ...proof.proof,
        siblings: proof.proof.siblings.slice(0, proof.length),
      }

      expect(tree.verifyProof(unpaddedProof)).toBe(true)
      expect(tree.verifyProof({ ...unpaddedProof, leaf: hashLeaf(address, balance + 1n) })).toBe(false)
    })

    it('Should return path indices in least-significant-bit-first order', () => {
      const leaves = [1000n, 1001n, 1002n, 1003n, 1004n, hashLeaf(address, balance), 1006n, 1007n]
      const proof = generateMerkleProof(balance, address, leaves)

      expect(proof.indices.slice(0, proof.length)).toEqual([1, 0, 1])
    })

    it('accepts the fixed-width unprefixed hex leaves returned by the server', () => {
      const leaves = generateTestLeaves([{ address, balance }])
      const serverLeaves = leaves.map((leaf) => leaf.toString(16).padStart(64, '0'))
      const proof = generateMerkleProof(balance, address, serverLeaves)

      expect(proof.leaf).toBe(hashLeaf(address, balance))
      expect(
        generateMerkleTree(leaves).verifyProof({
          ...proof.proof,
          siblings: proof.proof.siblings.slice(0, proof.length),
        }),
      ).toBe(true)
    })

    it('Should throw if the leaf does not exist in the tree', () => {
      expect(() => generateMerkleProof(balance, address, [])).toThrow('Leaf not found in the tree')
      const leaves = generateTestLeaves([{ address, balance }])
      expect(() => generateMerkleProof(999n, address, leaves)).toThrow('Leaf not found in the tree')
    })
  })

  describe('extractSignatureComponents', () => {
    it('Should extract signature components correctly', async () => {
      const { messageHash, publicKeyX, publicKeyY, signature: extractedSignature } = await extractSignatureComponents(MASK_SIGNATURE)

      expect(bytesToHex(messageHash)).toBe('0x136f9726bf0927af0b8be9fd5b24fe25ee8047f7940e9efc359d7caf154110fd')
      expect(bytesToHex(publicKeyX)).toBe('0x803f440eb94e8a18831bb33268d20363b8c6e632fe425de5a9b16e6caa2d6bf6')
      expect(bytesToHex(publicKeyY)).toBe('0x7d8572b3029dbc17a0021271fee5faf58f1367104b96df09d923892984acf77e')
      expect(bytesToHex(extractedSignature)).toBe(MASK_SIGNATURE.slice(0, 130))
    })
  })
})
