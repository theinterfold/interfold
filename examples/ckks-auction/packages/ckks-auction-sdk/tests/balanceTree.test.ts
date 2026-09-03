// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

// Poseidon / tree parity against the REAL `ckks_auction_ps2` fixture root produced by the Rust
// `BalanceTree` (light-poseidon 0.2, circom params) — the value the on-chain gate compared and the
// circuit verified. If poseidon-lite ever drifted from it, every bid would fail with WrongRoot.

import { describe, expect, it } from 'vitest'

import { BalanceTree, balanceLeaf, rootFromProof, toRootHex } from '../src/balanceTree'
import { poseidon2 } from 'poseidon-lite'

const FIXTURE_ADDRESS = '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266' as const
const FIXTURE_SIBLING = 18385459649577497665220684845508695793320800046942131834489884290641637195370n
const FIXTURE_ROOT = '0x2ae63b169ba05aec6ff47eddae2294da69ee64ed900fd79c4116178450b4db47'

describe('balance tree', () => {
  it('matches the Rust BalanceTree / circuit fixture root', () => {
    const leaf = balanceLeaf(FIXTURE_ADDRESS, 800n)
    expect(toRootHex(poseidon2([leaf, FIXTURE_SIBLING]))).toBe(FIXTURE_ROOT)
  })

  it('pads with zero LEAVES and opens every entry to the root', () => {
    const entries = [
      { address: FIXTURE_ADDRESS, balance: '100' },
      { address: '0x70997970C51812dc3A010C7d01b50e0d17dc79C8' as const, balance: '500' },
      { address: '0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC' as const, balance: '1000' },
    ]
    const tree = new BalanceTree(entries)
    expect(tree.depth).toBe(2)
    for (const e of entries) {
      const proof = tree.proof(e.address)
      expect(proof.depth).toBe(2)
      expect(rootFromProof(proof)).toBe(tree.rootHex())
    }
    // Padding leaf is 0 (poseidon of [0,0] is NOT what the circuit expects for an absent leaf).
    const last = tree.proof(entries[2].address)
    expect(last.siblings[0]).toBe('0')
  })
})
