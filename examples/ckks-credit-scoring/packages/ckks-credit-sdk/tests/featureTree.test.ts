// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

// The client's poseidon-lite tree must reproduce the root the on-chain gate accepted a real proof
// under (packages/interfold-contracts/test/fixtures/ckks_credit_ps4) — i.e. light-poseidon 0.2 /
// Noir `hash_9`/`hash_2`.

import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'

import { FeatureTree, featureLeaf, rootFromProof } from '../src/featureTree'
import { creditLogit, modelWords, recoverScore, sigmoidCubic, toFixedPoint } from '../src/apply'

const fixture = JSON.parse(readFileSync(new URL('../../../../../packages/interfold-contracts/test/fixtures/ckks_credit_ps4/verified_input.json', import.meta.url), 'utf8'))

describe('feature tree', () => {
  it('reproduces the fixture root and the Noir leaf vector', () => {
    const alice = '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266' as const
    const bob = '0x70997970C51812dc3A010C7d01b50e0d17dc79C8' as const
    const tree = new FeatureTree([
      { address: alice, features: JSON.parse(fixture.extra.features) },
      { address: bob, features: [1, 2, 3, 4, 5, 6, 7, 8] },
    ])
    expect(tree.rootHex()).toBe(fixture.extra.merkleRoot)
    expect(featureLeaf(alice, [520, 130, 350, 999, 0, 1, 777, 42]).toString(16)).toBe('2e70bfe6109556e0a2a8885470e8fdb18abb76d03a135766b644ab2bd2ad0c0e')
    const proof = { address: alice, index: 0, features: [520, 130, 350, 999, 0, 1, 777, 42], cap: 1000, merkleRoot: tree.rootHex(), depth: 1, indices: [false], siblings: [featureLeaf(bob, [1, 2, 3, 4, 5, 6, 7, 8]).toString()] }
    expect(rootFromProof(proof)).toBe(tree.rootHex())
  })
  it('reproduces the fixture model words and logit, and recovers the score only with the right mask', () => {
    const fixed = toFixedPoint({ weights: [1.7, -2.3, 0.9, 0.4, -1.1, 2.6, -0.5, 1.2], bias: -0.8 })
    expect(fixed.weights).toEqual(fixture.model.weights)
    expect(fixed.bias).toBe(fixture.model.bias)
    expect(modelWords(fixed)).toEqual(fixture.modelWords)
    const z = creditLogit(fixed, JSON.parse(fixture.extra.features), fixture.cap)
    expect(Math.abs(z - fixture.logitValue)).toBeLessThan(1e-12)
    const mask = fixture.maskValue as number
    const opened = [sigmoidCubic(z) + mask / 1024]
    const r = recoverScore(opened, 0, mask)
    expect(Math.abs(r.probability - sigmoidCubic(z))).toBeLessThan(1e-9)
    const wrong = recoverScore(opened, 0, (mask + 1) % (1 << 20))
    expect(Math.abs(wrong.probability - sigmoidCubic(z))).toBeGreaterThan(1e-4)
  })
})
