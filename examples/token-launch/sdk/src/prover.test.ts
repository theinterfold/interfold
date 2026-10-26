// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

/**
 * Real proofs against two local l-BFV keys (one per E3). A bid proof takes minutes, so that test runs
 * only with `TL_PROVE=1`. It writes the timings, and with `TL_WRITE_FIXTURES=1` it writes the proofs to
 * `test-vectors/proofs.json` for the contract tests (`pnpm proofs:regenerate` does both).
 *
 *   TL_PROVE=1 pnpm vitest run src/prover.test.ts
 *
 * The keys come from `circuits/tools` (`lbfv_key`) unless `TL_KEY1` and `TL_KEY2` name key files.
 */
import { Barretenberg, UltraHonkBackend } from '@aztec-foundation/bb.js'
import type { CompiledCircuit } from '@noir-lang/noir_js'
import { execFileSync } from 'node:child_process'
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'
import bidCircuitJson from '../circuits/token_launch_bid.json'
import claimCircuitJson from '../circuits/token_launch_claim.json'
import vkAnchorJson from '../circuits/vk_anchor.json'
import { BN254_R, bidCommitment, fieldHex, nullifier, randomSalt } from './commitments'
import { ClaimTree } from './merkle'
import { BID_PUBLIC_INPUTS, BidProver, CLAIM_PUBLIC_INPUTS, ClaimProver } from './prover'

const here = dirname(fileURLToPath(import.meta.url))
const run = process.env.TL_PROVE === '1'

function committeeKey(fromEnv: string | undefined): Uint8Array {
  if (fromEnv) return readFileSync(fromEnv)
  const file = join(mkdtempSync(join(tmpdir(), 'tl-key-')), 'key.bin')
  execFileSync(
    'cargo',
    ['run', '--release', '--quiet', '--manifest-path', join(here, '../../circuits/tools/Cargo.toml'), '--bin', 'lbfv_key', '--', file],
    { stdio: 'inherit' },
  )
  return readFileSync(file)
}

const bidder = '0x70997970C51812dc3A010C7d01b50e0d17dc79C8' as const
const saleId = 7n

describe('commitments', () => {
  it('equal the values the circuits compute', async () => {
    // The same inputs and values as `the_commitment_equals_the_sdk_value` and
    // `the_nullifier_and_the_tree_hash_equal_the_sdk_values` in `circuits/{bid,claim}/src/main.nr`.
    const opening = { step: 7, budget: 1500, escrowUnits: 2000, salt: 12345n, bidder, saleId: 4n }
    expect(await bidCommitment(opening)).toBe('0x2324c51ea4ffd7d2c8e6f0f4f2a34c869e5781e72ebd51021d6b19e7f0771a61')
    expect(await nullifier({ salt: 12345n, saleId: 4n })).toBe('0x21a2afcf84a2f86125299d906c6c755645eb5b1e47773a190dbaf95872ecd2b6')
  })

  it('bind every input of the bid', async () => {
    const base = { step: 5, budget: 1234, escrowUnits: 2000, salt: 12345n, bidder, saleId }
    const commitment = await bidCommitment(base)
    expect(await bidCommitment(base)).toBe(commitment)
    const others = [
      { ...base, step: 6 },
      { ...base, budget: 1235 },
      { ...base, escrowUnits: 2001 },
      { ...base, salt: 12346n },
      { ...base, saleId: 8n },
      { ...base, bidder: '0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC' as const },
    ]
    for (const other of others) expect(await bidCommitment(other)).not.toBe(commitment)
  })

  it('give a nullifier that depends on the salt and the sale only', async () => {
    const value = await nullifier({ salt: 12345n, saleId })
    expect(await nullifier({ salt: 12346n, saleId })).not.toBe(value)
    expect(await nullifier({ salt: 12345n, saleId: saleId + 1n })).not.toBe(value)
  })

  it('draw a salt of 31 bytes: one field element, fresh every time', () => {
    const salt = randomSalt()
    expect(salt).toMatch(/^0x00[0-9a-f]{62}$/)
    expect(BigInt(salt) < BN254_R).toBe(true)
    expect(randomSalt()).not.toBe(salt)
  })

  it('refuse a value that is not a field element', () => {
    expect(() => fieldHex(BN254_R)).toThrow('field element')
    expect(() => fieldHex(-1n)).toThrow('field element')
  })
})

describe.skipIf(!run)('real proofs', () => {
  it('proves a bid for two E3 keys and a claim of it', { timeout: 60 * 60_000 }, async () => {
    const key1 = committeeKey(process.env.TL_KEY1)
    const key2 = committeeKey(process.env.TL_KEY2)
    const timings: Record<string, number> = {}
    const step = 5
    const budget = 1234
    const escrowUnits = 2000
    const levels = 12
    const index = 2

    const bidProver = await BidProver.create()
    const started = performance.now()
    let stepStart = started
    const bid = await bidProver.prove({
      committeeKey1: key1,
      committeeKey2: key2,
      step,
      budget,
      escrowUnits,
      bidder,
      saleId,
      index,
      levels,
      onProgress: (progress) => {
        const now = performance.now()
        timings[`before ${progress.kind}${'round' in progress ? ` ${progress.round}` : ''}`] = now - stepStart
        stepStart = now
      },
    })
    timings['bid total'] = performance.now() - started
    await bidProver.destroy()

    expect(bid.publicInputs).toHaveLength(BID_PUBLIC_INPUTS)
    expect(bid.publicInputs.slice(0, 8)).toEqual([
      bid.ctCommitment1,
      bid.ctCommitment2,
      bid.bidCommitment,
      fieldHex(BigInt(bidder)),
      fieldHex(saleId),
      fieldHex(BigInt(levels)),
      fieldHex(BigInt(index)),
      fieldHex(BigInt(escrowUnits)),
    ])
    expect(bid.ctCommitment1).not.toBe(bid.ctCommitment2)
    expect(bid.pkCommitment1).not.toBe(bid.pkCommitment2)
    expect(bid.vkAnchor).toBe(vkAnchorJson.vkAnchor)
    expect(bid.bidCommitment).toBe(await bidCommitment({ step, budget, escrowUnits, salt: bid.salt, bidder, saleId }))

    const verifier = await Barretenberg.new({ threads: 4 })
    const bidBackend = new UltraHonkBackend((bidCircuitJson as CompiledCircuit).bytecode, verifier)
    expect(
      await bidBackend.verifyProof(
        { proof: Buffer.from(bid.proof.slice(2), 'hex'), publicInputs: bid.publicInputs },
        { verifierTarget: 'evm' },
      ),
    ).toBe(true)

    // The claim tree: this bid at its index among other leaves.
    const tree = ClaimTree.from([123n, 456n, BigInt(bid.bidCommitment), 789n])
    const { siblings } = tree.path(index)
    const countedMask = 0b1111n
    const claimProver = await ClaimProver.create()
    const claims = [] as { k: number; cmp: number; proof: string; publicInputs: string[]; seconds: number }[]
    const claimOf = (overrides: Partial<Parameters<ClaimProver['prove']>[0]> = {}) =>
      claimProver.prove({
        step,
        budget,
        escrowUnits,
        salt: bid.salt,
        bidder,
        index,
        saleId,
        k: 3,
        recipient: '0x90F79bf6EB2c4f870365E785982E1f101E93b906',
        revealIndex: false,
        root: tree.root,
        countedMask,
        path: siblings,
        ...overrides,
      })
    for (const [k, revealIndex] of [
      [3, false],
      [step, false],
      [7, false],
      [step, true],
      [3, true],
    ] as const) {
      const t0 = performance.now()
      const claim = await claimOf({ k, revealIndex })
      const seconds = (performance.now() - t0) / 1000
      expect(claim.cmp).toBe(step < k ? 0 : step === k ? 1 : 2)
      expect(claim.budgetUnits).toBe(claim.cmp === 0 ? 0 : budget)
      expect(claim.nullifier).toBe(await nullifier({ salt: bid.salt, saleId }))
      expect(claim.publicInputs).toHaveLength(CLAIM_PUBLIC_INPUTS)
      expect(claim.indexPlusOne).toBe(claim.cmp === 1 && revealIndex ? index + 1 : 0)
      expect(claim.publicInputs.slice(0, 5)).toEqual([
        fieldHex(tree.root),
        fieldHex(countedMask),
        fieldHex(saleId),
        fieldHex(BigInt(k)),
        claim.nullifier,
      ])
      expect(claim.publicInputs.slice(6, 11).map(BigInt)).toEqual([
        BigInt(escrowUnits),
        BigInt(claim.budgetUnits),
        revealIndex ? 1n : 0n,
        BigInt(claim.cmp),
        BigInt(claim.indexPlusOne),
      ])
      const backend = new UltraHonkBackend((claimCircuitJson as CompiledCircuit).bytecode, verifier)
      expect(
        await backend.verifyProof(
          { proof: Buffer.from(claim.proof.slice(2), 'hex'), publicInputs: claim.publicInputs },
          { verifierTarget: 'evm' },
        ),
      ).toBe(true)
      claims.push({ k, cmp: claim.cmp, proof: claim.proof, publicInputs: claim.publicInputs, seconds })
    }
    // A claim for a bid that did not count, with another salt, or from another leaf must not prove.
    await expect(claimOf({ countedMask: 0b1011n })).rejects.toThrow()
    await expect(claimOf({ salt: randomSalt() })).rejects.toThrow()
    await expect(claimOf({ index: 1, path: tree.path(1).siblings })).rejects.toThrow()
    await claimProver.destroy()
    await verifier.destroy()

    console.log('bid timings (ms):', JSON.stringify(timings))
    console.log('claim seconds:', claims.map((claim) => claim.seconds.toFixed(2)).join(', '))
    if (process.env.TL_WRITE_FIXTURES === '1') {
      // The claim of the first run (`k = 3`, a winner): the contract tests feed these to the generated verifiers. `claims[3]`
      // is a marginal registration (`cmp = 1`, index revealed).
      writeFileSync(
        join(here, '../test-vectors/proofs.json'),
        `${JSON.stringify(
          {
            bid: { proof: bid.proof, publicInputs: bid.publicInputs },
            claim: { proof: claims[0].proof, publicInputs: claims[0].publicInputs },
            claimMarginal: { proof: claims[3].proof, publicInputs: claims[3].publicInputs },
          },
          null,
          2,
        )}\n`,
      )
    }
  })
})
