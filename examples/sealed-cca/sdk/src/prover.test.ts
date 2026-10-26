// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

/**
 * Real proofs against a local l-BFV key. A bid proof takes minutes, so the test runs only with
 * `SCCA_PROVE=1`. It writes the timings, and with `SCCA_WRITE_FIXTURES=1` it writes the proofs to
 * `test-vectors/proofs.json` for the contract tests.
 *
 *   SCCA_PROVE=1 pnpm vitest run src/prover.test.ts
 *
 * The key comes from `circuits/tools` (`lbfv_key`) unless `SCCA_KEY` names a key file.
 */
import { Barretenberg, UltraHonkBackend } from '@aztec-foundation/bb.js'
import type { CompiledCircuit } from '@noir-lang/noir_js'
import { execFileSync } from 'node:child_process'
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'
import bidCircuitJson from '../circuits/sealed_cca_bid.json'
import claimCircuitJson from '../circuits/sealed_cca_claim.json'
import vkAnchorJson from '../circuits/vk_anchor.json'
import { BN254_R, e3Field } from './layout'
import { bidSalt, computeBidCommitment } from './prover'
import { BidProver, ClaimProver } from './prover'

const here = dirname(fileURLToPath(import.meta.url))
const run = process.env.SCCA_PROVE === '1'

function committeeKey(): Uint8Array {
  if (process.env.SCCA_KEY) return readFileSync(process.env.SCCA_KEY)
  const file = join(mkdtempSync(join(tmpdir(), 'scca-key-')), 'key.bin')
  execFileSync(
    'cargo',
    ['run', '--release', '--quiet', '--manifest-path', join(here, '../../circuits/tools/Cargo.toml'), '--bin', 'lbfv_key', '--', file],
    {
      stdio: 'inherit',
    },
  )
  return readFileSync(file)
}

const bidder = '0x70997970C51812dc3A010C7d01b50e0d17dc79C8' as const
const e3Id = 7n
/** A real l-BFV E3 id: 256 bits and above `BN254_R`, as 81% of them are. */
const e3IdAboveField = 68460186016439450058677660870455064315333898776819568879520586884256307871744n
/** `actors[0]` of the Hardhat contract tests: the bidder of the claim proofs they verify. */
const hardhatActor = '0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC' as const

describe('e3Field', () => {
  it('reduces an E3 id above the field and keeps one below it', () => {
    expect(e3IdAboveField >= BN254_R).toBe(true)
    expect(e3Field(e3IdAboveField)).toBe(e3IdAboveField % BN254_R)
    expect(e3Field(e3IdAboveField) < BN254_R).toBe(true)
    expect(e3Field(e3Id)).toBe(e3Id)
    expect(e3Field(BN254_R)).toBe(0n)
  })
})

describe('commitment', () => {
  it('is deterministic and binds every input', async () => {
    const base = { b: 5, salt: 12345n, bidder, e3Id }
    const commitment = await computeBidCommitment(base)
    expect(await computeBidCommitment(base)).toBe(commitment)
    expect(await computeBidCommitment({ ...base, b: 6 })).not.toBe(commitment)
    expect(await computeBidCommitment({ ...base, salt: 12346n })).not.toBe(commitment)
    expect(await computeBidCommitment({ ...base, e3Id: 8n })).not.toBe(commitment)
    expect(await computeBidCommitment({ ...base, bidder: '0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC' })).not.toBe(commitment)
  })

  it('commits to the E3 id as a field element', async () => {
    const base = { b: 5, salt: 12345n, bidder }
    const commitment = await computeBidCommitment({ ...base, e3Id: e3IdAboveField })
    expect(commitment).toBe(await computeBidCommitment({ ...base, e3Id: e3Field(e3IdAboveField) }))
    expect(commitment).not.toBe(await computeBidCommitment({ ...base, e3Id: e3Field(e3IdAboveField) + 1n }))
  })

  it('accepts a salt from bidSalt() below the field', async () => {
    const salt = bidSalt()
    expect(salt).toMatch(/^0x[0-9a-f]{64}$/)
    expect(BigInt(salt) < 2n ** 248n).toBe(true)
  })
})

describe('claim of an E3 id above the field', () => {
  it('proves with e3_id = e3Id mod r, for every clearing step', { timeout: 5 * 60_000 }, async () => {
    const level = 2
    const salt = 0x5ca1ab1en
    const bidCommitment = await computeBidCommitment({ b: level, salt, bidder: hardhatActor, e3Id: e3IdAboveField })
    const prover = await ClaimProver.create()
    const verifier = await Barretenberg.new({ threads: 4 })
    const backend = new UltraHonkBackend((claimCircuitJson as CompiledCircuit).bytecode, verifier)
    const claims = []
    for (const k of [0, 1, 2, 3]) {
      const claim = await prover.prove({ b: level, salt, bidder: hardhatActor, e3Id: e3IdAboveField, bidCommitment, k })
      expect(claim.publicInputs[0]).toBe(bidCommitment)
      expect(BigInt(claim.publicInputs[2])).toBe(e3IdAboveField % BN254_R)
      expect(
        await backend.verifyProof(
          { proof: Buffer.from(claim.proof.slice(2), 'hex'), publicInputs: claim.publicInputs },
          { verifierTarget: 'evm' },
        ),
      ).toBe(true)
      claims.push({ b: level, k, cmp: claim.cmp, proof: claim.proof, publicInputs: claim.publicInputs })
    }
    await prover.destroy()
    await verifier.destroy()
    // The contract tests verify these proofs on chain with the generated claim verifier.
    if (process.env.SCCA_WRITE_FIXTURES === '1') {
      writeFileSync(
        join(here, '../test-vectors/claims-e3-above-field.json'),
        `${JSON.stringify(
          {
            note: 'Real claim proofs from src/prover.test.ts for an E3 id above the BN254 field: public input 2 is e3Id mod r. The bidder is actors[0] of the Hardhat contract tests.',
            e3Id: e3IdAboveField.toString(),
            bidder: hardhatActor,
            salt: `0x${salt.toString(16)}`,
            bidCommitment,
            claims,
          },
          null,
          2,
        )}\n`,
      )
    }
  })
})

describe.skipIf(!run)('real proofs', () => {
  it('proves a bid and a claim against a local l-BFV key', { timeout: 40 * 60_000 }, async () => {
    const key = committeeKey()
    const timings: Record<string, number> = {}
    const level = 5
    const levels = 8
    const bidderIndex = 3
    const version = 2

    const bidProver = await BidProver.create()
    const started = performance.now()
    let stepStart = started
    const bid = await bidProver.prove(level, levels, key, bidder, e3IdAboveField, bidderIndex, version, (step) => {
      const now = performance.now()
      timings[`before ${step.kind}`] = now - stepStart
      stepStart = now
    })
    timings['bid total'] = performance.now() - started
    await bidProver.destroy()

    expect(bid.publicInputs).toHaveLength(9)
    expect(bid.publicInputs[0]).toBe(bid.ctCommitment)
    expect(bid.publicInputs[1]).toBe(bid.bidCommitment)
    expect(BigInt(bid.publicInputs[2])).toBe(BigInt(bidder))
    expect(BigInt(bid.publicInputs[3])).toBe(e3Field(e3IdAboveField))
    expect(BigInt(bid.publicInputs[4])).toBe(BigInt(levels))
    expect(BigInt(bid.publicInputs[5])).toBe(BigInt(bidderIndex))
    expect(BigInt(bid.publicInputs[6])).toBe(BigInt(version))
    expect(bid.publicInputs[8]).toBe(vkAnchorJson.vkAnchor)

    const verifier = await Barretenberg.new({ threads: 4 })
    const bidBackend = new UltraHonkBackend((bidCircuitJson as CompiledCircuit).bytecode, verifier)
    expect(
      await bidBackend.verifyProof(
        { proof: Buffer.from(bid.proof.slice(2), 'hex'), publicInputs: bid.publicInputs },
        { verifierTarget: 'evm' },
      ),
    ).toBe(true)

    const claimProver = await ClaimProver.create()
    const claims = [] as { k: number; cmp: number; proof: string; publicInputs: string[]; seconds: number }[]
    for (const k of [3, level, 7]) {
      const t0 = performance.now()
      const claim = await claimProver.prove({ b: level, salt: bid.salt, bidder, e3Id: e3IdAboveField, bidCommitment: bid.bidCommitment, k })
      const seconds = (performance.now() - t0) / 1000
      expect(claim.cmp).toBe(level < k ? 0 : level === k ? 1 : 2)
      expect(claim.publicInputs).toHaveLength(5)
      expect(claim.publicInputs[0]).toBe(bid.bidCommitment)
      expect(BigInt(claim.publicInputs[2])).toBe(e3Field(e3IdAboveField))
      expect(BigInt(claim.publicInputs[3])).toBe(BigInt(k))
      expect(BigInt(claim.publicInputs[4])).toBe(BigInt(claim.cmp))
      const backend = new UltraHonkBackend((claimCircuitJson as CompiledCircuit).bytecode, verifier)
      expect(
        await backend.verifyProof(
          { proof: Buffer.from(claim.proof.slice(2), 'hex'), publicInputs: claim.publicInputs },
          { verifierTarget: 'evm' },
        ),
      ).toBe(true)
      claims.push({ k, cmp: claim.cmp, proof: claim.proof, publicInputs: claim.publicInputs, seconds })
    }
    // A claim for the wrong commitment (another salt) must not prove.
    await expect(
      claimProver.prove({ b: level, salt: bidSalt(), bidder, e3Id: e3IdAboveField, bidCommitment: bid.bidCommitment, k: 3 }),
    ).rejects.toThrow()
    await claimProver.destroy()
    await verifier.destroy()

    console.log('bid timings (ms):', JSON.stringify(timings))
    console.log('claim seconds:', claims.map((claim) => claim.seconds.toFixed(2)).join(', '))
    if (process.env.SCCA_WRITE_FIXTURES === '1') {
      writeFileSync(
        join(here, '../test-vectors/proofs.json'),
        `${JSON.stringify(
          {
            note: 'Real proofs from src/prover.test.ts against a local l-BFV key. Bid public inputs: ct_commitment, bid_commitment, bidder, e3_id, levels, bidder_index, version, pk_commitment, vk_anchor.',
            bid: {
              level,
              levels,
              bidder,
              e3Id: e3IdAboveField.toString(),
              bidderIndex,
              version,
              salt: bid.salt,
              proof: bid.proof,
              publicInputs: bid.publicInputs,
            },
            claims: claims.map(({ seconds: _seconds, ...claim }) => ({ b: level, ...claim })),
          },
          null,
          2,
        )}\n`,
      )
    }
  })
})
