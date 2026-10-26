// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

/**
 * Real proofs against a local l-BFV key. A bid proof (two encryption proofs and the bid circuit) takes
 * minutes, so the test runs only with `PRND_PROVE=1`. It writes the timings, and with `PRND_WRITE_FIXTURES=1` it writes the proofs to
 * `test-vectors/proofs.json` for the contract tests.
 *
 *   PRND_PROVE=1 pnpm vitest run src/prover.test.ts
 *
 * The key comes from `circuits/tools` (`lbfv_key`) unless `PRND_KEY` names a key file.
 */
import { Barretenberg, UltraHonkBackend } from '@aztec-foundation/bb.js'
import type { CompiledCircuit } from '@noir-lang/noir_js'
import { execFileSync } from 'node:child_process'
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'
import bidCircuitJson from '../circuits/private_round_bid.json'
import claimCircuitJson from '../circuits/private_round_claim.json'
import vkAnchorJson from '../circuits/vk_anchor.json'
import { bidSalt, computeBidCommitment } from './prover'
import { BidProver, ClaimProver } from './prover'

const here = dirname(fileURLToPath(import.meta.url))
const run = process.env.PRND_PROVE === '1'

function committeeKey(): Uint8Array {
  if (process.env.PRND_KEY) return readFileSync(process.env.PRND_KEY)
  const file = join(mkdtempSync(join(tmpdir(), 'prnd-key-')), 'key.bin')
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

  it('accepts a salt from bidSalt() below the field', async () => {
    const salt = bidSalt()
    expect(salt).toMatch(/^0x[0-9a-f]{64}$/)
    expect(BigInt(salt) < 2n ** 248n).toBe(true)
  })
})

describe.skipIf(!run)('real proofs', () => {
  it('proves a bid and a claim against a local l-BFV key', { timeout: 40 * 60_000 }, async () => {
    const key = committeeKey()
    const timings: Record<string, number> = {}
    const level = 5
    const levels = 8
    const reserveStep = 2
    const bidderIndex = 3
    const version = 2

    const bidProver = await BidProver.create()
    const started = performance.now()
    let stepStart = started
    const bid = await bidProver.prove({
      level,
      levels,
      reserveStep,
      committeeKey: key,
      bidder,
      e3Id,
      bidderIndex,
      version,
      onStep: (step) => {
        const now = performance.now()
        timings[`before ${step.kind}`] = now - stepStart
        stepStart = now
      },
    })
    timings['bid total'] = performance.now() - started
    timings['bid proof'] = performance.now() - stepStart
    await bidProver.destroy()

    expect(bid.ciphertexts).toHaveLength(2)
    expect(bid.ciphertexts[0]).not.toBe(bid.ciphertexts[1])
    expect(bid.publicInputs).toHaveLength(11)
    expect(bid.publicInputs[0]).toBe(bid.ctCommitments[0])
    expect(bid.publicInputs[1]).toBe(bid.ctCommitments[1])
    expect(bid.publicInputs[2]).toBe(bid.bidCommitment)
    expect(BigInt(bid.publicInputs[3])).toBe(BigInt(bidder))
    expect(BigInt(bid.publicInputs[4])).toBe(e3Id)
    expect(BigInt(bid.publicInputs[5])).toBe(BigInt(levels))
    expect(BigInt(bid.publicInputs[6])).toBe(BigInt(reserveStep))
    expect(BigInt(bid.publicInputs[7])).toBe(BigInt(bidderIndex))
    expect(BigInt(bid.publicInputs[8])).toBe(BigInt(version))
    expect(bid.publicInputs[9]).toBe(bid.pkCommitment)
    expect(bid.publicInputs[10]).toBe(vkAnchorJson.vkAnchor)

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
      const claim = await claimProver.prove({ b: level, salt: bid.salt, bidder, e3Id, bidCommitment: bid.bidCommitment, k })
      const seconds = (performance.now() - t0) / 1000
      expect(claim.cmp).toBe(level < k ? 0 : level === k ? 1 : 2)
      expect(claim.publicInputs).toHaveLength(5)
      expect(claim.publicInputs[0]).toBe(bid.bidCommitment)
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
    await expect(claimProver.prove({ b: level, salt: bidSalt(), bidder, e3Id, bidCommitment: bid.bidCommitment, k: 3 })).rejects.toThrow()
    await claimProver.destroy()
    await verifier.destroy()

    console.log('bid timings (ms):', JSON.stringify(timings))
    console.log('claim seconds:', claims.map((claim) => claim.seconds.toFixed(2)).join(', '))
    if (process.env.PRND_WRITE_FIXTURES === '1') {
      writeFileSync(
        join(here, '../test-vectors/proofs.json'),
        `${JSON.stringify(
          {
            note: 'Real proofs from src/prover.test.ts against a local l-BFV key. Bid public inputs: ct_commitment_bid, ct_commitment_mask, bid_commitment, bidder, e3_id, levels, reserve_step, bidder_index, version, pk_commitment, vk_anchor. Claim public inputs: bid_commitment, bidder, e3_id, k, cmp.',
            bid: {
              level,
              levels,
              reserveStep,
              bidder,
              e3Id: e3Id.toString(),
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
