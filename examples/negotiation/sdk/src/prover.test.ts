// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

/**
 * Unit tests of the prover wiring (no proving), and real proofs against a local l-BFV key. An offer proof
 * takes minutes, so the real test runs only with `NEG_PROVE=1`. It prints the timings, and with
 * `NEG_WRITE_FIXTURES=1` it writes the proof to `test-vectors/proofs.json` for the contract tests.
 *
 *   NEG_PROVE=1 pnpm vitest run src/prover.test.ts
 *
 * The key comes from `circuits/tools` (`lbfv_key`) unless `NEG_KEY` names a key file. `NEG_ROLE=0|1`
 * chooses the role of the real offer (the default is the buyer).
 */
import { Barretenberg, UltraHonkBackend } from '@aztec-foundation/bb.js'
import type { CompiledCircuit } from '@noir-lang/noir_js'
import { execFileSync } from 'node:child_process'
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'
import lanesCircuitJson from '../circuits/negotiation_offer_lanes.json'
import offerCircuitJson from '../circuits/negotiation_offer.json'
import vkAnchorJson from '../circuits/vk_anchor.json'
import { LEVELS, maskSlots, OFFER_CIPHERTEXTS, Role } from './layout'
import { OfferProver, PARAM_SET, toHex } from './prover'

const here = dirname(fileURLToPath(import.meta.url))
const run = process.env.NEG_PROVE === '1'

function committeeKey(): Uint8Array {
  if (process.env.NEG_KEY) return readFileSync(process.env.NEG_KEY)
  const file = join(mkdtempSync(join(tmpdir(), 'neg-key-')), 'key.bin')
  execFileSync(
    'cargo',
    ['run', '--release', '--quiet', '--manifest-path', join(here, '../../circuits/tools/Cargo.toml'), '--bin', 'lbfv_key', '--', file],
    {
      stdio: 'inherit',
    },
  )
  return readFileSync(file)
}

const party = '0x70997970C51812dc3A010C7d01b50e0d17dc79C8' as const

describe('circuits', () => {
  it('has the public inputs the contract supplies, in order', () => {
    const offer = (offerCircuitJson as unknown as CompiledCircuit).abi
    expect(offer.parameters.filter(({ visibility }) => visibility === 'public').map(({ name }) => name)).toEqual([
      'ct_commitments',
      'party',
      'role',
      'levels',
    ])
    // The returned `(pk_commitment, vk_anchor)` come after the parameters.
    expect(offer.return_type?.visibility).toBe('public')
    expect(offer.return_type?.abi_type).toEqual({ kind: 'tuple', fields: [{ kind: 'field' }, { kind: 'field' }] })
  })

  it('has the public inputs the offer circuit recomputes for the lanes proof, in order', () => {
    const { abi } = lanesCircuitJson as unknown as CompiledCircuit
    expect(abi.parameters.filter(({ visibility }) => visibility === 'public').map(({ name }) => name)).toEqual([
      'ct_commitments',
      'role',
      'levels',
      'pk_row0',
      'user_data_encryption_key_hash',
      'ct0_chain',
      'ct1_chain',
    ])
    expect(abi.return_type).toBeNull()
  })

  it('ships a VK anchor', () => {
    expect(vkAnchorJson.vkAnchor).toMatch(/^0x[0-9a-f]{64}$/)
  })
})

describe('prover', () => {
  it('uses the parameter set of the l-BFV committee', () => {
    expect(PARAM_SET).toBe(5)
    expect(OFFER_CIPHERTEXTS).toBe(3)
  })

  it('formats hex words', () => {
    expect(toHex(new Uint8Array([0, 1, 255]))).toBe('0x0001ff')
  })

  it('rejects an invalid offer before any proving', async () => {
    // `create` builds an SRS; a prover cannot be built cheaply, so reach `prove` through a bare instance.
    const prover = Object.create(OfferProver.prototype) as OfferProver
    const base = { role: Role.Seller, step: 3, party, levels: 8, committeeKey: new Uint8Array() }
    await expect(prover.prove({ ...base, step: 8 })).rejects.toThrow(/price step/)
    await expect(prover.prove({ ...base, step: -1 })).rejects.toThrow(/price step/)
    await expect(prover.prove({ ...base, share: 16 })).rejects.toThrow(/share/)
    await expect(prover.prove({ ...base, levels: 1 })).rejects.toThrow(/price levels/)
    await expect(prover.prove({ ...base, levels: LEVELS + 1 })).rejects.toThrow(/price levels/)
  })
})

describe.skipIf(!run)('real proofs', () => {
  it('proves an offer against a local l-BFV key', { timeout: 40 * 60_000 }, async () => {
    const key = committeeKey()
    const timings: Record<string, number> = {}
    const role = process.env.NEG_ROLE === '0' ? Role.Seller : Role.Buyer
    const step = 9
    const share = 6
    const levels = 12
    const mask = maskSlots()

    const prover = await OfferProver.create()
    const started = performance.now()
    let stepStart = started
    const offer = await prover.prove({
      role,
      step,
      share,
      mask,
      party,
      levels,
      committeeKey: key,
      onStep: (progress) => {
        const now = performance.now()
        const label = 'index' in progress ? `${progress.kind} ${progress.index}` : progress.kind
        timings[`before ${label}`] = now - stepStart
        stepStart = now
      },
    })
    timings.total = performance.now() - started
    await prover.destroy()

    expect(offer.ciphertexts).toHaveLength(OFFER_CIPHERTEXTS)
    expect(offer.commitments).toHaveLength(OFFER_CIPHERTEXTS)
    expect(offer.vkAnchor).toBe(vkAnchorJson.vkAnchor)

    // The proof binds the public inputs in the order of the contract.
    const word = (value: bigint | number) => `0x${BigInt(value).toString(16).padStart(64, '0')}`
    const publicInputs = [...offer.commitments, word(BigInt(party)), word(role), word(levels), offer.pkCommitment, offer.vkAnchor]
    const verifier = await Barretenberg.new({ threads: 4 })
    const backend = new UltraHonkBackend((offerCircuitJson as unknown as CompiledCircuit).bytecode, verifier)
    const proof = { proof: Buffer.from(offer.proof.slice(2), 'hex'), publicInputs }
    expect(await backend.verifyProof(proof, { verifierTarget: 'evm' })).toBe(true)
    // Another party, role or levels fails.
    const tamper = (index: number, value: string) => publicInputs.map((input, i) => (i === index ? value : input))
    expect(
      await backend
        .verifyProof({ ...proof, publicInputs: tamper(3, word(BigInt(party) + 1n)) }, { verifierTarget: 'evm' })
        .catch(() => false),
    ).toBe(false)
    expect(
      await backend.verifyProof({ ...proof, publicInputs: tamper(4, word(1 - role)) }, { verifierTarget: 'evm' }).catch(() => false),
    ).toBe(false)
    expect(
      await backend.verifyProof({ ...proof, publicInputs: tamper(5, word(levels + 1)) }, { verifierTarget: 'evm' }).catch(() => false),
    ).toBe(false)
    await verifier.destroy()

    console.log('offer timings (ms):', JSON.stringify(timings))
    if (process.env.NEG_WRITE_FIXTURES === '1') {
      writeFileSync(
        join(here, '../test-vectors/proofs.json'),
        `${JSON.stringify(
          {
            note: 'A real offer proof from src/prover.test.ts against a local l-BFV key. Public inputs: ct_commitments[0..2], party, role, levels, pk_commitment, vk_anchor.',
            offer: {
              role,
              party,
              levels,
              commitments: offer.commitments,
              proof: offer.proof,
              publicInputs,
              ciphertexts: offer.ciphertexts,
            },
          },
          null,
          2,
        )}\n`,
      )
    }
  })
})
