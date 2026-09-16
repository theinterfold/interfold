// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

/**
 * `resolveSlotHeadOnChain` against a stub server.
 *
 * The pure walk is covered in `slotHead.test.ts`. What is exercised here is everything between it
 * and the network: the log topic filter, the `InputCommitted` body decoding, and the pairing of
 * server bytes with chain records. A wrong word offset in the decoder would leave the walk correct
 * and every answer wrong.
 */

import { describe, expect, it, vi, beforeAll, afterEach } from 'vitest'
import { keccak256, toEventSelector, encodeAbiParameters, parseAbiParameters, pad, toHex } from 'viem'

import { resolveSlotHeadOnChain } from '../src/slotHead'
import { getZkInputsGenerator } from '../src/encoding'

const SERVER = 'http://crisp.test'
const PROGRAM = '0x00000000000000000000000000000000000000aa'
const SLOT = '0x00000000000000000000000000000000000000bb'
const E3_ID = 7n

const INPUT_COMMITTED_TOPIC = toEventSelector('InputCommitted(uint256,bytes32,address,bytes32,bytes32,uint40,uint40)')

type Ballot = { ciphertext: Uint8Array; commitment: `0x${string}` }

/** An `InputCommitted` log as a node returns it: indexed fields in topics, the rest in `data`. */
const log = (ballot: Ballot, index: number, parentIndexPlusOne: number, overrides: { hash?: `0x${string}` } = {}) => ({
  address: PROGRAM,
  topics: [INPUT_COMMITTED_TOPIC, pad(toHex(E3_ID)), pad('0x01'), pad(SLOT)],
  data: encodeAbiParameters(parseAbiParameters('bytes32, bytes32, uint40, uint40'), [
    ballot.commitment,
    overrides.hash ?? keccak256(ballot.ciphertext),
    parentIndexPlusOne,
    index,
  ]),
  block_number: 100 + index,
  transaction_hash: null,
  log_index: index,
})

describe('resolveSlotHeadOnChain', () => {
  let ballots: Ballot[]

  beforeAll(() => {
    const generator = getZkInputsGenerator()
    const { publicKey } = generator.generateKeys()
    const degree = Number(generator.getBFVParams().degree)

    ballots = [0, 1, 2].map((seed) => {
      const vote = new BigInt64Array(degree)
      vote[0] = BigInt(seed + 1)
      const ciphertext = generator.encryptVote(publicKey, vote)

      return {
        ciphertext,
        commitment: `0x${Array.from(generator.computeCtCommitment(ciphertext))
          .map((byte) => byte.toString(16).padStart(2, '0'))
          .join('')}` as `0x${string}`,
      }
    })
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  /** Serve the two endpoints the resolver calls, and record what it asked for. */
  const stubServer = (entries: { ciphertext: Uint8Array; index: number }[], logs: unknown[]) => {
    const requests: { url: string; body: any }[] = []

    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: string, init: { body: string }) => {
        const body = JSON.parse(init.body)
        requests.push({ url, body })

        if (url.endsWith('state/slot-entries')) {
          return {
            ok: true,
            status: 200,
            json: async () => ({ entries: entries.map((e) => ({ ciphertext: Array.from(e.ciphertext), index: e.index })) }),
          }
        }

        if (url.endsWith('chain/logs')) {
          return { ok: true, status: 200, json: async () => logs }
        }

        throw new Error(`unexpected request to ${url}`)
      }),
    )

    return requests
  }

  it('resolves the head from the server bytes and the chain records', async () => {
    // Indices 0 and 2, so that `index` and `parentIndexPlusOne` never hold the same value and a
    // decoder that swapped the two words would be caught.
    const entries = [
      { ciphertext: ballots[0].ciphertext, index: 0 },
      { ciphertext: ballots[1].ciphertext, index: 2 },
    ]
    stubServer(entries, [log(ballots[0], 0, 0), log(ballots[1], 2, 1)])

    const resolved = await resolveSlotHeadOnChain(SERVER, PROGRAM, E3_ID, SLOT)

    expect(resolved.complete).toBe(true)
    expect(resolved.head?.index).toBe(2)
    expect(resolved.head?.ciphertext).toEqual(ballots[1].ciphertext)
  })

  /** The filter has to name the event, the round, and the slot, or it reads another slot's chain. */
  it('filters logs to this event, round, and slot', async () => {
    const requests = stubServer([], [])

    await resolveSlotHeadOnChain(SERVER, PROGRAM, E3_ID, SLOT, 42n)

    const logsRequest = requests.find((request) => request.url.endsWith('chain/logs'))
    expect(logsRequest?.body.address).toBe(PROGRAM)
    expect(logsRequest?.body.topics[0]).toBe(INPUT_COMMITTED_TOPIC)
    expect(BigInt(logsRequest?.body.topics[1])).toBe(E3_ID)
    expect(logsRequest?.body.topics[2]).toBeNull()
    expect(logsRequest?.body.topics[3].toLowerCase()).toBe(pad(SLOT).toLowerCase())
    expect(logsRequest?.body.from_block).toBe(42)
  })

  /**
   * A server answering with a stale head cannot move the answer.
   *
   * The bytes are genuine and so is the commitment, but the chain says entry 1 extends entry 0 and
   * holds the slot. Taking the server's word would name entry 0 as the parent, and the Secure
   * Process would drop the resulting ballot.
   */
  it('takes the chain head even when the server omits the newest entry', async () => {
    stubServer(
      [
        { ciphertext: ballots[0].ciphertext, index: 0 },
        { ciphertext: ballots[1].ciphertext, index: 1 },
      ],
      [log(ballots[0], 0, 0), log(ballots[1], 1, 1)],
    )

    const resolved = await resolveSlotHeadOnChain(SERVER, PROGRAM, E3_ID, SLOT)

    expect(resolved.head?.index).toBe(1)
  })

  /** Bytes the contract never recorded leave the entry unjudged, so the walk is incomplete. */
  it('reports an incomplete walk when the server substitutes bytes', async () => {
    stubServer(
      [
        { ciphertext: ballots[0].ciphertext, index: 0 },
        // Entry 1's slot is served with entry 2's bytes.
        { ciphertext: ballots[2].ciphertext, index: 1 },
      ],
      [log(ballots[0], 0, 0), log(ballots[1], 1, 1)],
    )

    const resolved = await resolveSlotHeadOnChain(SERVER, PROGRAM, E3_ID, SLOT)

    expect(resolved.complete).toBe(false)
    expect(resolved.head?.index).toBe(0)
    expect(resolved.rejected).toContainEqual({ index: 1, reason: 'bytes-mismatch' })
  })

  it('reports no head for a slot the chain has no entries for', async () => {
    stubServer([], [])

    const resolved = await resolveSlotHeadOnChain(SERVER, PROGRAM, E3_ID, SLOT)

    expect(resolved.head).toBeUndefined()
    expect(resolved.complete).toBe(true)
  })
})
