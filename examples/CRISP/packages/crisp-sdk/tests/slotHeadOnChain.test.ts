// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

/**
 * `resolveSlotHeadOnChain` against a stub server and a stub client.
 *
 * The pure walk is covered in `slotHead.test.ts`. What is exercised here is everything between it
 * and the network: the log filter, the pairing of server bytes with chain records, and the fact
 * that the two come from different sources.
 *
 * The server and the client are stubbed separately on purpose. They are different sources, and the
 * whole point of the split is that the server cannot answer for both — so a test that let one stub
 * serve both would not be testing the arrangement this module depends on.
 */

import { describe, expect, it, vi, beforeAll, afterEach } from 'vitest'
import { keccak256, toEventSelector, encodeAbiParameters, parseAbiParameters, pad, toHex } from 'viem'

import { resolveSlotHeadOnChain } from '../src/slotHead'
import { getZkInputsGenerator } from '../src/encoding'

import type { PublicClient } from 'viem'

const SERVER = 'http://crisp.test'
const PROGRAM = '0x00000000000000000000000000000000000000aa'
const SLOT = '0x00000000000000000000000000000000000000bb'
const E3_ID = 7n

const INPUT_COMMITTED_TOPIC = toEventSelector('InputCommitted(uint256,bytes32,address,bytes32,bytes32,uint40,uint40)')

type Ballot = { ciphertext: Uint8Array; commitment: `0x${string}` }

/**
 * An `InputCommitted` log as viem returns one when the call names an event: the raw log, plus the
 * fields viem decoded from the topics and the body.
 *
 * The `args` are built here rather than left to viem, because the client is stubbed. What is under
 * test is the resolver's use of them, not viem's decoding.
 */
const log = (ballot: Ballot, index: number, parentIndexPlusOne: number, overrides: { hash?: `0x${string}` } = {}) => ({
  address: PROGRAM as `0x${string}`,
  topics: [INPUT_COMMITTED_TOPIC, pad(toHex(E3_ID)), pad('0x01'), pad(SLOT)],
  data: encodeAbiParameters(parseAbiParameters('bytes32, bytes32, uint40, uint40'), [
    ballot.commitment,
    overrides.hash ?? keccak256(ballot.ciphertext),
    parentIndexPlusOne,
    index,
  ]),
  args: {
    e3Id: E3_ID,
    inputId: pad('0x01'),
    slotAddress: SLOT,
    encryptedVoteCommitment: ballot.commitment,
    encryptedVoteHash: overrides.hash ?? keccak256(ballot.ciphertext),
    parentIndexPlusOne,
    index,
  },
  blockNumber: BigInt(100 + index),
  transactionHash: null,
  logIndex: index,
  blockHash: null,
  transactionIndex: null,
  removed: false,
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

  /**
   * A server that serves the entries it was given, and a client that returns the logs.
   *
   * Separate stubs because they are separate sources: `entries` is what the server reports, `logs`
   * is what the chain reports, and a test can vary either one.
   */
  const stubSources = (entries: { ciphertext: Uint8Array; index: number }[], logs: unknown[]) => {
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
            statusText: 'stubbed',
            json: async () => ({ entries: entries.map((e) => ({ ciphertext: Array.from(e.ciphertext), index: e.index })) }),
          }
        }

        throw new Error(`the resolver must not read logs from the server: ${url}`)
      }),
    )

    const getLogs = vi.fn(async (_filter: unknown) => logs)

    return { requests, getLogs, client: { getLogs } as unknown as PublicClient }
  }

  it('resolves the head from the server bytes and the chain records', async () => {
    // Indices 0 and 2, so that `index` and `parentIndexPlusOne` never hold the same value and a
    // decoder that swapped the two words would be caught.
    const entries = [
      { ciphertext: ballots[0].ciphertext, index: 0 },
      { ciphertext: ballots[1].ciphertext, index: 2 },
    ]
    const { client, getLogs } = stubSources(entries, [log(ballots[0], 0, 0), log(ballots[1], 2, 1)])

    const resolved = await resolveSlotHeadOnChain(client, SERVER, PROGRAM, E3_ID, SLOT)

    expect(resolved.complete).toBe(true)
    expect(resolved.head?.index).toBe(2)
    expect(resolved.head?.ciphertext).toEqual(ballots[1].ciphertext)

    // Filtered by event, round, and slot, so the walk never reads another slot's chain.
    const filter = getLogs.mock.calls[0][0] as any
    expect(filter.address).toBe(PROGRAM)
    expect(filter.event.name).toBe('InputCommitted')
    expect(filter.args.e3Id).toBe(E3_ID)
    expect(String(filter.args.slotAddress).toLowerCase()).toBe(SLOT)
  })

  /**
   * The scan must always carry an explicit `fromBlock`.
   *
   * An omitted `fromBlock` is not "from the beginning": the node reads it as the latest block, so
   * every input lands outside the range, the walk sees an empty chain, and it reports a head of
   * `undefined` as complete. A ballot built on that is published and dropped from the tally.
   *
   * This is the shape the e2e caught, from the other side: a `fromBlock` that was present but a
   * timestamp rather than a height made the node reject the range outright. Both are the same
   * mistake — a bound that is not a real height — so this asserts the value directly.
   */
  it('scans from block 0 when the caller gives no fromBlock', async () => {
    const { client, getLogs } = stubSources([], [])

    await resolveSlotHeadOnChain(client, SERVER, PROGRAM, E3_ID, SLOT)

    const filter = getLogs.mock.calls[0][0] as any
    expect(filter.fromBlock).toBe(0n)
    expect(typeof filter.fromBlock).toBe('bigint')
  })

  /** A caller that knows the deployment block gets a tight scan instead. */
  it('passes an explicit fromBlock through to the query', async () => {
    const { client, getLogs } = stubSources([], [])

    await resolveSlotHeadOnChain(client, SERVER, PROGRAM, E3_ID, SLOT, 42n)

    expect((getLogs.mock.calls[0][0] as any).fromBlock).toBe(42n)
  })

  /**
   * The regression this split exists for.
   *
   * If the logs came from the server's own index, an omitted entry would leave the walk with no
   * evidence it ever existed. The server's single entry would be the whole chain, the walk would
   * take it, and it would answer `complete: true` with an empty `rejected` — the voter names a
   * parent the tally has already moved past, the proof verifies, the input is published, and the
   * ballot is dropped with no error anywhere.
   *
   * The chain's record is not something the server can withdraw, so entry 1 stays visible even
   * though its bytes were withheld. That makes the result a lower bound instead of a settled
   * answer.
   */
  it('does not report a superseded head as settled when the server hides an entry', async () => {
    // The server admits only the first entry. The chain knows about the second.
    const serverEntries = [{ ciphertext: ballots[0].ciphertext, index: 0 }]
    const chainLogs = [log(ballots[0], 0, 0), log(ballots[1], 1, 1)]

    const { client } = stubSources(serverEntries, chainLogs)

    const resolved = await resolveSlotHeadOnChain(client, SERVER, PROGRAM, E3_ID, SLOT)

    expect(resolved.complete).toBe(false)
    expect(resolved.rejected).toEqual([{ index: 1, reason: 'missing-bytes' }])
  })

  /** Bytes the contract never recorded leave the entry unjudged, so the walk is incomplete. */
  it('reports an incomplete walk when the server substitutes bytes', async () => {
    const { client } = stubSources(
      [
        { ciphertext: ballots[0].ciphertext, index: 0 },
        // Entry 1's slot is served with entry 2's bytes.
        { ciphertext: ballots[2].ciphertext, index: 1 },
      ],
      [log(ballots[0], 0, 0), log(ballots[1], 1, 1)],
    )

    const resolved = await resolveSlotHeadOnChain(client, SERVER, PROGRAM, E3_ID, SLOT)

    expect(resolved.complete).toBe(false)
    expect(resolved.head?.index).toBe(0)
    expect(resolved.rejected).toContainEqual({ index: 1, reason: 'bytes-mismatch' })
  })

  it('reports no head for a slot the chain has no entries for', async () => {
    const { client } = stubSources([], [])

    const resolved = await resolveSlotHeadOnChain(client, SERVER, PROGRAM, E3_ID, SLOT)

    expect(resolved.head).toBeUndefined()
    expect(resolved.complete).toBe(true)
  })
})
