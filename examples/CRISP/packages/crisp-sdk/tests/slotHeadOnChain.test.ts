// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

/**
 * `resolveSlotHeadOnChain` against a stub server and a stub client.
 *
 * The pure walk is covered in `slotHead.test.ts`. What is exercised here is everything between it
 * and the network: the log filter, the windowed scan, the pairing of server bytes with chain
 * records, and the fact that the two come from different sources.
 *
 * The server and the client are stubbed separately on purpose. They are different sources, and the
 * whole point of the split is that the server cannot answer for both — so a test that let one stub
 * serve both would not be testing the arrangement this module depends on.
 */

import { describe, expect, it, vi, beforeAll, afterEach } from 'vitest'
import { keccak256, toEventSelector, encodeAbiParameters, parseAbiParameters, pad, toHex } from 'viem'

import { resolveSlotHeadOnChain } from '../src/slotHead'
import { getZkInputsGenerator } from '../src/encoding'
import { setCircuits } from '../src/circuits'
import { loadCircuits } from '../src/presets/insecure-512'

import type { PublicClient } from 'viem'

const SERVER = 'http://crisp.test'
const PROGRAM = '0x00000000000000000000000000000000000000aa'
const SLOT = '0x00000000000000000000000000000000000000bb'
const E3_ID = 7n

/** The preset the stubbed ballots are encrypted under. Passed explicitly to the resolver. */
const PRESET = 'insecure-512' as const

/** A deployment block and a head far enough apart that the scan needs more than one window. */
const DEPLOYMENT_BLOCK = 1_000n
const HEAD = 5_000n

/** Blocks per request. Must match `LOG_WINDOW` in the module under test. */
const LOG_WINDOW = 2_000n

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
  // Inside the scanned range, so the window filter has something real to select on.
  blockNumber: DEPLOYMENT_BLOCK + BigInt(index),
  transactionHash: null,
  logIndex: index,
  blockHash: null,
  transactionIndex: null,
  removed: false,
})

describe('resolveSlotHeadOnChain', () => {
  let ballots: Ballot[]

  beforeAll(async () => {
    setCircuits(await loadCircuits())

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

  /** What the resolver needs beyond the round and the slot. */
  const resolution = (deploymentBlock = DEPLOYMENT_BLOCK) => ({ preset: PRESET, deploymentBlock })

  /**
   * A server that serves the entries it was given, and a client that returns the logs.
   *
   * Separate stubs because they are separate sources: `entries` is what the server reports, `logs`
   * is what the chain reports, and a test can vary either one.
   *
   * The client's `getLogs` filters by the requested window, so a resolver that asked for the wrong
   * range would come back empty rather than accidentally correct.
   */
  const stubSources = (entries: { ciphertext: Uint8Array; index: number }[], logs: unknown[]) => {
    const requests: { url: string; body: any }[] = []
    const windows: { fromBlock: bigint; toBlock: bigint }[] = []

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

    const getLogs = vi.fn(async (filter: any) => {
      windows.push({ fromBlock: filter.fromBlock, toBlock: filter.toBlock })

      return (logs as any[]).filter((entry) => entry.blockNumber >= filter.fromBlock && entry.blockNumber <= filter.toBlock)
    })

    const getBlockNumber = vi.fn(async () => HEAD)

    return {
      requests,
      windows,
      getLogs,
      getBlockNumber,
      client: { getLogs, getBlockNumber } as unknown as PublicClient,
    }
  }

  it('resolves the head from the server bytes and the chain records', async () => {
    // Indices 0 and 2, so that `index` and `parentIndexPlusOne` never hold the same value and a
    // decoder that swapped the two words would be caught.
    const entries = [
      { ciphertext: ballots[0].ciphertext, index: 0 },
      { ciphertext: ballots[1].ciphertext, index: 2 },
    ]
    const { client, getLogs } = stubSources(entries, [log(ballots[0], 0, 0), log(ballots[1], 2, 1)])

    const resolved = await resolveSlotHeadOnChain(client, SERVER, PROGRAM, E3_ID, SLOT, resolution())

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
   * The scan must be windowed, and must start at the contract rather than at genesis.
   *
   * This is the shape that fails on a deployed chain. Starting at `0` and running to the head is
   * one request spanning the whole history, which every hosted provider refuses — Publicnode caps
   * `eth_getLogs` at 50,000 blocks — so voting failed outright rather than slowly. The deployment
   * block is also the only bound available: nothing in the round's public state is a height, and a
   * timestamp there is rejected as an invalid block range.
   */
  it('windows the scan from the deployment block to the head', async () => {
    const { client, windows } = stubSources([], [])

    await resolveSlotHeadOnChain(client, SERVER, PROGRAM, E3_ID, SLOT, resolution())

    // Contiguous from the deployment block to the head, with no gap and no overlap: a gap would
    // silently drop an entry, and an overlap would re-read one.
    expect(windows.length).toBeGreaterThan(1)
    expect(windows[0].fromBlock).toBe(DEPLOYMENT_BLOCK)
    expect(windows[windows.length - 1].toBlock).toBe(HEAD)

    for (const [position, window] of windows.entries()) {
      expect(window.toBlock - window.fromBlock + 1n).toBeLessThanOrEqual(LOG_WINDOW)

      if (position > 0) {
        expect(window.fromBlock).toBe(windows[position - 1].toBlock + 1n)
      }
    }
  })

  /** Every request carries both bounds, so none of them can be read as "the latest block". */
  it('never issues a request without both bounds', async () => {
    const { client, getLogs } = stubSources([], [])

    await resolveSlotHeadOnChain(client, SERVER, PROGRAM, E3_ID, SLOT, resolution())

    for (const [filter] of getLogs.mock.calls as any[]) {
      expect(typeof filter.fromBlock).toBe('bigint')
      expect(typeof filter.toBlock).toBe('bigint')
      expect(filter.fromBlock).toBeGreaterThanOrEqual(DEPLOYMENT_BLOCK)
      expect(filter.toBlock).toBeLessThanOrEqual(HEAD)
    }
  })

  /** A window the server would refuse is never requested, so nothing depends on the provider's cap. */
  it('does not ask the provider for a range it would reject', async () => {
    const { client, getLogs } = stubSources([], [])

    await resolveSlotHeadOnChain(client, SERVER, PROGRAM, E3_ID, SLOT, resolution())

    for (const [filter] of getLogs.mock.calls as [{ fromBlock: bigint; toBlock: bigint }][]) {
      const span = filter.toBlock - filter.fromBlock + 1n

      expect(span).toBeLessThanOrEqual(LOG_WINDOW)
    }
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

    const resolved = await resolveSlotHeadOnChain(client, SERVER, PROGRAM, E3_ID, SLOT, resolution())

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

    const resolved = await resolveSlotHeadOnChain(client, SERVER, PROGRAM, E3_ID, SLOT, resolution())

    expect(resolved.complete).toBe(false)
    expect(resolved.head?.index).toBe(0)
    expect(resolved.rejected).toContainEqual({ index: 1, reason: 'bytes-mismatch' })
  })

  it('reports no head for a slot the chain has no entries for', async () => {
    const { client } = stubSources([], [])

    const resolved = await resolveSlotHeadOnChain(client, SERVER, PROGRAM, E3_ID, SLOT, resolution())

    expect(resolved.head).toBeUndefined()
    expect(resolved.complete).toBe(true)
  })
})
