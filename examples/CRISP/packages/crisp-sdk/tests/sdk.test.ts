// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

/**
 * The trust boundary `CrispSDK.resolveSlotHead` enforces.
 *
 * Slot-head verification is only worth anything while the two sources stay apart: the server
 * supplies the ciphertext bytes, and an independent endpoint supplies the `InputCommitted` logs
 * that judge them. Read both from the CRISP server and the check becomes circular — a server that
 * omits an entry and its log together leaves nothing behind to notice the gap, and the resolver
 * answers with a superseded head as though the walk had completed.
 *
 * `SERVER_RPC` is only a sentinel for the server's own route, so it is not the whole class of
 * "same source". A caller can name that route directly, and these tests pin both spellings.
 */

import { afterEach, describe, expect, it, vi } from 'vitest'

import { chainRpcUrl } from '../src/api'
import { CrispSDK, SERVER_RPC } from '../src/sdk'

const SERVER = 'https://crisp.example'
const INDEPENDENT = 'http://127.0.0.1:9/rpc'
const PROGRAM = '0x00000000000000000000000000000000000000aa'
const SLOT = '0x00000000000000000000000000000000000000bb'
const E3_ID = 7n

/** The guard runs before any circuit work, so the preset only has to be nameable here. */
const resolution = { preset: 'insecure-512' as const, deploymentBlock: 1n }

const refusal = /chain reads go through the CRISP server/

describe('CrispSDK.resolveSlotHead', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('refuses the SERVER_RPC sentinel', async () => {
    const sdk = new CrispSDK(SERVER, SERVER_RPC)

    await expect(sdk.resolveSlotHead(1, PROGRAM, E3_ID, SLOT, resolution)).rejects.toThrow(refusal)
  })

  /**
   * The regression this guard was widened for.
   *
   * The sentinel resolves to the server's own route, and passing that route as a URL is the same
   * source. A guard keyed on the sentinel alone would accept this and hand the server both halves
   * of its own check.
   */
  it('refuses the server route passed as a plain URL', async () => {
    const sdk = new CrispSDK(SERVER, chainRpcUrl(SERVER))

    await expect(sdk.resolveSlotHead(1, PROGRAM, E3_ID, SLOT, resolution)).rejects.toThrow(refusal)
  })

  /** The same endpoint written with a trailing slash is still the same endpoint. */
  it('refuses the server route written with a trailing slash', async () => {
    const sdk = new CrispSDK(SERVER, `${chainRpcUrl(SERVER)}/`)

    await expect(sdk.resolveSlotHead(1, PROGRAM, E3_ID, SLOT, resolution)).rejects.toThrow(refusal)
  })

  /**
   * An endpoint that is not the server is allowed through the guard.
   *
   * Resolution then proceeds to the network, which is not stubbed for the chain read, so it fails
   * there. What matters is that the failure is a transport one and not the trust boundary: the check
   * must not refuse everything it cannot prove is independent, or it would refuse real callers.
   */
  it('does not refuse an independent endpoint', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => {
        throw new Error('stubbed transport')
      }),
    )

    const sdk = new CrispSDK(SERVER, INDEPENDENT)

    let message = ''
    try {
      await sdk.resolveSlotHead(1, PROGRAM, E3_ID, SLOT, resolution)
    } catch (error) {
      message = error instanceof Error ? error.message : String(error)
    }

    expect(message).not.toMatch(refusal)
  })
})
