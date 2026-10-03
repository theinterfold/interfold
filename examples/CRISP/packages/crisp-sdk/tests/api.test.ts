// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { afterEach, describe, expect, it, vi } from 'vitest'

import { getInputSelection, requestNewRound } from '../src/api'
import type { InputIdentity, InputSelectionResponse, NewRoundRequest } from '../src/types'

const request: NewRoundRequest = {
  cronApiKey: 'secret',
  tokenAddress: '0x1234567890123456789012345678901234567890',
  balanceThreshold: '100',
  censusMode: 0,
}

describe('requestNewRound', () => {
  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('requires HTTPS for a remote server', async () => {
    const fetch = vi.spyOn(globalThis, 'fetch')

    await expect(requestNewRound('http://crisp.example', request)).rejects.toThrow('must use HTTPS')
    expect(fetch).not.toHaveBeenCalled()
  })

  it('rejects misleading user information before sending the secret', async () => {
    const fetch = vi.spyOn(globalThis, 'fetch')

    await expect(requestNewRound('http://localhost@crisp.example', request)).rejects.toThrow('must not contain user information')
    expect(fetch).not.toHaveBeenCalled()
  })

  it.each([
    ['/relative', 'absolute HTTP or HTTPS'],
    ['ftp://crisp.example', 'use HTTP or HTTPS'],
    ['https://crisp.example?mode=cron', 'query or fragment'],
    ['https://crisp.example?', 'query or fragment'],
    ['https://crisp.example#cron', 'query or fragment'],
    ['https://crisp.example#', 'query or fragment'],
  ])('rejects invalid authenticated server URL %s', async (serverUrl, message) => {
    const fetch = vi.spyOn(globalThis, 'fetch')

    await expect(requestNewRound(serverUrl, request)).rejects.toThrow(message)
    expect(fetch).not.toHaveBeenCalled()
  })

  it.each(['http://localhost:4000', 'http://127.0.0.2:4000', 'http://[::1]:4000'])(
    'allows the loopback development server %s',
    async (serverUrl) => {
      vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce({
        ok: true,
        json: async () => ({ message: 'created' }),
      } as Response)

      await requestNewRound(serverUrl, request)

      expect(fetch).toHaveBeenCalledWith(expect.stringContaining('/rounds/request'), expect.objectContaining({ redirect: 'error' }))
    },
  )

  it('sends the complete request to a remote HTTPS server without following redirects', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce({
      ok: true,
      json: async () => ({ message: 'created' }),
    } as Response)

    await requestNewRound('https://crisp.example/base/', request)

    expect(fetch).toHaveBeenCalledWith('https://crisp.example/base/rounds/request', {
      method: 'POST',
      redirect: 'error',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        cron_api_key: request.cronApiKey,
        token_address: request.tokenAddress,
        balance_threshold: request.balanceThreshold,
        census_mode: request.censusMode,
      }),
    })
  })
})

describe('getInputSelection', () => {
  const identity: InputIdentity = {
    slotAddress: '0x1234567890123456789012345678901234567890',
    encryptedVoteCommitment: `0x${'11'.repeat(32)}`,
    encryptedVoteHash: `0x${'22'.repeat(32)}`,
    parentIndexPlusOne: 4,
  }

  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('posts the round and the input identity in the body, not the URL', async () => {
    const answer: InputSelectionResponse = { status: 'excluded', index: 7, head_index: 5, reason: 'earlier_sibling' }
    const fetch = vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: async () => answer,
    } as Response)

    await expect(getInputSelection('https://crisp.example', 12n, identity)).resolves.toEqual(answer)

    const [url, init] = fetch.mock.calls[0]
    expect(url).toBe('https://crisp.example/voting/selection')
    expect(init?.method).toBe('POST')
    expect(JSON.parse(init?.body as string)).toEqual({
      round_id: '12',
      slot_address: identity.slotAddress,
      encrypted_vote_commitment: identity.encryptedVoteCommitment,
      encrypted_vote_hash: identity.encryptedVoteHash,
      parent_index_plus_one: 4,
    })
  })

  it('tells a round the server does not know apart from a failed request', async () => {
    vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce({ ok: false, status: 404, text: async () => 'unknown round' } as Response)
      .mockResolvedValueOnce({ ok: false, status: 503, text: async () => 'indexer busy' } as Response)

    await expect(getInputSelection('https://crisp.example', 12n, identity)).resolves.toBeUndefined()
    await expect(getInputSelection('https://crisp.example', 12n, identity)).rejects.toThrow('503')
  })
})
