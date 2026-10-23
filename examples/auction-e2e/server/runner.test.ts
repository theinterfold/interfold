// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { afterEach, describe, expect, it, vi } from 'vitest'

import { callFheRunner } from './runner'

describe('callFheRunner', () => {
  afterEach(() => {
    vi.restoreAllMocks()
    vi.unstubAllGlobals()
  })

  it('submits without authorization and does not log the payload', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ status: 'processing', e3_id: '7' }),
    })
    vi.stubGlobal('fetch', fetchMock)
    const logMock = vi.spyOn(console, 'log').mockImplementation(() => undefined)

    await callFheRunner(
      7n,
      {
        chainId: 31_337,
        interfoldAddress: '0x1111111111111111111111111111111111111111',
        encryptionSchemeId: `0x${'22'.repeat(32)}`,
        committeePublicKeyHash: `0x${'33'.repeat(32)}`,
      },
      '0x0102',
      '0x0405',
      {
        ciphertexts: [['0x03', 0]],
        commitments: [`0x${'00'.repeat(32)}`],
        slots: [`0x${'00'.repeat(20)}`],
        parents: [0],
      },
      { runnerUrl: 'http://127.0.0.1:13151', callbackUrl: 'http://127.0.0.1:8080/callback/7/secret' },
    )

    expect(fetchMock).toHaveBeenCalledOnce()
    expect(fetchMock).toHaveBeenCalledWith(
      'http://127.0.0.1:13151/run_compute',
      expect.objectContaining({
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          e3_id: '7',
          chain_id: 31_337,
          interfold_address: '0x1111111111111111111111111111111111111111',
          encryption_scheme_id: `0x${'22'.repeat(32)}`,
          committee_public_key_hash: `0x${'33'.repeat(32)}`,
          params: '0x0102',
          committee_public_key: '0x0405',
          ciphertext_inputs: [['0x03', 0]],
          input_commitments: [`0x${'00'.repeat(32)}`],
          input_slots: [`0x${'00'.repeat(20)}`],
          input_parents: [0],
          callback_url: 'http://127.0.0.1:8080/callback/7/secret',
        }),
      }),
    )
    expect(JSON.stringify(logMock.mock.calls)).not.toContain('0x0102')
    expect(JSON.stringify(logMock.mock.calls)).not.toContain('0x03')
  })
})
