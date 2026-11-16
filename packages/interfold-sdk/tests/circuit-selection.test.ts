// SPDX-License-Identifier: LGPL-3.0-only

import { readFileSync as readFixture } from 'node:fs'
import { COMMITTEES, type BfvProfile } from '@interfold/contracts/bfv'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { PublicClient, WalletClient } from 'viem'
import { assertSdkMinimumCircuits } from '../src/circuits/assert-minimum-circuits'
import { ContractClient } from '../src/contracts/contract-client'
import { CommitteeSize, ParamSet } from '../src/contracts/types'
import { DEFAULT_E3_CONFIG, bfvConfigForRequest } from '../src/utils'

const { readFileSync } = vi.hoisted(() => ({ readFileSync: vi.fn() }))
vi.mock('node:fs', async () => {
  const fs = await vi.importActual<typeof import('node:fs')>('node:fs')
  return {
    ...fs,
    readFileSync: (...args: Parameters<typeof fs.readFileSync>) =>
      args[0].toString().endsWith('.active-preset.json') ? readFileSync(...args) : fs.readFileSync(...args),
  }
})

describe('SDK circuit selection', () => {
  it('preserves public committee enum values and the minimum-committee default', () => {
    for (const [name, value] of [
      ['minimum', CommitteeSize.Minimum],
      ['micro', CommitteeSize.Micro],
      ['small', CommitteeSize.Small],
    ] as const) {
      expect(value).toBe(COMMITTEES[name].committeeSize)
    }
    expect(DEFAULT_E3_CONFIG.committeeSize).toBe(CommitteeSize.Minimum)
  })

  it('uses current configuration IDs and the current secure registry entry', () => {
    const fixture = JSON.parse(readFixture(new URL('../../../crates/bfv/params/tests/fixtures/bfv_profiles.json', import.meta.url), 'utf8'))
    for (const vector of fixture.profiles) {
      const profile = vector.profile as BfvProfile
      for (const configuration of vector.configurations) {
        const committee = COMMITTEES[configuration.committee as keyof typeof COMMITTEES].committeeSize
        if (vector.protocol === 'synchronized') {
          expect(() => bfvConfigForRequest(profile, committee)).toThrow('disabled')
        } else {
          const selected = bfvConfigForRequest(profile, committee)
          expect(selected.configId).toBe(configuration.cryptoConfigId)
          expect(selected.paramSet).toBe(profile === 'ss-secure-8192' ? ParamSet.Secure8192 : ParamSet.Insecure64)
        }
      }
    }
    expect(() => bfvConfigForRequest('unknown' as BfvProfile, CommitteeSize.Minimum)).toThrowError(
      expect.objectContaining({ code: 'UNSUPPORTED_CRYPTO_CONFIG' }),
    )
    expect(() => bfvConfigForRequest('ss-insecure-64', 255 as CommitteeSize)).toThrow('Unsupported BFV profile/committee')
  })

  beforeEach(() => {
    readFileSync.mockReset()
  })

  it('quotes and submits one profile identity and rejects disabled work before RPC', async () => {
    const fixture = JSON.parse(readFixture(new URL('../../../crates/bfv/params/tests/fixtures/bfv_profiles.json', import.meta.url), 'utf8'))
    const secure = fixture.profiles.find((profile: { profile: string }) => profile.profile === 'ss-secure-8192')
    const expected = secure.configurations.find(
      (configuration: { committee: string }) => configuration.committee === 'micro',
    ).cryptoConfigId
    const readContract = vi.fn().mockResolvedValue(7n)
    const simulation = { address: `0x${'11'.repeat(20)}` }
    const simulateContract = vi.fn().mockResolvedValue({ request: simulation })
    const writeContract = vi.fn().mockResolvedValue(`0x${'ab'.repeat(32)}`)
    const client = new ContractClient({
      publicClient: { readContract, simulateContract } as unknown as PublicClient,
      walletClient: { account: { address: `0x${'44'.repeat(20)}` }, writeContract } as unknown as WalletClient,
      contracts: { interfold: `0x${'11'.repeat(20)}`, ciphernodeRegistry: `0x${'22'.repeat(20)}`, feeToken: `0x${'33'.repeat(20)}` },
    })
    const request = {
      profile: 'ss-secure-8192' as const,
      committeeSize: CommitteeSize.Micro,
      inputWindow: [10n, 20n] as const,
      e3Program: `0x${'55'.repeat(20)}` as const,
      computeProviderParams: '0x' as const,
    }
    await client.requestE3(request)
    expect(readContract.mock.calls[0][0].args[0]).toMatchObject({
      paramSet: ParamSet.Secure8192,
      committeeSize: CommitteeSize.Micro,
      expectedCryptoConfigId: expected,
    })
    expect(simulateContract.mock.calls[0][0].args[0]).toMatchObject({
      paramSet: ParamSet.Secure8192,
      committeeSize: CommitteeSize.Micro,
      expectedCryptoConfigId: expected,
      maxFee: 7n,
    })
    expect(writeContract).toHaveBeenCalledWith(simulation)

    readContract.mockClear()
    simulateContract.mockClear()
    writeContract.mockClear()
    const disabled = { ...request, profile: 'sync-insecure-64' as const, committeeSize: CommitteeSize.Minimum }
    await expect(client.getE3Quote(disabled)).rejects.toThrow('disabled')
    await expect(client.requestE3(disabled)).rejects.toThrow('disabled')
    expect(readContract).not.toHaveBeenCalled()
    expect(simulateContract).not.toHaveBeenCalled()
    expect(writeContract).not.toHaveBeenCalled()
  })

  it('accepts the supported preset and committee', async () => {
    readFileSync.mockReturnValue(JSON.stringify({ preset: 'insecure-64', committee: 'minimum' }))
    await expect(assertSdkMinimumCircuits()).resolves.toBeUndefined()
  })

  it('rejects missing artifacts through the awaited request', async () => {
    readFileSync.mockImplementation(() => {
      throw new Error('ENOENT')
    })
    await expect(assertSdkMinimumCircuits()).rejects.toMatchObject({ code: 'SDK_CIRCUIT_STAMP_MISSING' })
  })

  it.each(['{', 'null', '[]', '"invalid"'])('rejects invalid stamp %s', async (stamp) => {
    readFileSync.mockReturnValue(stamp)
    await expect(assertSdkMinimumCircuits()).rejects.toMatchObject({ code: 'SDK_CIRCUIT_STAMP_INVALID' })
  })

  it.each(['micro', 'small', undefined])('rejects committee %s', async (committee) => {
    readFileSync.mockReturnValue(JSON.stringify({ preset: 'insecure-64', committee }))
    await expect(assertSdkMinimumCircuits()).rejects.toMatchObject({ code: 'SDK_CIRCUIT_COMMITTEE_MISMATCH' })
  })

  it('rechecks the selection after another build changes the stamp', async () => {
    readFileSync.mockReturnValueOnce(JSON.stringify({ preset: 'insecure-64', committee: 'minimum' }))
    readFileSync.mockReturnValueOnce(JSON.stringify({ preset: 'secure-8192', committee: 'minimum' }))
    await assertSdkMinimumCircuits()
    await expect(assertSdkMinimumCircuits()).rejects.toMatchObject({ code: 'SDK_CIRCUIT_PRESET_MISMATCH' })
  })
})
