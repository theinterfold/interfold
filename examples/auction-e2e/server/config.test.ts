// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { describe, expect, it } from 'vitest'

import { loadConfig } from './config'

const address = (digit: string) => `0x${digit.repeat(40)}`

const local = {
  RPC_URL: 'http://localhost:8545',
  PRIVATE_KEY: `0x${'ab'.repeat(32)}`,
  CHAIN_ID: '31337',
  INTERFOLD_ADDRESS: address('1'),
  REGISTRY_ADDRESS: address('2'),
  FEE_TOKEN_ADDRESS: address('3'),
  E3_PROGRAM_ADDRESS: address('4'),
}

const avail = {
  DATA_AVAILABILITY_MODE: 'avail',
  AVAIL_RPC_URL: 'https://turing-rpc.avail.so/rpc',
  AVAIL_APP_ID: '7',
  AVAIL_SEED: 'test seed',
  AVAIL_BRIDGE_API_URL: 'https://turing-bridge-api.avail.so',
}

describe('loadConfig', () => {
  it('defaults to the local mock flow', () => {
    const config = loadConfig(local)
    expect(config.chain.id).toBe(31337)
    expect(config.dataAvailability).toEqual({ mode: 'mock_http' })
    expect(config.deployBlock).toBe(0n)
    expect(config.logChunkSize).toBe(10_000n)
    expect(config.port).toBe(8080)
    expect(config.wsRpcUrl).toBeUndefined()
    expect(config.programRunnerUrl).toBe('http://127.0.0.1:13151')
    expect(loadConfig({ ...local, CALLBACK_URL: 'http://server:8080/' }).callbackUrl).toBe('http://server:8080')
  })

  it('requires the deployment block on a public chain', () => {
    const sepolia = { ...local, CHAIN_ID: '11155111' }
    expect(() => loadConfig(sepolia)).toThrow('DEPLOY_BLOCK is required')
    expect(loadConfig({ ...sepolia, DEPLOY_BLOCK: '9000000' }).deployBlock).toBe(9_000_000n)
  })

  it('rejects an unsupported chain, a bad key and a wrong URL scheme', () => {
    expect(() => loadConfig({ ...local, CHAIN_ID: '1' })).toThrow('not supported')
    expect(() => loadConfig({ ...local, PRIVATE_KEY: '0x12' })).toThrow('PRIVATE_KEY')
    expect(() => loadConfig({ ...local, RPC_URL: 'ws://localhost:8545' })).toThrow('RPC_URL must use http or https')
    expect(() => loadConfig({ ...local, WS_RPC_URL: 'http://localhost:8545' })).toThrow('WS_RPC_URL must use ws or wss')
    expect(() => loadConfig({ ...local, INTERFOLD_ADDRESS: '0x12' })).toThrow('INTERFOLD_ADDRESS')
  })

  it('reads the Avail settings and requires every one of them', () => {
    const config = loadConfig({ ...local, ...avail })
    expect(config.dataAvailability).toMatchObject({ mode: 'avail', appId: 7, proofPollIntervalMs: 60_000, helperBinary: 'auction-da' })
    for (const name of ['AVAIL_RPC_URL', 'AVAIL_APP_ID', 'AVAIL_SEED', 'AVAIL_BRIDGE_API_URL']) {
      expect(() => loadConfig({ ...local, ...avail, [name]: '' })).toThrow(name)
    }
    expect(() => loadConfig({ ...local, DATA_AVAILABILITY_MODE: 'ipfs' })).toThrow('DATA_AVAILABILITY_MODE')
  })
})
