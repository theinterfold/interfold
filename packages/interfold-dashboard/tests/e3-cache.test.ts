// SPDX-License-Identifier: LGPL-3.0-only
import { beforeEach, expect, it, vi } from 'vitest'

const mocks = vi.hoisted(() => ({
  getBlock: vi.fn(),
  getLogs: vi.fn(),
  multicall: vi.fn(),
  readContract: vi.fn(),
}))
vi.mock('../src/lib/chain', () => ({
  CONTRACTS: { Interfold: '0x1', CiphernodeRegistry: '0x2', CRISPProgram: '0x3' },
  DEPLOY_BLOCK: 1n,
  E3Stage: { None: 0, Requested: 1, CommitteeFinalized: 2, KeyPublished: 3, CiphertextReady: 4, Complete: 5, Failed: 6 },
  TIMEOUTS: { computeWindow: 10, decryptionWindow: 10 },
  interfoldAbi: ['E3Requested', 'PlaintextOutputPublished', 'RewardsDistributed', 'E3StageChanged'].map((name) => ({
    type: 'event',
    name,
  })),
  ciphernodeRegistryAbi: ['CommitteeRequested', 'SortitionCommitteeFinalized'].map((name) => ({ type: 'event', name })),
  publicClient: { ...mocks, chain: { id: 1 } },
}))
const round = (id: bigint) => ({
  blockNumber: id,
  blockHash: `hash:${id}`,
  transactionHash: `tx:${id}`,
  logIndex: 0,
  args: {
    e3Id: id,
    e3: {
      e3Program: '0x3',
      requester: '0x4',
      requestBlock: 1n,
      inputWindow: [1n, 2n],
      committeeSize: 1,
      seed: 1n,
      encryptionSchemeId: '0x',
      committeePublicKey: '0x',
      ciphertextOutput: '0x',
      plaintextOutput: '0x1234',
    },
  },
})

beforeEach(() => {
  vi.resetModules()
  vi.resetAllMocks()
  mocks.getBlock.mockImplementation(async ({ blockNumber }) => ({ hash: `hash:${blockNumber}`, timestamp: blockNumber }))
  mocks.getLogs.mockImplementation(async ({ event, fromBlock, toBlock }) =>
    event.name === 'E3Requested' ? [round(1n), round(2n)].filter((log) => log.blockNumber >= fromBlock && log.blockNumber <= toBlock) : [],
  )
  mocks.multicall.mockImplementation(async ({ contracts }) =>
    contracts.map(({ args }: any) => ({ status: 'success', result: args[0] === 1n ? 5 : 3 })),
  )
})

it('polls only nonterminal stages and fetches only the new event range', async () => {
  const { fetchE3List } = await import('../src/lib/e3')
  expect((await fetchE3List({ crispOnly: true, toBlock: 10n })).map((row) => row.stage)).toEqual([5, 3])
  await fetchE3List({ crispOnly: true, toBlock: 10n })
  expect(mocks.getLogs).toHaveBeenCalledTimes(2)
  expect(mocks.multicall.mock.calls[1][0].contracts.map((contract: any) => contract.args[0])).toEqual([2n])
  expect(mocks.multicall.mock.calls[1][0].blockNumber).toBe(10n)
  await fetchE3List({ crispOnly: true, toBlock: 12n })
  expect(mocks.getLogs.mock.calls.slice(2).every(([args]) => args.fromBlock === 11n && args.toBlock === 12n)).toBe(true)
})

it('re-reads terminal stages after a reorg', async () => {
  const { fetchE3List } = await import('../src/lib/e3')
  await fetchE3List({ toBlock: 10n })
  mocks.getBlock.mockImplementation(async ({ blockNumber }) => ({ hash: `replacement:${blockNumber}`, timestamp: blockNumber }))
  mocks.multicall.mockImplementation(async ({ contracts }) => contracts.map(() => ({ status: 'success', result: 1 })))
  expect((await fetchE3List({ toBlock: 12n })).map((row) => row.stage)).toEqual([1, 1])
  expect(mocks.multicall.mock.calls[1][0].contracts).toHaveLength(2)
  expect(mocks.getLogs.mock.calls[1][0].fromBlock).toBe(1n)
})

it('reuses completed result data and request history but refreshes the refundable balance', async () => {
  mocks.readContract.mockImplementation(async ({ functionName }) => {
    if (functionName === 'getE3') return round(1n).args.e3
    if (functionName === 'getE3Stage') return 5
    if (functionName === 'e3Payments') return 0n
    if (functionName === 'getRoundData') return [0n, '0x', 2n]
    throw new Error('Unexpected contract read')
  })
  const { fetchE3Details, fetchE3List } = await import('../src/lib/e3')
  await fetchE3List({ toBlock: 10n })
  const first = await fetchE3Details(1n, 10n)
  const logCalls = mocks.getLogs.mock.calls.length
  const readCalls = mocks.readContract.mock.calls.length
  const second = await fetchE3Details(1n, 10n)
  expect(second).toEqual(first)
  expect(second.plaintextOutput).toBe('0x1234')
  expect(mocks.getLogs).toHaveBeenCalledTimes(logCalls)
  expect(mocks.readContract.mock.calls.slice(readCalls).map(([args]) => args.functionName)).toEqual(['e3Payments'])
  expect(mocks.readContract.mock.calls.every(([args]) => args.blockNumber === 10n)).toBe(true)
})
