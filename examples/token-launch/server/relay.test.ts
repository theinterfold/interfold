// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { describe, expect, it, vi } from 'vitest'
import {
  ContractFunctionExecutionError,
  ContractFunctionRevertedError,
  encodeErrorResult,
  type PublicClient,
  type WalletClient,
} from 'viem'
import { TokenLaunchProgram__factory } from '../types/factories/contracts'
import {
  parseRelayClaimRequest,
  parseRelayRequest,
  relayBid,
  relayClaim,
  RelayRequestError,
  RelayRevertError,
  revertReason,
  sendFromRelayer,
} from './relay'

const program = '0x4444444444444444444444444444444444444444'
const bidder = '0x5555555555555555555555555555555555555555'
const hash = `0x${'ab'.repeat(32)}` as const
const account = { address: '0x6666666666666666666666666666666666666666' }

/** The error that viem throws when `publishInput` reverts with the custom error `AlreadyBid(bidder)`. */
function alreadyBid(): ContractFunctionExecutionError {
  const abi = TokenLaunchProgram__factory.abi
  const data = encodeErrorResult({ abi, errorName: 'AlreadyBid', args: [bidder] })
  return new ContractFunctionExecutionError(new ContractFunctionRevertedError({ abi, data, functionName: 'publishInput' }), {
    abi,
    functionName: 'publishInput',
    args: [3n, '0x0102'],
  })
}

/** A relayer whose simulation and transaction succeed. */
function workingClients() {
  const request = { address: program, functionName: 'sent' }
  const publicClient = {
    simulateContract: vi.fn().mockResolvedValue({ request }),
    waitForTransactionReceipt: vi.fn().mockResolvedValue({ status: 'success' }),
  }
  const walletClient = { account, writeContract: vi.fn().mockResolvedValue(hash) }
  return { request, publicClient, walletClient }
}

describe('parseRelayRequest', () => {
  it('reads a decimal e3Id (the sale id) and the hex data', () => {
    expect(parseRelayRequest({ e3Id: '12', data: '0x0102' })).toEqual({ e3Id: 12n, data: '0x0102' })
  })

  it('rejects a missing body, a number for e3Id, and data that is not bytes', () => {
    for (const body of [
      undefined,
      {},
      { e3Id: 12, data: '0x01' },
      { e3Id: '-1', data: '0x01' },
      { e3Id: '1', data: '01' },
      { e3Id: '1', data: '0x' },
      { e3Id: '1', data: '0x012' },
      { saleId: '1', data: '0x01' },
    ]) {
      expect(() => parseRelayRequest(body)).toThrow(RelayRequestError)
    }
  })
})

describe('parseRelayClaimRequest', () => {
  it('reads a decimal saleId and the hex data', () => {
    expect(parseRelayClaimRequest({ saleId: '12', data: '0x0102' })).toEqual({ saleId: 12n, data: '0x0102' })
  })

  it('rejects a body with a bad field, and a bid body', () => {
    for (const body of [
      undefined,
      {},
      { saleId: 12, data: '0x01' },
      { saleId: '1.5', data: '0x01' },
      { saleId: '1', data: '0x' },
      { saleId: '1', data: 'zz' },
      { e3Id: '1', data: '0x01' },
    ]) {
      expect(() => parseRelayClaimRequest(body)).toThrow(RelayRequestError)
    }
  })
})

describe('revertReason', () => {
  it('names the custom error and its arguments', () => {
    expect(revertReason(alreadyBid())).toBe(`AlreadyBid(${bidder})`)
  })

  it('falls back to the message of any other error', () => {
    expect(revertReason(new Error('network down'))).toBe('network down')
  })
})

describe('relayBid', () => {
  it('simulates, sends from the relayer and returns the hash of the mined transaction', async () => {
    const { request, publicClient, walletClient } = workingClients()

    const sent = await relayBid(publicClient as unknown as PublicClient, walletClient as unknown as WalletClient, program, 3n, '0x0102')

    expect(sent).toBe(hash)
    expect(publicClient.simulateContract).toHaveBeenCalledWith(
      expect.objectContaining({ address: program, functionName: 'publishInput', args: [3n, '0x0102'], account }),
    )
    expect(walletClient.writeContract).toHaveBeenCalledWith(request)
    expect(publicClient.waitForTransactionReceipt).toHaveBeenCalledWith({ hash })
  })

  it('returns the revert reason of the simulation and sends nothing', async () => {
    const publicClient = { simulateContract: vi.fn().mockRejectedValue(alreadyBid()), waitForTransactionReceipt: vi.fn() }
    const walletClient = { account, writeContract: vi.fn() }

    await expect(
      relayBid(publicClient as unknown as PublicClient, walletClient as unknown as WalletClient, program, 3n, '0x0102'),
    ).rejects.toThrow(new RelayRevertError(`AlreadyBid(${bidder})`))
    expect(walletClient.writeContract).not.toHaveBeenCalled()
  })

  it('reports a transaction that reverted after the simulation passed', async () => {
    const publicClient = {
      simulateContract: vi.fn().mockResolvedValue({ request: {} }),
      waitForTransactionReceipt: vi.fn().mockResolvedValue({ status: 'reverted' }),
    }
    const walletClient = { account, writeContract: vi.fn().mockResolvedValue(hash) }

    await expect(
      relayBid(publicClient as unknown as PublicClient, walletClient as unknown as WalletClient, program, 3n, '0x0102'),
    ).rejects.toThrow(`the transaction ${hash} reverted`)
  })
})

describe('relayClaim', () => {
  it('simulates claim(saleId, data) and sends it from the relayer, so the recipient needs no gas', async () => {
    const { request, publicClient, walletClient } = workingClients()

    const sent = await relayClaim(publicClient as unknown as PublicClient, walletClient as unknown as WalletClient, program, 7n, '0xaabb')

    expect(sent).toBe(hash)
    expect(publicClient.simulateContract).toHaveBeenCalledWith(
      expect.objectContaining({ address: program, functionName: 'claim', args: [7n, '0xaabb'], account }),
    )
    expect(walletClient.writeContract).toHaveBeenCalledWith(request)
  })

  it('returns the revert reason of the simulation and sends nothing', async () => {
    const publicClient = { simulateContract: vi.fn().mockRejectedValue(new Error('NullifierUsed')), waitForTransactionReceipt: vi.fn() }
    const walletClient = { account, writeContract: vi.fn() }

    await expect(
      relayClaim(publicClient as unknown as PublicClient, walletClient as unknown as WalletClient, program, 7n, '0xaabb'),
    ).rejects.toThrow(new RelayRevertError('NullifierUsed'))
    expect(walletClient.writeContract).not.toHaveBeenCalled()
  })
})

describe('sendFromRelayer', () => {
  it('sends the keeper calls of one argument', async () => {
    const { publicClient, walletClient } = workingClients()
    for (const functionName of ['publishProbes', 'clear'] as const) {
      await sendFromRelayer(publicClient as unknown as PublicClient, walletClient as unknown as WalletClient, program, {
        functionName,
        args: [5n],
      })
      expect(publicClient.simulateContract).toHaveBeenLastCalledWith(expect.objectContaining({ functionName, args: [5n], account }))
    }
  })

  it('sends the calls of one relayer one after the other, so no two transactions take the same nonce', async () => {
    const events: string[] = []
    const publicClient = {
      simulateContract: vi.fn().mockImplementation(async ({ args }: { args: readonly bigint[] }) => {
        events.push(`simulate ${args[0]}`)
        return { request: { id: args[0] } }
      }),
      waitForTransactionReceipt: vi.fn().mockResolvedValue({ status: 'success' }),
    }
    const walletClient = {
      account,
      writeContract: vi.fn().mockImplementation(async ({ id }: { id: bigint }) => {
        events.push(`write ${id} start`)
        // Yield: without the queue, the second call would run its simulation here.
        await Promise.resolve()
        events.push(`write ${id} end`)
        return hash
      }),
    }
    const clients = [publicClient as unknown as PublicClient, walletClient as unknown as WalletClient] as const
    await Promise.all([
      sendFromRelayer(...clients, program, { functionName: 'clear', args: [1n] }),
      sendFromRelayer(...clients, program, { functionName: 'clear', args: [2n] }),
    ])
    expect(events).toEqual(['simulate 1', 'write 1 start', 'write 1 end', 'simulate 2', 'write 2 start', 'write 2 end'])
  })

  it('keeps going after a call failed', async () => {
    const failing = { simulateContract: vi.fn().mockRejectedValue(new Error('no')), waitForTransactionReceipt: vi.fn() }
    const { publicClient, walletClient } = workingClients()
    await expect(
      sendFromRelayer(failing as unknown as PublicClient, walletClient as unknown as WalletClient, program, { functionName: 'clear', args: [1n] }),
    ).rejects.toThrow(RelayRevertError)
    await expect(
      sendFromRelayer(publicClient as unknown as PublicClient, walletClient as unknown as WalletClient, program, { functionName: 'clear', args: [2n] }),
    ).resolves.toBe(hash)
  })
})
