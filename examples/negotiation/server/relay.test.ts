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
  parseAbi,
  type PublicClient,
  type WalletClient,
} from 'viem'
import { parseRelayRequest, relayOffer, RelayRequestError, RelayRevertError, revertReason } from './relay'

const program = '0x4444444444444444444444444444444444444444'
const stranger = '0x5555555555555555555555555555555555555555'
const hash = `0x${'ab'.repeat(32)}` as const
const abi = parseAbi(['error NotAParty(address party)'])

/** The error that viem throws when `publishInput` reverts with the custom error `NotAParty(stranger)`. */
function notAParty(): ContractFunctionExecutionError {
  const data = encodeErrorResult({ abi, errorName: 'NotAParty', args: [stranger] })
  return new ContractFunctionExecutionError(new ContractFunctionRevertedError({ abi, data, functionName: 'publishInput' }), {
    abi,
    functionName: 'publishInput',
    args: [3n, '0x0102'],
  })
}

describe('parseRelayRequest', () => {
  it('reads a decimal e3Id and the hex data', () => {
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
    ]) {
      expect(() => parseRelayRequest(body)).toThrow(RelayRequestError)
    }
  })
})

describe('revertReason', () => {
  it('names the custom error and its arguments', () => {
    expect(revertReason(notAParty())).toBe(`NotAParty(${stranger})`)
  })

  it('falls back to the message of any other error', () => {
    expect(revertReason(new Error('network down'))).toBe('network down')
  })
})

describe('relayOffer', () => {
  const account = { address: '0x6666666666666666666666666666666666666666' }

  it('simulates, sends from the relayer and returns the hash of the mined transaction', async () => {
    const request = { address: program, functionName: 'publishInput' }
    const publicClient = {
      simulateContract: vi.fn().mockResolvedValue({ request }),
      waitForTransactionReceipt: vi.fn().mockResolvedValue({ status: 'success' }),
    }
    const walletClient = { account, writeContract: vi.fn().mockResolvedValue(hash) }

    const sent = await relayOffer(publicClient as unknown as PublicClient, walletClient as unknown as WalletClient, program, 3n, '0x0102')

    expect(sent).toBe(hash)
    expect(publicClient.simulateContract).toHaveBeenCalledWith(
      expect.objectContaining({ address: program, functionName: 'publishInput', args: [3n, '0x0102'], account }),
    )
    expect(walletClient.writeContract).toHaveBeenCalledWith(request)
    expect(publicClient.waitForTransactionReceipt).toHaveBeenCalledWith({ hash })
  })

  it('returns the revert reason of the simulation and sends nothing', async () => {
    const publicClient = { simulateContract: vi.fn().mockRejectedValue(notAParty()), waitForTransactionReceipt: vi.fn() }
    const walletClient = { account, writeContract: vi.fn() }

    await expect(
      relayOffer(publicClient as unknown as PublicClient, walletClient as unknown as WalletClient, program, 3n, '0x0102'),
    ).rejects.toThrow(new RelayRevertError(`NotAParty(${stranger})`))
    expect(walletClient.writeContract).not.toHaveBeenCalled()
  })

  it('reports a transaction that reverted after the simulation passed', async () => {
    const publicClient = {
      simulateContract: vi.fn().mockResolvedValue({ request: {} }),
      waitForTransactionReceipt: vi.fn().mockResolvedValue({ status: 'reverted' }),
    }
    const walletClient = { account, writeContract: vi.fn().mockResolvedValue(hash) }

    await expect(
      relayOffer(publicClient as unknown as PublicClient, walletClient as unknown as WalletClient, program, 3n, '0x0102'),
    ).rejects.toThrow(`the transaction ${hash} reverted`)
  })
})
