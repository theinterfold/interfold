// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { describe, expect, it, vi } from 'vitest'
import {
  ContractFunctionExecutionError,
  ContractFunctionRevertedError,
  decodeAbiParameters,
  encodeErrorResult,
  parseAbiParameters,
  type Hex,
  type PublicClient,
  type WalletClient,
} from 'viem'
import { encodeBidInput } from '@interfold/private-round'
import { PrivateRoundProgram__factory } from '../types/factories/contracts'
import {
  parseRelayDepositRequest,
  parseRelayRequest,
  relayBid,
  relayDeposit,
  RelayRequestError,
  RelayRevertError,
  revertReason,
} from './relay'

const program = '0x4444444444444444444444444444444444444444'
const bidder = '0x5555555555555555555555555555555555555555'
const hash = `0x${'ab'.repeat(32)}` as const

/** The error that viem throws when `publishInput` reverts with the custom error `BidderNotEligible(bidder)`. */
function notEligible(): ContractFunctionExecutionError {
  const abi = PrivateRoundProgram__factory.abi
  const data = encodeErrorResult({ abi, errorName: 'BidderNotEligible', args: [bidder] })
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

  it('passes the data of a two-ciphertext bid through unchanged', () => {
    const word = (digit: string): Hex => `0x${digit.repeat(64)}`
    const data = encodeBidInput({
      bidder,
      ciphertexts: ['0x0a0b', '0x0c0d'],
      ctCommitments: [word('1'), word('2')],
      bidCommitment: word('3'),
      proof: '0x99',
      gateProof: '0x',
      signature: '0x',
    })
    const parsed = parseRelayRequest({ e3Id: '7', data })
    expect(parsed).toEqual({ e3Id: 7n, data })
    // The relayer sends this `data` as the second argument of `publishInput`: two ciphertexts, two commitments.
    const [decodedBidder, ciphertexts, commitments, bidCommitment] = decodeAbiParameters(
      parseAbiParameters('address, bytes[], bytes32[], bytes32, bytes, bytes, bytes'),
      parsed.data,
    )
    expect(decodedBidder).toBe(bidder)
    expect(ciphertexts).toEqual(['0x0a0b', '0x0c0d'])
    expect(commitments).toEqual([word('1'), word('2')])
    expect(bidCommitment).toBe(word('3'))
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
    expect(revertReason(notEligible())).toBe(`BidderNotEligible(${bidder})`)
  })

  it('falls back to the message of any other error', () => {
    expect(revertReason(new Error('network down'))).toBe('network down')
  })
})

describe('relayBid', () => {
  const account = { address: '0x6666666666666666666666666666666666666666' }

  it('simulates, sends from the relayer and returns the hash of the mined transaction', async () => {
    const request = { address: program, functionName: 'publishInput' }
    const publicClient = {
      simulateContract: vi.fn().mockResolvedValue({ request }),
      waitForTransactionReceipt: vi.fn().mockResolvedValue({ status: 'success' }),
    }
    const walletClient = { account, writeContract: vi.fn().mockResolvedValue(hash) }

    const sent = await relayBid(publicClient as unknown as PublicClient, walletClient as unknown as WalletClient, program, 3n, '0x0102')

    expect(sent).toBe(hash)
    expect(publicClient.simulateContract).toHaveBeenCalledWith(
      expect.objectContaining({ address: program, functionName: 'publishInput', args: [3n, '0x0102'], account }),
    )
    expect(walletClient.writeContract).toHaveBeenCalledWith(request)
    expect(publicClient.waitForTransactionReceipt).toHaveBeenCalledWith({ hash })
  })

  it('returns the revert reason of the simulation and sends nothing', async () => {
    const publicClient = { simulateContract: vi.fn().mockRejectedValue(notEligible()), waitForTransactionReceipt: vi.fn() }
    const walletClient = { account, writeContract: vi.fn() }

    await expect(
      relayBid(publicClient as unknown as PublicClient, walletClient as unknown as WalletClient, program, 3n, '0x0102'),
    ).rejects.toThrow(new RelayRevertError(`BidderNotEligible(${bidder})`))
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

describe('parseRelayDepositRequest', () => {
  const body = {
    e3Id: '12',
    bidder,
    gateProof: '0x01',
    deadline: '1700000000',
    v: 27,
    r: `0x${'11'.repeat(32)}`,
    s: `0x${'22'.repeat(32)}`,
  }

  it('reads the permit signature, the deadline and the gate proof', () => {
    expect(parseRelayDepositRequest(body)).toEqual({ ...body, e3Id: 12n, deadline: 1700000000n })
  })

  it('takes an empty gate proof when the body has none', () => {
    const { gateProof, ...withoutGate } = body
    expect(gateProof).toBe('0x01')
    expect(parseRelayDepositRequest(withoutGate).gateProof).toBe('0x')
  })

  it('rejects a body with a bad field', () => {
    for (const bad of [
      undefined,
      { ...body, e3Id: 12 },
      { ...body, bidder: '0x12' },
      { ...body, deadline: 5 },
      { ...body, v: '27' },
      { ...body, v: 256 },
      { ...body, r: '0x11' },
      { ...body, s: `0x${'zz'.repeat(32)}` },
      { ...body, gateProof: '0x012' },
    ]) {
      expect(() => parseRelayDepositRequest(bad)).toThrow(RelayRequestError)
    }
  })
})

describe('relayDeposit', () => {
  const account = { address: '0x6666666666666666666666666666666666666666' }
  const request = { e3Id: 3n, bidder, gateProof: '0x', deadline: 99n, v: 28, r: `0x${'11'.repeat(32)}`, s: `0x${'22'.repeat(32)}` } as const

  it('simulates depositFor and sends it from the relayer', async () => {
    const publicClient = {
      simulateContract: vi.fn().mockResolvedValue({ request: { functionName: 'depositFor' } }),
      waitForTransactionReceipt: vi.fn().mockResolvedValue({ status: 'success' }),
    }
    const walletClient = { account, writeContract: vi.fn().mockResolvedValue(hash) }

    const sent = await relayDeposit(publicClient as unknown as PublicClient, walletClient as unknown as WalletClient, program, request)

    expect(sent).toBe(hash)
    expect(publicClient.simulateContract).toHaveBeenCalledWith(
      expect.objectContaining({
        address: program,
        functionName: 'depositFor',
        args: [3n, bidder, '0x', 99n, 28, request.r, request.s],
        account,
      }),
    )
  })

  it('returns the revert reason of the simulation and sends nothing', async () => {
    const publicClient = { simulateContract: vi.fn().mockRejectedValue(new Error('permit expired')), waitForTransactionReceipt: vi.fn() }
    const walletClient = { account, writeContract: vi.fn() }

    await expect(
      relayDeposit(publicClient as unknown as PublicClient, walletClient as unknown as WalletClient, program, request),
    ).rejects.toThrow(new RelayRevertError('permit expired'))
    expect(walletClient.writeContract).not.toHaveBeenCalled()
  })
})
