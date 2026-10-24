// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { useCallback, useEffect, useRef, useState } from 'react'
import { useWalletClient } from 'wagmi'
import { type Address, parseSignature } from 'viem'
import { SealedCcaProgram__factory } from '@contract-types/factories/contracts/SealedCcaProgram__factory'
import { chain, publicClient } from '@/utils/chain'
import { getContractAddresses } from '@/utils/env-config'
import { formatError } from '@/utils/error-formatting'
import { relayDeposit } from '@/utils/relayer'
import { allowanceOf, approveToken, balanceOf, erc20Abi } from '@/utils/tokens'

const POLL_MS = 5_000
/** Seconds a permit signature stays valid, counted from the latest block. */
const PERMIT_VALID_SECONDS = 3600n

/** What the chain says of the escrow of `account`: not deposited, or deposited with the bidder index it was given. */
export type DepositState = { deposited: false } | { deposited: true; index: number }

export interface UseDeposit {
  /** `null` before the first read. */
  state: DepositState | null
  /** The payment-token balance of the account, `null` before the first read. */
  balance: bigint | null
  /** The step the deposit runs, or `null` when idle. */
  step: 'approving' | 'signing' | 'sending' | 'confirming' | null
  error: string | null
  /** Lock the escrow. `relayed` signs an EIP-2612 permit and lets the server send the deposit. */
  deposit: (relayed: boolean) => Promise<void>
  refresh: () => void
}

interface Params {
  e3Id: bigint
  paymentToken: Address
  escrow: bigint
  account: Address | undefined
}

/** The escrow step of a bid: one `deposit` (or relayed `depositFor` with a permit) locks the escrow and gives the bidder its index. */
export function useDeposit({ e3Id, paymentToken, escrow, account }: Params): UseDeposit {
  const { data: walletClient } = useWalletClient({ chainId: chain.id })
  const { e3Program } = getContractAddresses()
  const [state, setState] = useState<DepositState | null>(null)
  const [balance, setBalance] = useState<bigint | null>(null)
  const [step, setStep] = useState<UseDeposit['step']>(null)
  const [error, setError] = useState<string | null>(null)
  const target = useRef({ e3Id, account })

  const refresh = useCallback(() => {
    const { e3Id: id, account: bidder } = target.current
    if (!bidder) return
    const read = { address: e3Program, abi: SealedCcaProgram__factory.abi } as const
    Promise.all([
      publicClient.readContract({ ...read, functionName: 'deposited', args: [id, bidder] }),
      publicClient.readContract({ ...read, functionName: 'bidderIndex', args: [id, bidder] }),
      balanceOf(paymentToken, bidder),
    ])
      .then(([deposited, index, held]) => {
        if (target.current.e3Id !== id || target.current.account !== bidder) return
        setState(deposited ? { deposited: true, index: Number(index) } : { deposited: false })
        setBalance(held)
      })
      .catch((err) => console.warn('Could not read the deposit:', err))
  }, [e3Program, paymentToken])

  useEffect(() => {
    target.current = { e3Id, account }
    setState(null)
    setBalance(null)
    setError(null)
    if (!account) return
    refresh()
    const timer = setInterval(refresh, POLL_MS)
    return () => clearInterval(timer)
  }, [e3Id, account, refresh])

  const deposit = useCallback(
    async (relayed: boolean) => {
      if (!account || !walletClient || step !== null) return
      setError(null)
      try {
        const held = await balanceOf(paymentToken, account)
        if (held < escrow) throw new Error('This account holds less than the escrow. Get payment tokens first.')
        const read = { address: e3Program, abi: SealedCcaProgram__factory.abi } as const

        let hash: `0x${string}`
        if (relayed) {
          // A permit lets the relayer pull the escrow with no approval transaction of the bidder.
          setStep('signing')
          const token = { address: paymentToken, abi: erc20Abi } as const
          const [name, nonce, block] = await Promise.all([
            publicClient.readContract({ ...token, functionName: 'name' }),
            publicClient.readContract({ ...token, functionName: 'nonces', args: [account] }),
            publicClient.getBlock(),
          ])
          const deadline = block.timestamp + PERMIT_VALID_SECONDS
          const signature = await walletClient.signTypedData({
            account,
            domain: { name, version: '1', chainId: chain.id, verifyingContract: paymentToken },
            types: {
              Permit: [
                { name: 'owner', type: 'address' },
                { name: 'spender', type: 'address' },
                { name: 'value', type: 'uint256' },
                { name: 'nonce', type: 'uint256' },
                { name: 'deadline', type: 'uint256' },
              ],
            },
            primaryType: 'Permit',
            message: { owner: account, spender: e3Program, value: escrow, nonce, deadline },
          })
          const { r, s, v, yParity } = parseSignature(signature)
          setStep('sending')
          hash = await relayDeposit(e3Id, account, { deadline, v: Number(v ?? BigInt(27 + (yParity ?? 0))), r, s })
        } else {
          if ((await allowanceOf(paymentToken, account, e3Program)) < escrow) {
            setStep('approving')
            await approveToken(walletClient, paymentToken, account, e3Program, escrow)
          }
          setStep('sending')
          const { request } = await publicClient.simulateContract({ ...read, functionName: 'deposit', args: [e3Id, '0x'], account })
          hash = await walletClient.writeContract(request)
        }

        setStep('confirming')
        const receipt = await publicClient.waitForTransactionReceipt({ hash })
        if (receipt.status !== 'success') throw new Error('The deposit transaction reverted')
      } catch (err) {
        setError(formatError(err))
      } finally {
        setStep(null)
        refresh()
      }
    },
    [account, walletClient, step, paymentToken, escrow, e3Program, e3Id, refresh],
  )

  return { state, balance, step, error, deposit, refresh }
}
