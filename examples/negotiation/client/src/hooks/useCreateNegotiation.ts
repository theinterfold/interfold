// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { useCallback, useEffect, useMemo, useState } from 'react'
import { useWalletClient } from 'wagmi'
import { type Address, parseAbi, parseEventLogs } from 'viem'
import { CommitteeSize, DEFAULT_COMPUTE_PROVIDER_PARAMS, calculateInputWindow, encodeComputeProviderParams } from '@interfold/sdk'
import { encodeNegotiationParams, negotiationProgramAbi } from '@interfold/negotiation'
import { PARAM_SET } from '@interfold/negotiation/prover'
import { TEST_TOKEN_SOURCE, chain, createSdk, publicClient, waitForWalletSync } from '@/utils/chain'
import { FAUCET_ADDRESS, getContractAddresses } from '@/utils/env-config'
import { formatError } from '@/utils/error-formatting'
import { allowanceOf, balanceOf, erc20Abi, mintTestTokens, readTokenInfo, type TokenInfo } from '@/utils/tokens'

/**
 * Seconds between the request and the start of the input window. The window must not start before
 * the request is mined, and the wallet prompts for the approval and the request take a while.
 */
const INPUT_WINDOW_START_BUFFER = 240n

export interface CreateInput {
  /** The title with the unit label already joined to it (`joinTitle`). */
  title: string
  seller: Address
  buyer: Address
  /** The levels of the price grid (2 to 16). */
  levels: number
  minPrice: bigint
  stepPrice: bigint
  /** Seconds the input window stays open, counted from its start. */
  durationSeconds: number
}

/** The faucet of the Sepolia deployment: sends fee tokens to a caller that holds too few. */
const faucetAbi = parseAbi(['function faucet() external'])

export type CreateStep = 'idle' | 'quoting' | 'funding' | 'approving-fee' | 'requesting' | 'confirming'

export const STEP_LABELS: Record<Exclude<CreateStep, 'idle'>, string> = {
  quoting: 'Quoting the E3 fee…',
  funding: 'Getting test tokens…',
  'approving-fee': 'Approving the fee token…',
  requesting: 'Requesting the negotiation…',
  confirming: 'Waiting for the request to be mined…',
}

/** The fee token that the account holds too little of. */
export interface Shortfall {
  token: TokenInfo
  needed: bigint
  balance: bigint
}

export interface UseCreateNegotiation {
  step: CreateStep
  error: string | null
  /** Set when the account cannot pay the fee; cleared by the next attempt. */
  shortfall: Shortfall | null
  /** How a user can get fee tokens on this deployment. */
  tokenSource: typeof TEST_TOKEN_SOURCE
  /** Request the negotiation. Resolves to its E3 id, or `null` if it stopped (error or missing tokens). */
  create: (input: CreateInput) => Promise<bigint | null>
  /** Get the fee tokens `shortfall` lacks, from the faucet or by minting. */
  getTestTokens: () => Promise<void>
}

/** The create flow: quote, (get test tokens,) approve the fee, request, then read the E3 id from the receipt. */
export function useCreateNegotiation(account: `0x${string}` | undefined): UseCreateNegotiation {
  const { data: walletClient } = useWalletClient({ chainId: chain.id })
  const sdk = useMemo(() => (walletClient ? createSdk(walletClient) : null), [walletClient])
  const { e3Program, feeToken: feeTokenAddress, interfold } = getContractAddresses()

  const [step, setStep] = useState<CreateStep>('idle')
  const [error, setError] = useState<string | null>(null)
  const [shortfall, setShortfall] = useState<Shortfall | null>(null)

  // The user may fund the account outside this page: drop the shortfall as soon as the balance covers it.
  const needed = shortfall?.needed ?? null
  useEffect(() => {
    if (needed === null || !account) return
    let cancelled = false
    const check = () =>
      balanceOf(feeTokenAddress, account)
        .then((balance) => {
          if (cancelled) return
          setShortfall((prev) =>
            prev === null ? null : balance >= prev.needed ? null : balance === prev.balance ? prev : { ...prev, balance },
          )
        })
        .catch((err) => console.warn('Could not read the token balance:', err))
    const timer = setInterval(() => void check(), 4000)
    return () => {
      cancelled = true
      clearInterval(timer)
    }
  }, [needed, account, feeTokenAddress])

  useEffect(() => {
    setShortfall(null)
  }, [account])

  const create = useCallback(
    async (input: CreateInput): Promise<bigint | null> => {
      if (!sdk || !walletClient || !account) return null
      setError(null)
      setShortfall(null)
      try {
        const inputWindow = await calculateInputWindow(publicClient, input.durationSeconds, INPUT_WINDOW_START_BUFFER)
        const params = {
          committeeSize: CommitteeSize.Minimum,
          inputWindow,
          e3Program,
          paramSet: PARAM_SET,
          // The mock flag makes the compute provider return 32 zero bytes; the program server computes the real result.
          computeProviderParams: encodeComputeProviderParams(DEFAULT_COMPUTE_PROVIDER_PARAMS, true),
          customParams: encodeNegotiationParams({
            seller: input.seller,
            buyer: input.buyer,
            levels: input.levels,
            minPrice: input.minPrice,
            stepPrice: input.stepPrice,
            title: input.title,
          }),
        }

        setStep('quoting')
        const quote = await sdk.getE3Quote(params)
        const [feeBalance, feeAllowance] = await Promise.all([
          balanceOf(feeTokenAddress, account),
          allowanceOf(feeTokenAddress, account, interfold),
        ])
        if (feeBalance < quote) {
          setShortfall({ token: await readTokenInfo(feeTokenAddress), needed: quote, balance: feeBalance })
          return null
        }

        if (feeAllowance < quote) {
          setStep('approving-fee')
          const approval = await publicClient.waitForTransactionReceipt({ hash: await sdk.approveFeeToken(quote) })
          if (approval.status !== 'success') throw new Error('The fee approval transaction reverted')
          await waitForWalletSync(walletClient, account, approval)
        }

        setStep('requesting')
        const hash = await sdk.requestE3({ ...params, maxFee: quote })
        setStep('confirming')
        const receipt = await publicClient.waitForTransactionReceipt({ hash })
        if (receipt.status !== 'success') throw new Error('The request transaction reverted')

        // The receipt carries the id; no need to race a subscription for the event.
        const created = parseEventLogs({ abi: negotiationProgramAbi, eventName: 'NegotiationCreated', logs: receipt.logs }).find(
          (log) => log.address.toLowerCase() === e3Program.toLowerCase() && log.args.creator.toLowerCase() === account.toLowerCase(),
        )
        if (!created) throw new Error('The request was mined, but its NegotiationCreated event is missing from the receipt')
        return created.args.e3Id
      } catch (err) {
        setError(formatError(err))
        return null
      } finally {
        setStep('idle')
      }
    },
    [sdk, walletClient, account, e3Program, feeTokenAddress, interfold],
  )

  const getTestTokens = useCallback(async () => {
    if (!walletClient || !account || !shortfall || !TEST_TOKEN_SOURCE) return
    setError(null)
    setStep('funding')
    try {
      if (TEST_TOKEN_SOURCE === 'faucet') {
        const { request } = await publicClient.simulateContract({
          address: FAUCET_ADDRESS as `0x${string}`,
          abi: faucetAbi,
          functionName: 'faucet',
          account,
        })
        const receipt = await publicClient.waitForTransactionReceipt({ hash: await walletClient.writeContract(request) })
        if (receipt.status !== 'success') throw new Error('The transaction reverted')
        await waitForWalletSync(walletClient, account, receipt)
      } else {
        await mintTestTokens(walletClient, shortfall.token.address, account, shortfall.needed - shortfall.balance)
      }
      // The faucet pays a fixed amount: check it covered the need before letting the user continue.
      const balance = await publicClient.readContract({
        address: shortfall.token.address,
        abi: erc20Abi,
        functionName: 'balanceOf',
        args: [account],
      })
      setShortfall(balance < shortfall.needed ? { ...shortfall, balance } : null)
    } catch (err) {
      setError(formatError(err))
    } finally {
      setStep('idle')
    }
  }, [walletClient, account, shortfall])

  return { step, error, shortfall, tokenSource: TEST_TOKEN_SOURCE, create, getTestTokens }
}
