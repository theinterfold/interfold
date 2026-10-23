// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { useCallback, useEffect, useMemo, useState } from 'react'
import { useWalletClient } from 'wagmi'
import { type Address, type Hex, parseAbi, parseEventLogs } from 'viem'
import { CommitteeSize, DEFAULT_COMPUTE_PROVIDER_PARAMS, calculateInputWindow, encodeComputeProviderParams } from '@interfold/sdk'
import { MockUSDC__factory } from '@interfold/contracts/types'
import { type AuctionType, encodeAuctionParams, type PriceList } from '@shared/layout'
import { PARAM_SET } from '@shared/prover'
import { AuctionProgram__factory } from '@contract-types/factories/contracts/AuctionProgram__factory'
import { TEST_TOKEN_SOURCE, chain, createSdk, publicClient } from '@/utils/chain'
import { FAUCET_ADDRESS, getContractAddresses } from '@/utils/env-config'
import { formatError } from '@/utils/error-formatting'

/**
 * Seconds between the request and the start of the input window. The window must not start before
 * the request is mined, and the wallet prompts for the approval and the request take a while.
 */
const INPUT_WINDOW_START_BUFFER = 180n

export interface CreateInput {
  title: string
  auctionType: AuctionType
  prices: PriceList
  /** The bidder gate contract, or the zero address when anyone may bid. */
  gate: Address
  /** What `gate.configure` takes; `0x` without a gate. */
  gateConfig: Hex
  /** Seconds the input window stays open, counted from its start. */
  durationSeconds: number
}

/** The faucet of the Sepolia deployment: sends fee tokens to a caller that holds too few. */
const faucetAbi = parseAbi(['function faucet() external'])

export type CreateStep = 'idle' | 'quoting' | 'funding' | 'approving' | 'requesting' | 'confirming'

export const STEP_LABELS: Record<Exclude<CreateStep, 'idle'>, string> = {
  quoting: 'Quoting the E3 fee…',
  funding: 'Getting test tokens…',
  approving: 'Approving the fee token…',
  requesting: 'Requesting the auction…',
  confirming: 'Waiting for the request to be mined…',
}

export interface FeeShortfall {
  needed: bigint
  balance: bigint
}

export interface UseCreateAuction {
  step: CreateStep
  error: string | null
  /** Set when the account cannot pay the fee; cleared by the next attempt. */
  shortfall: FeeShortfall | null
  /** How a user can get fee tokens on this deployment: from the faucet, by minting the mock token, or not at all. */
  tokenSource: typeof TEST_TOKEN_SOURCE
  feeToken: { symbol: string; decimals: number } | null
  /** Request the auction. Resolves to its E3 id, or `null` if it stopped (error or missing fee tokens). */
  create: (input: CreateInput) => Promise<bigint | null>
  /** Get the fee tokens `shortfall` lacks, from the faucet or by minting, per `tokenSource`. */
  getTestTokens: () => Promise<void>
}

/** The create flow: quote, (get test tokens,) approve, request, then read the E3 id from the receipt. */
export function useCreateAuction(account: `0x${string}` | undefined): UseCreateAuction {
  const { data: walletClient } = useWalletClient({ chainId: chain.id })
  const sdk = useMemo(() => (walletClient ? createSdk(walletClient) : null), [walletClient])
  const { e3Program, feeToken: feeTokenAddress, interfold } = getContractAddresses()

  const [step, setStep] = useState<CreateStep>('idle')
  const [error, setError] = useState<string | null>(null)
  const [shortfall, setShortfall] = useState<FeeShortfall | null>(null)
  const [feeToken, setFeeToken] = useState<UseCreateAuction['feeToken']>(null)

  useEffect(() => {
    let cancelled = false
    const read = { address: feeTokenAddress, abi: MockUSDC__factory.abi } as const
    Promise.all([
      publicClient.readContract({ ...read, functionName: 'symbol' }),
      publicClient.readContract({ ...read, functionName: 'decimals' }),
    ])
      .then(([symbol, decimals]) => {
        if (!cancelled) setFeeToken({ symbol, decimals })
      })
      .catch((err) => console.warn('Could not read the fee token:', err))
    return () => {
      cancelled = true
    }
  }, [feeTokenAddress])

  // The user may fund the account outside this page: drop the shortfall as soon as the balance covers the fee.
  const needed = shortfall?.needed
  useEffect(() => {
    if (needed === undefined || !account) return
    let cancelled = false
    const check = () =>
      publicClient
        .readContract({ address: feeTokenAddress, abi: MockUSDC__factory.abi, functionName: 'balanceOf', args: [account] })
        .then((balance) => {
          if (cancelled) return
          setShortfall((prev) =>
            prev === null ? null : balance >= prev.needed ? null : balance === prev.balance ? prev : { ...prev, balance },
          )
        })
        .catch((err) => console.warn('Could not read the fee token balance:', err))
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
          customParams: encodeAuctionParams(input.auctionType, input.prices, input.title, input.gate, input.gateConfig),
        }

        setStep('quoting')
        const quote = await sdk.getE3Quote(params)
        const token = { address: feeTokenAddress, abi: MockUSDC__factory.abi } as const
        const [balance, allowance] = await Promise.all([
          publicClient.readContract({ ...token, functionName: 'balanceOf', args: [account] }),
          publicClient.readContract({ ...token, functionName: 'allowance', args: [account, interfold] }),
        ])
        if (balance < quote) {
          setShortfall({ needed: quote, balance })
          return null
        }

        if (allowance < quote) {
          setStep('approving')
          await publicClient.waitForTransactionReceipt({ hash: await sdk.approveFeeToken(quote) })
        }

        setStep('requesting')
        const hash = await sdk.requestE3({ ...params, maxFee: quote })
        setStep('confirming')
        const receipt = await publicClient.waitForTransactionReceipt({ hash })
        if (receipt.status !== 'success') throw new Error('The request transaction reverted')

        // The receipt carries the id; no need to race a subscription for the event.
        const created = parseEventLogs({ abi: AuctionProgram__factory.abi, eventName: 'AuctionCreated', logs: receipt.logs }).find(
          (log) => log.address.toLowerCase() === e3Program.toLowerCase() && log.args.creator.toLowerCase() === account.toLowerCase(),
        )
        if (!created) throw new Error('The request was mined, but its AuctionCreated event is missing from the receipt')
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
      let hash: `0x${string}`
      if (TEST_TOKEN_SOURCE === 'faucet') {
        const { request } = await publicClient.simulateContract({
          address: FAUCET_ADDRESS as `0x${string}`,
          abi: faucetAbi,
          functionName: 'faucet',
          account,
        })
        hash = await walletClient.writeContract(request)
      } else {
        const { request } = await publicClient.simulateContract({
          address: feeTokenAddress,
          abi: MockUSDC__factory.abi,
          functionName: 'mint',
          args: [account, shortfall.needed - shortfall.balance],
          account,
        })
        hash = await walletClient.writeContract(request)
      }
      const receipt = await publicClient.waitForTransactionReceipt({ hash })
      if (receipt.status !== 'success') throw new Error('The transaction reverted')
      // The faucet pays a fixed amount: check it covered the fee before letting the user continue.
      const balance = await publicClient.readContract({
        address: feeTokenAddress,
        abi: MockUSDC__factory.abi,
        functionName: 'balanceOf',
        args: [account],
      })
      setShortfall(balance < shortfall.needed ? { needed: shortfall.needed, balance } : null)
    } catch (err) {
      setError(formatError(err))
    } finally {
      setStep('idle')
    }
  }, [walletClient, account, shortfall, feeTokenAddress])

  return { step, error, shortfall, tokenSource: TEST_TOKEN_SOURCE, feeToken, create, getTestTokens }
}
