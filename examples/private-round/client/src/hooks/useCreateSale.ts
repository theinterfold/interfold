// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { useCallback, useEffect, useMemo, useState } from 'react'
import { useWalletClient } from 'wagmi'
import { type Address, parseAbi, parseEventLogs, zeroAddress } from 'viem'
import { CommitteeSize, DEFAULT_COMPUTE_PROVIDER_PARAMS, calculateInputWindow, encodeComputeProviderParams } from '@interfold/sdk'
import { type PriceList, encodeSaleParams } from '@interfold/private-round'
import { PARAM_SET } from '@interfold/private-round/prover'
import { PrivateRoundProgram__factory } from '@contract-types/factories/contracts/PrivateRoundProgram__factory'
import { CAN_MINT_TEST_TOKENS, TEST_TOKEN_SOURCE, chain, createSdk, publicClient } from '@/utils/chain'
import { FAUCET_ADDRESS, getContractAddresses } from '@/utils/env-config'
import { formatError } from '@/utils/error-formatting'
import { allowanceOf, approveToken, balanceOf, erc20Abi, mintTestTokens, readTokenInfo, type TokenInfo } from '@/utils/tokens'

/**
 * Seconds between the request and the start of the input window. The window must not start before
 * the request is mined, and the wallet prompts for the approvals and the request take a while.
 */
const INPUT_WINDOW_START_BUFFER = 240n

export interface CreateInput {
  title: string
  prices: PriceList
  saleToken: Address
  /** Sale-token base units of one lot: what each bidder buys. */
  lot: bigint
  /** The lots for sale, 1 to 12. The program takes `lot * lots` from the creator. */
  lots: number
  /** The reserve step: the round needs `minLots` bidders at this step or above. */
  reserveStep: number
  /** The fewest bidders at the reserve step or above for the round to go ahead, 1 to `lots`. */
  minLots: number
  paymentToken: Address
  /** Seconds the input window stays open, counted from its start. */
  durationSeconds: number
}

/** The faucet of the Sepolia deployment: sends fee tokens to a caller that holds too few. */
const faucetAbi = parseAbi(['function faucet() external'])

export type CreateStep = 'idle' | 'quoting' | 'funding' | 'approving-fee' | 'approving-sale' | 'requesting' | 'confirming'

export const STEP_LABELS: Record<Exclude<CreateStep, 'idle'>, string> = {
  quoting: 'Quoting the E3 fee…',
  funding: 'Getting test tokens…',
  'approving-fee': 'Approving the fee token…',
  'approving-sale': 'Approving the sale token for the lots…',
  requesting: 'Requesting the round…',
  confirming: 'Waiting for the request to be mined…',
}

/** A token the account holds too little of. */
export interface Shortfall {
  kind: 'fee' | 'sale'
  token: TokenInfo
  needed: bigint
  balance: bigint
}

export interface UseCreateSale {
  step: CreateStep
  error: string | null
  /** Set when the account cannot pay the fee or deposit the supply; cleared by the next attempt. */
  shortfall: Shortfall | null
  /** How a user can get the missing tokens on this deployment. */
  tokenSource: typeof TEST_TOKEN_SOURCE
  /** Request the sale. Resolves to its E3 id, or `null` if it stopped (error or missing tokens). */
  create: (input: CreateInput) => Promise<bigint | null>
  /** Get the tokens `shortfall` lacks, from the faucet or by minting. */
  getTestTokens: () => Promise<void>
}

/** The create flow: quote, (get test tokens,) approve the fee and the supply, request, then read the E3 id from the receipt. */
export function useCreateSale(account: `0x${string}` | undefined): UseCreateSale {
  const { data: walletClient } = useWalletClient({ chainId: chain.id })
  const sdk = useMemo(() => (walletClient ? createSdk(walletClient) : null), [walletClient])
  const { e3Program, feeToken: feeTokenAddress, interfold } = getContractAddresses()

  const [step, setStep] = useState<CreateStep>('idle')
  const [error, setError] = useState<string | null>(null)
  const [shortfall, setShortfall] = useState<Shortfall | null>(null)

  // The user may fund the account outside this page: drop the shortfall as soon as the balance covers it.
  const missing = shortfall ? `${shortfall.kind}:${shortfall.needed}` : null
  useEffect(() => {
    if (missing === null || !account) return
    let cancelled = false
    const check = () =>
      balanceOf(shortfall!.token.address, account)
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
    // `shortfall` is read for its token only; `missing` identifies it.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [missing, account])

  useEffect(() => {
    setShortfall(null)
  }, [account])

  const create = useCallback(
    async (input: CreateInput): Promise<bigint | null> => {
      if (!sdk || !walletClient || !account) return null
      setError(null)
      setShortfall(null)
      try {
        const supply = input.lot * BigInt(input.lots)
        const inputWindow = await calculateInputWindow(publicClient, input.durationSeconds, INPUT_WINDOW_START_BUFFER)
        const params = {
          committeeSize: CommitteeSize.Minimum,
          inputWindow,
          e3Program,
          paramSet: PARAM_SET,
          // The mock flag makes the compute provider return 32 zero bytes; the program server computes the real result.
          computeProviderParams: encodeComputeProviderParams(DEFAULT_COMPUTE_PROVIDER_PARAMS, true),
          customParams: encodeSaleParams({
            prices: input.prices,
            saleToken: input.saleToken,
            lot: input.lot,
            lots: input.lots,
            reserveStep: input.reserveStep,
            minLots: input.minLots,
            paymentToken: input.paymentToken,
            title: input.title,
            gate: zeroAddress,
            gateConfig: '0x',
          }),
        }

        setStep('quoting')
        const quote = await sdk.getE3Quote(params)
        const [feeBalance, feeAllowance, saleBalance, saleAllowance] = await Promise.all([
          balanceOf(feeTokenAddress, account),
          allowanceOf(feeTokenAddress, account, interfold),
          balanceOf(input.saleToken, account),
          allowanceOf(input.saleToken, account, e3Program),
        ])
        if (feeBalance < quote) {
          setShortfall({ kind: 'fee', token: await readTokenInfo(feeTokenAddress), needed: quote, balance: feeBalance })
          return null
        }
        if (saleBalance < supply) {
          setShortfall({ kind: 'sale', token: await readTokenInfo(input.saleToken), needed: supply, balance: saleBalance })
          return null
        }

        if (feeAllowance < quote) {
          setStep('approving-fee')
          await publicClient.waitForTransactionReceipt({ hash: await sdk.approveFeeToken(quote) })
        }
        // The program pulls the supply from the creator when the request validates, so it needs the allowance first.
        if (saleAllowance < supply) {
          setStep('approving-sale')
          await approveToken(walletClient, input.saleToken, account, e3Program, supply)
        }

        setStep('requesting')
        const hash = await sdk.requestE3({ ...params, maxFee: quote })
        setStep('confirming')
        const receipt = await publicClient.waitForTransactionReceipt({ hash })
        if (receipt.status !== 'success') throw new Error('The request transaction reverted')

        // The receipt carries the id; no need to race a subscription for the event.
        const created = parseEventLogs({ abi: PrivateRoundProgram__factory.abi, eventName: 'SaleCreated', logs: receipt.logs }).find(
          (log) => log.address.toLowerCase() === e3Program.toLowerCase() && log.args.creator.toLowerCase() === account.toLowerCase(),
        )
        if (!created) throw new Error('The request was mined, but its SaleCreated event is missing from the receipt')
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

  // The faucet pays the fee token only; the sale token can be minted where the mocks allow it.
  const tokenSource: UseCreateSale['tokenSource'] = shortfall?.kind === 'sale' ? (CAN_MINT_TEST_TOKENS ? 'mint' : null) : TEST_TOKEN_SOURCE

  const getTestTokens = useCallback(async () => {
    if (!walletClient || !account || !shortfall || !tokenSource) return
    setError(null)
    setStep('funding')
    try {
      if (tokenSource === 'faucet') {
        const { request } = await publicClient.simulateContract({
          address: FAUCET_ADDRESS as `0x${string}`,
          abi: faucetAbi,
          functionName: 'faucet',
          account,
        })
        const receipt = await publicClient.waitForTransactionReceipt({ hash: await walletClient.writeContract(request) })
        if (receipt.status !== 'success') throw new Error('The transaction reverted')
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
  }, [walletClient, account, shortfall, tokenSource])

  return { step, error, shortfall, tokenSource, create, getTestTokens }
}
