// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { useCallback, useEffect, useMemo, useState } from 'react'
import { useWalletClient } from 'wagmi'
import { type Address, parseAbi, parseEventLogs } from 'viem'
import {
  CommitteeSize,
  DEFAULT_COMPUTE_PROVIDER_PARAMS,
  type E3RequestParams,
  type InterfoldSDK,
  calculateInputWindow,
  encodeComputeProviderParams,
} from '@interfold/sdk'
import { type PriceList, type TierList, encodeLinkParams, encodeSaleParams } from '@interfold/token-launch'
import { PARAM_SET } from '@interfold/token-launch/prover'
import { TokenLaunchProgram__factory } from '@contract-types/factories/contracts/TokenLaunchProgram__factory'
import { CAN_MINT_TEST_TOKENS, TEST_TOKEN_SOURCE, chain, createSdk, publicClient } from '@/utils/chain'
import { FAUCET_ADDRESS, getContractAddresses } from '@/utils/env-config'
import { formatError } from '@/utils/error-formatting'
import { allowanceOf, approveToken, balanceOf, erc20Abi, mintTestTokens, readTokenInfo, type TokenInfo } from '@/utils/tokens'

/**
 * Seconds between the first request and the start of the input window. The window must not start before
 * the second request is mined, and the wallet prompts for the approvals and for two requests take a while.
 */
const INPUT_WINDOW_START_BUFFER = 420n

export interface CreateInput {
  title: string
  prices: PriceList
  saleToken: Address
  /** Sale-token base units on offer. */
  supply: bigint
  paymentToken: Address
  /** Payment-token base units in one budget unit. */
  budgetUnit: bigint
  /** The escrow tiers in budget units. */
  tiers: TierList
  /** Seconds the input window stays open, counted from its start. */
  durationSeconds: number
}

/** The faucet of the Sepolia deployment: sends fee tokens to a caller that holds too few. */
const faucetAbi = parseAbi(['function faucet() external'])

export type CreateStep =
  | 'idle'
  | 'quoting'
  | 'funding'
  | 'approving-fee'
  | 'approving-sale'
  | 'requesting-1'
  | 'confirming-1'
  | 'requesting-2'
  | 'confirming-2'

export const STEP_LABELS: Record<Exclude<CreateStep, 'idle'>, string> = {
  quoting: 'Quoting the two E3 fees…',
  funding: 'Getting test tokens…',
  'approving-fee': 'Approving the fee token…',
  'approving-sale': 'Approving the sale token for the supply…',
  'requesting-1': 'Request 1 of 2: round 1 (confirm in your wallet)…',
  'confirming-1': 'Waiting for request 1 to be mined…',
  'requesting-2': 'Request 2 of 2: round 2 (confirm in your wallet)…',
  'confirming-2': 'Waiting for request 2 to be mined…',
}

/** The parameters that the two requests of a sale share. Round 2 must match round 1 in window and committee size. */
function requestParams(
  inputWindow: readonly [bigint, bigint],
  committeeSize: number,
  e3Program: `0x${string}`,
  customParams: `0x${string}`,
): E3RequestParams {
  return {
    committeeSize,
    inputWindow,
    e3Program,
    paramSet: PARAM_SET,
    // The mock flag makes the compute provider return 32 zero bytes; the program server computes the real result.
    computeProviderParams: encodeComputeProviderParams(DEFAULT_COMPUTE_PROVIDER_PARAMS, true),
    customParams,
  }
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
  /** Set when the account cannot pay the fees or deposit the supply; cleared by the next attempt. */
  shortfall: Shortfall | null
  /** How a user can get the missing tokens on this deployment. */
  tokenSource: typeof TEST_TOKEN_SOURCE
  /** Request the sale (two requests). Resolves to its id, or `null` if it stopped (error or missing tokens). */
  create: (input: CreateInput) => Promise<bigint | null>
  /** Request round 2 for a sale that has none, with the window and the committee size of round 1. Resolves to `true` when it is linked. */
  linkRoundTwo: (saleId: bigint) => Promise<boolean>
  /** Get the tokens `shortfall` lacks, from the faucet or by minting. */
  getTestTokens: () => Promise<void>
}

/** The id of the sale that a receipt creates: the `SaleCreated` event of the program. */
function readSaleId(logs: Parameters<typeof parseEventLogs>[0]['logs'], e3Program: `0x${string}`, creator: Address): bigint {
  const created = parseEventLogs({ abi: TokenLaunchProgram__factory.abi, eventName: 'SaleCreated', logs }).find(
    (log) => log.address.toLowerCase() === e3Program.toLowerCase() && log.args.creator.toLowerCase() === creator.toLowerCase(),
  )
  if (!created) throw new Error('Request 1 was mined, but its SaleCreated event is missing from the receipt')
  return created.args.saleId
}

/** Send a request and wait for it. */
async function sendRequest(sdk: InterfoldSDK, params: E3RequestParams, maxFee: bigint, onSent: () => void) {
  const hash = await sdk.requestE3({ ...params, maxFee })
  onSent()
  const receipt = await publicClient.waitForTransactionReceipt({ hash })
  if (receipt.status !== 'success') throw new Error('The request transaction reverted')
  return receipt
}

/**
 * The create flow: quote both fees, (get test tokens,) approve the fee and the supply, request round 1,
 * read the sale id from the receipt, then request round 2 with that id.
 */
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
      let saleId: bigint | null = null
      try {
        const inputWindow = await calculateInputWindow(publicClient, input.durationSeconds, INPUT_WINDOW_START_BUFFER)
        const committeeSize = CommitteeSize.Minimum
        const round1 = requestParams(
          inputWindow,
          committeeSize,
          e3Program,
          encodeSaleParams({
            prices: input.prices,
            saleToken: input.saleToken,
            supply: input.supply,
            paymentToken: input.paymentToken,
            budgetUnit: input.budgetUnit,
            tiers: input.tiers,
            title: input.title,
          }),
        )
        // The quote of round 2 does not depend on the sale id: quote it with a placeholder id.
        const round2Quote = requestParams(inputWindow, committeeSize, e3Program, encodeLinkParams(0n))

        setStep('quoting')
        const [quote1, quote2] = await Promise.all([sdk.getE3Quote(round1), sdk.getE3Quote(round2Quote)])
        const totalFee = quote1 + quote2
        const [feeBalance, feeAllowance, saleBalance, saleAllowance] = await Promise.all([
          balanceOf(feeTokenAddress, account),
          allowanceOf(feeTokenAddress, account, interfold),
          balanceOf(input.saleToken, account),
          allowanceOf(input.saleToken, account, e3Program),
        ])
        if (feeBalance < totalFee) {
          setShortfall({ kind: 'fee', token: await readTokenInfo(feeTokenAddress), needed: totalFee, balance: feeBalance })
          return null
        }
        if (saleBalance < input.supply) {
          setShortfall({ kind: 'sale', token: await readTokenInfo(input.saleToken), needed: input.supply, balance: saleBalance })
          return null
        }

        if (feeAllowance < totalFee) {
          setStep('approving-fee')
          await publicClient.waitForTransactionReceipt({ hash: await sdk.approveFeeToken(totalFee) })
        }
        // The program pulls the supply from the creator when round 1 validates, so it needs the allowance first.
        if (saleAllowance < input.supply) {
          setStep('approving-sale')
          await approveToken(walletClient, input.saleToken, account, e3Program, input.supply)
        }

        setStep('requesting-1')
        const receipt1 = await sendRequest(sdk, round1, quote1, () => setStep('confirming-1'))
        saleId = readSaleId(receipt1.logs, e3Program, account)

        // Round 2 names the sale. Same window and committee size, or the program rejects it.
        setStep('requesting-2')
        const round2 = requestParams(inputWindow, committeeSize, e3Program, encodeLinkParams(saleId))
        await sendRequest(sdk, round2, quote2, () => setStep('confirming-2'))
        return saleId
      } catch (err) {
        setError(
          saleId === null
            ? formatError(err)
            : `Request 2 failed: ${formatError(err)}. Round 1 of sale Nº ${saleId} exists. Open the sale to request round 2 again before the bidding window starts.`,
        )
        return null
      } finally {
        setStep('idle')
      }
    },
    [sdk, walletClient, account, e3Program, feeTokenAddress, interfold],
  )

  const linkRoundTwo = useCallback(
    async (saleId: bigint): Promise<boolean> => {
      if (!sdk || !walletClient || !account) return false
      setError(null)
      try {
        // Round 2 copies the window and the committee size of round 1.
        const { inputWindow, committeeSize } = await sdk.getE3(saleId)
        const round2 = requestParams(inputWindow, committeeSize, e3Program, encodeLinkParams(saleId))
        setStep('quoting')
        const quote = await sdk.getE3Quote(round2)
        if ((await balanceOf(feeTokenAddress, account)) < quote) {
          setShortfall({
            kind: 'fee',
            token: await readTokenInfo(feeTokenAddress),
            needed: quote,
            balance: await balanceOf(feeTokenAddress, account),
          })
          return false
        }
        if ((await allowanceOf(feeTokenAddress, account, interfold)) < quote) {
          setStep('approving-fee')
          await publicClient.waitForTransactionReceipt({ hash: await sdk.approveFeeToken(quote) })
        }
        setStep('requesting-2')
        await sendRequest(sdk, round2, quote, () => setStep('confirming-2'))
        return true
      } catch (err) {
        setError(formatError(err))
        return false
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

  return { step, error, shortfall, tokenSource, create, linkRoundTwo, getTestTokens }
}
