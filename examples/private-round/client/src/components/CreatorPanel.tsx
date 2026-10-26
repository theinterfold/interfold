// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import React, { useCallback, useEffect, useRef, useState } from 'react'
import { useWalletClient } from 'wagmi'
import { Outcome } from '@interfold/private-round'
import { PrivateRoundProgram__factory } from '@contract-types/factories/contracts/PrivateRoundProgram__factory'
import { useChainTime } from '@/hooks/useChainTime'
import { chain, publicClient } from '@/utils/chain'
import { getContractAddresses } from '@/utils/env-config'
import { formatError } from '@/utils/error-formatting'
import { scanLogs } from '@/utils/logs'
import { type SaleState, formatDateTime, formatDuration, formatPayment, formatSaleTokens } from '@/utils/sale'
import { TxLink } from './Explorer'
import Spinner from './Spinner'

const POLL_MS = 6_000

type Kind = 'proceeds' | 'supply' | 'sweep'

/** What the creator can withdraw now: the proceeds, the whole supply of a round that did not sell, and the sweep. */
const CreatorPanel: React.FC<{ sale: SaleState }> = ({ sale }) => {
  const { data: walletClient } = useWalletClient({ chainId: chain.id })
  const { e3Program } = getContractAddresses()
  const now = useChainTime()
  const [available, setAvailable] = useState<{ proceeds: bigint } | null>(null)
  const [claimDeadline, setClaimDeadline] = useState<bigint | null>(null)
  /** The outcome of the cleared round, `null` before the clearing. */
  const [outcome, setOutcome] = useState<Outcome | null>(null)
  /** Whether the supply is back with the creator: `withdrawSupply`, `sweep` or `refundSupply` took it. */
  const [supplyBack, setSupplyBack] = useState(false)
  /** What the sweep sent, once it happened; the `swept` view tells, the `Swept` event has the amounts. */
  const [swept, setSwept] = useState<{ saleTokens: bigint; paymentTokens: bigint } | null>(null)
  const sweptRead = useRef(false)
  const [busy, setBusy] = useState<Kind | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [last, setLast] = useState<{ kind: Kind; hash: `0x${string}` } | null>(null)

  const refresh = useCallback(() => {
    const read = { address: e3Program, abi: PrivateRoundProgram__factory.abi } as const
    Promise.all([
      publicClient.readContract({ ...read, functionName: 'proceedsAvailable', args: [sale.e3Id] }),
      publicClient.readContract({ ...read, functionName: 'clearing', args: [sale.e3Id] }),
      publicClient.readContract({ ...read, functionName: 'swept', args: [sale.e3Id] }),
      publicClient.readContract({ ...read, functionName: 'supplyReturned', args: [sale.e3Id] }),
    ])
      .then(async ([proceeds, cleared, isSwept, returned]) => {
        setSupplyBack(returned)
        setAvailable({ proceeds })
        setClaimDeadline(cleared[0] ? cleared[7] : null)
        setOutcome(cleared[0] ? (cleared[1] as Outcome) : null)
        if (!isSwept) return setSwept(null)
        if (sweptRead.current) return
        sweptRead.current = true
        // The amounts of the sweep are in its event.
        const { logs } = await scanLogs((range) =>
          publicClient.getContractEvents({ ...read, eventName: 'Swept', args: { e3Id: sale.e3Id }, strict: true, ...range }),
        )
        const event = logs.at(-1)
        setSwept({ saleTokens: event?.args.saleTokens ?? 0n, paymentTokens: event?.args.paymentTokens ?? 0n })
      })
      .catch((err) => console.warn('Could not read the creator balances:', err))
  }, [e3Program, sale.e3Id])

  useEffect(() => {
    refresh()
    const timer = setInterval(refresh, POLL_MS)
    return () => clearInterval(timer)
  }, [refresh])

  const withdraw = async (kind: Kind) => {
    if (!walletClient) return
    setBusy(kind)
    setError(null)
    try {
      const [account] = await walletClient.getAddresses()
      const { request } = await publicClient.simulateContract({
        address: e3Program,
        abi: PrivateRoundProgram__factory.abi,
        functionName: kind === 'proceeds' ? 'withdrawProceeds' : kind === 'supply' ? 'withdrawSupply' : 'sweep',
        args: [sale.e3Id],
        account,
      })
      const hash = await walletClient.writeContract(request)
      const receipt = await publicClient.waitForTransactionReceipt({ hash })
      if (receipt.status !== 'success') throw new Error('The withdraw transaction reverted')
      setLast({ kind, hash })
    } catch (err) {
      setError(formatError(err))
    } finally {
      setBusy(null)
      refresh()
    }
  }

  return (
    <div className='space-y-5'>
      <p className='text-sm text-ink-2'>
        You created this round. The program pays you the payments of the claims made so far. If the reserve was not met, you take back the
        whole supply. After the claim window closes you sweep what is left: the lots that did not sell, the escrows that nobody claimed and
        the proceeds that you did not withdraw. Lots of bidders who have not claimed yet stay in the program until the window closes.
      </p>
      <div className='grid gap-4 sm:grid-cols-2'>
        <div className='space-y-3 border border-rule-strong bg-card p-4'>
          <p className='mono-sm muted'>Proceeds to withdraw</p>
          <p className='font-serif text-3xl'>{available ? formatPayment(sale, available.proceeds) : '…'}</p>
          <button
            onClick={() => void withdraw('proceeds')}
            disabled={busy !== null || !walletClient || !available || available.proceeds === 0n}
            className='btn sm'
          >
            {busy === 'proceeds' ? <Spinner size={12} /> : 'Withdraw proceeds'}
          </button>
        </div>
        <div className='space-y-3 border border-rule-strong bg-card p-4'>
          <p className='mono-sm muted'>Supply of a round that did not sell</p>
          <p className='font-serif text-3xl'>
            {outcome === null
              ? '…'
              : outcome === Outcome.NotMet || outcome === Outcome.Aborted
                ? supplyBack
                  ? 'Withdrawn'
                  : formatSaleTokens(sale, sale.supply)
                : 'Sells: see the sweep'}
          </p>
          <button
            onClick={() => void withdraw('supply')}
            disabled={busy !== null || !walletClient || (outcome !== Outcome.NotMet && outcome !== Outcome.Aborted) || supplyBack}
            className='btn sm'
          >
            {busy === 'supply' ? <Spinner size={12} /> : 'Withdraw supply'}
          </button>
          <p className='muted text-xs'>Only a round that did not meet its reserve returns the whole supply, once.</p>
        </div>
      </div>
      <div className='space-y-3 border border-rule-strong bg-card p-4'>
        <p className='mono-sm muted'>Unclaimed funds</p>
        {swept ? (
          <p className='text-sm'>
            Swept: {formatSaleTokens(sale, swept.saleTokens)} and {formatPayment(sale, swept.paymentTokens)} went to you.
          </p>
        ) : claimDeadline === null ? (
          <p className='text-sm text-ink-soft'>The round is not cleared on chain yet.</p>
        ) : now > claimDeadline ? (
          <p className='text-sm'>
            The claim window closed on {formatDateTime(claimDeadline)}. You can take every remaining token, every unclaimed escrow and the
            unwithdrawn proceeds, once.
          </p>
        ) : (
          <p className='text-sm text-ink-soft'>
            Bidders can claim for another {formatDuration(claimDeadline - now)} (until {formatDateTime(claimDeadline)}). After that you can
            sweep what is left.
          </p>
        )}
        <button
          onClick={() => void withdraw('sweep')}
          disabled={busy !== null || !walletClient || swept !== null || claimDeadline === null || now <= claimDeadline}
          className='btn sm'
        >
          {busy === 'sweep' ? <Spinner size={12} /> : 'Sweep unclaimed'}
        </button>
      </div>
      {error && <div className='note bad'>{error}</div>}
      {last && (
        <div className='note ok'>
          {last.kind === 'proceeds' ? 'Proceeds withdrawn.' : last.kind === 'supply' ? 'Supply withdrawn.' : 'Unclaimed funds swept.'}{' '}
          Transaction <TxLink hash={last.hash} />
        </div>
      )}
    </div>
  )
}

export default CreatorPanel
