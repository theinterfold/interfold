// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import React, { useCallback, useEffect, useRef, useState } from 'react'
import { useWalletClient } from 'wagmi'
import { SealedCcaProgram__factory } from '@contract-types/factories/contracts/SealedCcaProgram__factory'
import { useChainTime } from '@/hooks/useChainTime'
import { chain, publicClient } from '@/utils/chain'
import { getContractAddresses } from '@/utils/env-config'
import { formatError } from '@/utils/error-formatting'
import { scanLogs } from '@/utils/logs'
import { type SaleState, formatDateTime, formatDuration, formatPayment, formatSaleTokens } from '@/utils/sale'
import { TxLink } from './Explorer'
import Spinner from './Spinner'

const POLL_MS = 6_000

type Kind = 'proceeds' | 'unsold' | 'sweep'

/** What the creator can withdraw now, and the two withdraw buttons. */
const CreatorPanel: React.FC<{ sale: SaleState }> = ({ sale }) => {
  const { data: walletClient } = useWalletClient({ chainId: chain.id })
  const { e3Program } = getContractAddresses()
  const now = useChainTime()
  const [available, setAvailable] = useState<{ proceeds: bigint; unsold: bigint } | null>(null)
  const [claimDeadline, setClaimDeadline] = useState<bigint | null>(null)
  /** What the sweep sent, once it happened; the `swept` view tells, the `Swept` event has the amounts. */
  const [swept, setSwept] = useState<{ saleTokens: bigint; paymentTokens: bigint } | null>(null)
  const sweptRead = useRef(false)
  const [busy, setBusy] = useState<Kind | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [last, setLast] = useState<{ kind: Kind; hash: `0x${string}` } | null>(null)

  const refresh = useCallback(() => {
    const read = { address: e3Program, abi: SealedCcaProgram__factory.abi } as const
    Promise.all([
      publicClient.readContract({ ...read, functionName: 'proceedsAvailable', args: [sale.e3Id] }),
      publicClient.readContract({ ...read, functionName: 'unsoldAmount', args: [sale.e3Id] }),
      publicClient.readContract({ ...read, functionName: 'clearing', args: [sale.e3Id] }),
      publicClient.readContract({ ...read, functionName: 'swept', args: [sale.e3Id] }),
    ])
      .then(async ([proceeds, unsold, cleared, isSwept]) => {
        setAvailable({ proceeds, unsold })
        setClaimDeadline(cleared[0] ? cleared[7] : null)
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
        abi: SealedCcaProgram__factory.abi,
        functionName: kind === 'proceeds' ? 'withdrawProceeds' : kind === 'unsold' ? 'withdrawUnsold' : 'sweep',
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
      <p className='text-sm text-ink'>
        You created this sale. The program pays you the payments of the claims made so far, and the tokens that no bidder can claim. Tokens
        of winners who have not claimed yet stay in the program until they claim.
      </p>
      <div className='grid gap-4 sm:grid-cols-2'>
        <div className='inset space-y-3 p-4'>
          <p className='meta muted'>Proceeds to withdraw</p>
          <p className='value md'>{available ? formatPayment(sale, available.proceeds) : '…'}</p>
          <button
            onClick={() => void withdraw('proceeds')}
            disabled={busy !== null || !walletClient || !available || available.proceeds === 0n}
            className='btn sm'
          >
            {busy === 'proceeds' ? <Spinner size={12} /> : 'Withdraw proceeds'}
          </button>
        </div>
        <div className='inset space-y-3 p-4'>
          <p className='meta muted'>Unsold tokens to withdraw</p>
          <p className='value md'>{available ? formatSaleTokens(sale, available.unsold) : '…'}</p>
          <button
            onClick={() => void withdraw('unsold')}
            disabled={busy !== null || !walletClient || !available || available.unsold === 0n}
            className='btn sm'
          >
            {busy === 'unsold' ? <Spinner size={12} /> : 'Withdraw unsold tokens'}
          </button>
        </div>
      </div>
      <div className='inset space-y-3 p-4'>
        <p className='meta muted'>Unclaimed funds</p>
        {swept ? (
          <p className='text-sm'>
            Swept: {formatSaleTokens(sale, swept.saleTokens)} and {formatPayment(sale, swept.paymentTokens)} went to you.
          </p>
        ) : claimDeadline === null ? (
          <p className='text-sm text-muted'>The sale is not cleared on chain yet.</p>
        ) : now > claimDeadline ? (
          <p className='text-sm'>
            The claim window closed on {formatDateTime(claimDeadline)}. You can take every remaining token, every unclaimed escrow and the
            unwithdrawn proceeds, once.
          </p>
        ) : (
          <p className='text-sm text-muted'>
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
          {last.kind === 'proceeds'
            ? 'Proceeds withdrawn.'
            : last.kind === 'unsold'
              ? 'Unsold tokens withdrawn.'
              : 'Unclaimed funds swept.'}{' '}
          Transaction <TxLink hash={last.hash} />
        </div>
      )}
    </div>
  )
}

export default CreatorPanel
