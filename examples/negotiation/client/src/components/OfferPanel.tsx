// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import React, { useEffect, useState } from 'react'
import { CheckCircleIcon, CircleIcon, LockKeyIcon, WarningCircleIcon } from '@phosphor-icons/react'
import { Role, priceAt, stepFor } from '@interfold/negotiation'
import { type StepRow, useOffer } from '@/hooks/useOffer'
import type { Wallet } from '@/hooks/useWallet'
import { type NegotiationPhase, type NegotiationState, ROLE_NAMES, formatLevel, formatPrice } from '@/utils/negotiation'
import { ConnectPrompt } from './ConnectPrompt'
import { TxLink } from './Explorer'
import Spinner from './Spinner'

function formatElapsed(ms: number): string {
  const seconds = Math.floor(ms / 1000)
  return `${Math.floor(seconds / 60)}:${String(seconds % 60).padStart(2, '0')}`
}

/** Elapsed time since `startedAt`, ticking each second while `running`. */
function useElapsed(startedAt: number | undefined, running: boolean): number {
  const [now, setNow] = useState(() => Date.now())
  useEffect(() => {
    if (!running) return
    setNow(Date.now())
    const timer = setInterval(() => setNow(Date.now()), 1000)
    return () => clearInterval(timer)
  }, [running])
  return startedAt === undefined ? 0 : Math.max(now - startedAt, 0)
}

const StepIcon: React.FC<{ status: StepRow['status'] }> = ({ status }) =>
  status === 'done' ? (
    <CheckCircleIcon size={16} weight='fill' className='text-brand-green' />
  ) : status === 'active' ? (
    <Spinner size={14} />
  ) : status === 'error' ? (
    <WarningCircleIcon size={16} weight='fill' className='text-negative' />
  ) : (
    <CircleIcon size={16} />
  )

const PRICE_LABEL: Record<Role, { label: string; hint: string }> = {
  [Role.Seller]: {
    label: 'Your minimum price',
    hint: 'The lowest price you accept. The agreed price is never below it.',
  },
  [Role.Buyer]: {
    label: 'Your maximum price',
    hint: 'The highest price you accept. The agreed price is never above it.',
  },
}

interface OfferPanelProps {
  negotiation: NegotiationState
  phase: NegotiationPhase
  wallet: Wallet
  committeeKey: Uint8Array | null
  /** The role of the connected account, or `null` if it is neither the seller nor the buyer. */
  role: Role | null
  onSubmitted: () => void
}

const OfferPanel: React.FC<OfferPanelProps> = ({ negotiation, phase, wallet, committeeKey, role, onSubmitted }) => {
  const offer = useOffer({
    e3Id: negotiation.e3Id,
    levels: negotiation.levels,
    role,
    account: wallet.address,
    committeeKey,
    onSubmitted,
  })
  const [priceText, setPriceText] = useState('')
  const [relayed, setRelayed] = useState(false)
  const [revealed, setRevealed] = useState(false)
  const elapsed = useElapsed(offer.run?.startedAt, offer.submitting)

  if (!wallet.isConnected) {
    return (
      <div className='space-y-4'>
        <ConnectPrompt>Connect the wallet of the seller or the buyer to send an offer.</ConnectPrompt>
        <p className='muted text-sm'>Only the seller and the buyer of this negotiation can send an offer. Everyone else can follow it.</p>
      </div>
    )
  }
  if (role === null) {
    return (
      <div className='note'>
        This account is neither the seller nor the buyer, so it cannot send an offer. You can follow the progress and read the result.
      </div>
    )
  }

  const roleName = ROLE_NAMES[role]
  const sealed = negotiation.offered[roleName]
  const open = phase === 'offers'
  const price = /^\d+$/.test(priceText) ? BigInt(priceText) : null
  const step = price === null ? null : stepFor(price, negotiation.minPrice, negotiation.stepPrice, negotiation.levels)
  const stepError = priceText === '' ? null : step === null ? 'The price is a whole number.' : typeof step === 'object' ? step.error : null

  let blocked: string | null = null
  if (phase === 'awaiting-key') blocked = 'Offers open once the committee has published its key. Key generation takes several minutes.'
  else if (!open) blocked = 'The offer window is closed.'
  else if (committeeKey === null) blocked = 'Fetching the committee key…'

  const canSubmit = wallet.ready && blocked === null && typeof step === 'number' && !offer.submitting

  return (
    <div className='space-y-6'>
      {wallet.wrongChain && <div className='note bad'>Your wallet is on another network. Switch networks to send an offer.</div>}

      <p className='muted text-sm'>
        You are the <strong>{roleName}</strong>.
      </p>

      {sealed ? (
        <div className='inset ok p-5'>
          <p className='flex items-center gap-2 font-semibold'>
            <LockKeyIcon size={20} weight='fill' /> Your offer is sealed
          </p>
          <p className='muted mt-2 text-sm'>
            The chain holds an encrypted offer of yours. Nobody can read it, not the other party, the committee or the program.
          </p>
          {offer.stored ? (
            <div className='mt-3 space-y-1'>
              <p className='meta muted'>{PRICE_LABEL[role].label}</p>
              {revealed ? (
                <p className='value'>{formatLevel(negotiation, offer.stored.step)}</p>
              ) : (
                <p className='value tracking-widest' aria-label='hidden'>
                  ••••
                </p>
              )}
              <button type='button' onClick={() => setRevealed((prev) => !prev)} className='btn ghost sm'>
                {revealed ? 'Hide my price' : 'Show my price'}
              </button>
              <p className='muted text-xs'>Kept in this browser only. The chain and the server never see it.</p>
              {offer.stored.txHash !== '0x' && (
                <p className='muted text-xs'>
                  Transaction <TxLink hash={offer.stored.txHash} />
                </p>
              )}
            </div>
          ) : (
            <p className='muted mt-3 text-xs'>This browser does not hold your price. Only the browser that made the offer can show it.</p>
          )}
        </div>
      ) : (
        <div className='space-y-4'>
          <div>
            <label htmlFor='price' className='label'>
              {PRICE_LABEL[role].label}
              {negotiation.unit !== '' ? ` (${negotiation.unit})` : ''}
            </label>
            <input
              id='price'
              inputMode='numeric'
              value={priceText}
              onChange={(event) => setPriceText(event.target.value.trim())}
              disabled={offer.submitting}
              placeholder={negotiation.minPrice.toString()}
              className='field font-mono'
            />
            <p className={`mt-1 text-xs ${stepError ? 'text-negative' : 'text-muted'}`}>
              {stepError ??
                `${PRICE_LABEL[role].hint} Choose a price on the grid: ${formatLevel(negotiation, 0)} to ${formatLevel(negotiation, negotiation.levels - 1)}, in steps of ${formatPrice(negotiation, negotiation.stepPrice)}.`}
            </p>
          </div>

          <div className='grid grid-cols-4 gap-2' role='group' aria-label='Grid prices'>
            {Array.from({ length: negotiation.levels }, (_, level) => {
              const value = priceAt(negotiation.minPrice, negotiation.stepPrice, level)
              return (
                <button
                  key={level}
                  type='button'
                  disabled={offer.submitting}
                  onClick={() => setPriceText(value.toString())}
                  className={`opt px-2 text-center ${price === value ? 'on' : ''}`}
                >
                  {value.toLocaleString('en-US')}
                </button>
              )
            })}
          </div>

          <p className='muted text-xs'>
            Your price never leaves this browser unencrypted. Only three ciphertexts and a zero-knowledge proof are published. You can send
            one offer and cannot change it.
          </p>

          {blocked && <div className='note'>{blocked}</div>}
          {offer.error && <div className='note bad'>{offer.error}</div>}

          <label className='flex cursor-pointer items-start gap-3 text-sm'>
            <input
              type='checkbox'
              checked={relayed}
              disabled={offer.submitting}
              onChange={(event) => setRelayed(event.target.checked)}
              className='mt-1'
            />
            <span>
              <span className='block font-semibold'>Send through relayer</span>
              <span className='muted block text-xs'>
                You sign the offer in your wallet and the server sends the transaction and pays the gas. The relayer cannot change the
                offer.
              </span>
            </span>
          </label>
          <button
            onClick={() => typeof step === 'number' && void offer.submit(step, relayed)}
            disabled={!canSubmit}
            className='btn accent block'
          >
            {offer.submitting ? (
              <>
                <Spinner size={14} /> Sealing and submitting…
              </>
            ) : (
              'Seal my price'
            )}
          </button>
          <p className='muted text-xs'>Proving runs in this tab and takes several minutes. Keep the tab open.</p>
        </div>
      )}

      {offer.steps.length > 0 && (
        <div className='space-y-3'>
          <div className='flex items-center justify-between'>
            <p className='label !mb-0'>Your submission</p>
            <p className='muted font-mono text-xs'>
              {offer.run?.elapsedMs != null
                ? `done in ${formatElapsed(offer.run.elapsedMs)}`
                : offer.submitting
                  ? formatElapsed(elapsed)
                  : ''}
            </p>
          </div>
          <ol className='inset space-y-1.5 p-4 text-sm'>
            {offer.steps.map((row) => (
              <li
                key={row.id}
                className={`flex items-center gap-2 ${row.status === 'active' ? 'font-semibold' : row.status === 'pending' ? 'text-muted' : 'text-ink'}`}
              >
                <StepIcon status={row.status} />
                {row.label}
              </li>
            ))}
          </ol>
        </div>
      )}
    </div>
  )
}

export default OfferPanel
