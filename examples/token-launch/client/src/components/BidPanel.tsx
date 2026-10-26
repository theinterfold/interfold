// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import React, { useEffect, useState } from 'react'
import { CheckCircleIcon, CircleIcon, WarningCircleIcon } from '@phosphor-icons/react'
import { MAX_BIDDERS } from '@interfold/token-launch'
import { type StepRow, useBid } from '@/hooks/useBid'
import type { LoggedBid } from '@/hooks/useBidLog'
import type { UseSecrets } from '@/hooks/useSecrets'
import type { Wallet } from '@/hooks/useWallet'
import { Phase } from '@/utils/phase'
import { type SaleState, formatBudget, formatPayment, formatStepPrice } from '@/utils/sale'
import { balanceOf, formatAmount } from '@/utils/tokens'
import BackupPanel from './BackupPanel'
import { ConnectPrompt } from './ConnectPrompt'
import MintButton from './MintButton'
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
    <CheckCircleIcon size={16} weight='fill' className='text-accent' />
  ) : status === 'active' ? (
    <Spinner size={14} />
  ) : status === 'error' ? (
    <WarningCircleIcon size={16} weight='fill' className='text-danger' />
  ) : (
    <CircleIcon size={16} />
  )

/** The payment-token balance of an account, refreshed on demand. `null` before the first read. */
function useBalance(token: `0x${string}`, account: `0x${string}` | undefined): { balance: bigint | null; refresh: () => void } {
  const [balance, setBalance] = useState<bigint | null>(null)
  const [tick, setTick] = useState(0)
  useEffect(() => {
    setBalance(null)
    if (!account) return
    let cancelled = false
    balanceOf(token, account)
      .then((held) => {
        if (!cancelled) setBalance(held)
      })
      .catch((err) => console.warn('Could not read the balance:', err))
    return () => {
      cancelled = true
    }
  }, [token, account, tick])
  return { balance, refresh: () => setTick((value) => value + 1) }
}

interface BidPanelProps {
  sale: SaleState
  wallet: Wallet
  keys: { round1: Uint8Array | null; round2: Uint8Array | null }
  bids: readonly LoggedBid[] | null
  secrets: UseSecrets
  /** The chain time in unix seconds. */
  now: bigint
  onSubmitted: () => void
}

const BidPanel: React.FC<BidPanelProps> = ({ sale, wallet, keys, bids, secrets, now, onSubmitted }) => {
  const afterSubmit = () => {
    secrets.reload()
    onSubmitted()
  }
  const bid = useBid({ sale, account: wallet.address, keys, onSubmitted: afterSubmit })
  const { balance, refresh: refreshBalance } = useBalance(sale.paymentToken.address, wallet.address)
  const [tier, setTier] = useState(0)
  const [budgetText, setBudgetText] = useState('1')
  const [step, setStep] = useState(0)
  const [relayed, setRelayed] = useState(false)
  const elapsed = useElapsed(bid.run?.startedAt, bid.submitting)

  const escrowUnits = sale.tiers[tier]
  const budget = /^\d+$/.test(budgetText) ? Number(budgetText) : Number.NaN
  const budgetValid = Number.isInteger(budget) && budget >= 1 && budget <= escrowUnits
  const escrow = BigInt(escrowUnits) * sale.budgetUnit
  const short = balance !== null && balance < escrow
  const saleUnit = 10n ** BigInt(sale.saleToken.decimals)

  const mine = secrets.held.filter(({ secret }) => secret.bidder.toLowerCase() === wallet.address?.toLowerCase())
  const onChain = bids?.find((logged) => logged.bidder.toLowerCase() === wallet.address?.toLowerCase())
  const confirmed = mine.find((entry) => entry.confirmed)
  const open = sale.phase === Phase.Bidding && now >= sale.inputWindow[0] && now < sale.inputWindow[1]

  // Why a bid is not possible right now, if it is not.
  let blocked: string | null = null
  if (sale.phase !== Phase.Bidding || now >= sale.inputWindow[1]) blocked = 'Bidding is closed.'
  else if (sale.roundTwoId === null) blocked = 'The creator has not requested round 2. Bids need both rounds.'
  else if (!sale.keysReady || now < sale.inputWindow[0]) {
    blocked = 'Bidding opens when both committee keys exist and the window starts. Key generation takes several minutes.'
  } else if (sale.bidCount >= MAX_BIDDERS) blocked = `This sale is full: ${MAX_BIDDERS} bids.`
  else if (onChain) blocked = 'This account already has a bid in this sale. A sale takes one bid for each address.'
  else if (short) blocked = `This account holds less than the escrow of ${formatPayment(sale, escrow)}.`
  else if (keys.round1 === null || keys.round2 === null) blocked = 'Fetching the committee keys…'
  else if (!budgetValid) blocked = `The budget is a whole number from 1 to ${escrowUnits} budget units.`

  const canSubmit = wallet.ready && open && blocked === null && !bid.submitting

  if (!wallet.isConnected) {
    return (
      <div className='space-y-4'>
        <ConnectPrompt>Connect a wallet to bid.</ConnectPrompt>
        <p className='muted text-sm'>
          A bid locks an escrow tier. The clearing price takes what it needs and refunds the rest. Your budget and your max price stay
          private.
        </p>
        {secrets.held.length > 0 && <BackupPanel secrets={secrets} />}
      </div>
    )
  }

  return (
    <div className='space-y-8'>
      {wallet.wrongChain && <div className='note bad'>Your wallet is on another network. Switch networks to bid.</div>}

      {confirmed && (
        <div className='space-y-3 border border-accent bg-accent-soft p-4'>
          <p className='mono-sm muted'>Your bid · Nº {confirmed.secret.index}</p>
          <p className='font-serif text-4xl'>
            {formatBudget(sale, confirmed.secret.budget)} <span className='text-lg'>budget</span>
          </p>
          <p className='muted text-xs'>
            Max price {formatStepPrice(sale, confirmed.secret.step)} {sale.paymentToken.symbol} (step {confirmed.secret.step} of{' '}
            {sale.levels - 1}). Escrow tier {formatBudget(sale, confirmed.secret.escrow)}. Only this browser and your backup file hold these
            values.
          </p>
          {confirmed.secret.txHash && (
            <p className='muted text-xs'>
              Transaction <TxLink hash={confirmed.secret.txHash} />
            </p>
          )}
        </div>
      )}
      {!confirmed && onChain && (
        <div className='note warn'>
          This account has a bid in this sale, but this browser does not hold its secret. Import your backup file to claim it.
        </div>
      )}
      {mine.some((entry) => !entry.confirmed) && !confirmed && !onChain && (
        <div className='note'>
          This browser holds a secret of a bid that is not on chain. It is from a failed attempt or a transaction that is still pending.
        </div>
      )}

      {!confirmed && !onChain && (
        <div className='space-y-6'>
          <div className='space-y-3'>
            <p className='label !mb-0'>1. Escrow tier</p>
            <div className='grid grid-cols-2 gap-2 sm:grid-cols-4' role='radiogroup' aria-label='Escrow tier'>
              {sale.tiers.map((units, index) => (
                <button
                  key={units}
                  type='button'
                  role='radio'
                  aria-checked={tier === index}
                  disabled={bid.submitting}
                  onClick={() => {
                    setTier(index)
                    if (budget > units) setBudgetText(String(units))
                  }}
                  className={`border px-2 py-2.5 text-center font-mono text-sm transition-colors disabled:cursor-not-allowed ${
                    tier === index ? 'border-ink bg-ink text-paper' : 'border-rule-strong bg-card hover:border-ink'
                  }`}
                >
                  {formatBudget(sale, units)}
                </button>
              ))}
            </div>
            <p className='muted text-xs'>
              The contract locks the whole tier. Your budget is at most the tier. The clearing price refunds the rest. Your balance:{' '}
              {balance === null ? '…' : formatPayment(sale, balance)}.
            </p>
            {short && (
              <MintButton token={sale.paymentToken} account={wallet.address} amount={escrow - (balance ?? 0n)} onMinted={refreshBalance} />
            )}
          </div>

          <div className='space-y-3'>
            <label htmlFor='budget' className='label !mb-0'>
              2. Budget (budget units, 1 to {escrowUnits})
            </label>
            <div className='flex items-center gap-4'>
              <input
                type='range'
                aria-label='Budget'
                min={1}
                max={escrowUnits}
                value={budgetValid ? budget : 1}
                disabled={bid.submitting}
                onChange={(event) => setBudgetText(event.target.value)}
                className='h-2 min-w-0 flex-1 cursor-pointer accent-[var(--accent)] disabled:cursor-not-allowed'
              />
              <input
                id='budget'
                inputMode='numeric'
                value={budgetText}
                disabled={bid.submitting}
                onChange={(event) => setBudgetText(event.target.value.trim())}
                className='field w-28 font-mono'
              />
            </div>
            <p className='muted text-xs'>
              {budgetValid ? `${formatBudget(sale, budget)} is the most you spend.` : 'Enter a whole number in the range.'} You pay the
              clearing price for your tokens, never more than your budget.
            </p>
          </div>

          <div className='space-y-3'>
            <p className='label !mb-0'>3. Max price step</p>
            <div className='grid grid-cols-4 gap-2' role='radiogroup' aria-label='Max price step'>
              {Array.from({ length: sale.levels }, (_, level) => (
                <button
                  key={level}
                  type='button'
                  role='radio'
                  aria-checked={step === level}
                  disabled={bid.submitting}
                  onClick={() => setStep(level)}
                  className={`border px-2 py-2 text-center font-mono text-sm transition-colors disabled:cursor-not-allowed ${
                    step === level ? 'border-ink bg-ink text-paper' : 'border-rule-strong bg-card hover:border-ink'
                  }`}
                >
                  <span className='block text-[10px] opacity-70'>step {level}</span>
                  {formatStepPrice(sale, level)}
                </button>
              ))}
            </div>
            <p className='muted text-xs'>
              Prices are in {sale.paymentToken.symbol} for one {sale.saleToken.symbol}. You never pay a price above your max.
              {budgetValid &&
                ` At step ${step} your budget buys at most ${formatAmount((BigInt(budget) * sale.budgetUnit * saleUnit) / sale.prices[step], sale.saleToken.decimals)} ${sale.saleToken.symbol}.`}
            </p>
          </div>

          <div className='note space-y-2 text-xs'>
            <p className='font-semibold'>What leaks</p>
            <ul className='list-disc space-y-1 pl-5'>
              <li>Public: your address, your escrow tier and the time of your bid.</li>
              <li>
                Private: your budget and your max price. Only the sum of all budgets at a few price steps is revealed, so your values add
                into a total.
              </li>
              <li>
                Your claim shows your tier and whether you are below, at or above the clearing step. A winning claim shows your budget.
              </li>
              <li>Your claim goes to a fresh address. Nothing on chain links it to this bid.</li>
              <li>
                Exception: if your max price is the clearing step of a capped sale, you must register. The registration shows your bid
                index, your budget and your recipient, and links your address to the recipient.
              </li>
            </ul>
          </div>

          {blocked && <div className='note'>{blocked}</div>}
          {bid.error && <div className='note bad'>{bid.error}</div>}

          <div className='space-y-3'>
            <label className='flex cursor-pointer items-start gap-3 text-sm'>
              <input
                type='checkbox'
                checked={relayed}
                disabled={bid.submitting}
                onChange={(event) => setRelayed(event.target.checked)}
                className='mt-1'
              />
              <span>
                <span className='block font-semibold'>Send through relayer</span>
                <span className='muted block text-xs'>
                  You sign a permit for the escrow and the bid. The server sends the transaction and pays the gas. The relayer cannot change
                  the bid. The payment token must support permits.
                </span>
              </span>
            </label>
            <button onClick={() => void bid.submit({ tier, budget, step }, relayed)} disabled={!canSubmit} className='btn accent lg block'>
              {bid.submitting ? (
                <>
                  <Spinner size={14} /> Proving and submitting…
                </>
              ) : (
                'Submit bid'
              )}
            </button>
            <p className='muted text-xs'>
              One proof covers both ciphertexts. It runs in this tab. The three proofs together take about 6 minutes or more. Keep the tab
              open.
            </p>
          </div>
        </div>
      )}

      {bid.steps.length > 0 && (
        <div className='space-y-3'>
          <div className='flex items-center justify-between'>
            <p className='label !mb-0'>Your submission</p>
            <p className='muted font-mono text-xs'>
              {bid.run?.elapsedMs != null ? `done in ${formatElapsed(bid.run.elapsedMs)}` : bid.submitting ? formatElapsed(elapsed) : ''}
            </p>
          </div>
          <ol className='space-y-1.5 border border-rule-strong bg-card p-4 text-sm'>
            {bid.steps.map((row) => (
              <li
                key={row.id}
                className={`flex items-center gap-2 ${row.status === 'active' ? 'font-semibold' : row.status === 'pending' ? 'text-ink-soft' : 'text-ink-2'}`}
              >
                <StepIcon status={row.status} />
                {row.label}
              </li>
            ))}
          </ol>
        </div>
      )}

      {(bid.txHash || confirmed) && (
        <div className='note warn'>
          <strong>Export the backup file now.</strong> The secret of your bid is the only way to claim. It is not on chain.
        </div>
      )}
      <BackupPanel secrets={secrets} />
    </div>
  )
}

export default BidPanel
