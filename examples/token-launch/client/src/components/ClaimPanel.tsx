// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import React, { useState } from 'react'
import { useWalletClient } from 'wagmi'
import type { LoggedBid } from '@/hooks/useBidLog'
import { CLAIM_STEP_LABELS, type ClaimRow, type ClaimStep, useClaims } from '@/hooks/useClaims'
import type { UseSecrets } from '@/hooks/useSecrets'
import { useChainTime } from '@/hooks/useChainTime'
import { chain } from '@/utils/chain'
import { formatError, shorten } from '@/utils/error-formatting'
import { formatDuration } from '@/utils/phase'
import { sendIndexAction } from '@/utils/program-tx'
import { type SaleState, formatBudget, formatDateTime, formatPayment, formatSaleTokens, formatStepPrice } from '@/utils/sale'
import BackupPanel from './BackupPanel'
import { AddressLink, TxLink } from './Explorer'
import RecipientPicker, { type Recipient } from './RecipientPicker'
import Spinner from './Spinner'

interface Props {
  sale: SaleState
  account: `0x${string}` | undefined
  secrets: UseSecrets
  bids: readonly LoggedBid[] | null
}

const outcomeText = (sale: SaleState, row: ClaimRow): { title: string; body: string } => {
  if (row.cmp === 0)
    return { title: 'You did not win.', body: 'Your max price was below the clearing price. The claim returns your whole escrow.' }
  if (row.cmp === 1 && sale.clearing?.kind === 'capped') {
    return {
      title: 'The registration window closed.',
      body: 'Your max price is the clearing step. A bid at the step had to register in time. You get your whole escrow back and no tokens.',
    }
  }
  return { title: 'You won.', body: 'You get your full tokens at the clearing price. The claim returns the rest of your escrow.' }
}

const Amounts: React.FC<{ sale: SaleState; tokens: bigint; paid: bigint; refund: bigint }> = ({ sale, tokens, paid, refund }) => (
  <dl className='grid grid-cols-3 gap-4'>
    <div>
      <dt className='mono-sm muted'>Tokens</dt>
      <dd className='mt-1 font-serif text-2xl'>{formatSaleTokens(sale, tokens)}</dd>
    </div>
    <div>
      <dt className='mono-sm muted'>You pay</dt>
      <dd className='mt-1 font-serif text-2xl'>{formatPayment(sale, paid)}</dd>
    </div>
    <div>
      <dt className='mono-sm muted'>Refund</dt>
      <dd className='mt-1 font-serif text-2xl'>{formatPayment(sale, refund)}</dd>
    </div>
  </dl>
)

/** A secret that was claimed: where the funds went, with the key of a generated recipient. */
const ClaimedCard: React.FC<{ sale: SaleState; row: ClaimRow }> = ({ sale, row }) => {
  const [showKey, setShowKey] = useState(false)
  const { result } = row
  return (
    <div className='space-y-3'>
      <div className='note ok'>Claimed. The funds went to the recipient below.</div>
      {result ? (
        <>
          <Amounts sale={sale} {...result.amounts} />
          <dl className='grid gap-2 text-xs'>
            <div>
              <dt className='mono-sm muted'>Recipient</dt>
              <dd>
                <AddressLink address={result.recipient} full />
              </dd>
            </div>
            {row.nullifier && (
              <div>
                <dt className='mono-sm muted'>Nullifier</dt>
                <dd className='addr break-all'>{row.nullifier}</dd>
              </div>
            )}
            {result.txHash && (
              <div>
                <dt className='mono-sm muted'>Transaction</dt>
                <dd>
                  <TxLink hash={result.txHash} />
                </dd>
              </div>
            )}
          </dl>
          {result.recipientKey && (
            <div className='note warn space-y-2 text-xs'>
              <p>
                This browser holds the private key of the recipient. Save it, then clear it from this browser if you wish. Anyone who has it
                can take the funds.
              </p>
              {showKey ? (
                <p className='addr break-all'>{result.recipientKey}</p>
              ) : (
                <button type='button' onClick={() => setShowKey(true)} className='btn ghost sm'>
                  Show the private key
                </button>
              )}
            </div>
          )}
        </>
      ) : (
        <p className='muted text-xs'>
          This browser does not hold the details. The nullifier {row.nullifier && shorten(row.nullifier)} is used.
        </p>
      )}
    </div>
  )
}

/** A bid at the clearing step that registered: the status of the payment and the pay button. */
const MarginalCard: React.FC<{ sale: SaleState; row: ClaimRow; account: `0x${string}` | undefined; now: bigint; onPaid: () => void }> = ({
  sale,
  row,
  now,
  onPaid,
}) => {
  const { data: walletClient } = useWalletClient({ chainId: chain.id })
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [hash, setHash] = useState<`0x${string}` | null>(null)
  const deadline = sale.clearing?.marginalDeadline ?? 0n
  const open = now <= deadline
  const { marginal } = row
  if (!marginal) return null
  const paid = row.status === 'marginal-paid'

  const pay = async () => {
    if (!walletClient) return
    setBusy(true)
    setError(null)
    try {
      setHash(await sendIndexAction(walletClient, 'payMarginal', sale.saleId, row.secret.index))
      onPaid()
    } catch (err) {
      setError(formatError(err))
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className='space-y-4'>
      <div className={`note ${paid ? 'ok' : ''}`}>
        {paid ? (
          <p>
            <strong>Paid.</strong> Earlier bids at the clearing step filled first. The amounts below went to{' '}
            {marginal.recipient && <AddressLink address={marginal.recipient} />}.
          </p>
        ) : open ? (
          <p>
            <strong>Registered.</strong> The claim waits for the end of the registration window: {formatDateTime(deadline)} (
            {formatDuration(deadline - now)} left). Then anyone can pay it. Bids at the clearing step fill in bid order, so the amounts
            below can still change.
          </p>
        ) : (
          <p>
            <strong>Registered.</strong> The registration window is over. Anyone can pay this claim now, and the keeper does it too.
          </p>
        )}
      </div>
      {marginal.amounts && <Amounts sale={sale} {...marginal.amounts} />}
      {!paid && !open && (
        <div className='space-y-2'>
          <button onClick={() => void pay()} disabled={busy || !walletClient} className='btn accent lg block'>
            {busy ? <Spinner size={14} /> : 'Pay the claim'}
          </button>
          {!walletClient && <p className='muted text-xs'>Connect a wallet to send the payment. Any account may do it.</p>}
        </div>
      )}
      {hash && (
        <p className='mono-sm muted'>
          Transaction <TxLink hash={hash} />
        </p>
      )}
      {error && <div className='note bad'>{error}</div>}
    </div>
  )
}

const ClaimCard: React.FC<{
  sale: SaleState
  row: ClaimRow
  account: `0x${string}` | undefined
  busy: boolean
  step: ClaimStep | null
  closed: boolean
  now: bigint
  onClaim: (recipient: Recipient) => void
  onPaid: () => void
}> = ({ sale, row, account, busy, step, closed, now, onClaim, onPaid }) => {
  const [recipient, setRecipient] = useState<Recipient | null>(null)
  const [understood, setUnderstood] = useState(false)
  const { secret } = row
  const register = row.status === 'ready' && row.marginal?.register === true

  return (
    <div className='card flat space-y-5'>
      <div className='flex flex-wrap items-baseline justify-between gap-2'>
        <p className='mono-sm muted'>
          Your bid · Nº {secret.index} · {formatBudget(sale, secret.budget)} at {formatStepPrice(sale, secret.step)}{' '}
          {sale.paymentToken.symbol}
        </p>
      </div>
      {row.status === 'not-on-chain' && (
        <div className='note'>No bid on chain opens this secret. It is from a failed attempt or another sale. It cannot claim.</div>
      )}
      {row.status === 'dropped' && (
        <div className='note'>This bid did not count in both rounds. It has no claim. Refund its escrow with the dropped bids below.</div>
      )}
      {row.status === 'claimed' && <ClaimedCard sale={sale} row={row} />}
      {(row.status === 'marginal-registered' || row.status === 'marginal-paid') && (
        <MarginalCard sale={sale} row={row} account={account} now={now} onPaid={onPaid} />
      )}
      {register && row.marginal && (
        <>
          <div className='note'>
            <p>
              <strong>Your max price is the clearing step.</strong> Bids at the step fill in bid order: the earliest bid fills first and
              later bids get a refund when the tokens run out. You can get up to{' '}
              <span className='font-mono'>{formatSaleTokens(sale, row.marginal.maxTokens)}</span>. The rest of your escrow comes back.
            </p>
            <p className='mt-2'>
              <strong>This claim is public.</strong> It shows your bid number {secret.index}, your budget and your recipient. Anyone can
              link your bid address to the recipient. Registration ends {formatDateTime(sale.clearing?.marginalDeadline ?? 0n)} (
              {formatDuration((sale.clearing?.marginalDeadline ?? 0n) - now)} left). The payment follows after that. If you do not register,
              you get your escrow back and no tokens.
            </p>
          </div>
          <RecipientPicker value={recipient} onChange={setRecipient} disabled={busy} linked={[account, secret.bidder]} />
          <label className='flex items-start gap-2 text-sm'>
            <input type='checkbox' checked={understood} onChange={(event) => setUnderstood(event.target.checked)} className='mt-1' />
            <span>I understand that this claim links my bid address to the recipient.</span>
          </label>
          <button
            onClick={() => recipient && onClaim(recipient)}
            disabled={busy || closed || recipient === null || !understood}
            className='btn accent lg block'
          >
            {busy && step ? (
              <>
                <Spinner size={14} /> {CLAIM_STEP_LABELS[step]}
              </>
            ) : closed ? (
              'Claim window closed'
            ) : (
              'Register this claim'
            )}
          </button>
        </>
      )}
      {row.status === 'ready' && row.preview && (
        <>
          <div className={`note ${row.cmp === 0 ? '' : 'ok'}`}>
            <p>
              <strong>{outcomeText(sale, row).title}</strong> {outcomeText(sale, row).body}
            </p>
          </div>
          <Amounts sale={sale} {...row.preview} />
          <RecipientPicker value={recipient} onChange={setRecipient} disabled={busy} linked={[account, secret.bidder]} />
          <div className='space-y-2'>
            <button
              onClick={() => recipient && onClaim(recipient)}
              disabled={busy || closed || recipient === null}
              className='btn accent lg block'
            >
              {busy && step ? (
                <>
                  <Spinner size={14} /> {CLAIM_STEP_LABELS[step]}
                </>
              ) : closed ? (
                'Claim window closed'
              ) : (
                'Claim to this address'
              )}
            </button>
            <p className='muted text-xs'>
              The proof runs in this tab and takes a few seconds. The relayer sends the claim, so the recipient needs no gas. The claim
              shows your escrow tier{row.cmp !== 0 ? ', your budget' : ''} and whether your max price is below, at or above the clearing
              step.
            </p>
          </div>
        </>
      )}
    </div>
  )
}

/** The claims of the bid secrets that this browser holds. The proof shows a counted bid exists and names no bid. */
const ClaimPanel: React.FC<Props> = ({ sale, account, secrets, bids }) => {
  const now = useChainTime()
  const claims = useClaims(sale, secrets.held, bids)
  const closed = sale.clearing !== null && now > sale.clearing.claimDeadline

  return (
    <div className='space-y-6'>
      <p className='text-sm text-ink-2'>
        Claim in this browser with your bid secret. You do not need the bidder wallet. Pick a fresh recipient address. The relayer sends the
        claim. Nothing on chain links the recipient to your bid. One exception: a bid at the clearing step of a capped sale must register,
        and the registration is public.
      </p>
      {secrets.held.length === 0 && (
        <div className='note'>This browser holds no bid secret for this sale. Import your backup file to claim.</div>
      )}
      {claims.error && <div className='note bad'>{claims.error}</div>}
      {claims.rows.map((row) => (
        <ClaimCard
          key={row.secret.bidCommitment}
          sale={sale}
          row={row}
          account={account}
          busy={claims.busyIndex === row.secret.index}
          step={claims.step}
          closed={closed}
          now={now}
          onPaid={claims.reload}
          onClaim={(recipient) => void claims.claim(row.secret, recipient.address, recipient.privateKey)}
        />
      ))}
      <BackupPanel secrets={secrets} />
    </div>
  )
}

export default ClaimPanel
