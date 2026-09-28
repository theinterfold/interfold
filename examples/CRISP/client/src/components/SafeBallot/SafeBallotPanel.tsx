// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import React, { useState } from 'react'
import { Poll } from '@/model/poll.model'
import { useSafeBallot } from '@/hooks/voting/useSafeBallot'
import type { CastVoteWithProof } from '@/hooks/voting/useVoteCasting'

type SafeBallotPanelProps = {
  pollSelected: Poll | null
  /** The page's own function, so its step indicator and busy state follow the Safe inputs too. */
  castVoteWithProof: CastVoteWithProof
  /** True while the page makes any input. */
  disabled: boolean
}

/**
 * Vote on behalf of a Safe: load it, encrypt the ballot, collect the owners' signatures from a
 * private link, then prove and submit.
 *
 * Any account can coordinate. The coordinator's wallet signs only when it is one of the owners,
 * and never as the Safe itself: the Safe app publishes the messages it signs.
 */
const SafeBallotPanel: React.FC<SafeBallotPanelProps> = ({ pollSelected, castVoteWithProof, disabled }) => {
  const safeBallot = useSafeBallot(castVoteWithProof)
  const { safe, pending, link, signers, busy, error } = safeBallot
  const [open, setOpen] = useState(false)
  const [address, setAddress] = useState('')
  const [pasted, setPasted] = useState('')
  const [copied, setCopied] = useState(false)

  const locked = disabled || Boolean(busy)

  if (!open) {
    return (
      <div>
        <button className='btn ghost' disabled={disabled} onClick={() => setOpen(true)}>
          Vote as a Safe
        </button>
      </div>
    )
  }

  const copyLink = async () => {
    if (!link) return
    await navigator.clipboard.writeText(link)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  return (
    <div className='card col' style={{ gap: 16 }} data-test-id='safe-ballot-panel'>
      <div className='row' style={{ justifyContent: 'space-between', alignItems: 'center' }}>
        <div className='mono muted'>Vote as a Safe</div>
        <button className='btn ghost' disabled={Boolean(busy)} onClick={() => setOpen(false)}>
          Close
        </button>
      </div>

      <div className='col' style={{ gap: 8 }}>
        <div className='cap muted'>Safe address</div>
        <div className='row' style={{ gap: 8 }}>
          <input className='field' value={address} placeholder='0x…' disabled={locked} onChange={(e) => setAddress(e.target.value)} />
          <button className='btn' disabled={locked || !address} onClick={() => safeBallot.loadSafe(address)}>
            {busy === 'loading' ? 'Loading…' : 'Load'}
          </button>
        </div>
      </div>

      {safe && (
        <div className='col' style={{ gap: 8 }}>
          <div className='cap'>
            {safe.threshold} of {safe.owners.length} owners must sign.
          </div>
          <ul className='hex'>
            {safe.owners.map((owner) => (
              <li key={owner}>
                {owner} {signers.includes(owner) ? '· signed' : safe.keyOwners.includes(owner) ? '' : '· contract, cannot sign'}
              </li>
            ))}
          </ul>
          <div className='row' style={{ gap: 8, flexWrap: 'wrap' }}>
            <button className='btn' disabled={locked || !pollSelected} onClick={() => pollSelected && safeBallot.prepare(pollSelected)}>
              {busy === 'preparing'
                ? 'Encrypting…'
                : pollSelected
                  ? `Prepare a ballot for ${pollSelected.label}`
                  : 'Select an option first'}
            </button>
            {/* Owners who mask their own Safe make their direct writes to it ambiguous. */}
            <button className='btn ghost' disabled={locked} onClick={() => safeBallot.maskSafe()}>
              {busy === 'masking' ? 'Masking…' : 'Mask this Safe'}
            </button>
          </div>
        </div>
      )}

      {pending && (
        <div className='col' style={{ gap: 12 }}>
          <div className='cap'>
            Send this link to the other owners through a private channel. Each owner opens it, connects their own wallet, and sends back the
            signature. Keep this tab open: the encrypted ballot exists only here.
          </div>
          <div className='cap muted'>
            Do not collect the signatures in the Safe app. It publishes the message, and anyone could then tell this vote from a mask.
          </div>
          <div className='row' style={{ gap: 8 }}>
            <input className='field' readOnly value={link ?? ''} onFocus={(e) => e.target.select()} />
            <button className='btn' onClick={copyLink}>
              {copied ? 'Copied' : 'Copy link'}
            </button>
          </div>
          <div className='row' style={{ gap: 8, flexWrap: 'wrap' }}>
            <button className='btn ghost' disabled={locked} onClick={() => safeBallot.signWithWallet()}>
              {busy === 'signing' ? 'Waiting for the wallet…' : 'Sign with my owner wallet'}
            </button>
          </div>
          <div className='row' style={{ gap: 8 }}>
            <input
              className='field'
              value={pasted}
              placeholder='Paste an owner signature (0x…)'
              disabled={locked}
              onChange={(e) => setPasted(e.target.value)}
            />
            <button
              className='btn'
              disabled={locked || !pasted}
              onClick={async () => {
                if (await safeBallot.addSignature(pasted)) setPasted('')
              }}
            >
              Add
            </button>
          </div>
          <div className='cap'>
            {signers.length} of {pending.request.threshold} signatures
          </div>
          <div>
            <button className='btn lg' disabled={locked || signers.length < pending.request.threshold} onClick={() => safeBallot.submit()}>
              {busy === 'submitting' ? 'Proving…' : 'Prove and submit the Safe vote →'}
            </button>
          </div>
        </div>
      )}
      {error && <div className='cap error'>{error}</div>}
    </div>
  )
}

export default SafeBallotPanel
