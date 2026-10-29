// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import React from 'react'
import { useInvalidMasks } from '@/hooks/useMaskCheck'
import { useMask } from '@/hooks/useMask'
import type { Wallet } from '@/hooks/useWallet'
import { type AuctionPhase, type AuctionState, maskCount } from '@/utils/auction'
import { AddressLink } from './Explorer'
import Spinner from './Spinner'
import SubmissionSteps from './SubmissionSteps'

const sameAddress = (a: string, b: string | undefined) => b !== undefined && a.toLowerCase() === b.toLowerCase()

interface MaskPanelProps {
  auction: AuctionState
  phase: AuctionPhase
  wallet: Wallet
  committeeKey: Uint8Array | null
  onSubmitted: () => void
}

/**
 * The mask providers of a mask-provider auction and whether each has sent its mask. A connected provider
 * that has not sent its mask can prove and send it here. Bidding opens when every mask is in.
 */
const MaskPanel: React.FC<MaskPanelProps> = ({ auction, phase, wallet, committeeKey, onSubmitted }) => {
  const mask = useMask({ e3Id: auction.e3Id, account: wallet.address, committeeKey, onSubmitted })
  const sent = maskCount(auction)
  const total = auction.providers.length
  const invalid = useInvalidMasks(
    auction.e3Id,
    auction.providers.map((provider) => provider.address),
    sent,
  )

  const mine = auction.providers.find((provider) => sameAddress(provider.address, wallet.address))
  // A mask goes in while the auction takes inputs: before the committee key it cannot be made, after the window it is too late.
  const open = phase === 'awaiting-key' || phase === 'bidding'
  const blocked =
    !mine || mine.submitted
      ? null
      : !open
        ? 'The window for masks is closed.'
        : phase === 'awaiting-key'
          ? 'Masks can be sent once the committee has published its key. Key generation takes several minutes.'
          : committeeKey === null
            ? 'Fetching the committee key…'
            : null

  return (
    <div className='space-y-6'>
      <p className='text-sm text-ink'>
        Before bidding opens, each mask provider sends one random mask, encrypted to the committee key. The program multiplies the encrypted
        result by the masks, so that the committee decrypts only the winner and the price. Bidding opens when every provider has sent its
        mask. One honest provider is enough to keep the bids private.
      </p>
      <ul className='space-y-2'>
        {auction.providers.map((provider) => (
          <li key={provider.address} className='flex flex-wrap items-center gap-2 text-sm'>
            <AddressLink address={provider.address} />
            {sameAddress(provider.address, wallet.address) && <span className='tag muted'>you</span>}
            {provider.submitted ? <span className='tag live'>mask sent</span> : <span className='tag muted'>waiting</span>}
            {invalid.some((address) => sameAddress(address, provider.address)) && <span className='tag bad'>mask does not open</span>}
          </li>
        ))}
      </ul>
      <p className='font-mono text-xs text-muted'>
        {sent}/{total} masks sent
      </p>

      {invalid.length > 0 && (
        <div role='alert' className='note bad'>
          A mask on chain does not open its commitment: its bytes are not the encryption that the proof covers. The program needs every
          mask, so this auction cannot be computed.
        </div>
      )}

      {mine && !mine.submitted && wallet.isConnected && !wallet.wrongChain && (
        <div className='space-y-3'>
          <p className='label !mb-0'>You are a mask provider of this auction</p>
          <p className='muted text-xs'>
            Your mask is 128 random values, none of them zero. It never leaves this browser unencrypted. Proving runs in this tab and takes
            a few minutes: one encryption with its proof, then one proof that no value is zero. Keep the tab open. A mask provider sends the
            transaction itself: nobody can send it for you.
          </p>
          {blocked && <div className='note'>{blocked}</div>}
          <button onClick={() => void mask.submit()} disabled={blocked !== null || mask.submitting} className='btn accent block'>
            {mask.submitting ? (
              <>
                <Spinner size={14} /> Proving and submitting…
              </>
            ) : (
              'Submit mask'
            )}
          </button>
        </div>
      )}
      {mine?.submitted && <div className='note ok'>Your mask is on chain. Thank you.</div>}
      {mask.error && <div className='note bad'>{mask.error}</div>}
      {mask.steps.length > 0 && <SubmissionSteps title='Your mask' steps={mask.steps} running={mask.submitting} run={mask.run} />}
    </div>
  )
}

export default MaskPanel
