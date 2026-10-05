// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import React, { useEffect } from 'react'
import CardContent from '@/components/Cards/CardContent'
import { useVoteManagementContext } from '@/context/voteManagement'

const ConfirmVote: React.FC<{ confirmationUrl?: string }> = ({ confirmationUrl }) => {
  const { setTxUrl, txRoute, setTxRoute } = useVoteManagementContext()

  useEffect(() => {
    return () => {
      setTxUrl(undefined)
      setTxRoute(undefined)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  return (
    <CardContent>
      <div className='col' style={{ gap: 10 }}>
        <p className='mono muted'>WHAT JUST HAPPENED?</p>
        <p className='lede' style={{ maxWidth: 'none' }}>
          Your browser encrypted your ballot and sent it to the CRISP server, which sees the request.{' '}
          {txRoute === 'wallet' && <>Your wallet sent the on-chain transaction, so the transaction also shows your address. </>}
          {txRoute === 'relay' && <>The CRISP server sent the on-chain transaction. </>}
          {txRoute === undefined && <>The ballot is on-chain. </>}
          When the poll closes, the committee tallies the ballots with Fully Homomorphic Encryption (FHE). It uses threshold cryptography to
          decrypt only the combined result.
        </p>
        {confirmationUrl && (
          <p>
            <a href={confirmationUrl} target='_blank' rel='noreferrer' className='linkish'>
              View the transaction
            </a>
          </p>
        )}
      </div>
      <div className='col' style={{ gap: 10 }}>
        <p className='mono muted'>WHAT DOES THIS MEAN?</p>
        <p className='lede' style={{ maxWidth: 'none' }}>
          No single committee member can decrypt your ballot. The combined result is public, and in a small or one-sided poll it can show
          how individual participants voted. Privacy also depends on the committee threshold: enough committee members who collude can
          decrypt ballots. Masks make a vote, an update, and a mask look the same on-chain, which makes a receipt of your vote less reliable
          when these conditions hold.
        </p>
      </div>
    </CardContent>
  )
}

export default ConfirmVote
