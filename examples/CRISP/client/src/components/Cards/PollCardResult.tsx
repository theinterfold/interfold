// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import React from 'react'
import { PollOption } from '@/model/poll.model'
import Card from '@/components/Cards/Card'
import { ShieldSlash } from '@phosphor-icons/react'

type PollCardResultProps = {
  results: PollOption[]
  totalVotes: number
  spaceCards?: string
  height?: number
  width?: number
  isResult?: boolean
  isActive?: boolean
}
const PollCardResult: React.FC<PollCardResultProps> = ({ isResult, results, totalVotes, isActive }) => {
  const validVotes = results.reduce((sum, poll) => sum + Number.parseInt(poll.votes.toString(), 10), 0)
  const percentDenominator = validVotes > 0 ? validVotes : totalVotes

  const calculatePercentage = (votes: number) => {
    if (percentDenominator <= 0) {
      return '0'
    }
    return ((votes / percentDenominator) * 100).toFixed(0)
  }

  return (
    <div
      className='grid'
      style={{ gridTemplateColumns: '1fr 1fr', gap: isResult ? 24 : 16, width: '100%', maxWidth: isResult ? 420 : undefined }}
    >
      {results.map((poll) => (
        <div data-test-id={`poll-result-${poll.value}`} key={`${poll.label}-${poll.value}`}>
          <div className='col' style={{ alignItems: 'center', gap: isResult ? 16 : 10 }}>
            <Card isDetails checked={totalVotes === 0 ? false : poll.checked} isActive={isActive}>
              <span className='faceoff-emoji' style={{ fontSize: isResult ? undefined : 40 }}>
                {poll.label}
              </span>
            </Card>

            {isActive && isResult && (
              <div className='col' style={{ alignItems: 'center', gap: 6 }}>
                <span className='tag dot'>
                  <ShieldSlash weight='bold' size={14} />
                  vote encrypted
                </span>
                <span className='mono-sm muted'>revealed when poll ends</span>
              </div>
            )}
            {!isActive && (
              <div className='col' style={{ alignItems: 'center', gap: 2 }}>
                <div
                  className={isResult ? 'display' : 'h2'}
                  style={{
                    fontSize: isResult ? 'clamp(40px, 8vw, 80px)' : undefined,
                    color: totalVotes > 0 && poll.checked ? 'var(--accent)' : 'var(--ink-soft)',
                  }}
                >
                  {totalVotes ? calculatePercentage(poll.votes) : 0}%
                </div>
                <span className='cap'>
                  {poll.votes} {poll.votes === 1 ? 'vote' : 'votes'}
                </span>
              </div>
            )}
          </div>
        </div>
      ))}
    </div>
  )
}

export default PollCardResult
