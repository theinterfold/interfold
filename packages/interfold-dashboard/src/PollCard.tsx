// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
// Today's CRISP poll card — the most prominent surface when a poll is live.

import { useState } from 'react'
import { STAGES, STAGE_STATUS, type Poll } from './data'
import { LINKS } from './lib/links'

// Live "time remaining" for the input window, from the on-chain close time.
function formatRemaining(closesTs: number): string {
  if (!closesTs) return 'Voting open'
  const secs = closesTs - Math.floor(Date.now() / 1000)
  if (secs <= 0) return 'Voting closed'
  const d = Math.floor(secs / 86400)
  const h = Math.floor((secs % 86400) / 3600)
  const m = Math.floor((secs % 3600) / 60)
  if (d > 0) return `${d} day${d === 1 ? '' : 's'}, ${h} hour${h === 1 ? '' : 's'} remaining`
  if (h > 0) return `${h} hour${h === 1 ? '' : 's'}, ${m} min remaining`
  if (m > 0) return `${m} min remaining`
  return `${secs}s remaining`
}

function StageBadge({ stageIdx, label }: { stageIdx: number; label?: string }) {
  const s = STAGES[stageIdx]
  const variant = stageIdx >= 6 ? 'published' : stageIdx === 3 ? 'open' : 'working'
  return (
    <span className={`stage-badge stage-badge--${variant}`}>
      <span className='stage-badge__dot' />
      <span>{label ?? s.label}</span>
    </span>
  )
}

function EncryptedBallotGrid({ count }: { count: number }) {
  return (
    <div className='ballot-grid' aria-label={`${count} encrypted ballots received`}>
      <div className='ballot-grid__head'>
        <div className='ballot-grid__count' key={count}>
          {count.toLocaleString()}
        </div>
        <div className='ballot-grid__label'>
          encrypted ballots received
          <div className='ballot-grid__sub'>Each is sealed on the voter's device. None have been opened.</div>
        </div>
      </div>
    </div>
  )
}

function PrivacyExplainer() {
  const [open, setOpen] = useState(false)
  return (
    <div className={`privacy ${open ? 'privacy--open' : ''}`}>
      <button className='privacy__toggle' onClick={() => setOpen((o) => !o)} aria-expanded={open}>
        <span className='privacy__icon' aria-hidden='true'>
          <svg viewBox='0 0 16 16' width='14' height='14'>
            <path
              d='M8 1.5 L13 3.5 V8 C13 11 10.5 13.4 8 14.5 C5.5 13.4 3 11 3 8 V3.5 Z'
              fill='none'
              stroke='currentColor'
              strokeWidth='1.2'
              strokeLinejoin='round'
            />
          </svg>
        </span>
        <span>How this poll stayed private</span>
        <span className={`privacy__chev ${open ? 'privacy__chev--open' : ''}`} aria-hidden='true'>
          <svg viewBox='0 0 10 10' width='10' height='10'>
            <path d='M2 4 L5 7 L8 4' fill='none' stroke='currentColor' strokeWidth='1.4' strokeLinecap='round' strokeLinejoin='round' />
          </svg>
        </span>
      </button>
      {open && (
        <div className='privacy__body'>
          <ol className='privacy__steps'>
            <li>
              <span className='privacy__num'>1</span>
              <div>
                <b>Sealed on your device.</b> Each ballot is encrypted in your browser before it leaves you. The Interfold network only ever
                sees ciphertext.
              </div>
            </li>
            <li>
              <span className='privacy__num'>2</span>
              <div>
                <b>No single party holds the key.</b> A freshly-drawn committee generates a shared key collaboratively. No member can
                decrypt anything alone.
              </div>
            </li>
            <li>
              <span className='privacy__num'>3</span>
              <div>
                <b>The tally happens under encryption.</b> Votes are added together while still sealed. The aggregate — and only the
                aggregate — is ever decrypted.
              </div>
            </li>
            <li>
              <span className='privacy__num'>4</span>
              <div>
                <b>Verifiable on-chain.</b> Every stage transition is recorded publicly, so anyone can check that the process was followed.
                Individual ballots remain sealed forever.
              </div>
            </li>
          </ol>
          <a className='privacy__more' href={LINKS.architecture} target='_blank' rel='noreferrer'>
            Read the full privacy model →
          </a>
        </div>
      )}
    </div>
  )
}

export default function PollCard({
  pollState,
  currentStageIdx,
  liveMode,
  onToggleLive,
  ballotCount,
  onNavigate,
  poll,
}: {
  pollState: string
  currentStageIdx: number
  liveMode?: boolean
  onToggleLive?: () => void
  ballotCount?: number
  onNavigate?: (view: string) => void
  poll: Poll
}) {
  const effective = { ...poll, ballotCount: ballotCount ?? poll.ballotCount }
  const safeStageIdx = Math.min(Math.max(currentStageIdx, 0), STAGES.length - 1)
  const stageId = STAGES[safeStageIdx].id
  const status = STAGE_STATUS[stageId]
  const isPublished = pollState === 'published'
  const isOpen = pollState === 'open'
  const isComputing = pollState === 'computing'
  const isIdle = pollState === 'idle' // input window closed with no ballots
  // Live countdown only meaningful while the input window is open. For idle
  // (window closed with no ballots) override the canned "In progress" copy.
  const timeValue = stageId === 'input' ? formatRemaining(poll.closesTs) : isIdle ? 'Closed · no ballots' : status.label
  const statusSub = isIdle ? 'No encrypted ballots were submitted before close' : status.sub

  return (
    <section className='poll-card' aria-label="Today's CRISP poll">
      <div className='poll-card__inner'>
        <header className='poll-card__head'>
          <div className='poll-card__eyebrow'>
            <span className='poll-card__kicker'>Today on CRISP</span>
            <span className='poll-card__sep'>·</span>
            <span className='poll-card__id'>{poll.id}</span>
          </div>
          {onToggleLive && (
            <button
              type='button'
              className={`live-toggle ${liveMode ? 'live-toggle--on' : ''}`}
              onClick={onToggleLive}
              aria-pressed={!!liveMode}
            >
              <span className='live-toggle__icon' aria-hidden='true'>
                {liveMode ? (
                  <svg viewBox='0 0 10 10' width='10' height='10'>
                    <rect x='2' y='1.5' width='2' height='7' fill='currentColor' />
                    <rect x='6' y='1.5' width='2' height='7' fill='currentColor' />
                  </svg>
                ) : (
                  <svg viewBox='0 0 10 10' width='10' height='10'>
                    <path d='M2 1 L9 5 L2 9 Z' fill='currentColor' />
                  </svg>
                )}
              </span>
              <span>{liveMode ? 'Pause demo' : 'Watch the lifecycle'}</span>
            </button>
          )}
          <StageBadge stageIdx={safeStageIdx} label={isIdle ? 'No ballots' : undefined} />
        </header>

        <h1 className='poll-card__question'>{poll.question}</h1>
        <p className='poll-card__context'>{poll.context}</p>

        <div className='poll-card__timing'>
          <div>
            <div className='poll-card__timing-label'>Time</div>
            <div className='poll-card__timing-value'>{timeValue}</div>
            <div className='poll-card__timing-sub'>{statusSub}</div>
          </div>
          <div>
            <div className='poll-card__timing-label'>Opened</div>
            <div className='poll-card__timing-value mono'>{poll.opened}</div>
          </div>
          <div>
            <div className='poll-card__timing-label'>Closes</div>
            <div className='poll-card__timing-value mono'>{poll.closes}</div>
          </div>
        </div>

        {!isPublished && (
          <div className='poll-card__options'>
            <div className='poll-card__cta-row'>
              <span className='poll-card__cta-note'>
                {isOpen
                  ? "Voting is open. Ballots are encrypted on the voter's device and submitted to the network."
                  : isIdle
                    ? 'Voting has closed without any ballots submitted.'
                    : isComputing
                      ? 'Voting has closed. The committee is now tallying the encrypted ballots.'
                      : 'Voting has not opened yet for this poll.'}
              </span>
              <a
                className='link-inline'
                href='#inspector'
                onClick={(e) => {
                  if (onNavigate) {
                    e.preventDefault()
                    onNavigate('inspector')
                  }
                }}
              >
                Inspect this E3
                <span className='btn__arrow' aria-hidden='true'>
                  →
                </span>
              </a>
            </div>
          </div>
        )}

        {isPublished && (
          <div className='poll-card__result'>
            <PrivacyExplainer />
          </div>
        )}
      </div>

      <aside className='poll-card__side'>
        <EncryptedBallotGrid count={effective.ballotCount} />
      </aside>
    </section>
  )
}
