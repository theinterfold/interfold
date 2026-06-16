// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
// Main app shell + tweak wiring.

import { Fragment, type ReactNode, useEffect, useMemo, useRef, useState } from 'react'
import { STAGES, type Poll } from './data'
import PollCard from './PollCard'
import Timeline from './Timeline'
import History from './History'
import Pulse from './Pulse'
import Inspector from './Inspector'
import Loader from './Loader'
import { useAllE3s, useCrispPolls, useE3Details, useRecentBallots } from './lib/useE3s'
import { adaptHistoryEntries, adaptInspectorDetail, adaptInspectorE3List, adaptPoll } from './lib/adapt'
import { formatE3Id } from './lib/pollMeta'
import { LINKS, explorerAddress } from './lib/links'
import { CONTRACTS } from './lib/chain'
import { isE3Active, solidityStageToUiIdx, type E3FullDetails, type E3Summary } from './lib/e3'

function Header({ density, view, onNav }: { density: string; view: string; onNav: (id: string) => void }) {
  const link = (id: string, label: string) => (
    <a
      className={`site-nav__link ${view === id ? 'site-nav__link--on' : ''}`}
      href={`#${id}`}
      onClick={(e) => {
        e.preventDefault()
        onNav(id)
      }}
    >
      {label}
    </a>
  )
  return (
    <header className={`site-head site-head--${density}`}>
      <div className='site-head__inner'>
        <a
          className='wordmark'
          href='#'
          onClick={(e) => {
            e.preventDefault()
            onNav('inspector')
          }}
          aria-label='Interfold home'
        >
          <span className='wordmark__logo' aria-hidden='true' />
        </a>
        <nav className='site-nav' aria-label='Primary'>
          {link('inspector', 'E3 inspector')}
          {link('crisp', 'CRISP')}
        </nav>
      </div>
    </header>
  )
}

function Intro() {
  return (
    <section className='intro'>
      <div className='intro__eyebrow'>
        <span className='dot-live' /> Live · public poll
      </div>
      <h1 className='intro__title'>Watch an encrypted poll execute on the Interfold network.</h1>
      <p className='intro__lede'>
        CRISP is an example e3 running live. Ballots are encrypted on each voter's device, tallied without ever being decrypted, and only
        the final result is revealed. This page shows the lifecycle as it happens — and the archive of every poll that came before.
      </p>
    </section>
  )
}

function StatusNote({ children }: { children: ReactNode }) {
  return (
    <div className='emptystate'>
      <div className='emptystate__note'>
        <span className='emptystate__dot' aria-hidden='true' />
        <span>{children}</span>
      </div>
    </div>
  )
}

function SiteFooter() {
  return (
    <footer className='site-foot'>
      <div className='site-foot__inner'>
        <div className='site-foot__brand'>
          <div className='wordmark wordmark--foot'>
            <span className='wordmark__logo' aria-label='Interfold' role='img' />
          </div>
          <p className='site-foot__tag'>
            Infrastructure for confidential coordination between independent parties. CRISP is one of the example applications running on
            the network.
          </p>
        </div>
        <div className='site-foot__cols'>
          <div>
            <div className='site-foot__col-head'>Learn</div>
            <a href={LINKS.docs} target='_blank' rel='noreferrer'>
              Documentation
            </a>
            <a href={LINKS.architecture} target='_blank' rel='noreferrer'>
              Architecture
            </a>
            <a href={LINKS.crisp} target='_blank' rel='noreferrer'>
              CRISP
            </a>
          </div>
          <div>
            <div className='site-foot__col-head'>Project</div>
            <a href={LINKS.repo} target='_blank' rel='noreferrer'>
              Github
            </a>
            <a href={LINKS.blog} target='_blank' rel='noreferrer'>
              Blog
            </a>
            <a href={LINKS.site} target='_blank' rel='noreferrer'>
              Website
            </a>
          </div>
        </div>
      </div>
      <div className='site-foot__rule'>
        <span>© 2026 Interfold · Built in the open</span>
        <a className='mono' href={explorerAddress(CONTRACTS.Interfold)} target='_blank' rel='noreferrer'>
          Interfold on Sepolia ↗
        </a>
      </div>
    </footer>
  )
}

// Fixed presentation density (the live tweak panel was removed).
const DENSITY = 'comfortable'

// Derive the poll-card state from the UI stage + ballot count. Specifically,
// when the input window has closed (uiStageIdx >= 4) but no ballots ever arrived,
// the committee isn't actually tallying anything — surface that as a distinct
// "idle" state instead of falsely claiming a tally is in progress.
const pollStateForStage = (uiStageIdx: number, ballotCount: number): string => {
  if (uiStageIdx >= 6) return 'published'
  if (uiStageIdx >= 4) return ballotCount === 0 ? 'idle' : 'computing'
  return 'open'
}

// Synthetic poll used only for the "Watch the lifecycle" demo when nothing is live.
const DEMO_POLL: Poll = {
  id: 'Sample',
  question: 'A sample CRISP poll — watch how an encrypted poll moves through its lifecycle.',
  context: 'This is an interactive demonstration, not a live poll.',
  opened: '—',
  closes: '—',
  closesTs: 0,
  ballotCount: 0,
}

export default function App() {
  // View (tab) + demo poll state. These are the only values that change at
  // runtime; everything else is fixed (accent comes from the CSS :root mint).
  const [view, setView] = useState('inspector')
  const [pollState, setPollState] = useState('open')
  const [stageIdx, setStageIdx] = useState(3)

  const [nowMs, setNowMs] = useState(() => Date.now())
  const [liveMode, setLiveMode] = useState(false)
  // Demo autoplay step, persisted so pausing/resuming continues where it left off.
  const liveStepRef = useRef(0)

  // ─── On-chain data (Sepolia) ──────────────────────────────────────────────
  // CRISP tab: only CRISP-program polls. Inspector tab: every E3 on the network.
  const crispPolls = useCrispPolls()
  const allE3s = useAllE3s()
  const recentBallots = useRecentBallots()

  // Inspector keeps its own selection — track which id is currently selected.
  const [inspectorIdStr, setInspectorIdStr] = useState<string | null>(null)
  const selectedInspectorId = useMemo(() => {
    if (!allE3s.data || allE3s.data.length === 0) return null
    if (inspectorIdStr) {
      const match = allE3s.data.find((e) => formatE3Id(e.id) === inspectorIdStr)
      if (match) return match.id
    }
    return allE3s.data[0].id
  }, [allE3s.data, inspectorIdStr])
  const inspectorDetail = useE3Details(selectedInspectorId)

  // Detail cache for history verdicts (the inspector-selected E3, if any).
  const detailsCache = useMemo(() => {
    const m = new Map<string, E3FullDetails>()
    if (inspectorDetail.data) m.set(inspectorDetail.data.id.toString(), inspectorDetail.data)
    return m
  }, [inspectorDetail.data])

  // CRISP tab state: split into currently-active polls (featured) and the rest
  // (archived). Card data comes straight from the list summary — no per-poll fetch.
  const crispReady = crispPolls.status === 'ready'
  const polls = useMemo(() => crispPolls.data ?? [], [crispPolls.data])
  // `nowMs` updates each second so isE3Active re-evaluates and polls move from
  // active → past as their windows close, rather than waiting for the next 15s
  // on-chain refresh.
  const activePolls = useMemo<E3Summary[]>(
    () => polls.filter((p) => isE3Active(p.stage, p.inputWindow[1], { e3Program: p.e3Program, ballotCount: p.ballotCount, nowMs })),
    [polls, nowMs],
  )
  const pastPolls = useMemo<E3Summary[]>(
    () => polls.filter((p) => !isE3Active(p.stage, p.inputWindow[1], { e3Program: p.e3Program, ballotCount: p.ballotCount, nowMs })),
    [polls, nowMs],
  )
  const liveHistory = useMemo(() => adaptHistoryEntries(pastPolls, detailsCache), [pastPolls, detailsCache])

  // Inspector tab state.
  const inspectorReady = allE3s.status === 'ready'
  const hasE3s = (allE3s.data?.length ?? 0) > 0
  const inspectorList = useMemo(() => adaptInspectorE3List(allE3s.data ?? []), [allE3s.data])
  const inspectorE3 = useMemo(() => adaptInspectorDetail(inspectorDetail.data), [inspectorDetail.data])

  const setStage = (i: number) => {
    setStageIdx(i)
    if (i >= 6) setPollState('published')
    else if (i >= 4) setPollState('computing')
    else setPollState('open')
  }

  useEffect(() => {
    const id = setInterval(() => setNowMs(Date.now()), 1000)
    return () => clearInterval(id)
  }, [])

  useEffect(() => {
    if (!liveMode) return undefined
    const program = [
      { state: 'open', stage: 0, hold: 2200 },
      { state: 'open', stage: 1, hold: 2200 },
      { state: 'open', stage: 2, hold: 2400 },
      { state: 'open', stage: 3, hold: 4600 },
      { state: 'computing', stage: 4, hold: 2800 },
      { state: 'computing', stage: 5, hold: 2400 },
      { state: 'published', stage: 6, hold: 4000 },
    ]
    let cancelled = false
    let timer: ReturnType<typeof setTimeout> | null = null
    const advance = () => {
      if (cancelled) return
      const i = liveStepRef.current
      if (i >= program.length) {
        // Completed one full lifecycle — stop instead of looping.
        liveStepRef.current = 0
        setLiveMode(false)
        return
      }
      const step = program[i]
      setPollState(step.state)
      setStageIdx(step.stage)
      liveStepRef.current = i + 1
      timer = setTimeout(advance, step.hold)
    }
    advance()
    return () => {
      cancelled = true
      if (timer) clearTimeout(timer)
    }
  }, [liveMode])

  // Demo card's current stage, reconciled from the demo's pollState/stageIdx.
  const demoStage = (() => {
    if (pollState === 'published') return 6
    if (pollState === 'computing') return Math.max(4, Math.min(5, stageIdx))
    return Math.min(stageIdx, 3)
  })()

  return (
    <div className={`page page--${DENSITY}`}>
      <Header density={DENSITY} view={view} onNav={setView} />
      {view === 'inspector' ? (
        <main className='main'>
          {allE3s.status === 'error' ? (
            <div className='inspector'>
              <StatusNote>Couldn't load E3s from Sepolia. Retrying automatically…</StatusNote>
            </div>
          ) : !inspectorReady ? (
            <div className='inspector'>
              <Loader label='Loading E3s' sub='Reading from Sepolia…' />
            </div>
          ) : !hasE3s ? (
            <div className='inspector'>
              <StatusNote>No E3s on the network yet. They will appear here once one is requested on-chain.</StatusNote>
            </div>
          ) : (
            <Inspector
              e3List={inspectorList}
              e3={inspectorE3}
              selectedId={selectedInspectorId ? formatE3Id(selectedInspectorId) : undefined}
              onSelect={(id) => setInspectorIdStr(id)}
              loading={inspectorDetail.status === 'loading'}
              error={inspectorDetail.status === 'error' ? inspectorDetail.error : null}
            />
          )}
        </main>
      ) : (
        <main className='main'>
          <Intro />

          {crispPolls.status === 'error' ? (
            <StatusNote>Couldn't load CRISP polls from Sepolia. Retrying automatically…</StatusNote>
          ) : !crispReady ? (
            <Loader label='Loading CRISP polls' sub='Reading from Sepolia…' />
          ) : activePolls.length > 0 ? (
            <>
              {activePolls.map((s) => {
                const poll = adaptPoll(s)
                const stageIdx = solidityStageToUiIdx(s.stage, s.inputWindow)
                return (
                  <Fragment key={s.id.toString()}>
                    <PollCard
                      poll={poll}
                      pollState={pollStateForStage(stageIdx, s.ballotCount)}
                      currentStageIdx={stageIdx}
                      ballotCount={s.ballotCount}
                      onNavigate={setView}
                    />
                    <Timeline stages={STAGES} currentStageIdx={stageIdx} pollId={poll.id} density={DENSITY} />
                  </Fragment>
                )
              })}
            </>
          ) : (
            // No live polls — offer the lifecycle as an interactive demo.
            <>
              <StatusNote>No live CRISP polls right now. Here's how an encrypted poll moves through its lifecycle:</StatusNote>
              <PollCard
                poll={DEMO_POLL}
                pollState={pollState}
                currentStageIdx={demoStage}
                liveMode={liveMode}
                onToggleLive={() => setLiveMode((v) => !v)}
                ballotCount={0}
                onNavigate={setView}
              />
              <Timeline
                stages={STAGES}
                currentStageIdx={demoStage}
                pollId='demo'
                density={DENSITY}
                onStageClick={liveMode ? undefined : setStage}
              />
            </>
          )}

          {liveHistory.length > 0 && <History entries={liveHistory} onNavigate={setView} />}
        </main>
      )}

      <Pulse
        data={{
          activeNow: activePolls.length,
          ballots24h: recentBallots,
          pollsAllTime: polls.length,
        }}
      />
      <SiteFooter />
    </div>
  )
}
