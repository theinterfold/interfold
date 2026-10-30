// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
// Main app shell + tweak wiring.

import { Fragment, type ReactNode, useEffect, useMemo, useState } from 'react'
import { STAGES } from './data'
import PollCard from './PollCard'
import Timeline from './Timeline'
import History from './History'
import Pulse from './Pulse'
import Inspector from './Inspector'
import Loader from './Loader'
import Operator from './Operator'
import { useAllE3s, useCrispPolls, useE3Details, useRecentBallots } from './lib/useE3s'
import { useNetworkStats } from './lib/network'
import { adaptHistoryEntries, adaptInspectorDetail, adaptInspectorE3List, adaptPoll } from './lib/adapt'
import { formatE3Id } from './lib/pollMeta'
import { LINKS, explorerAddress } from './lib/links'
import { CONTRACTS, NETWORK_NAME } from './lib/chain'
import { isE3Active, solidityStageToUiIdx, type E3Summary } from './lib/e3'

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
          {link('operator', 'Run a ciphernode')}
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
          Interfold on {NETWORK_NAME} ↗
        </a>
      </div>
    </footer>
  )
}

// Fixed presentation density (the live tweak panel was removed).
const DENSITY = 'comfortable'

// Linkable views. Anything else in the hash falls back to the inspector, so a
// stale or hand-typed fragment can never render a blank page.
const VIEWS = ['inspector', 'crisp', 'operator']

function viewFromHash(): string {
  const id = globalThis.location?.hash.replace(/^#/, '') ?? ''
  return VIEWS.includes(id) ? id : 'inspector'
}

// Derive the poll-card state from the UI stage + ballot count. Specifically,
// when the input window has closed (uiStageIdx >= 4) but no ballots ever arrived,
// the committee isn't actually tallying anything — surface that as a distinct
// "idle" state instead of falsely claiming a tally is in progress.
const pollStateForStage = (uiStageIdx: number, ballotCount: number): string => {
  if (uiStageIdx >= 6) return 'published'
  if (uiStageIdx >= 4) return ballotCount === 0 ? 'idle' : 'computing'
  return 'open'
}

export default function App() {
  // View (tab) state. The view is mirrored into the URL hash so each tab is
  // linkable from outside — the docs site points at `#operator` for the ciphernode guide.
  const [view, setView] = useState(viewFromHash)
  const [nowMs, setNowMs] = useState(() => Date.now())

  // ─── On-chain data (selected network) ──────────────────────────────────────────────
  // CRISP tab: only CRISP-program polls. Inspector tab: every E3 on the network.
  const crispPolls = useCrispPolls()
  const allE3s = useAllE3s()
  const recentBallots = useRecentBallots()
  const networkStats = useNetworkStats()

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
  const liveHistory = useMemo(() => adaptHistoryEntries(pastPolls), [pastPolls])

  // Inspector tab state.
  const inspectorReady = allE3s.status === 'ready'
  const hasE3s = (allE3s.data?.length ?? 0) > 0
  const inspectorList = useMemo(() => adaptInspectorE3List(allE3s.data ?? []), [allE3s.data])
  const inspectorE3 = useMemo(() => adaptInspectorDetail(inspectorDetail.data), [inspectorDetail.data])

  useEffect(() => {
    const id = setInterval(() => setNowMs(Date.now()), 1000)
    return () => clearInterval(id)
  }, [])

  // Keep the view in sync with back/forward navigation and inbound deep links.
  useEffect(() => {
    const onHashChange = () => setView(viewFromHash())
    window.addEventListener('hashchange', onHashChange)
    return () => window.removeEventListener('hashchange', onHashChange)
  }, [])

  const navigate = (id: string) => {
    setView(id)
    // Writing the hash fires `hashchange`, which is a no-op here since the
    // state already matches — it just keeps the URL shareable.
    if (viewFromHash() !== id) window.location.hash = id
  }

  return (
    <div className={`page page--${DENSITY}`}>
      <Header density={DENSITY} view={view} onNav={navigate} />
      <Pulse
        data={{
          activeNow: activePolls.length,
          ballots24h: recentBallots,
          pollsAllTime: polls.length,
        }}
        network={networkStats}
      />
      {view === 'operator' ? (
        <main className='main'>
          <Operator />
        </main>
      ) : view === 'inspector' ? (
        <main className='main'>
          {allE3s.status === 'error' ? (
            <div className='inspector'>
              <StatusNote>Couldn't load E3s from {NETWORK_NAME}. Retrying automatically…</StatusNote>
            </div>
          ) : !inspectorReady ? (
            <div className='inspector'>
              <Loader label='Loading E3s' />
            </div>
          ) : !hasE3s ? (
            <div className='inspector'>
              <StatusNote>No active E3s yet. New requests will appear here onchain.</StatusNote>
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
            <StatusNote>Couldn't load CRISP polls from {NETWORK_NAME}. Retrying automatically…</StatusNote>
          ) : !crispReady ? (
            <Loader label='Loading CRISP polls' />
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
                      onNavigate={navigate}
                    />
                    <Timeline stages={STAGES} currentStageIdx={stageIdx} pollLabel={poll.displayId} density={DENSITY} />
                  </Fragment>
                )
              })}
            </>
          ) : (
            <StatusNote>No live CRISP polls right now.</StatusNote>
          )}

          {liveHistory.length > 0 && <History entries={liveHistory} onNavigate={navigate} />}
        </main>
      )}

      <SiteFooter />
    </div>
  )
}
