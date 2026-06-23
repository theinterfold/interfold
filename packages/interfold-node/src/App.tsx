// SPDX-License-Identifier: LGPL-3.0-only

import { useEffect, useState } from 'react'
import { useSnapshot, useUpdates } from './api'
import type { ViewId } from './types'
import EventsView from './views/EventsView'
import FlowGraphView from './views/FlowGraphView'
import E3Inspector from './views/E3Inspector'
import LogsView from './views/LogsView'
import Overview from './views/Overview'
import UpdatesView from './views/UpdatesView'
import './App.css'

const NAV: Array<{ id: ViewId; label: string }> = [
  { id: 'overview', label: 'Overview' },
  { id: 'e3', label: 'E3 traces' },
  { id: 'flow', label: 'Flow graph' },
  { id: 'events', label: 'Events' },
  { id: 'logs', label: 'Logs' },
  { id: 'updates', label: 'Updates' },
]

function initialView(): ViewId {
  const hash = window.location.hash.slice(1)
  return NAV.some((item) => item.id === hash) ? (hash as ViewId) : 'overview'
}

function ShellHeader({
  view,
  setView,
  nodeName,
  connected,
  updateAvailable,
}: {
  view: ViewId
  setView: (view: ViewId) => void
  nodeName?: string
  connected: boolean
  updateAvailable: boolean
}) {
  const navigate = (next: ViewId) => {
    window.history.replaceState(null, '', `#${next}`)
    setView(next)
  }
  return (
    <header className='site-head'>
      <div className='site-head__inner'>
        <button className='wordmark' type='button' aria-label='Interfold node overview' onClick={() => navigate('overview')}>
          <span />
        </button>
        <span className='product-name'>Node observatory</span>
        <nav className='site-nav' aria-label='Dashboard views'>
          {NAV.map((item) => (
            <button
              type='button'
              className={view === item.id ? 'site-nav__link site-nav__link--on' : 'site-nav__link'}
              onClick={() => navigate(item.id)}
              key={item.id}
            >
              {item.label}
              {item.id === 'updates' && updateAvailable && <span className='nav-update-dot' />}
            </button>
          ))}
        </nav>
        <div className='node-chip'>
          <span className={connected ? 'node-chip__dot' : 'node-chip__dot node-chip__dot--waiting'} />
          <span>{nodeName ?? 'Connecting…'}</span>
        </div>
      </div>
    </header>
  )
}

function LoadingState({ error }: { error?: string }) {
  return (
    <main className='loading-page'>
      <span className='loader-ring' />
      <h1>{error ? 'The node API is unavailable' : 'Building the node picture'}</h1>
      <p>{error ?? 'Reading protocol history and live transport state…'}</p>
    </main>
  )
}

export default function App() {
  const [view, setView] = useState<ViewId>(initialView)
  const [selectedE3, setSelectedE3] = useState<string>()
  const snapshot = useSnapshot()
  const updates = useUpdates()

  // Auto-select the first E3 when data first loads and none is selected.
  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect
    if (!selectedE3 && snapshot.data?.e3s[0]) setSelectedE3(snapshot.data.e3s[0].e3_id)
  }, [selectedE3, snapshot.data?.e3s])

  const connected = Boolean(snapshot.data && !snapshot.error)
  return (
    <div className='page'>
      <ShellHeader
        view={view}
        setView={setView}
        nodeName={snapshot.data?.node.node_name}
        connected={connected}
        updateAvailable={Boolean(updates.data?.update_available)}
      />
      {!snapshot.data ? (
        <LoadingState error={snapshot.error} />
      ) : (
        <>
          <div className={view === 'e3' ? 'app-main app-main--inspector' : 'app-main'}>
            {snapshot.error && (
              <div className='stale-banner'>Live refresh paused: {snapshot.error}. Showing the last successful snapshot.</div>
            )}
            {view === 'overview' && <Overview snapshot={snapshot.data} />}
            {view === 'e3' && (
              <E3Inspector
                e3s={snapshot.data.e3s}
                selected={selectedE3}
                onSelect={setSelectedE3}
                refreshKey={snapshot.data.protocol.events_observed}
              />
            )}
            {view === 'flow' && (
              <FlowGraphView
                e3s={snapshot.data.e3s}
                selectedE3={selectedE3}
                onSelectE3={setSelectedE3}
                refreshKey={snapshot.data.protocol.events_observed}
              />
            )}
            {view === 'events' && <EventsView />}
            {view === 'logs' && <LogsView />}
            {view === 'updates' && <UpdatesView updates={updates} activeE3s={snapshot.data.protocol.e3_active} />}
          </div>
          <footer className='site-foot'>
            <span>Local operator surface · bound to 127.0.0.1</span>
            <span className='mono'>Interfold {snapshot.data.node.version}</span>
          </footer>
        </>
      )}
    </div>
  )
}
