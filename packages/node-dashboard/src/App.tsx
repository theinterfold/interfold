// SPDX-License-Identifier: LGPL-3.0-only
import { useMemo, useState, useEffect } from 'react'
import type { TabId } from './types'
import { useEvents } from './hooks/useEvents'
import { useNodeInfo } from './hooks/useNodeInfo'
import { buildE3Map } from './lib/events'
import Header from './components/Header'
import StreamTab from './tabs/StreamTab'
import PipelineTab from './tabs/PipelineTab'
import EventsTab from './tabs/EventsTab'
import FlowTab from './tabs/FlowTab'
import NodeTab from './tabs/NodeTab'

const TABS: { id: TabId; label: string }[] = [
  { id: 'flow', label: 'Flow' },
  { id: 'pipeline', label: 'Pipeline' },
  { id: 'events', label: 'Events' },
  { id: 'stream', label: 'Stream' },
  { id: 'node', label: 'Node' },
]

export default function App() {
  const [activeTab, setActiveTab] = useState<TabId>('flow')
  const { allEvents, eventCursor, connected, loadMore } = useEvents()
  const { info, status, loadInfo, loadStatus } = useNodeInfo()

  const e3s = useMemo(() => buildE3Map(allEvents), [allEvents])

  // Load node info + status when Node tab is first opened
  useEffect(() => {
    if (activeTab === 'node' && !info) {
      loadInfo()
        .then(() => loadStatus())
        .catch(() => undefined)
    }
  }, [activeTab, info, loadInfo, loadStatus])

  const nodeName = info?.name ?? 'Node'

  return (
    <>
      <Header nodeName={nodeName} e3Count={Object.keys(e3s).length} eventCount={allEvents.length} connected={connected} />
      <nav className='tab-nav'>
        {TABS.map((t) => (
          <button key={t.id} className={`tab-btn${activeTab === t.id ? ' active' : ''}`} onClick={() => setActiveTab(t.id)}>
            {t.label}
          </button>
        ))}
      </nav>
      <main className='main-content'>
        {activeTab === 'flow' && <FlowTab events={allEvents} />}
        {activeTab === 'pipeline' && <PipelineTab e3s={e3s} />}
        {activeTab === 'events' && <EventsTab events={allEvents} cursor={eventCursor} onLoadMore={loadMore} />}
        {activeTab === 'stream' && <StreamTab events={allEvents} />}
        {activeTab === 'node' && <NodeTab info={info} status={status} />}
      </main>
    </>
  )
}
