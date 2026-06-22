// SPDX-License-Identifier: LGPL-3.0-only

import { useState } from 'react'
import type { QueryState } from '../api'
import type { UpdateSnapshot } from '../types'

export default function UpdatesView({ updates, activeE3s }: { updates: QueryState<UpdateSnapshot>; activeE3s: number }) {
  const [copied, setCopied] = useState(false)
  const copyUpdate = () => {
    void navigator.clipboard.writeText('interfoldup update').then(() => {
      setCopied(true)
      window.setTimeout(() => setCopied(false), 1_500)
    })
  }
  const data = updates.data
  return (
    <div className='view-stack'>
      <header className='view-title'>
        <div>
          <span className='section-kicker'>Operator continuity</span>
          <h1>Updates and release desk</h1>
          <p>Release awareness and a deliberately manual, auditable upgrade path. The dashboard never replaces a running binary itself.</p>
        </div>
      </header>

      <div className='update-grid'>
        <section className='panel update-status'>
          <span className={`update-orbit ${data?.update_available ? 'update-orbit--available' : ''}`}>
            <i />
          </span>
          <div>
            <span className='section-kicker'>Installed</span>
            <h2>Interfold {data?.current_version ?? '…'}</h2>
            <p>
              {data?.update_available
                ? `${data.latest?.tag ?? 'A newer release'} is available.`
                : data?.latest
                  ? `This node matches the latest stable release, ${data.latest.tag}.`
                  : 'Checking the release channel…'}
            </p>
            {(data?.error || updates.error) && <div className='alert alert--warning'>{data?.error ?? updates.error}</div>}
          </div>
        </section>

        <section className='panel safe-update'>
          <header className='panel__head'>
            <div>
              <span className='section-kicker'>Runbook</span>
              <h2>Safe update sequence</h2>
            </div>
            <span className={`status-tag status-tag--${activeE3s ? 'active' : 'complete'}`}>
              {activeE3s ? `${activeE3s} active E3` : 'Safe window'}
            </span>
          </header>
          <ol className='update-steps'>
            <li>
              <strong>Wait for active work.</strong>
              <span>
                {activeE3s
                  ? 'Do not stop yet; let the active E3s settle unless this is an emergency.'
                  : 'No active E3 is currently projected.'}
              </span>
            </li>
            <li>
              <strong>Stop gracefully.</strong>
              <span>Send SIGTERM or Ctrl+C and wait for “Graceful shutdown complete.”</span>
            </li>
            <li>
              <strong>Install the release.</strong>
              <button type='button' className='copy-command mono' onClick={copyUpdate}>
                {copied ? 'Copied' : 'interfoldup update'}
              </button>
            </li>
            <li>
              <strong>Restart identically.</strong>
              <span>Use the same service account, configuration, database, and event-log paths.</span>
            </li>
            <li>
              <strong>Verify recovery.</strong>
              <span>Confirm version, peers, operator state, and the resumed E3 stage before leaving the node unattended.</span>
            </li>
          </ol>
        </section>
      </div>

      <section className='panel panel--wide release-notes'>
        <header className='panel__head'>
          <div>
            <span className='section-kicker'>Release channel</span>
            <h2>{data?.latest?.name ?? 'Latest stable release'}</h2>
          </div>
          <a href={data?.latest?.url ?? data?.releases_url} target='_blank' rel='noreferrer'>
            Open on GitHub ↗
          </a>
        </header>
        {data?.latest?.published_at && <p className='release-date'>Published {new Date(data.latest.published_at).toLocaleString()}</p>}
        <pre>{data?.latest?.notes || 'Release notes will appear here when GitHub is reachable.'}</pre>
      </section>
    </div>
  )
}
