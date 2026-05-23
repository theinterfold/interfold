// SPDX-License-Identifier: LGPL-3.0-only
import type { NodeInfo, NodeStatus } from '../hooks/useNodeInfo'

interface NodeTabProps {
  info: NodeInfo | null
  status: NodeStatus | null
}

function tryPretty(raw: string): string {
  try {
    return JSON.stringify(JSON.parse(raw), null, 2)
  } catch {
    return raw
  }
}

export default function NodeTab({ info, status }: NodeTabProps) {
  return (
    <div className='tab-pane node-pane'>
      <section className='info-section'>
        <h3 className='section-title'>Node info</h3>
        {!info ? (
          <div className='empty-state'>Loading…</div>
        ) : (
          <dl className='info-grid'>
            <dt>Name</dt>
            <dd>{info.name}</dd>
            <dt>Address</dt>
            <dd>
              <code>{info.address}</code>
            </dd>
            <dt>Peer ID</dt>
            <dd>
              <code>{info.peer}</code>
            </dd>
            <dt>QUIC port</dt>
            <dd>{info.quicPort}</dd>
            <dt>Ctrl port</dt>
            <dd>{info.ctrlPort}</dd>
          </dl>
        )}
      </section>

      {status && (
        <>
          <section className='info-section'>
            <h3 className='section-title'>Status</h3>
            <pre className='json-pre'>{tryPretty(status.status)}</pre>
          </section>
          <section className='info-section'>
            <h3 className='section-title'>Wallet</h3>
            <pre className='json-pre'>{tryPretty(status.wallet)}</pre>
          </section>
          <section className='info-section'>
            <h3 className='section-title'>Noir / ZK</h3>
            <pre className='json-pre'>{tryPretty(status.noir)}</pre>
          </section>
        </>
      )}
    </div>
  )
}
