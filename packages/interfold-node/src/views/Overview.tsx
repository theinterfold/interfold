// SPDX-License-Identifier: LGPL-3.0-only

import EventTimeline from '../components/EventTimeline'
import { compactInteger, number, short } from '../format'
import type { DashboardSnapshot } from '../types'

interface OperatorCard {
  chainId: number
  chainName: string
  registeredNodes: string
  activeNodes: string
  registered: boolean
  active: boolean
  exitInProgress: boolean
  ticketBalance?: string
  availableTickets?: string
  licenseBond?: string
  rewardCredits: number
}

function sumIntegerStrings(values: string[]): string {
  try {
    return values.reduce((sum, value) => sum + BigInt(value), 0n).toLocaleString()
  } catch {
    return '—'
  }
}

function Metric({ label, value, note, tone }: { label: string; value: string | number; note: string; tone?: string }) {
  return (
    <div className={`metric ${tone ? `metric--${tone}` : ''}`}>
      <span className='metric__label'>{label}</span>
      <strong className='metric__value'>{typeof value === 'number' ? number(value) : value}</strong>
      <span className='metric__note'>{note}</span>
    </div>
  )
}

export default function Overview({ snapshot }: { snapshot: DashboardSnapshot }) {
  const { node, network, operator, protocol } = snapshot
  const liveChains = new Map(operator.chains.map((chain) => [chain.chain_id, chain]))
  const projectedChains = new Map(protocol.chains.map((chain) => [chain.chain_id, chain]))
  const chainIds = new Set([
    ...node.chains.map((chain) => chain.id),
    ...operator.chains.map((chain) => chain.chain_id),
    ...protocol.chains.map((chain) => chain.chain_id),
  ])
  const operatorCards: OperatorCard[] = [...chainIds]
    .sort((left, right) => left - right)
    .map((chainId) => {
      const live = liveChains.get(chainId)
      const projected = projectedChains.get(chainId)
      return {
        chainId,
        chainName: live?.chain_name ?? node.chains.find((chain) => chain.id === chainId)?.name ?? `Chain ${chainId}`,
        registeredNodes: live?.registered_nodes ?? String(projected?.registered_nodes ?? 0),
        activeNodes: live?.active_nodes ?? String(projected?.active_nodes ?? 0),
        registered: live?.operator_registered ?? projected?.operator_registered ?? false,
        active: live?.operator_active ?? projected?.operator_active ?? false,
        exitInProgress: live?.exit_in_progress ?? projected?.exit_unlock_at !== undefined,
        ticketBalance: live?.ticket_balance ?? projected?.ticket_balance,
        availableTickets: live?.available_tickets,
        licenseBond: live?.license_bond ?? projected?.license_bond,
        rewardCredits: projected?.rewards_credited.length ?? 0,
      }
    })
  const totalNodes = sumIntegerStrings(operatorCards.map((chain) => chain.registeredNodes))
  const totalActive = sumIntegerStrings(operatorCards.map((chain) => chain.activeNodes))
  return (
    <div className='view-stack'>
      <section className='view-intro'>
        <div>
          <div className='eyebrow'>
            <span className='live-dot' /> Node online · {node.node_name}
          </div>
          <h1>Everything your ciphernode knows, in one place.</h1>
          <p>Live transport health, durable protocol history, and causal E3 traces projected from this node’s own EventStore.</p>
        </div>
        <div className='identity-card'>
          <span>Operator identity</span>
          <strong className='mono' title={node.address}>
            {short(node.address, 12, 8)}
          </strong>
          <span className='mono' title={node.peer_id}>
            {short(node.peer_id, 13, 8)}
          </span>
        </div>
      </section>

      <section className='metrics-grid'>
        <Metric
          label='Network reach'
          value={`${network.connected_peers.length}/${network.configured_peers}`}
          note='connected / configured peers'
          tone={network.last_error ? 'bad' : 'good'}
        />
        <Metric label='Registered nodes' value={totalNodes} note={`${totalActive} currently active`} />
        <Metric label='E3 workload' value={protocol.e3_total} note={`${protocol.e3_active} active · ${protocol.e3_completed} complete`} />
        <Metric label='Durable events' value={protocol.events_observed} note='observed across all aggregates' />
      </section>

      <div className='overview-grid'>
        <section className='panel'>
          <header className='panel__head'>
            <div>
              <span className='section-kicker'>Transport</span>
              <h2>Connected nodes</h2>
            </div>
            <span className={`health-pill ${network.last_error ? 'health-pill--bad' : ''}`}>
              {network.last_error ? 'Attention' : 'Healthy'}
            </span>
          </header>
          {network.connected_peers.length ? (
            <div className='peer-list'>
              {network.connected_peers.map((peer) => (
                <div className='peer-row' key={peer.peer_id}>
                  <span className='peer-row__status' />
                  <div>
                    <strong className='mono'>{short(peer.peer_id, 12, 7)}</strong>
                    <span className='mono'>{short(peer.remote_address, 22, 10)}</span>
                  </div>
                  <span className='peer-row__direction'>
                    {peer.direction} · {peer.connections} conn.
                  </span>
                </div>
              ))}
            </div>
          ) : (
            <div className='empty-inline'>No live peer connections. The node will keep dialing its configured peers.</div>
          )}
          {network.last_error && <div className='alert alert--warning'>{network.last_error}</div>}
          <div className='listen-addresses'>
            <span>Listening</span>
            {network.listen_addresses.map((address) => (
              <code key={address}>{address}</code>
            ))}
            {!network.listen_addresses.length && <code>UDP / QUIC {node.quic_port}</code>}
          </div>
        </section>

        <section className='panel'>
          <header className='panel__head'>
            <div>
              <span className='section-kicker'>On-chain position</span>
              <h2>Operator state</h2>
            </div>
          </header>
          <div className='chain-list'>
            {operatorCards.map((chain) => (
              <div className='chain-card' key={chain.chainId}>
                <div className='chain-card__head'>
                  <strong>{chain.chainName}</strong>
                  <span className={`status-tag status-tag--${chain.active ? 'complete' : chain.registered ? 'active' : 'pending'}`}>
                    {chain.exitInProgress ? 'Exit queued' : chain.active ? 'Active' : chain.registered ? 'Registered' : 'Not registered'}
                  </span>
                </div>
                <dl className='mini-dl'>
                  <div>
                    <dt>Available tickets</dt>
                    <dd className='mono' title={chain.availableTickets}>
                      {compactInteger(chain.availableTickets)}
                    </dd>
                  </div>
                  <div>
                    <dt>Ticket balance</dt>
                    <dd className='mono' title={chain.ticketBalance}>
                      {compactInteger(chain.ticketBalance)}
                    </dd>
                  </div>
                  <div>
                    <dt>License bond</dt>
                    <dd className='mono' title={chain.licenseBond}>
                      {compactInteger(chain.licenseBond)}
                    </dd>
                  </div>
                  <div>
                    <dt>Network</dt>
                    <dd>
                      {chain.activeNodes} / {chain.registeredNodes} active
                    </dd>
                  </div>
                  <div>
                    <dt>Rewards</dt>
                    <dd>{chain.rewardCredits} credits</dd>
                  </div>
                </dl>
              </div>
            ))}
            {!operatorCards.length && <div className='empty-inline'>Waiting for on-chain registry state to sync.</div>}
            {operator.error && <div className='alert alert--warning'>{operator.error}</div>}
          </div>
        </section>
      </div>

      <section className='panel panel--wide'>
        <header className='panel__head'>
          <div>
            <span className='section-kicker'>Live activity</span>
            <h2>Latest protocol events</h2>
          </div>
          <span className='panel__aside'>Newest first</span>
        </header>
        <EventTimeline
          events={snapshot.recent_events.slice(0, 12)}
          empty='The EventStore is synced; no protocol events have been observed yet.'
        />
      </section>
    </div>
  )
}
