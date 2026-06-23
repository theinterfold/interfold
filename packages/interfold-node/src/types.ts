// SPDX-License-Identifier: LGPL-3.0-only

export type ViewId = 'overview' | 'e3' | 'flow' | 'events' | 'logs' | 'updates'
export type E3PhaseId =
  | 'request'
  | 'committee'
  | 'dkg_setup'
  | 'dkg_shares'
  | 'key_publication'
  | 'computation'
  | 'decryption'
  | 'settlement'
export type EventSeverity = 'debug' | 'info' | 'warn' | 'error'
export type EventSource = 'local' | 'network' | 'evm'

export interface DashboardChain {
  id: number
  name: string
}

export interface DashboardRuntime {
  node_name: string
  address: string
  peer_id: string
  quic_port: number
  dashboard_port: number
  version: string
  chains: DashboardChain[]
}

export interface ConnectedPeer {
  peer_id: string
  remote_address: string
  direction: string
  connections: number
  connected_at_ms: number
}

export interface NetworkSnapshot {
  configured_peers: number
  connected_peers: ConnectedPeer[]
  listen_addresses: string[]
  last_error?: string
}

export interface RewardView {
  account: string
  token?: string
  amount: string
  claimed: boolean
}

export interface ChainOperatorView {
  chain_id: number
  registered_nodes: number
  active_nodes: number
  operator_registered: boolean
  operator_active: boolean
  ticket_balance?: string
  license_bond?: string
  exit_unlock_at?: number
  rewards_credited: RewardView[]
}

export interface ProtocolOverview {
  chains: ChainOperatorView[]
  e3_total: number
  e3_active: number
  e3_completed: number
  e3_failed: number
  events_observed: number
}

export interface OperatorChainStatus {
  chain_id: number
  chain_name: string
  registered_nodes: string
  active_nodes: string
  operator_registered: boolean
  operator_active: boolean
  exit_in_progress: boolean
  ticket_balance: string
  available_tickets: string
  license_bond: string
}

export interface OperatorStatusSnapshot {
  chains: OperatorChainStatus[]
  error?: string
  updated_at_ms: number
}

export interface EventView {
  seq: number
  aggregate_id: number
  timestamp_us: number
  logical_counter: number
  producer_fingerprint: string
  block?: number
  source: EventSource
  producer: string
  event_type: string
  e3_id?: string
  phase?: E3PhaseId
  severity: EventSeverity
  event_id: string
  causation_id: string
  origin_id: string
  payload: unknown
}

export interface E3Summary {
  e3_id: string
  chain_id: number
  status: 'active' | 'complete' | 'failed'
  current_phase: E3PhaseId
  event_count: number
  error_count: number
  warning_count: number
  committee_size: number
  first_seen_us: number
  last_seen_us: number
}

export interface SourceCounts {
  local: number
  net: number
  evm: number
}

export interface PhaseView {
  id: E3PhaseId
  label: string
  state: 'pending' | 'active' | 'complete' | 'failed'
  event_count: number
  sources: SourceCounts
  errors: number
  warnings: number
}

export interface CommitteeMemberView {
  address: string
  party_id: number
  score?: string
  expelled: boolean
}

export interface TicketView {
  node: string
  ticket_id: number
  score: string
}

export interface E3Trace extends E3Summary {
  phases: PhaseView[]
  committee: CommitteeMemberView[]
  tickets: TicketView[]
  rewards: RewardView[]
  failure?: unknown
  events: EventView[]
}

export interface DashboardSnapshot {
  node: DashboardRuntime
  network: NetworkSnapshot
  protocol: ProtocolOverview
  operator: OperatorStatusSnapshot
  e3s: E3Summary[]
  recent_events: EventView[]
}

export interface EventsResponse {
  events: EventView[]
}

export interface LogEntry {
  seq: number
  timestamp_ms: number
  level: string
  target: string
  message: string
  node: string
  fields?: Record<string, unknown>
}

export interface LogResponse {
  entries: LogEntry[]
  next_cursor: number
  oldest_cursor: number
  total_stored: number
}

export interface ReleaseInfo {
  tag: string
  name: string
  url: string
  published_at?: string
  notes: string
}

export interface UpdateSnapshot {
  current_version: string
  latest?: ReleaseInfo
  update_available: boolean
  releases_url: string
  checked_at_ms: number
  error?: string
}
