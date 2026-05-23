// SPDX-License-Identifier: LGPL-3.0-only

export interface EventCtx {
  id?: string // 0x-prefixed hex, globally unique per event
  seq: number
  ts: string // HLC u128 stringified
  source: 'Local' | 'Net' | 'Evm' | string
  aggregate_id?: number // per-store aggregate identifier
}

export interface ParsedEvent {
  ctx: EventCtx
  payload: Record<string, unknown>
}

export interface E3Entry {
  stepIdx: number
  latestTs: string
  evLog: Array<{ type: string; ts: string; src: string }>
  error: boolean
}

export type TabId = 'flow' | 'stream' | 'pipeline' | 'events' | 'node'
