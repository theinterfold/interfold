// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

/** The `phase(saleId)` enum of the program contract, in its order. */
export enum Phase {
  None,
  Bidding,
  Round1,
  Probing,
  Round2,
  Clearable,
  Cleared,
  Aborted,
  Failed,
}

/** The stages that the timeline shows, in the order a sale passes through them. */
export const TIMELINE = [Phase.Bidding, Phase.Round1, Phase.Probing, Phase.Round2, Phase.Cleared] as const

export const PHASE_LABELS: Record<Phase, string> = {
  [Phase.None]: 'Unknown',
  [Phase.Bidding]: 'Bidding',
  [Phase.Round1]: 'Round 1',
  [Phase.Probing]: 'Probing',
  [Phase.Round2]: 'Round 2',
  [Phase.Clearable]: 'Ready to clear',
  [Phase.Cleared]: 'Cleared',
  [Phase.Aborted]: 'Stopped',
  [Phase.Failed]: 'Failed',
}

/** A sale that ended without a clearing: bidders and the creator take their funds back. */
export const isRefundPhase = (phase: Phase): boolean => phase === Phase.Aborted || phase === Phase.Failed

/** A sale that still accepts or awaits work before its result. */
export const isRunning = (phase: Phase): boolean => phase >= Phase.Bidding && phase <= Phase.Clearable

/** The position of `phase` in the timeline; `Clearable` is the last step of round 2 and a clearing is next. */
export function timelineIndex(phase: Phase): number {
  if (phase === Phase.Clearable) return TIMELINE.indexOf(Phase.Cleared)
  return TIMELINE.findIndex((stage) => stage === phase)
}

/** "1h 05m", "4m 10s" or "0s" for a span in seconds. */
export function formatDuration(seconds: bigint): string {
  const total = Number(seconds > 0n ? seconds : 0n)
  const hours = Math.floor(total / 3600)
  const minutes = Math.floor((total % 3600) / 60)
  const rest = total % 60
  if (hours > 0) return `${hours}h ${String(minutes).padStart(2, '0')}m`
  if (minutes > 0) return `${minutes}m ${String(rest).padStart(2, '0')}s`
  return `${rest}s`
}
