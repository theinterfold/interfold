// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { E3Stage } from '@interfold/sdk/contracts'

/** What the chain says about the compute of one E3. All times are chain time, in seconds. */
export interface E3Window {
  stage: E3Stage
  /** The timestamp of the latest block. */
  now: bigint
  computeDeadline: bigint
}

/**
 * Whether Interfold still accepts a ciphertext output for this E3. The stored stage stays
 * `KeyPublished` after the compute deadline until someone marks the E3 failed, so the deadline has
 * to be checked on its own. Interfold rejects an output when `computeDeadline < block.timestamp`.
 */
export function computeWindowOpen(window: E3Window): boolean {
  return window.stage === E3Stage.KeyPublished && window.now <= window.computeDeadline
}

/** A short reason for a closed window, for logs and records. */
export function closedReason(window: E3Window): string {
  if (window.stage !== E3Stage.KeyPublished) return `the E3 is in stage ${E3Stage[window.stage]}`
  return `the compute deadline ${window.computeDeadline} has passed (chain time ${window.now})`
}
