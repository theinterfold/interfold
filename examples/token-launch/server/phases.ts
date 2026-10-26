// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

/** `ITokenLaunch.Phase`. The contract derives it from the stage of the two E3s and from its own state. */
export enum SalePhase {
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

/**
 * What the keeper does for a sale in this phase: `publishProbes` once round 1 has its plaintext,
 * `clear` once round 2 has its plaintext, `settle` once the sale is cleared (a capped sale has
 * marginal claims to pay), and nothing for a sale that was aborted or failed. Every other phase
 * waits for the committee or for the input window.
 */
export function keeperStep(phase: SalePhase): 'publishProbes' | 'clear' | 'settle' | 'wait' | 'done' {
  switch (phase) {
    case SalePhase.Probing:
      return 'publishProbes'
    case SalePhase.Clearable:
      return 'clear'
    case SalePhase.Cleared:
      return 'settle'
    case SalePhase.Aborted:
    case SalePhase.Failed:
      return 'done'
    default:
      return 'wait'
  }
}

/**
 * Whether the compute of round 2 may start (the input window of both rounds is closed by now). It
 * needs the probes of round 1, which `publishProbes` writes into the config input of round 2: a run
 * before that would hold the pending config and the program refuses it. After `Round2` the compute
 * has no use, because the output is out or the sale ended.
 */
export function roundTwoGate(phase: SalePhase): 'ready' | 'wait' | 'never' {
  switch (phase) {
    case SalePhase.Round2:
      return 'ready'
    case SalePhase.Clearable:
    case SalePhase.Cleared:
    case SalePhase.Aborted:
    case SalePhase.Failed:
      return 'never'
    default:
      return 'wait'
  }
}
