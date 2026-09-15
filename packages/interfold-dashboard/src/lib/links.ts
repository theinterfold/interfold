// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
// External destinations. Only URLs we can verify (from the repo's docs/llms.txt,
// README, and the selected network's block explorer) — no guessed paths.

import { EXPLORER_URL } from './chain'

export const LINKS = {
  site: 'https://theinterfold.com/',
  blog: 'https://blog.theinterfold.com/',
  docs: 'https://docs.theinterfold.com/introduction',
  architecture: 'https://docs.theinterfold.com/architecture-overview',
  crisp: 'https://docs.theinterfold.com/CRISP/introduction',
  repo: 'https://github.com/theinterfold/interfold',
  explorer: EXPLORER_URL,
} as const

export function explorerAddress(address: string): string {
  return `${LINKS.explorer}/address/${address}`
}

export function explorerTx(txHash: string): string {
  return `${LINKS.explorer}/tx/${txHash}`
}
