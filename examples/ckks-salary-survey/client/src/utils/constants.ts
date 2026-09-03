// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

export const SURVEY_API: string = import.meta.env.VITE_SURVEY_API ?? 'http://127.0.0.1:8091'
export const ADMIN_KEY: string = import.meta.env.VITE_ADMIN_KEY ?? ''
export const CHAIN_ID: number = Number(import.meta.env.VITE_CHAIN_ID ?? 31337)
/** Optional explorer template, e.g. https://sepolia.etherscan.io/tx/ */
export const EXPLORER_TX: string = import.meta.env.VITE_EXPLORER_TX ?? ''

export const short = (h: string, n = 10): string => (h && h.length > 2 * n ? `${h.slice(0, n)}…${h.slice(-4)}` : h)
export const fmtMoney = (v: number): string => v.toLocaleString(undefined, { maximumFractionDigits: 2 })
export const fmtTime = (secs: number): string => (secs ? new Date(secs * 1000).toLocaleTimeString() : '—')
