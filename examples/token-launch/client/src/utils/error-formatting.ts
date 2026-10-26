// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

/** The most specific human-readable message viem or the SDK gave us. */
export function formatError(error: unknown): string {
  if (error instanceof Error) {
    return 'shortMessage' in error && typeof error.shortMessage === 'string' ? error.shortMessage : error.message
  }
  return String(error)
}

export function shorten(hex: string, head = 10, tail = 8): string {
  return hex.length <= head + tail + 3 ? hex : `${hex.slice(0, head)}…${hex.slice(-tail)}`
}
