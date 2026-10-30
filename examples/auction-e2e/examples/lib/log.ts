// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

/** Print a transcript line with the time since the start of the run: `[ 12m34s] text`. */
export function createLog(): { say: (text: string) => void; heading: (text: string) => void; since: () => number } {
  const start = Date.now()
  const since = () => (Date.now() - start) / 1000
  const stamp = () => {
    const s = Math.round(since())
    return `${Math.floor(s / 60)}m${String(s % 60).padStart(2, '0')}s`.padStart(7)
  }
  return {
    say: (text) => console.log(`[${stamp()}] ${text}`),
    heading: (text) => console.log(`\n== ${text} ==`),
    since,
  }
}

/** Seconds as `8m06s` (or `42s`). */
export function formatSeconds(seconds: number): string {
  const s = Math.round(seconds)
  return s >= 60 ? `${Math.floor(s / 60)}m${String(s % 60).padStart(2, '0')}s` : `${s}s`
}

/** Wait `ms` milliseconds. */
export const sleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms))

/** Call `read` every `intervalMs` until it returns a value. Throws on timeout. */
export async function waitFor<T>(
  what: string,
  read: () => Promise<T | undefined> | T | undefined,
  timeoutMs: number,
  intervalMs = 2000,
): Promise<T> {
  const deadline = Date.now() + timeoutMs
  for (;;) {
    const value = await read()
    if (value !== undefined) return value
    if (Date.now() > deadline) throw new Error(`Timed out after ${formatSeconds(timeoutMs / 1000)} while waiting for ${what}`)
    await sleep(intervalMs)
  }
}
