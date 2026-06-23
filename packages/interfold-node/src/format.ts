// SPDX-License-Identifier: LGPL-3.0-only

export function short(value?: string, head = 8, tail = 5): string {
  if (!value || value.length <= head + tail + 2) return value ?? '—'
  return `${value.slice(0, head)}…${value.slice(-tail)}`
}

export function eventTime(timestampUs: number): string {
  if (!timestampUs) return '—'
  return new Intl.DateTimeFormat(undefined, {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    fractionalSecondDigits: 3,
  }).format(new Date(timestampUs / 1_000))
}

export function absoluteTime(timestampUs: number): string {
  return new Date(timestampUs / 1_000).toLocaleString()
}

export function number(value: number): string {
  return new Intl.NumberFormat().format(value)
}

export function compactInteger(value?: string): string {
  if (!value) return '—'
  try {
    const integer = BigInt(value)
    if (integer < 1_000_000n) return integer.toLocaleString()
    const digits = integer.toString().length
    const unit = digits > 18 ? 'e18+' : digits > 12 ? 'T+' : digits > 9 ? 'B+' : 'M+'
    return `${integer.toString().slice(0, 4)}… ${unit}`
  } catch {
    return value
  }
}

export function json(value: unknown): string {
  return JSON.stringify(value, null, 2)
}
