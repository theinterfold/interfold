// SPDX-License-Identifier: LGPL-3.0-only

import type { BidRecord, Profile } from '../types'

export function defer(task: () => void): void {
  window.setTimeout(task, 0)
}

export function readBidRecords(key: string): BidRecord[] {
  try {
    const raw = localStorage.getItem(key)
    return raw ? (JSON.parse(raw) as BidRecord[]) : []
  } catch {
    return []
  }
}

export function writeBidRecords(key: string, bids: BidRecord[]): void {
  localStorage.setItem(key, JSON.stringify(bids))
}

export function readProfiles(key: string): Profile[] {
  try {
    const raw = localStorage.getItem(key)
    return raw ? (JSON.parse(raw) as Profile[]) : []
  } catch {
    return []
  }
}

export function writeProfiles(key: string, profiles: Profile[]): void {
  localStorage.setItem(key, JSON.stringify(profiles))
}

export async function fetchJson<T>(url: string): Promise<T> {
  const response = await fetch(url, { cache: 'no-store' })
  if (!response.ok) throw new Error(`${url} returned ${response.status}`)
  return (await response.json()) as T
}
