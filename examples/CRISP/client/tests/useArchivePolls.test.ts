// SPDX-License-Identifier: LGPL-3.0-only
import { afterEach, expect, it, vi } from 'vitest'
import { createElement, useLayoutEffect } from 'react'
import { act, create, type ReactTestRenderer } from 'react-test-renderer'
import { useArchivePolls } from '../src/hooks/voting/useArchivePolls'
import type { ArchivePage, PollRequestResult } from '../src/model/poll.model'

let renderer: ReactTestRenderer | undefined
let archive: ReturnType<typeof useArchivePolls>
function Probe({ fetchPage }: { fetchPage: (cursor?: string) => Promise<ArchivePage | undefined> }) {
  const value = useArchivePolls(fetchPage)
  useLayoutEffect(() => {
    archive = value
  })
  return null
}
const row = (round_id: string): PollRequestResult => ({
  round_id,
  tally: [1, 0],
  option_1_emoji: 'one',
  option_2_emoji: 'two',
  end_time: 1,
  total_votes: 1,
})
afterEach(() => {
  act(() => renderer?.unmount())
  renderer = undefined
})

it('shows loaded rows immediately and requests the next cursor only once', async () => {
  let resolve!: (page: ArchivePage) => void
  const fetchPage = vi
    .fn()
    .mockResolvedValueOnce({ items: [row('1')], next_cursor: 'v1:2' })
    .mockImplementationOnce(
      () =>
        new Promise<ArchivePage>((done) => {
          resolve = done
        }),
    )
  await act(async () => {
    renderer = create(createElement(Probe, { fetchPage }))
  })
  expect(archive.items.map((item) => item.round_id)).toEqual(['1'])
  let pending!: Promise<void>
  act(() => {
    pending = archive.loadMore()
    void archive.loadMore()
  })
  expect(fetchPage).toHaveBeenCalledTimes(2)
  expect(fetchPage).toHaveBeenLastCalledWith('v1:2')
  expect(archive.items).toHaveLength(1)
  await act(async () => {
    resolve({ items: [row('1'), row('340282366920938463463374607431768211456')], next_cursor: null })
    await pending
  })
  expect(archive.items).toHaveLength(2)
  expect(archive.hasMore).toBe(false)
})

it('retains the cursor after a failure and allows a retry', async () => {
  const fetchPage = vi
    .fn()
    .mockResolvedValueOnce({ items: [], next_cursor: 'v1:5' })
    .mockRejectedValueOnce(new Error('Offline'))
    .mockResolvedValueOnce({ items: [row('5')], next_cursor: null })
  await act(async () => {
    renderer = create(createElement(Probe, { fetchPage }))
  })
  await act(async () => {
    await archive.loadMore()
  })
  expect(archive.error).toContain('Try again')
  expect(archive.hasMore).toBe(true)
  await act(async () => {
    await archive.loadMore()
  })
  expect(fetchPage.mock.calls.slice(1)).toEqual([['v1:5'], ['v1:5']])
  expect(archive.items[0].round_id).toBe('5')
  expect(archive.error).toBeNull()
})

it('discards late results after changing the data source or unmounting', async () => {
  let resolve!: (page: ArchivePage) => void
  const oldFetch = vi.fn(
    () =>
      new Promise<ArchivePage>((done) => {
        resolve = done
      }),
  )
  const newFetch = vi.fn().mockResolvedValue({ items: [row('new')], next_cursor: null })
  act(() => {
    renderer = create(createElement(Probe, { fetchPage: oldFetch }))
  })
  await act(async () => {
    renderer!.update(createElement(Probe, { fetchPage: newFetch }))
  })
  await act(async () => {
    resolve({ items: [row('old')], next_cursor: null })
    await Promise.resolve()
  })
  expect(archive.items.map((item) => item.round_id)).toEqual(['new'])
})
