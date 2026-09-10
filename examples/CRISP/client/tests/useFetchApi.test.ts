// SPDX-License-Identifier: LGPL-3.0-only
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { createElement, useLayoutEffect } from 'react'
import { act, create, type ReactTestRenderer } from 'react-test-renderer'
import axios from 'axios'
import { useApi } from '../src/hooks/generic/useFetchApi'

vi.mock('axios', () => ({
  default: { request: vi.fn(), isAxiosError: (error: { isAxiosError?: boolean }) => error.isAxiosError === true },
}))
vi.mock('@/utils/handle-generic-error', () => ({ handleGenericError: vi.fn() }))
let api: ReturnType<typeof useApi>
let renderer: ReactTestRenderer
function Probe() {
  const value = useApi()
  useLayoutEffect(() => {
    api = value
  })
  return null
}
beforeEach(() => {
  vi.mocked(axios.request).mockReset()
  act(() => {
    renderer = create(createElement(Probe))
  })
})
afterEach(() => act(() => renderer.unmount()))

it.each(['get', 'GET', 'post', 'PUT', 'PATCH', 'DELETE', 'HEAD'] as const)('dispatches %s without changing it to POST', async (method) => {
  vi.mocked(axios.request).mockResolvedValue({ data: { ok: true } })
  let response: unknown
  await act(async () => {
    response = await api.fetchData('/round', method, { id: 1 }, { timeout: 500, params: { page: 2 } })
  })
  expect(response).toEqual({ ok: true })
  expect(axios.request).toHaveBeenCalledWith({ url: '/round', method, data: { id: 1 }, timeout: 500, params: { page: 2 } })
  expect(api.isLoading).toBe(false)
})

it('rejects original errors and suppresses only an explicitly allowed 404', async () => {
  const unavailable = { isAxiosError: true, response: { status: 503 } }
  vi.mocked(axios.request).mockRejectedValue(unavailable)
  await act(async () => {
    await expect(api.fetchData('/round', 'get', undefined, { suppressNotFound: true })).rejects.toBe(unavailable)
  })
  const missing = { isAxiosError: true, response: { status: 404 } }
  vi.mocked(axios.request).mockRejectedValue(missing)
  await act(async () => {
    await expect(api.fetchData('/round')).rejects.toBe(missing)
  })
  await act(async () => {
    await expect(api.fetchData('/round', 'get', undefined, { suppressNotFound: true })).resolves.toBeUndefined()
  })
  expect(api.isLoading).toBe(false)
})

it('stays loading until every concurrent request settles', async () => {
  let resolveFirst!: (value: unknown) => void
  let resolveSecond!: (value: unknown) => void
  vi.mocked(axios.request)
    .mockImplementationOnce(
      () =>
        new Promise((resolve) => {
          resolveFirst = resolve
        }),
    )
    .mockImplementationOnce(
      () =>
        new Promise((resolve) => {
          resolveSecond = resolve
        }),
    )
  let first!: Promise<unknown>
  let second!: Promise<unknown>
  const fetchData = api.fetchData
  act(() => {
    first = api.fetchData('/one')
    second = api.fetchData('/two')
  })
  expect(api.isLoading).toBe(true)
  expect(api.fetchData).toBe(fetchData)
  await act(async () => {
    resolveSecond({ data: 2 })
    await second
  })
  expect(api.isLoading).toBe(true)
  await act(async () => {
    resolveFirst({ data: 1 })
    await first
  })
  expect(api.isLoading).toBe(false)
})
