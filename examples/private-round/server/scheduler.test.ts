// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { E3Stage } from '@interfold/sdk/contracts'

import { ComputeScheduler, type SchedulerDeps } from './scheduler'

const key = new Uint8Array([1, 2, 3])
const window = { stage: E3Stage.KeyPublished, now: 100n, inputDeadline: 50n, computeDeadline: 200n }

const tick = (ms = 2) => new Promise<void>((resolve) => setTimeout(resolve, ms))

async function until(condition: () => boolean) {
  for (let i = 0; i < 500 && !condition(); i++) await tick()
  expect(condition()).toBe(true)
}

describe('ComputeScheduler', () => {
  beforeEach(() => {
    vi.spyOn(console, 'log').mockImplementation(() => undefined)
    vi.spyOn(console, 'warn').mockImplementation(() => undefined)
    vi.spyOn(console, 'error').mockImplementation(() => undefined)
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  const scheduler = (overrides: Partial<SchedulerDeps> = {}) => {
    const submit = vi.fn().mockResolvedValue('submitted')
    const instance = new ComputeScheduler({
      getWindow: async () => window,
      waitForChainTime: async () => undefined,
      submit,
      sleep: () => tick(1),
      outcomePollMs: 1_000,
      retryBaseMs: 1,
      ...overrides,
    })
    return { instance, submit }
  }

  it('submits an E3 once, however often it is scheduled, and accepts only the token of the run', async () => {
    const { instance, submit } = scheduler()
    instance.schedule(7n, key)
    instance.schedule(7n, key)
    await until(() => submit.mock.calls.length > 0)
    expect(submit).toHaveBeenCalledOnce()
    const token = submit.mock.calls[0][2] as string
    expect(token).toMatch(/^[0-9a-f]{64}$/)

    expect(instance.authorize(7n, token)).toBe(true)
    expect(instance.authorize(7n, `${token.slice(0, -1)}${token.endsWith('0') ? '1' : '0'}`)).toBe(false)
    expect(instance.authorize(7n, '')).toBe(false)
    expect(instance.authorize(8n, token)).toBe(false)

    instance.completed(7n)
    await until(() => !instance.isScheduled(7n))
    expect(instance.authorize(7n, token)).toBe(false)
    expect(submit).toHaveBeenCalledOnce()
  })

  it('tries again with a new token after a failed submission and after a failed callback', async () => {
    const submit = vi.fn().mockRejectedValueOnce(new Error('runner is down')).mockResolvedValue('submitted')
    const { instance } = scheduler({ submit })
    instance.schedule(7n, key)
    await until(() => submit.mock.calls.length === 2)

    const first = submit.mock.calls[1][2] as string
    instance.failed(7n, 'compute failed')
    expect(instance.authorize(7n, first)).toBe(false)
    await until(() => submit.mock.calls.length === 3)
    const second = submit.mock.calls[2][2] as string
    expect(second).not.toBe(first)
    expect(instance.authorize(7n, second)).toBe(true)
    instance.completed(7n)
    await until(() => !instance.isScheduled(7n))
  })

  it('does not submit an E3 whose compute deadline passed', async () => {
    const { instance, submit } = scheduler({ getWindow: async () => ({ ...window, now: 201n }) })
    instance.schedule(7n, key)
    await until(() => !instance.isScheduled(7n))
    expect(submit).not.toHaveBeenCalled()
  })

  it('stops retrying when the deadline passes during the retries', async () => {
    let now = 100n
    const submit = vi.fn().mockImplementation(async () => {
      now = 201n
      throw new Error('runner is down')
    })
    const { instance } = scheduler({ submit, getWindow: async () => ({ ...window, now }) })
    instance.schedule(7n, key)
    await until(() => !instance.isScheduled(7n))
    expect(submit).toHaveBeenCalledOnce()
  })

  it('waits for the input window before it submits', async () => {
    let now = 10n
    const submit = vi.fn().mockResolvedValue('submitted')
    const waitForChainTime = vi.fn().mockImplementation(async (target: bigint) => {
      now = target
    })
    const { instance } = scheduler({ submit, waitForChainTime, getWindow: async () => ({ ...window, now }) })
    instance.schedule(7n, key)
    await until(() => submit.mock.calls.length > 0)
    expect(waitForChainTime).toHaveBeenCalledWith(50n)
    instance.completed(7n)
  })

  it('stops when the E3 needs no compute', async () => {
    const submit = vi.fn().mockResolvedValue('skipped')
    const { instance } = scheduler({ submit })
    instance.schedule(7n, key)
    await until(() => !instance.isScheduled(7n))
    expect(submit).toHaveBeenCalledOnce()
  })
})
