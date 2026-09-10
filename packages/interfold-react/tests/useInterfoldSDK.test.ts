// SPDX-License-Identifier: LGPL-3.0-only
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { createElement, useLayoutEffect } from 'react'
import { act, create, type ReactTestRenderer } from 'react-test-renderer'
import { useInterfoldSDK, type UseInterfoldSDKConfig } from '../src/useInterfoldSDK'

const mocks = vi.hoisted(() => ({
  publicClient: {} as object | undefined,
  walletClient: {} as object | undefined,
  instances: [] as { cleanup: ReturnType<typeof vi.fn>; config: unknown }[],
  fail: false,
}))
vi.mock('wagmi', () => ({
  usePublicClient: () => mocks.publicClient,
  useWalletClient: () => ({ data: mocks.walletClient }),
}))
vi.mock('@interfold/sdk', () => ({
  InterfoldSDK: class {
    cleanup = vi.fn()
    constructor(readonly config: unknown) {
      if (mocks.fail) throw new Error('Constructor failed')
      mocks.instances.push(this)
    }
  },
  SDKError: class extends Error {},
  InterfoldEventType: {},
  RegistryEventType: {},
}))

let renderer: ReactTestRenderer | undefined
let result: ReturnType<typeof useInterfoldSDK>
const contracts = {
  interfold: '0x1111',
  ciphernodeRegistry: '0x2222',
  feeToken: '0x3333',
} as const
function Probe({ config = {} }: { config?: Partial<UseInterfoldSDKConfig> }) {
  const value = useInterfoldSDK({ autoConnect: true, contracts: { ...contracts }, ...config })
  useLayoutEffect(() => {
    result = value
  })
  return null
}
const render = (config?: Partial<UseInterfoldSDKConfig>) =>
  act(() => {
    const element = createElement(Probe, { config })
    if (renderer) renderer.update(element)
    else renderer = create(element)
  })

beforeEach(() => {
  mocks.publicClient = {}
  mocks.walletClient = {}
  mocks.instances.length = 0
  mocks.fail = false
})
afterEach(() => {
  act(() => renderer?.unmount())
  renderer = undefined
})

describe('SDK lifecycle', () => {
  it('retains the instance and subscriptions for identical inline configuration', () => {
    render()
    const sdk = result.sdk
    for (let i = 0; i < 5; i++) render()
    expect(result.sdk).toBe(sdk)
    expect(result.isInitialized).toBe(true)
    expect(mocks.instances).toHaveLength(1)
    expect(mocks.instances[0].cleanup).not.toHaveBeenCalled()
  })

  it('releases each old instance once on wallet change, disconnect, and unmount', () => {
    render()
    mocks.walletClient = {}
    render()
    mocks.walletClient = undefined
    render()
    expect(mocks.instances).toHaveLength(3)
    expect(mocks.instances[2].config).toMatchObject({ walletClient: undefined })
    act(() => renderer!.unmount())
    renderer = undefined
    for (const instance of mocks.instances) expect(instance.cleanup).toHaveBeenCalledTimes(1)
  })

  it('reacts to address, preset, and public-client changes', () => {
    render()
    render({ contracts: { ...contracts, interfold: '0x4444' } })
    render({ thresholdBfvParamsPresetName: 'INSECURE_THRESHOLD_512' })
    mocks.publicClient = {}
    render({ thresholdBfvParamsPresetName: 'INSECURE_THRESHOLD_512' })
    expect(mocks.instances).toHaveLength(4)
    expect(mocks.instances.slice(0, 3).every((instance) => instance.cleanup.mock.calls.length === 1)).toBe(true)
  })

  it('clears initialized state on disabled connection, missing client, or constructor failure', () => {
    render()
    render({ autoConnect: false })
    expect(result.sdk).toBeNull()
    render()
    mocks.publicClient = undefined
    render()
    expect(result.isInitialized).toBe(false)
    mocks.publicClient = {}
    mocks.fail = true
    render()
    expect(result.sdk).toBeNull()
    expect(result.error).toContain('Constructor failed')
    expect(mocks.instances).toHaveLength(2)
    for (const instance of mocks.instances) expect(instance.cleanup).toHaveBeenCalledTimes(1)
  })
})
