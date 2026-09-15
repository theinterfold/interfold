// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import {
  InterfoldSDK,
  calculateInputWindow,
  DEFAULT_COMPUTE_PROVIDER_PARAMS,
  encodeComputeProviderParams,
  decodePlaintextOutput,
  CommitteeSize,
  CommitteePublicKeyAssembler,
  ThresholdBfvParamsPresetNames,
} from '@interfold/sdk'
import { InterfoldEventType, RegistryEventType } from '@interfold/sdk/events'
import type { AllEventTypes, InterfoldEvent } from '@interfold/sdk/events'
import { E3Stage } from '@interfold/sdk/contracts'
import type { E3 } from '@interfold/sdk/contracts'
import { bytesToHex, createWalletClient, hexToBytes, http, parseAbi } from 'viem'
import assert from 'assert'

import { describe, expect, it } from 'vitest'
import { publishInput } from '../server/input'
import { privateKeyToAccount } from 'viem/accounts'
import { anvil } from 'viem/chains'

import { advanceAnvilTime, sleep } from './anvil-helpers'

const registryReadAbi = parseAbi(['function sortitionSeed(uint256 e3Id) view returns (bool ready, uint256 seed)'])

export function getContractAddresses() {
  return {
    interfold: process.env.INTERFOLD_ADDRESS as `0x${string}`,
    ciphernodeRegistry: process.env.REGISTRY_ADDRESS as `0x${string}`,
    bondingRegistry: process.env.BONDING_REGISTRY_ADDRESS as `0x${string}`,
    e3Program: process.env.E3_PROGRAM_ADDRESS as `0x${string}`,
    feeToken: process.env.FEE_TOKEN_ADDRESS as `0x${string}`,
  }
}

type E3Shared = {
  e3Id: bigint
  e3Program: string
  e3: E3
}

type E3StateRequested = E3Shared & {
  type: 'requested'
}

type E3StatePublished = E3Shared & {
  type: 'committee_published'
  publicKey: `0x${string}`
}

type E3StateOutputPublished = E3Shared & {
  type: 'output_published'
  plaintextOutput: string
}

type E3State = E3StateRequested | E3StatePublished | E3StateOutputPublished

async function setupEventListeners(sdk: InterfoldSDK, store: Map<bigint, E3State>) {
  const committeeKeyAssembler = new CommitteePublicKeyAssembler()
  const readyCommitteeKeys = new Map<bigint, Uint8Array>()
  const committeeKeyWaiters = new Map<bigint, Set<(publicKey: Uint8Array) => void>>()

  async function waitForEvent<T extends AllEventTypes>(
    type: T,
    trigger?: () => Promise<void>,
    timeoutMs?: number,
  ): Promise<InterfoldEvent<T>> {
    return new Promise((resolve, reject) => {
      let settled = false
      let timer: ReturnType<typeof setTimeout> | undefined

      const handler = (event: InterfoldEvent<T>) => {
        if (settled) return
        settled = true
        if (timer !== undefined) clearTimeout(timer)
        sdk.off(type, handler)
        resolve(event)
      }

      const fail = (err: unknown) => {
        if (settled) return
        settled = true
        if (timer !== undefined) clearTimeout(timer)
        sdk.off(type, handler)
        reject(err)
      }

      // Use onInterfoldEvent so `handler` is the actual registered reference
      // (sdk.once wraps in an internal closure, making sdk.off unable to remove it)
      sdk.onInterfoldEvent(type, handler).catch(fail)

      if (timeoutMs !== undefined) {
        timer = setTimeout(() => {
          fail(new Error(`Timed out waiting for event: ${type} after ${timeoutMs}ms`))
        }, timeoutMs)
      }

      if (trigger) {
        trigger().catch(fail)
      }
    })
  }

  await sdk.onInterfoldEvent(InterfoldEventType.E3_REQUESTED, (event) => {
    const id = event.data.e3Id

    if (store.has(id)) {
      throw new Error('E3 has already been requested ')
    }

    store.set(event.data.e3Id, {
      type: 'requested',
      ...event.data,
    })
  })

  await sdk.onInterfoldEvent(RegistryEventType.COMMITTEE_PUBLIC_KEY_CHUNK_PUBLISHED, async (event) => {
    const id = event.data.e3Id
    if (readyCommitteeKeys.has(id)) return

    const assembled = committeeKeyAssembler.add(event.data)
    if (!assembled) return

    const isBoundKey = await sdk.validatePublicKeyCommitment(assembled.publicKey, hexToBytes(assembled.pkCommitment))
    if (!isBoundKey) {
      return
    }

    const state = store.get(id)
    assert(state, `State for ID '${id}' was not found`)
    assert.strictEqual(state.type, 'requested', 'State must be requested before the committee key is accepted')

    store.set(id, {
      publicKey: bytesToHex(assembled.publicKey),
      ...state,
      type: 'committee_published',
    })
    readyCommitteeKeys.set(id, assembled.publicKey)
    committeeKeyAssembler.clear(id)
    committeeKeyWaiters.get(id)?.forEach((resolve) => resolve(assembled.publicKey))
    committeeKeyWaiters.delete(id)
  })

  await sdk.onInterfoldEvent(InterfoldEventType.PLAINTEXT_OUTPUT_PUBLISHED, (event) => {
    const id = event.data.e3Id

    const state = store.get(id)

    if (!state) {
      throw new Error(`State for ID '${id}' not found.`)
    }

    if (state.type !== 'committee_published') {
      throw new Error(`State must be in the committee_published state`)
    }

    store.set(id, {
      ...state,
      plaintextOutput: event.data.plaintextOutput,
      type: 'output_published',
    })
  })

  function waitForCommitteeKey(e3Id: bigint, timeoutMs: number): Promise<Uint8Array> {
    const ready = readyCommitteeKeys.get(e3Id)
    if (ready) return Promise.resolve(ready)

    return new Promise((resolve, reject) => {
      const waiters = committeeKeyWaiters.get(e3Id) ?? new Set()
      let timer: ReturnType<typeof setTimeout>
      const done = (publicKey: Uint8Array) => {
        clearTimeout(timer)
        waiters.delete(done)
        resolve(publicKey)
      }
      waiters.add(done)
      committeeKeyWaiters.set(e3Id, waiters)
      timer = setTimeout(() => {
        waiters.delete(done)
        if (waiters.size === 0) committeeKeyWaiters.delete(e3Id)
        reject(new Error(`Timed out waiting for a verified committee key after ${timeoutMs}ms`))
      }, timeoutMs)
    })
  }

  return { waitForEvent, waitForCommitteeKey }
}

describe('Integration', () => {
  console.log('Testing...')

  const contracts = getContractAddresses()

  const testPrivateKey = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80'

  const store = new Map<bigint, E3State>()
  const sdk = InterfoldSDK.create({
    contracts: {
      interfold: contracts.interfold,
      ciphernodeRegistry: contracts.ciphernodeRegistry,
      feeToken: contracts.feeToken,
    },
    rpcUrl: 'ws://localhost:8545',
    chain: anvil,
    thresholdBfvParamsPresetName: ThresholdBfvParamsPresetNames[0],
    privateKey: testPrivateKey,
  })

  const publicClient = sdk.getPublicClient()

  const account = privateKeyToAccount(testPrivateKey)

  const walletClient = createWalletClient({
    account,
    chain: anvil,
    transport: http('http://localhost:8545'),
  })

  it('completes an E3 from request through plaintext output', async () => {
    const { waitForEvent, waitForCommitteeKey } = await setupEventListeners(sdk, store)

    const committeeSize = CommitteeSize.Minimum
    const inputWindowDurationSeconds = 300
    const phaseTimeoutMs = 180_000
    const randomnessAcceptanceTimeoutMs = 30_000
    const inputWindow = await calculateInputWindow(publicClient, inputWindowDurationSeconds)
    const computeProviderParams = encodeComputeProviderParams(
      DEFAULT_COMPUTE_PROVIDER_PARAMS,
      true, // Mock the compute provider parameters, return 32 bytes of 0x00
    )

    let state

    // Verify fee quoting works
    const requestParams = {
      committeeSize,
      inputWindow,
      e3Program: contracts.e3Program,
      paramSet: 0, // ParamSet.InsecureThreshold512
      computeProviderParams,
    }
    const quote = await sdk.getE3Quote(requestParams)
    console.log('E3 quote:', quote)
    assert(quote >= 0n, 'E3 quote should be a non-negative bigint')

    // Approve fee token
    console.log('Approving fee token...')
    const hash = await sdk.approveFeeToken(quote)
    console.log('Fee token approved:', hash)

    await sleep(1000)

    // REQUEST phase
    const requestEvent = await waitForEvent(
      InterfoldEventType.E3_REQUESTED,
      async () => {
        console.log('Requested E3...')
        await sdk.requestE3(requestParams)
      },
      phaseTimeoutMs,
    )

    state = store.get(requestEvent.data.e3Id)
    assert(state, 'store should have E3State but it was falsey')
    assert.strictEqual(state.e3Id, requestEvent.data.e3Id)
    assert.strictEqual(state.type, 'requested')
    console.log('E3 Sucessfully Requested!')

    // Verify E3 stage after request
    const stageAfterRequest = await sdk.getE3Stage(state.e3Id)
    assert.strictEqual(stageAfterRequest, E3Stage.Requested, 'E3 stage should be Requested after requestE3')

    const randomnessWaitDeadline = Date.now() + randomnessAcceptanceTimeoutMs
    for (;;) {
      const [ready] = await publicClient.readContract({
        address: contracts.ciphernodeRegistry,
        abi: registryReadAbi,
        functionName: 'sortitionSeed',
        args: [state.e3Id],
      })
      if (ready) break
      if (Date.now() >= randomnessWaitDeadline) {
        throw new Error(`Registry did not accept delayed randomness for E3 ${state.e3Id} within ${randomnessAcceptanceTimeoutMs}ms`)
      }
      await sleep(250)
    }

    console.log('Waiting for the verified chunked committee key...')
    const publicKeyBytes = await waitForCommitteeKey(state.e3Id, phaseTimeoutMs)

    state = store.get(state.e3Id)
    assert(state, 'store should have E3State but it was falsey')
    assert.strictEqual(state.type, 'committee_published')
    assert.strictEqual(state.publicKey, bytesToHex(publicKeyBytes))

    // Verify E3 stage after committee published
    const stageAfterCommittee = await sdk.getE3Stage(state.e3Id)
    assert.strictEqual(stageAfterCommittee, E3Stage.KeyPublished, 'E3 stage should be KeyPublished after committee published')

    // INPUT PUBLISHING phase
    console.log('PUBLISHING PRIVATE INPUT')
    const num1 = 1n
    const num2 = 2n

    console.log('ENCRYPTING NUMBERS')
    const enc1 = await sdk.encryptNumber(num1, publicKeyBytes)
    const enc2 = await sdk.encryptNumber(num2, publicKeyBytes)
    const commitment1 = await sdk.computeCiphertextCommitment(enc1)
    const commitment2 = await sdk.computeCiphertextCommitment(enc2)

    let txHash = await publishInput(
      walletClient,
      state.e3Id,
      `0x${Array.from(enc1, (b) => b.toString(16).padStart(2, '0')).join('')}` as `0x${string}`,
      `0x${Array.from(commitment1, (b) => b.toString(16).padStart(2, '0')).join('')}` as `0x${string}`,
      account.address,
      contracts.e3Program,
    )
    await sdk.waitForTransaction(txHash)
    txHash = await publishInput(
      walletClient,
      state.e3Id,
      `0x${Array.from(enc2, (b) => b.toString(16).padStart(2, '0')).join('')}` as `0x${string}`,
      `0x${Array.from(commitment2, (b) => b.toString(16).padStart(2, '0')).join('')}` as `0x${string}`,
      account.address,
      contracts.e3Program,
    )
    await sdk.waitForTransaction(txHash)

    const currentBlock = await publicClient.getBlock()
    if (currentBlock.timestamp <= inputWindow[1]) {
      const secondsUntilInputWindowCloses = Number(inputWindow[1] - currentBlock.timestamp + 1n)
      await advanceAnvilTime(publicClient, secondsUntilInputWindowCloses)
    }
    console.log('Closed the input window after both inputs were confirmed')

    const plaintextEvent = await waitForEvent(InterfoldEventType.PLAINTEXT_OUTPUT_PUBLISHED, undefined, phaseTimeoutMs)

    const result = decodePlaintextOutput(plaintextEvent.data.plaintextOutput)
    assert(result !== null, 'Failed to decode plaintext output')

    expect(BigInt(result)).toBe(num1 + num2)
    console.log('Answer was correct')
  }, 600_000)
})
