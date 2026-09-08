// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { type Abi, type Log, type PublicClient } from 'viem'
import { CiphernodeRegistryOwnable__factory, Interfold__factory, IRandomnessProvider__factory } from '@interfold/contracts/types'

import {
  RegistryEventType,
  type RandomnessProviderEvent,
  type RandomnessProviderEventCallback,
  type RandomnessProviderEventType,
  type AllEventTypes,
  type InterfoldEvent,
  type InterfoldEventData,
  type InterfoldEventType as InterfoldEventTypeT,
  type EventCallback,
  type EventListenerConfig,
  type RegistryEventData,
  type RegistryEventType as RegistryEventTypeT,
  type SDKEventEmitter,
} from './types'
import type { ContractAddresses } from '../contracts/types'
import { SDKError, sleep } from '../utils'

export interface EventListenerOptions {
  publicClient: PublicClient
  contracts: ContractAddresses
  config?: EventListenerConfig
}

export class EventListener implements SDKEventEmitter {
  private static readonly DEFAULT_HISTORICAL_BLOCK_RANGE = 10_000n
  private static readonly MAX_REMEMBERED_LOGS = 10_000
  private listeners: Map<AllEventTypes, Set<EventCallback>> = new Map()
  private activeWatchers: Map<string, () => void> = new Map()
  private watcherStartBlocks: Map<string, bigint | undefined> = new Map()
  private randomnessProviderListeners: Map<string, Set<RandomnessProviderEventCallback>> = new Map()
  private seenLiveLogs: Map<string, true> = new Map()
  private isPolling = false
  private lastBlockNumber: bigint = BigInt(0)
  private publicClient: PublicClient
  private contracts: ContractAddresses
  private config: EventListenerConfig

  constructor(options: EventListenerOptions) {
    this.publicClient = options.publicClient
    this.contracts = options.contracts
    this.config = options.config || {}
  }

  // Registry-exclusive event names that don't collide with InterfoldEventType.
  // Shared names like 'OwnershipTransferred' and 'Initialized' exist in both
  // enums with the same string value, so they cannot be disambiguated at
  // runtime; those default to the Interfold contract.
  private static readonly REGISTRY_ONLY_EVENTS: ReadonlySet<string> = new Set([
    RegistryEventType.COMMITTEE_REQUESTED,
    RegistryEventType.COMMITTEE_RANDOMNESS_REQUESTED,
    RegistryEventType.RANDOMNESS_CIRCUIT_BREAKER_TRIPPED,
    RegistryEventType.COMMITTEE_PUBLISHED,
    RegistryEventType.COMMITTEE_PUBLIC_KEY_CHUNK_PUBLISHED,
    RegistryEventType.COMMITTEE_FINALIZED,
    RegistryEventType.INTERFOLD_SET,
  ])

  private resolveContract(eventType: AllEventTypes): { address: `0x${string}`; abi: Abi } {
    const isRegistryEvent = EventListener.REGISTRY_ONLY_EVENTS.has(eventType as string)
    return {
      address: isRegistryEvent ? this.contracts.ciphernodeRegistry : this.contracts.interfold,
      abi: isRegistryEvent ? CiphernodeRegistryOwnable__factory.abi : Interfold__factory.abi,
    }
  }

  public async onInterfoldEvent<T extends AllEventTypes>(eventType: T, callback: EventCallback<T>): Promise<void> {
    const { address, abi } = this.resolveContract(eventType)
    return this.watchContractEvent(address, eventType, abi, callback)
  }

  public async onRandomnessProviderEvent<T extends RandomnessProviderEventType>(
    provider: `0x${string}`,
    eventType: T,
    callback: RandomnessProviderEventCallback<T>,
    fromBlock?: bigint,
  ): Promise<void> {
    const listenerKey = `${provider.toLowerCase()}:${eventType}`
    const watcherKey = `randomness-provider:${listenerKey}`
    const requestedStartBlock = fromBlock ?? this.config.fromBlock
    let callbacks = this.randomnessProviderListeners.get(listenerKey)
    if (!callbacks) {
      callbacks = new Set()
      this.randomnessProviderListeners.set(listenerKey, callbacks)
    }

    if (this.activeWatchers.has(watcherKey)) {
      const activeStartBlock = this.watcherStartBlocks.get(watcherKey)
      if (fromBlock !== undefined && requestedStartBlock !== activeStartBlock) {
        throw new SDKError(
          `Randomness provider watcher for ${eventType} on ${provider} already starts at ${activeStartBlock ?? 'latest'}; requested ${requestedStartBlock ?? 'latest'}`,
          'INVALID_EVENT_CONFIG',
        )
      }
      callbacks.add(callback as RandomnessProviderEventCallback)
      return
    }

    callbacks.add(callback as RandomnessProviderEventCallback)

    try {
      const unwatch = this.publicClient.watchContractEvent({
        address: provider,
        abi: IRandomnessProvider__factory.abi,
        eventName: eventType,
        fromBlock: requestedStartBlock,
        onLogs: (logs: Log[]) => {
          for (const log of logs) {
            if (!this.rememberLiveLog(log)) continue
            const event: RandomnessProviderEvent<T> = {
              type: eventType,
              data: (log as unknown as { args: RandomnessProviderEvent<T>['data'] }).args,
              provider,
              log,
              timestamp: new Date(),
              blockNumber: log.blockNumber ?? 0n,
              transactionHash: log.transactionHash ?? '0x',
            }
            const currentCallbacks = this.randomnessProviderListeners.get(listenerKey)
            currentCallbacks?.forEach((currentCallback) => {
              try {
                const result = currentCallback(event)
                if (result) {
                  void result.catch((error) => {
                    console.error(`Error in randomness provider callback for ${eventType}:`, error)
                  })
                }
              } catch (error) {
                console.error(`Error in randomness provider callback for ${eventType}:`, error)
              }
            })
          }
        },
      })
      this.activeWatchers.set(watcherKey, unwatch)
      this.watcherStartBlocks.set(watcherKey, requestedStartBlock)
    } catch (error) {
      callbacks.delete(callback as RandomnessProviderEventCallback)
      if (callbacks.size === 0) this.randomnessProviderListeners.delete(listenerKey)
      throw new SDKError(`Failed to watch randomness provider event ${eventType} on ${provider}: ${error}`, 'WATCH_EVENT_FAILED')
    }
  }

  public offRandomnessProviderEvent<T extends RandomnessProviderEventType>(
    provider: `0x${string}`,
    eventType: T,
    callback: RandomnessProviderEventCallback<T>,
  ): void {
    const listenerKey = `${provider.toLowerCase()}:${eventType}`
    const callbacks = this.randomnessProviderListeners.get(listenerKey)
    callbacks?.delete(callback as RandomnessProviderEventCallback)
    if (callbacks && callbacks.size === 0) {
      this.randomnessProviderListeners.delete(listenerKey)
      const watcherKey = `randomness-provider:${listenerKey}`
      const unwatch = this.activeWatchers.get(watcherKey)
      if (unwatch) unwatch()
      this.activeWatchers.delete(watcherKey)
      this.watcherStartBlocks.delete(watcherKey)
    }
  }

  public async getHistoricalRandomnessProviderEvents(
    provider: `0x${string}`,
    eventType: RandomnessProviderEventType,
    fromBlock?: bigint,
    toBlock?: bigint,
  ): Promise<Log[]> {
    const start = fromBlock ?? this.config.fromBlock
    if (start === undefined) {
      throw new SDKError('Randomness provider history requires fromBlock or EventListenerConfig.fromBlock', 'INVALID_EVENT_CONFIG')
    }
    try {
      return await this.getHistoricalContractEvents(provider, IRandomnessProvider__factory.abi, eventType, start, toBlock)
    } catch (error) {
      throw new SDKError(`Failed to get randomness provider events from ${provider}: ${error}`, 'HISTORICAL_EVENTS_FAILED')
    }
  }

  public async once<T extends AllEventTypes>(type: T, callback: EventCallback<T>): Promise<void> {
    const handler: EventCallback<T> = (event) => {
      this.off(type, handler)
      const prom = callback(event)
      if (prom) {
        prom.catch((e) => console.error(e))
      }
    }
    return this.onInterfoldEvent(type, handler)
  }

  public async watchContractEvent<T extends AllEventTypes>(
    address: `0x${string}`,
    eventType: T,
    abi: Abi,
    callback: EventCallback<T>,
  ): Promise<void> {
    const watcherKey = `${address}:${eventType}`

    if (!this.listeners.has(eventType)) {
      this.listeners.set(eventType, new Set())
    }
    this.listeners.get(eventType)!.add(callback as EventCallback)

    // eslint-disable-next-line @typescript-eslint/no-this-alias
    const emitter = this

    if (!this.activeWatchers.has(watcherKey)) {
      try {
        const unwatch = this.publicClient.watchContractEvent({
          address,
          abi,
          eventName: eventType as string,
          fromBlock: this.config.fromBlock,
          onLogs(logs: Log[]) {
            for (let i = 0; i < logs.length; i++) {
              const log = logs[i]
              if (!log) break
              if (!emitter.rememberLiveLog(log)) continue
              const event: InterfoldEvent<T> = {
                type: eventType,
                data: (log as unknown as { args: unknown }).args as T extends InterfoldEventTypeT
                  ? InterfoldEventData[T]
                  : T extends RegistryEventTypeT
                    ? RegistryEventData[T]
                    : unknown,
                log,
                timestamp: new Date(),
                blockNumber: log.blockNumber ?? BigInt(0),
                transactionHash: log.transactionHash ?? '0x',
              }
              emitter.emit(event)
            }
          },
        })

        this.activeWatchers.set(watcherKey, unwatch)
      } catch (error) {
        throw new SDKError(`Failed to watch contract event ${eventType} on ${address}: ${error}`, 'WATCH_EVENT_FAILED')
      }
    }
  }

  public async watchLogs(address: `0x${string}`, callback: (log: Log) => void): Promise<void> {
    const watcherKey = `logs:${address}`

    if (!this.activeWatchers.has(watcherKey)) {
      try {
        const unwatch = this.publicClient.watchEvent({
          address,
          onLogs: (logs: Log[]) => {
            logs.forEach((log: Log) => {
              callback(log)
            })
          },
        })

        this.activeWatchers.set(watcherKey, unwatch)
      } catch (error) {
        throw new SDKError(`Failed to watch logs for address ${address}: ${error}`, 'WATCH_LOGS_FAILED')
      }
    }
  }

  public async startPolling(): Promise<void> {
    if (this.isPolling) return

    this.isPolling = true

    try {
      this.lastBlockNumber = await this.publicClient.getBlockNumber()
      void this.pollForEvents()
    } catch (error) {
      this.isPolling = false
      throw new SDKError(`Failed to start polling: ${error}`, 'POLLING_START_FAILED')
    }
  }

  public stopPolling(): void {
    this.isPolling = false
  }

  public async getHistoricalEvents(eventType: AllEventTypes, fromBlock?: bigint, toBlock?: bigint): Promise<Log[]> {
    const { address, abi } = this.resolveContract(eventType)

    try {
      return await this.getHistoricalContractEvents(address, abi, eventType as string, fromBlock, toBlock)
    } catch (error) {
      throw new SDKError(`Failed to get historical events: ${error}`, 'HISTORICAL_EVENTS_FAILED')
    }
  }

  public on<T extends AllEventTypes>(eventType: T, callback: EventCallback<T>): void {
    if (!this.listeners.has(eventType)) {
      this.listeners.set(eventType, new Set())
    }
    this.listeners.get(eventType)!.add(callback as EventCallback)
  }

  public off<T extends AllEventTypes>(eventType: T, callback: EventCallback<T>): void {
    const callbacks = this.listeners.get(eventType)
    if (callbacks) {
      callbacks.delete(callback as EventCallback)
      if (callbacks.size === 0) {
        this.listeners.delete(eventType)
        const watchersToRemove: string[] = []
        this.activeWatchers.forEach((unwatch, key) => {
          if (key.endsWith(`:${eventType}`)) {
            try {
              unwatch()
            } catch (error) {
              console.error(`Error unwatching event ${eventType}:`, error)
            }
            watchersToRemove.push(key)
          }
        })
        watchersToRemove.forEach((key) => this.activeWatchers.delete(key))
      }
    }
  }

  public emit<T extends AllEventTypes>(event: InterfoldEvent<T>): void {
    const callbacks = this.listeners.get(event.type)
    if (callbacks) {
      callbacks.forEach((callback) => {
        try {
          const result = (callback as EventCallback<T>)(event)
          if (result) {
            void result.catch((error) => {
              console.error(`Error in event callback for ${event.type}:`, error)
            })
          }
        } catch (error) {
          console.error(`Error in event callback for ${event.type}:`, error)
        }
      })
    }
  }

  public cleanup(): void {
    this.stopPolling()

    this.activeWatchers.forEach((unwatch) => {
      try {
        unwatch()
      } catch (error) {
        console.error('Error unwatching during cleanup:', error)
      }
    })
    this.activeWatchers.clear()
    this.watcherStartBlocks.clear()
    this.listeners.clear()
    this.randomnessProviderListeners.clear()
    this.seenLiveLogs.clear()
  }

  private logIdentity(log: Log): string | undefined {
    if (log.blockHash && log.transactionHash && log.logIndex !== null && log.logIndex !== undefined) {
      return `${log.blockHash}:${log.transactionHash}:${log.logIndex}:${Boolean(log.removed)}`
    }
    return undefined
  }

  private rememberLiveLog(log: Log): boolean {
    const identity = this.logIdentity(log)
    if (!identity) return true
    if (this.seenLiveLogs.has(identity)) return false

    this.seenLiveLogs.set(identity, true)
    if (this.seenLiveLogs.size > EventListener.MAX_REMEMBERED_LOGS) {
      const oldest = this.seenLiveLogs.keys().next().value
      if (oldest !== undefined) this.seenLiveLogs.delete(oldest)
    }
    return true
  }

  private async getHistoricalContractEvents(
    address: `0x${string}`,
    abi: Abi,
    eventName: string,
    fromBlock?: bigint,
    toBlock?: bigint,
  ): Promise<Log[]> {
    const start = fromBlock ?? this.config.fromBlock
    const configuredEnd = toBlock ?? this.config.toBlock
    if (start === undefined) {
      return (await this.publicClient.getContractEvents({
        address,
        abi,
        eventName,
        toBlock: configuredEnd,
      })) as Log[]
    }

    const end = configuredEnd ?? (await this.publicClient.getBlockNumber({ cacheTime: 0 }))
    if (end < start) return []

    const range = this.config.historicalBlockRange ?? EventListener.DEFAULT_HISTORICAL_BLOCK_RANGE
    if (range <= 0n) throw new SDKError('Historical block range must be greater than zero', 'INVALID_EVENT_CONFIG')

    const logs: Log[] = []
    const seen = new Set<string>()
    for (let cursor = start; cursor <= end; cursor += range) {
      const chunkEnd = cursor + range - 1n < end ? cursor + range - 1n : end
      const chunk = (await this.publicClient.getContractEvents({
        address,
        abi,
        eventName,
        fromBlock: cursor,
        toBlock: chunkEnd,
      })) as Log[]
      for (const log of chunk) {
        const identity = this.logIdentity(log)
        if (identity && seen.has(identity)) continue
        if (identity) {
          seen.add(identity)
          this.rememberLiveLog(log)
        }
        logs.push(log)
      }
    }
    return logs
  }

  private async pollForEvents(): Promise<void> {
    while (this.isPolling) {
      try {
        const currentBlock = await this.publicClient.getBlockNumber()

        if (currentBlock > this.lastBlockNumber) {
          this.lastBlockNumber = currentBlock
        }

        await sleep(this.config.pollingInterval || 5000)
      } catch (error) {
        console.error('Error during polling:', error)
        await sleep(this.config.pollingInterval || 5000)
      }
    }
  }
}
