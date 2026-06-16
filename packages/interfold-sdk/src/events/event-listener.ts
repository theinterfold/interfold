// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { type Abi, type Log, type PublicClient } from 'viem'
import { CiphernodeRegistryOwnable__factory, Interfold__factory } from '@interfold/contracts/types'

import {
  RegistryEventType,
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
  private listeners: Map<AllEventTypes, Set<EventCallback>> = new Map()
  private activeWatchers: Map<string, () => void> = new Map()
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
    RegistryEventType.COMMITTEE_PUBLISHED,
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
      return await this.publicClient.getContractEvents({
        address,
        abi,
        eventName: eventType as string,
        fromBlock: fromBlock ?? this.config.fromBlock,
        toBlock: toBlock ?? this.config.toBlock,
      })
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
          void (callback as EventCallback<T>)(event)
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
    this.listeners.clear()
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
