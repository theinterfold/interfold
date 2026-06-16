// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import {
  type Abi,
  type Chain,
  type Hash,
  type Log,
  type PublicClient,
  type WalletClient,
  createPublicClient,
  createWalletClient,
  http,
  webSocket,
} from 'viem'
import { privateKeyToAccount } from 'viem/accounts'

import { ContractClient } from './contracts/contract-client'
import { EventListener } from './events/event-listener'
import {
  getThresholdBfvParamsSet,
  generatePublicKey,
  computePublicKeyCommitment,
  encryptNumber,
  encryptVector,
  encryptNumberAndGenInputs,
  encryptNumberAndGenProof,
  encryptVectorAndGenInputs,
  encryptVectorAndGenProof,
} from './crypto/encrypt'
import { ThresholdBfvParamsPresetNames } from './crypto/types'
import { SDKError, isValidAddress } from './utils'
import { DEFAULT_THRESHOLD_BFV_PARAMS_PRESET_NAME } from './constants'

import type { SDKConfig } from './types'
import type { AllEventTypes, EventCallback } from './events/types'
import type { E3, E3RequestParams } from './contracts/types'
import { E3Stage, FailureReason } from './contracts/types'
import type { BfvParams, EncryptedValueAndPublicInputs, ThresholdBfvParamsPresetName, VerifiableEncryptionResult } from './crypto/types'

export class InterfoldSDK {
  private eventListener: EventListener
  private contractClient: ContractClient
  private thresholdBfvParamsPresetName: ThresholdBfvParamsPresetName
  private publicClient: PublicClient

  constructor(private config: SDKConfig) {
    if (!config.publicClient) {
      throw new SDKError('Public client is required', 'MISSING_PUBLIC_CLIENT')
    }

    if (!isValidAddress(config.contracts.interfold)) {
      throw new SDKError('Invalid Interfold contract address', 'INVALID_ADDRESS')
    }

    if (!isValidAddress(config.contracts.ciphernodeRegistry)) {
      throw new SDKError('Invalid CiphernodeRegistry contract address', 'INVALID_ADDRESS')
    }

    if (!isValidAddress(config.contracts.feeToken)) {
      throw new SDKError('Invalid FeeToken contract address', 'INVALID_ADDRESS')
    }

    const presetName = config.thresholdBfvParamsPresetName ?? DEFAULT_THRESHOLD_BFV_PARAMS_PRESET_NAME

    if (!ThresholdBfvParamsPresetNames.includes(presetName)) {
      throw new SDKError(`Invalid threshold BFV parameters preset name: ${presetName}`, 'INVALID_THRESHOLD_BFV_PARAMS_PRESET_NAME')
    }

    this.thresholdBfvParamsPresetName = presetName
    this.publicClient = config.publicClient

    this.contractClient = new ContractClient({
      publicClient: config.publicClient,
      walletClient: config.walletClient,
      contracts: config.contracts,
    })

    this.eventListener = new EventListener({
      publicClient: config.publicClient,
      contracts: config.contracts,
    })
  }

  // --- Encryption (delegates to standalone functions) ---

  public getPublicClient(): PublicClient {
    return this.publicClient
  }

  public async getThresholdBfvParamsSet(): Promise<BfvParams> {
    return getThresholdBfvParamsSet(this.thresholdBfvParamsPresetName)
  }

  public async generatePublicKey(): Promise<Uint8Array> {
    return generatePublicKey(this.thresholdBfvParamsPresetName)
  }

  public async computePublicKeyCommitment(publicKey: Uint8Array): Promise<Uint8Array> {
    return computePublicKeyCommitment(publicKey, this.thresholdBfvParamsPresetName)
  }

  public async encryptNumber(data: bigint, publicKey: Uint8Array): Promise<Uint8Array> {
    return encryptNumber(data, publicKey, this.thresholdBfvParamsPresetName)
  }

  public async encryptVector(data: BigUint64Array, publicKey: Uint8Array): Promise<Uint8Array> {
    return encryptVector(data, publicKey, this.thresholdBfvParamsPresetName)
  }

  public async encryptNumberAndGenInputs(data: bigint, publicKey: Uint8Array): Promise<EncryptedValueAndPublicInputs> {
    return encryptNumberAndGenInputs(data, publicKey, this.thresholdBfvParamsPresetName)
  }

  public async encryptNumberAndGenProof(data: bigint, publicKey: Uint8Array): Promise<VerifiableEncryptionResult> {
    return encryptNumberAndGenProof(data, publicKey, this.thresholdBfvParamsPresetName)
  }

  public async encryptVectorAndGenInputs(data: BigUint64Array, publicKey: Uint8Array): Promise<EncryptedValueAndPublicInputs> {
    return encryptVectorAndGenInputs(data, publicKey, this.thresholdBfvParamsPresetName)
  }

  public async encryptVectorAndGenProof(data: BigUint64Array, publicKey: Uint8Array): Promise<VerifiableEncryptionResult> {
    return encryptVectorAndGenProof(data, publicKey, this.thresholdBfvParamsPresetName)
  }

  // --- Contracts (delegates to ContractClient) ---

  public async approveFeeToken(amount: bigint): Promise<Hash> {
    return this.contractClient.approveFeeToken(amount)
  }

  public async requestE3(params: {
    committeeSize: number
    inputWindow: [bigint, bigint]
    e3Program: `0x${string}`
    paramSet: number
    computeProviderParams: `0x${string}`
    customParams?: `0x${string}`
    proofAggregationEnabled?: boolean
    gasLimit?: bigint
  }): Promise<Hash> {
    return this.contractClient.requestE3(params)
  }

  public async getE3PublicKey(e3Id: bigint): Promise<`0x${string}`> {
    return this.contractClient.getE3PublicKey(e3Id)
  }

  public async publishCiphertextOutput(
    e3Id: bigint,
    ciphertextOutput: `0x${string}`,
    proof: `0x${string}`,
    gasLimit?: bigint,
  ): Promise<Hash> {
    return this.contractClient.publishCiphertextOutput(e3Id, ciphertextOutput, proof, gasLimit)
  }

  public async getE3(e3Id: bigint): Promise<E3> {
    return this.contractClient.getE3(e3Id)
  }

  public async getE3Quote(params: E3RequestParams): Promise<bigint> {
    return this.contractClient.getE3Quote(params)
  }

  public async getFailureReason(e3Id: bigint): Promise<FailureReason> {
    return this.contractClient.getFailureReason(e3Id)
  }

  public async getE3Stage(e3Id: bigint): Promise<E3Stage> {
    return this.contractClient.getE3Stage(e3Id)
  }

  public async estimateGas(
    functionName: string,
    args: readonly unknown[],
    contractAddress: `0x${string}`,
    abi: Abi,
    value?: bigint,
  ): Promise<bigint> {
    return this.contractClient.estimateGas(functionName, args, contractAddress, abi, value)
  }

  public async waitForTransaction(hash: Hash): Promise<unknown> {
    return this.contractClient.waitForTransaction(hash)
  }

  // --- Events (delegates to EventListener) ---

  public async onInterfoldEvent<T extends AllEventTypes>(eventType: T, callback: EventCallback<T>): Promise<void> {
    return this.eventListener.onInterfoldEvent(eventType, callback)
  }

  public off<T extends AllEventTypes>(eventType: T, callback: EventCallback<T>): void {
    this.eventListener.off(eventType, callback)
  }

  public async once<T extends AllEventTypes>(type: T, callback: EventCallback<T>): Promise<void> {
    return this.eventListener.once(type, callback)
  }

  public async getHistoricalEvents(eventType: AllEventTypes, fromBlock?: bigint, toBlock?: bigint): Promise<Log[]> {
    return this.eventListener.getHistoricalEvents(eventType, fromBlock, toBlock)
  }

  public startEventPolling(): Promise<void> {
    return this.eventListener.startPolling()
  }

  public stopEventPolling(): void {
    this.eventListener.stopPolling()
  }

  public cleanup(): void {
    this.eventListener.cleanup()
  }

  // --- Factory ---

  public static create(options: {
    rpcUrl: string
    contracts: {
      interfold: `0x${string}`
      ciphernodeRegistry: `0x${string}`
      feeToken: `0x${string}`
    }
    privateKey?: `0x${string}`
    chain: Chain
    thresholdBfvParamsPresetName?: ThresholdBfvParamsPresetName
  }): InterfoldSDK {
    const isWebSocket = options.rpcUrl.startsWith('ws://') || options.rpcUrl.startsWith('wss://')
    const transport = isWebSocket
      ? webSocket(options.rpcUrl, {
          keepAlive: { interval: 30_000 },
          reconnect: { attempts: 5, delay: 2_000 },
        })
      : http(options.rpcUrl)

    const publicClient = createPublicClient({
      chain: options.chain,
      transport,
    }) as SDKConfig['publicClient']

    let walletClient: WalletClient | undefined
    if (options.privateKey) {
      const account = privateKeyToAccount(options.privateKey)
      walletClient = createWalletClient({
        account,
        chain: options.chain,
        transport,
      })
    }

    return new InterfoldSDK({
      publicClient,
      walletClient,
      contracts: options.contracts,
      chain: options.chain,
      thresholdBfvParamsPresetName: options.thresholdBfvParamsPresetName,
    })
  }
}
