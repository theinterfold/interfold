// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import {
  type Abi,
  type Chain,
  type Hash,
  type PublicClient,
  type TransactionReceipt,
  type WalletClient,
  createPublicClient,
  createWalletClient,
  http,
  webSocket,
} from 'viem'
import { privateKeyToAccount } from 'viem/accounts'

import { CiphernodeRegistryOwnable__factory, Interfold__factory, InterfoldToken__factory } from '@interfold/contracts/types'
import type { ContractAddresses, E3, E3RequestParams, E3Stage, FailureReason } from './types'
import { validateCommitteeSize } from './types'
import { SDKError, isValidAddress } from '../utils'

export interface ContractClientConfig {
  publicClient: PublicClient
  walletClient?: WalletClient
  contracts: ContractAddresses
}

export class ContractClient {
  private publicClient: PublicClient
  private walletClient?: WalletClient
  private contracts: ContractAddresses
  private contractInfo: {
    interfold: { address: `0x${string}`; abi: Abi }
    ciphernodeRegistry: { address: `0x${string}`; abi: Abi }
    feeToken: { address: `0x${string}`; abi: Abi }
  }

  constructor(config: ContractClientConfig) {
    const { publicClient, walletClient, contracts } = config

    if (!isValidAddress(contracts.interfold)) {
      throw new SDKError('Invalid Interfold contract address', 'INVALID_ADDRESS')
    }
    if (!isValidAddress(contracts.ciphernodeRegistry)) {
      throw new SDKError('Invalid CiphernodeRegistry contract address', 'INVALID_ADDRESS')
    }
    if (!isValidAddress(contracts.feeToken)) {
      throw new SDKError('Invalid FeeToken contract address', 'INVALID_ADDRESS')
    }

    this.publicClient = publicClient
    this.walletClient = walletClient
    this.contracts = contracts

    this.contractInfo = {
      interfold: {
        address: contracts.interfold,
        abi: Interfold__factory.abi,
      },
      ciphernodeRegistry: {
        address: contracts.ciphernodeRegistry,
        abi: CiphernodeRegistryOwnable__factory.abi,
      },
      feeToken: {
        address: contracts.feeToken,
        abi: InterfoldToken__factory.abi,
      },
    }
  }

  public static create(options: {
    rpcUrl: string
    contracts: ContractAddresses
    privateKey?: `0x${string}`
    chain: Chain
  }): ContractClient {
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
    }) as PublicClient

    let walletClient: WalletClient | undefined
    if (options.privateKey) {
      const account = privateKeyToAccount(options.privateKey)
      walletClient = createWalletClient({
        account,
        chain: options.chain,
        transport,
      })
    }

    return new ContractClient({ publicClient, walletClient, contracts: options.contracts })
  }

  public getPublicClient(): PublicClient {
    return this.publicClient
  }

  public async approveFeeToken(amount: bigint): Promise<Hash> {
    if (!this.walletClient) {
      throw new SDKError('Wallet client required for write operations', 'NO_WALLET')
    }

    try {
      const account = this.walletClient.account
      if (!account) {
        throw new SDKError('No account connected', 'NO_ACCOUNT')
      }

      const { request } = await this.publicClient.simulateContract({
        address: this.contracts.feeToken,
        abi: InterfoldToken__factory.abi,
        functionName: 'approve',
        args: [this.contracts.interfold, amount],
        account,
      })

      return await this.walletClient.writeContract(request)
    } catch (error) {
      throw new SDKError(`Failed to approve fee token: ${error}`, 'APPROVE_FEE_TOKEN_FAILED')
    }
  }

  public async requestE3(params: E3RequestParams): Promise<Hash> {
    if (!this.walletClient) {
      throw new SDKError('Wallet client required for write operations', 'NO_WALLET')
    }

    try {
      const account = this.walletClient.account
      if (!account) {
        throw new SDKError('No account connected', 'NO_ACCOUNT')
      }

      const committeeSize = validateCommitteeSize(params.committeeSize)

      const { request } = await this.publicClient.simulateContract({
        address: this.contracts.interfold,
        abi: Interfold__factory.abi,
        functionName: 'request',
        args: [
          {
            committeeSize,
            inputWindow: params.inputWindow,
            e3Program: params.e3Program,
            paramSet: params.paramSet,
            computeProviderParams: params.computeProviderParams,
            customParams: params.customParams || '0x',
            proofAggregationEnabled: params.proofAggregationEnabled ?? true,
          },
        ],
        account,
        gas: params.gasLimit,
      })

      return await this.walletClient.writeContract(request)
    } catch (error) {
      throw new SDKError(`Failed to request E3: ${error}`, 'REQUEST_E3_FAILED')
    }
  }

  public async publishCiphertextOutput(
    e3Id: bigint,
    ciphertextOutput: `0x${string}`,
    proof: `0x${string}`,
    gasLimit?: bigint,
  ): Promise<Hash> {
    if (!this.walletClient) {
      throw new SDKError('Wallet client required for write operations', 'NO_WALLET')
    }

    try {
      const account = this.walletClient.account
      if (!account) {
        throw new SDKError('No account connected', 'NO_ACCOUNT')
      }

      const { request } = await this.publicClient.simulateContract({
        address: this.contracts.interfold,
        abi: Interfold__factory.abi,
        functionName: 'publishCiphertextOutput',
        args: [e3Id, ciphertextOutput, proof],
        account,
        gas: gasLimit,
      })

      return await this.walletClient.writeContract(request)
    } catch (error) {
      throw new SDKError(`Failed to publish ciphertext output: ${error}`, 'PUBLISH_CIPHERTEXT_OUTPUT_FAILED')
    }
  }

  public async getE3(e3Id: bigint): Promise<E3> {
    try {
      const result: E3 = await this.publicClient.readContract({
        address: this.contracts.interfold,
        abi: Interfold__factory.abi,
        functionName: 'getE3',
        args: [e3Id],
      })

      return result
    } catch (error) {
      throw new SDKError(`Failed to get E3: ${error}`, 'GET_E3_FAILED')
    }
  }

  public async getE3Quote(requestParams: E3RequestParams): Promise<bigint> {
    try {
      const committeeSize = validateCommitteeSize(requestParams.committeeSize)

      return this.publicClient.readContract({
        address: this.contracts.interfold,
        abi: Interfold__factory.abi,
        functionName: 'getE3Quote',
        args: [
          {
            committeeSize,
            inputWindow: requestParams.inputWindow,
            e3Program: requestParams.e3Program,
            paramSet: requestParams.paramSet,
            computeProviderParams: requestParams.computeProviderParams,
            customParams: requestParams.customParams || '0x',
            proofAggregationEnabled: requestParams.proofAggregationEnabled ?? true,
          },
        ],
      })
    } catch (error) {
      throw new SDKError(`Failed to get E3 quote: ${error}`, 'GET_E3_QUOTE_FAILED')
    }
  }

  public async getFailureReason(e3Id: bigint): Promise<FailureReason> {
    try {
      return this.publicClient.readContract({
        address: this.contracts.interfold,
        abi: Interfold__factory.abi,
        functionName: 'getFailureReason',
        args: [e3Id],
      })
    } catch (error) {
      throw new SDKError(`Failed to get failure reason: ${error}`, 'GET_FAILURE_REASON_FAILED')
    }
  }

  public async getE3PublicKey(e3Id: bigint): Promise<`0x${string}`> {
    try {
      const result: `0x${string}` = await this.publicClient.readContract({
        address: this.contracts.ciphernodeRegistry,
        abi: CiphernodeRegistryOwnable__factory.abi,
        functionName: 'committeePublicKey',
        args: [e3Id],
      })

      return result
    } catch (error) {
      throw new SDKError(`Failed to get E3 public key: ${error}`, 'GET_E3_PUBLIC_KEY_FAILED')
    }
  }

  public async getE3Stage(e3Id: bigint): Promise<E3Stage> {
    try {
      return this.publicClient.readContract({
        address: this.contracts.interfold,
        abi: Interfold__factory.abi,
        functionName: 'getE3Stage',
        args: [e3Id],
      })
    } catch (error) {
      throw new SDKError(`Failed to get E3 stage: ${error}`, 'GET_E3_STAGE_FAILED')
    }
  }

  public async estimateGas(
    functionName: string,
    args: readonly unknown[],
    contractAddress: `0x${string}`,
    abi: Abi,
    value?: bigint,
  ): Promise<bigint> {
    if (!this.walletClient) {
      throw new SDKError('Wallet client required for gas estimation', 'NO_WALLET')
    }

    try {
      const account = this.walletClient.account
      if (!account) {
        throw new SDKError('No account connected', 'NO_ACCOUNT')
      }

      const estimateParams = {
        address: contractAddress,
        abi,
        functionName,
        args,
        account,
        ...(value !== undefined && { value }),
      }

      return await this.publicClient.estimateContractGas(estimateParams)
    } catch (error) {
      throw new SDKError(`Failed to estimate gas: ${error}`, 'GAS_ESTIMATION_FAILED')
    }
  }

  public async waitForTransaction(hash: Hash): Promise<TransactionReceipt> {
    try {
      return await this.publicClient.waitForTransactionReceipt({
        hash,
        confirmations: 1,
      })
    } catch (error) {
      throw new SDKError(`Failed to wait for transaction: ${error}`, 'TRANSACTION_WAIT_FAILED')
    }
  }
}
