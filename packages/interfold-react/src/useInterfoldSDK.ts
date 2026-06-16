// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { useState, useEffect, useCallback, useRef } from 'react'
import { useWalletClient, usePublicClient } from 'wagmi'
import {
  InterfoldSDK,
  type SDKConfig,
  type AllEventTypes,
  type EventCallback,
  type ThresholdBfvParamsPresetName,
  InterfoldEventType,
  RegistryEventType,
  SDKError,
} from '@interfold/sdk'

export interface UseInterfoldSDKConfig {
  contracts?: {
    interfold: `0x${string}`
    ciphernodeRegistry: `0x${string}`
    feeToken: `0x${string}`
  }
  autoConnect?: boolean
  thresholdBfvParamsPresetName?: ThresholdBfvParamsPresetName
}

export interface UseInterfoldSDKReturn {
  sdk: InterfoldSDK | null
  isInitialized: boolean
  error: string | null
  requestE3: typeof InterfoldSDK.prototype.requestE3
  getThresholdBfvParamsSet: typeof InterfoldSDK.prototype.getThresholdBfvParamsSet
  onInterfoldEvent: <T extends AllEventTypes>(eventType: T, callback: EventCallback<T>) => void
  off: <T extends AllEventTypes>(eventType: T, callback: EventCallback<T>) => void
  InterfoldEventType: typeof InterfoldEventType
  RegistryEventType: typeof RegistryEventType
}

/**
 * React hook for interacting with Interfold SDK
 *
 * @param config Configuration for the SDK initialization
 * @returns Object containing SDK instance and helper methods
 *
 * @example
 * ```tsx
 * import { useInterfoldSDK } from '@interfold/react';
 *
 * function MyComponent() {
 *   const {
 *     sdk,
 *     isInitialized,
 *     error,
 *     requestE3,
 *     onInterfoldEvent
 *   } = useInterfoldSDK({
 *     autoConnect: true,
 *     contracts: {
 *       interfold: '0x...',
 *       ciphernodeRegistry: '0x...',
 *       feeToken: '0x...',
 *     },
 *     thresholdBfvParamsPresetName: 'INSECURE_THRESHOLD_512',
 *   });
 *
 *   // Use the SDK...
 * }
 * ```
 */
export const useInterfoldSDK = (config: UseInterfoldSDKConfig): UseInterfoldSDKReturn => {
  const [sdk, setSdk] = useState<InterfoldSDK | null>(null)
  const [isInitialized, setIsInitialized] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const sdkRef = useRef<InterfoldSDK | null>(null)

  const publicClient = usePublicClient()

  const { data: walletClient } = useWalletClient()
  const initializeSDK = useCallback(async () => {
    try {
      setError(null)

      if (!publicClient) {
        throw new Error('Public client not available')
      }

      if (sdkRef.current) {
        sdkRef.current.cleanup()
      }

      const sdkConfig: SDKConfig = {
        publicClient,
        walletClient,
        contracts: config.contracts || {
          interfold: '0x0000000000000000000000000000000000000000',
          ciphernodeRegistry: '0x0000000000000000000000000000000000000000',
          feeToken: '0x0000000000000000000000000000000000000000',
        },
        thresholdBfvParamsPresetName: config.thresholdBfvParamsPresetName,
      }

      const newSdk = new InterfoldSDK(sdkConfig)
      setSdk(newSdk)
      sdkRef.current = newSdk
      setIsInitialized(true)
    } catch (err: unknown) {
      const errorMessage = err instanceof SDKError ? `SDK Error (${err.code}): ${err.message}` : `Failed to initialize SDK: ${err}`
      setError(errorMessage)
      console.error('SDK initialization failed:', err)
    }
  }, [publicClient, walletClient, config.contracts, config.thresholdBfvParamsPresetName])

  // Initialize SDK when wagmi clients are available
  useEffect(() => {
    if (config.autoConnect && publicClient && !isInitialized) {
      initializeSDK()
    }
  }, [config.autoConnect, publicClient, isInitialized, initializeSDK])

  // Re-initialize when wallet client changes (connect/disconnect)
  useEffect(() => {
    if (isInitialized && publicClient && walletClient) {
      initializeSDK()
    }
  }, [walletClient, initializeSDK, isInitialized, publicClient])

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      if (sdkRef.current) {
        sdkRef.current.cleanup()
      }
    }
  }, [])

  const getThresholdBfvParamsSet = useCallback(async () => {
    if (!sdk) throw new Error('SDK not initialized')
    return sdk.getThresholdBfvParamsSet()
  }, [sdk])

  const requestE3 = useCallback(
    (...args: Parameters<typeof InterfoldSDK.prototype.requestE3>) => {
      if (!sdk) throw new Error('SDK not initialized')
      return sdk.requestE3(...args)
    },
    [sdk],
  )

  const onInterfoldEvent = useCallback(
    <T extends AllEventTypes>(eventType: T, callback: EventCallback<T>) => {
      if (!sdk) throw new Error('SDK not initialized')
      return sdk.onInterfoldEvent(eventType, callback)
    },
    [sdk],
  )

  const off = useCallback(
    <T extends AllEventTypes>(eventType: T, callback: EventCallback<T>) => {
      if (!sdk) throw new Error('SDK not initialized')
      return sdk.off(eventType, callback)
    },
    [sdk],
  )

  return {
    sdk,
    isInitialized,
    error,
    requestE3,
    getThresholdBfvParamsSet,
    onInterfoldEvent,
    off,
    InterfoldEventType,
    RegistryEventType,
  }
}
