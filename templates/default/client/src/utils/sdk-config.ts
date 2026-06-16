// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { getContractAddresses } from './env-config'
import type { ThresholdBfvParamsPresetName } from '@interfold/sdk'
import { THRESHOLD_BFV_PARAMS_PRESET_NAME } from './env-config'

/**
 * Get the Interfold SDK configuration.
 */
export function getInterfoldSDKConfig() {
  const contracts = getContractAddresses()
  return {
    autoConnect: true,
    contracts: {
      interfold: contracts.interfold,
      ciphernodeRegistry: contracts.ciphernodeRegistry,
      feeToken: contracts.feeToken,
    },
    thresholdBfvParamsPresetName: THRESHOLD_BFV_PARAMS_PRESET_NAME as ThresholdBfvParamsPresetName,
  }
}
