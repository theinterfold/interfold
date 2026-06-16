// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
import { deployInterfold, updateE3Config } from '@interfold/contracts/scripts'
import { deployCRISPContracts } from './crisp'
import { syncCrispEnvFromDeployments } from './syncCrispEnv'
import path from 'path'

import hre from 'hardhat'
import { fileURLToPath } from 'url'

// Map contract names to config keys
const contractMapping: Record<string, string> = {
  CRISPProgram: 'e3_program',
  Interfold: 'interfold',
  CiphernodeRegistryOwnable: 'ciphernode_registry',
  BondingRegistry: 'bonding_registry',
  SlashingManager: 'slashing_manager',
  MockUSDC: 'fee_token',
}

// Get __dirname equivalent in ES modules
const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)

/**
 * Deploys the Interfold and CRISP contracts
 */
export const deploy = async () => {
  const chain = hre.globalOptions.network ?? 'localhost'

  const shouldDeployInterfold = Boolean(process.env.DEPLOY_INTERFOLD)
  const withZkVerification = process.env.ENABLE_ZK_VERIFICATION === 'true'

  if (shouldDeployInterfold) {
    await deployInterfold(true, withZkVerification)
  }
  await deployCRISPContracts()

  const interfoldConfigPath = path.join(__dirname, '..', '..', '..', 'interfold.config.yaml')
  updateE3Config(chain, interfoldConfigPath, contractMapping)

  syncCrispEnvFromDeployments(chain)
}

deploy().catch((err) => {
  console.error(err)
  process.exit(1)
})
