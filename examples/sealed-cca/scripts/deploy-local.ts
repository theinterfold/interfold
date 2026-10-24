// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { deployInterfold } from '@interfold/contracts/scripts'
import { deployTemplate } from '../deploy/default'
import { ensureTemplateCwd } from './template-paths'

async function main() {
  ensureTemplateCwd()
  console.log('🚀 Deploying Interfold protocol locally...')

  // Get hardhat runtime environment
  const hre = await import('hardhat')

  const { ethers } = await hre.network.connect()

  // Get deployer account
  const [deployer] = await ethers.getSigners()
  console.log('Deploying with account:', deployer.address)
  console.log('Account balance:', ethers.formatEther(await ethers.provider.getBalance(deployer.address)))

  // Mocks for local dev; skip on-chain ZK verifiers (needs pnpm compile:circuits).
  await deployInterfold(true, false)
  await deployTemplate()
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
