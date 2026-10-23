// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { deployTemplate } from '../deploy/default'
import { ensureTemplateCwd } from './template-paths'

// Deploys the auction program to a chain that already runs an Interfold protocol, for example
// `hardhat run scripts/deploy-network.ts --network sepolia`. It does not deploy the protocol.
async function main() {
  ensureTemplateCwd()
  const hre = await import('hardhat')
  const { ethers } = await hre.network.connect()
  const [deployer] = await ethers.getSigners()
  const network = await ethers.provider.getNetwork()
  console.log(`Deploying the auction program to chain ${network.chainId} with account ${deployer.address}`)
  console.log('Account balance:', ethers.formatEther(await ethers.provider.getBalance(deployer.address)))
  await deployTemplate()
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
