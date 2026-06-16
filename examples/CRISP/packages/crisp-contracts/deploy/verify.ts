// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import hre from 'hardhat'

import { verifyContracts } from '@interfold/contracts/scripts'

async function main() {
  const { ethers } = await hre.network.connect()
  const [signer] = await ethers.getSigners()
  const chain = (await signer.provider?.getNetwork())?.name ?? 'localhost'

  verifyContracts(chain)
}

main().catch((error) => {
  console.error(error)
})
