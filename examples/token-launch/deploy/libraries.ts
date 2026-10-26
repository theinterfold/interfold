// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import type { HardhatEthers } from '@nomicfoundation/hardhat-ethers/types'
import type { TokenLaunchProgram__factory } from '../types/factories/contracts'

/** The link table of `TokenLaunchProgram__factory.linkBytecode`. */
export type ProgramLinks = Parameters<typeof TokenLaunchProgram__factory.linkBytecode>[0]

const POSEIDON_T3 = 'npm/poseidon-solidity@0.0.5/PoseidonT3.sol:PoseidonT3'
const source = <Name extends string>(name: Name) => `project/contracts/libraries/${name}.sol:${name}` as const

/**
 * Deploys the external libraries of `TokenLaunchProgram` (they keep it under the EIP-170 size limit) and returns the
 * link table. `IncrementalTree` links `PoseidonT3` and `Settlement` links `ProofInputs`, so those come first.
 * `record` sees each library after it is deployed.
 */
export async function deployProgramLibraries(
  ethers: HardhatEthers,
  poseidonT3: string,
  record: (name: string, address: string) => void | Promise<void> = () => {},
): Promise<ProgramLinks> {
  const deploy = async (name: string, libraries: Record<string, string> = {}) => {
    const library = await ethers.deployContract(name, [], { libraries })
    await library.waitForDeployment()
    const address = await library.getAddress()
    await record(name, address)
    return address
  }
  const proofInputs = await deploy('ProofInputs')
  return {
    [source('E3Reader')]: await deploy('E3Reader'),
    [source('ProofInputs')]: proofInputs,
    [source('Settlement')]: await deploy('Settlement', { [source('ProofInputs')]: proofInputs }),
    [source('IncrementalTree')]: await deploy('IncrementalTree', { [POSEIDON_T3]: poseidonT3 }),
    [source('ProbeSearch')]: await deploy('ProbeSearch'),
    [source('SaleClearing')]: await deploy('SaleClearing'),
    [source('SaleConfig')]: await deploy('SaleConfig'),
    [source('SaleOutput')]: await deploy('SaleOutput'),
  }
}
