// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { readDeploymentArgs, storeDeploymentArgs } from '@interfold/contracts/scripts'
import { Interfold__factory as InterfoldFactory } from '@interfold/contracts/types'
import { readFileSync } from 'fs'

import hre from 'hardhat'

import { CRISPProgram__factory as CRISPProgramFactory } from '../types'

const imageIdContent = readFileSync('../../.interfold/generated/contracts/ImageID.sol', 'utf-8')
const match = imageIdContent.match(/bytes32 public constant PROGRAM_ID = bytes32\((0x[a-fA-F0-9]+)\)/)
const IMAGE_ID = match ? match[1] : null

if (!IMAGE_ID) {
  throw new Error('IMAGE_ID not found')
}

export const deployCRISPContracts = async () => {
  const { ethers } = await hre.network.connect()
  const [owner] = await ethers.getSigners()

  const chain = hre.globalOptions.network

  const useMocks = Boolean(process.env.USE_MOCKS)

  const verifier = await deployVerifier(useMocks)

  const interfoldAddress = readDeploymentArgs('Interfold', chain)?.address
  if (!interfoldAddress) {
    throw new Error('Interfold address not found, it must be deployed first')
  }
  const interfold = InterfoldFactory.connect(interfoldAddress, owner)

  const poseidonT3Address = readDeploymentArgs('PoseidonT3', chain)?.address
  if (!poseidonT3Address) {
    throw new Error('PoseidonT3 address not found, it must be deployed first')
  }

  const zkTranscriptLib = await ethers.deployContract('contracts/CRISPVerifier.sol:ZKTranscriptLib')
  await zkTranscriptLib.waitForDeployment()
  const zkTranscriptLibAddress = await zkTranscriptLib.getAddress()

  const honkVerifierFactory = await ethers.getContractFactory('HonkVerifier', {
    libraries: {
      'project/contracts/CRISPVerifier.sol:ZKTranscriptLib': zkTranscriptLibAddress,
    },
  })
  const honkVerifier = await honkVerifierFactory.deploy()
  const honkVerifierAddress = await honkVerifier.getAddress()

  storeDeploymentArgs(
    {
      address: honkVerifierAddress,
      blockNumber: await ethers.provider.getBlockNumber(),
    },
    'HonkVerifier',
    chain,
  )

  const crispFactory = await ethers.getContractFactory(
    CRISPProgramFactory.abi,
    CRISPProgramFactory.linkBytecode({
      'npm/poseidon-solidity@0.0.5/PoseidonT3.sol:PoseidonT3': poseidonT3Address,
    }),
    owner,
  )

  const crisp = await crispFactory.deploy(interfoldAddress, verifier, honkVerifierAddress, IMAGE_ID)

  const crispAddress = await crisp.getAddress()
  storeDeploymentArgs(
    {
      address: crispAddress,
      blockNumber: await ethers.provider.getBlockNumber(),
      constructorArgs: {
        interfold: interfoldAddress,
        verifierAddress: verifier,
        honkVerifierAddress,
        imageId: IMAGE_ID,
      },
    },
    'CRISPProgram',
    chain,
  )

  // enable the program on Interfold
  const tx = await interfold.registerE3Program(crispAddress)
  await tx.wait()

  let tokenAddress
  if (useMocks) {
    const token = await ethers.deployContract('MockVotingToken')
    await token.waitForDeployment()
    tokenAddress = await token.getAddress()

    storeDeploymentArgs(
      {
        address: tokenAddress,
        blockNumber: await ethers.provider.getBlockNumber(),
      },
      'MockVotingToken',
      chain,
    )
  }

  console.log(`
      Deployments:
      ----------------------------------------------------------------------
      Interfold: ${interfoldAddress}
      Risc0Verifier: ${verifier}
      HonkVerifier: ${honkVerifierAddress}
      CRISPProgram: ${crispAddress}
      TokenAddress: ${tokenAddress}
      `)
}

/**
 * Deploys the verifier contract
 * @param useMockVerifier - whether to use a mock verifier
 * @returns The address of the verifier
 */
export const deployVerifier = async (useMockVerifier: boolean): Promise<string> => {
  const { ethers } = await hre.network.connect()
  const chain = hre.globalOptions.network

  if (!useMockVerifier) {
    const existingVerifier = readDeploymentArgs('RiscZeroGroth16Verifier', chain)
    if (existingVerifier?.address) {
      console.log('RiscZeroGroth16Verifier already deployed at:', existingVerifier.address)
      return existingVerifier.address
    }
    const verifierFactory = await ethers.getContractFactory('RiscZeroGroth16Verifier')
    const verifier = await verifierFactory.deploy()
    await verifier.waitForDeployment()
    const address = await verifier.getAddress()

    storeDeploymentArgs(
      {
        address,
        blockNumber: await ethers.provider.getBlockNumber(),
      },
      'RiscZeroGroth16Verifier',
      chain,
    )
    return address
  }
  // Check if mock verifier already deployed
  const existingMockVerifier = readDeploymentArgs('MockRISC0Verifier', chain)
  if (existingMockVerifier?.address) {
    console.log('MockRISC0Verifier already deployed at:', existingMockVerifier.address)
    return existingMockVerifier.address
  }
  const mockVerifierFactory = await ethers.getContractFactory('MockRISC0Verifier')
  const mockVerifier = await mockVerifierFactory.deploy()
  await mockVerifier.waitForDeployment()
  const mockVerifierAddress = await mockVerifier.getAddress()
  storeDeploymentArgs(
    {
      address: mockVerifierAddress,
      blockNumber: await ethers.provider.getBlockNumber(),
    },
    'MockRISC0Verifier',
    hre.globalOptions.network,
  )

  return mockVerifierAddress
}
