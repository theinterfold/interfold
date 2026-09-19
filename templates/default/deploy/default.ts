// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import {
  deployOpenVmReceiptVerifier,
  getDeploymentChain,
  readDeploymentArgs,
  storeDeploymentArgs,
  updateE3Config,
} from '@interfold/contracts/scripts'
import { Interfold__factory as InterfoldFactory } from '@interfold/contracts/types'
import { ensureTemplateCwd, INTERFOLD_CONFIG_FILE } from '../scripts/template-paths'
import { MyProgram__factory as MyProgramFactory } from '../types/factories/contracts'
import hre from 'hardhat'

// Map contract names to config keys
const contractMapping: Record<string, string> = {
  MyProgram: 'e3_program',
  Interfold: 'interfold',
  CiphernodeRegistryOwnable: 'ciphernode_registry',
  BondingRegistry: 'bonding_registry',
  MockUSDC: 'fee_token',
  Faucet: 'faucet',
}

export const deployTemplate = async () => {
  ensureTemplateCwd()
  const { ethers } = await hre.network.connect()
  const [owner] = await ethers.getSigners()

  const chain = getDeploymentChain(hre)

  const interfoldAddress = readDeploymentArgs('Interfold', chain)?.address
  if (!interfoldAddress) {
    throw new Error('Interfold address not found, it must be deployed first')
  }
  const interfold = InterfoldFactory.connect(interfoldAddress, owner)

  const poseidonT3Address = readDeploymentArgs('PoseidonT3', chain)?.address
  if (!poseidonT3Address) {
    throw new Error('PoseidonT3 address not found, it must be deployed first')
  }

  const unprovedTest = process.env.TEMPLATE_UNPROVED_TEST === '1'
  if (unprovedTest && (await ethers.provider.getNetwork()).chainId !== 31337n) {
    throw new Error('TEMPLATE_UNPROVED_TEST requires the isolated local chain')
  }
  let verifier
  let verifierConstructorArgs: Record<string, unknown> = {}
  if (unprovedTest) {
    verifier = await ethers.deployContract('MockOpenVmReceiptVerifier')
  } else {
    const deployed = await deployOpenVmReceiptVerifier(ethers)
    verifier = deployed.receipt
    verifierConstructorArgs = { verifier: deployed.halo2Verifier, appExeCommit: deployed.appExeCommit, appVmCommit: deployed.appVmCommit }
  }
  await verifier.waitForDeployment()
  const programId = await verifier.imageId()
  storeDeploymentArgs(
    { address: await verifier.getAddress(), blockNumber: await ethers.provider.getBlockNumber(), constructorArgs: verifierConstructorArgs },
    unprovedTest ? 'MockOpenVmReceiptVerifier' : 'OpenVmReceiptVerifier',
    chain,
  )
  const ciphertextVerifier = await ethers.deployContract('OpenVmBfvCiphertextVerifier', [await verifier.getAddress(), programId])
  await ciphertextVerifier.waitForDeployment()
  const encryptionSchemeId = ethers.keccak256(ethers.toUtf8Bytes('fhe.rs:BFV'))
  await (await interfold.setCiphertextVerifier(encryptionSchemeId, await ciphertextVerifier.getAddress())).wait()

  const e3ProgramFactory = await ethers.getContractFactory(
    MyProgramFactory.abi,
    MyProgramFactory.linkBytecode({
      'npm/poseidon-solidity@0.0.5/PoseidonT3.sol:PoseidonT3': poseidonT3Address,
    }),
    owner,
  )
  const e3Program = await e3ProgramFactory.deploy(await interfold.getAddress(), await verifier.getAddress(), programId)
  await e3Program.waitForDeployment()

  const programAddress = await e3Program.getAddress()
  const tx = await interfold.registerE3Program(programAddress)
  await tx.wait()

  const allowed = await interfold.e3Programs(programAddress)
  if (!allowed) {
    throw new Error(`MyProgram ${programAddress} was not enabled on Interfold ${interfoldAddress}`)
  }

  console.log("E3 Program enabled for Interfold's template")

  console.log(
    `
      Deployed MyProgram at address: ${await e3Program.getAddress()}
      Deployed ${unprovedTest ? 'local unproved test verifier' : 'OpenVmReceiptVerifier'} at address: ${await verifier.getAddress()}
    `,
  )

  storeDeploymentArgs(
    {
      address: await e3Program.getAddress(),
      blockNumber: await ethers.provider.getBlockNumber(),
    },
    'MyProgram',
    chain,
  )

  updateE3Config(chain, INTERFOLD_CONFIG_FILE, contractMapping)
}
