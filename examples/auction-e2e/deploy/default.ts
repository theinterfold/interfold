// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import {
  availVectorXForChain,
  compiledOpenVmEnvironment,
  deployOpenVmReceiptVerifier,
  getDeploymentChain,
  isLocalDeploymentChain,
  readDeploymentArgs,
  storeDeploymentArgs,
  updateE3Config,
} from '@interfold/contracts/scripts'
import { Interfold__factory as InterfoldFactory } from '@interfold/contracts/types'
import { ensureTemplateCwd, INTERFOLD_CONFIG_FILE, TEMPLATE_ROOT } from '../scripts/template-paths'
import { AuctionProgram__factory as AuctionProgramFactory } from '../types/factories/contracts'
import { readFileSync } from 'node:fs'
import path from 'node:path'
import hre from 'hardhat'

const LOCAL_CHAIN_ID = 31337n
const MAINNET_CHAIN_ID = 1n
const SEPOLIA_CHAIN_ID = 11155111n
// poseidon-solidity deploys PoseidonT3 to the same address on every chain.
const CANONICAL_POSEIDON_T3 = '0x3333333C0A88F9BE4fd23ed0536F9B6c427e3B93'

// Map contract names to config keys
const contractMapping: Record<string, string> = {
  AuctionProgram: 'e3_program',
  Interfold: 'interfold',
  CiphernodeRegistryOwnable: 'ciphernode_registry',
  BondingRegistry: 'bonding_registry',
  MockUSDC: 'fee_token',
  Faucet: 'faucet',
}

/** Read an env flag that is `true`, `false` or unset; reject any other text. */
function envFlag(name: string): boolean | undefined {
  const raw = process.env[name]?.trim().toLowerCase()
  if (!raw) return undefined
  if (raw !== 'true' && raw !== 'false') throw new Error(`${name} must be 'true', 'false', or unset`)
  return raw === 'true'
}

function envAddress(name: string): string | undefined {
  const raw = process.env[name]?.trim()
  return raw ? raw : undefined
}

export const deployTemplate = async () => {
  ensureTemplateCwd()
  const { ethers } = await hre.network.connect()
  const [owner] = await ethers.getSigners()
  const ownerAddress = await owner.getAddress()

  const chain = getDeploymentChain(hre)
  const chainId = (await ethers.provider.getNetwork()).chainId
  const isLocalChain = chainId === LOCAL_CHAIN_ID

  // On a public chain the Interfold record is often absent, so the address can come from the environment.
  const interfoldAddress = envAddress('INTERFOLD_ADDRESS') ?? readDeploymentArgs('Interfold', chain)?.address
  if (!interfoldAddress) {
    throw new Error(`Interfold address not found for ${chain}: deploy it first or set INTERFOLD_ADDRESS`)
  }
  if ((await ethers.provider.getCode(interfoldAddress)) === '0x') {
    throw new Error(`No contract at Interfold address ${interfoldAddress} on ${chain}`)
  }
  const interfold = InterfoldFactory.connect(interfoldAddress, owner)

  let poseidonT3Address = envAddress('POSEIDON_T3_ADDRESS') ?? readDeploymentArgs('PoseidonT3', chain)?.address
  if (poseidonT3Address && (await ethers.provider.getCode(poseidonT3Address)) === '0x') {
    throw new Error(`No contract at PoseidonT3 address ${poseidonT3Address} on ${chain}`)
  }
  if (!poseidonT3Address) {
    if (isLocalChain || isLocalDeploymentChain(chain)) {
      throw new Error('PoseidonT3 address not found, it must be deployed first')
    }
    if ((await ethers.provider.getCode(CANONICAL_POSEIDON_T3)) !== '0x') {
      poseidonT3Address = CANONICAL_POSEIDON_T3
    } else {
      const poseidonT3 = await ethers.deployContract('PoseidonT3')
      await poseidonT3.waitForDeployment()
      poseidonT3Address = await poseidonT3.getAddress()
      storeDeploymentArgs({ address: poseidonT3Address, blockNumber: await ethers.provider.getBlockNumber() }, 'PoseidonT3', chain)
    }
  }

  // Compute verifier. TEMPLATE_UNPROVED_TEST=1 selects the receipt verifier that accepts every
  // receipt. It runs on the isolated local chain, or on Sepolia with an explicit acknowledgment.
  const unprovedTest = process.env.TEMPLATE_UNPROVED_TEST === '1'
  if (unprovedTest) {
    if (chainId === SEPOLIA_CHAIN_ID) {
      if (!envFlag('ALLOW_SEPOLIA_UNPROVED_COMPUTE')) {
        throw new Error(
          'TEMPLATE_UNPROVED_TEST=1 on Sepolia (chain ID 11155111) requires ALLOW_SEPOLIA_UNPROVED_COMPUTE=true. ' +
            'This acknowledgment means the deployment accepts every compute receipt without proof verification.',
        )
      }
      console.warn('WARNING: this deployment uses MockOpenVmReceiptVerifier on Sepolia. Compute proofs are not verified.')
    } else if (!isLocalChain) {
      throw new Error('TEMPLATE_UNPROVED_TEST requires the isolated local chain (chain ID 31337) or Sepolia (chain ID 11155111)')
    }
  }
  let verifier
  let verifierConstructorArgs: Record<string, unknown> = {}
  if (unprovedTest) {
    verifier = await ethers.deployContract('MockOpenVmReceiptVerifier')
  } else {
    // The identity `interfold program compile` wrote, unless OPENVM_* settings name one.
    const deployed = await deployOpenVmReceiptVerifier(ethers, compiledOpenVmEnvironment(TEMPLATE_ROOT))
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
  const ciphertextVerifierAddress = await ciphertextVerifier.getAddress()
  storeDeploymentArgs(
    {
      address: ciphertextVerifierAddress,
      blockNumber: await ethers.provider.getBlockNumber(),
      constructorArgs: { verifier: await verifier.getAddress(), imageId: programId },
    },
    'OpenVmBfvCiphertextVerifier',
    chain,
  )
  const encryptionSchemeId = ethers.keccak256(ethers.toUtf8Bytes('fhe.rs:BFV'))

  // Data-availability verifier. The mock accepts the ciphertext itself as its proof; it is for the
  // local chain, or for a public testnet when MOCK_DATA_AVAILABILITY=true. Mainnet refuses it.
  const useMockDataAvailability = isLocalChain || envFlag('MOCK_DATA_AVAILABILITY') === true
  if (chainId === MAINNET_CHAIN_ID && useMockDataAvailability) {
    throw new Error('MOCK_DATA_AVAILABILITY cannot be enabled for a mainnet deployment')
  }
  let dataAvailabilityVerifier
  let dataAvailabilityConstructorArgs: Record<string, unknown> = {}
  if (useMockDataAvailability) {
    dataAvailabilityVerifier = await ethers.deployContract('MockDataAvailabilityVerifier')
  } else {
    const { bridge, vectorx } = availVectorXForChain(Number(chainId))
    dataAvailabilityConstructorArgs = { bridge, vectorx }
    dataAvailabilityVerifier = await ethers.deployContract('AvailVectorXDataAvailabilityVerifier', [bridge, vectorx])
  }
  await dataAvailabilityVerifier.waitForDeployment()
  const dataAvailabilityVerifierAddress = await dataAvailabilityVerifier.getAddress()
  storeDeploymentArgs(
    {
      address: dataAvailabilityVerifierAddress,
      blockNumber: await ethers.provider.getBlockNumber(),
      constructorArgs: dataAvailabilityConstructorArgs,
    },
    useMockDataAvailability ? 'MockDataAvailabilityVerifier' : 'AvailVectorXDataAvailabilityVerifier',
    chain,
  )

  // `scripts/compile_circuits.sh` writes the bid verifiers and the anchor of the circuits they were
  // generated from; they must come from the same run.
  const anchorFile: unknown = JSON.parse(readFileSync(path.join(TEMPLATE_ROOT, 'circuits/target/vk_anchor.json'), 'utf8'))
  if (
    !anchorFile ||
    typeof anchorFile !== 'object' ||
    !('vkAnchor3' in anchorFile) ||
    typeof anchorFile.vkAnchor3 !== 'string' ||
    !('vkAnchor4' in anchorFile) ||
    typeof anchorFile.vkAnchor4 !== 'string'
  ) {
    throw new Error('circuits/target/vk_anchor.json has no vkAnchor3 and vkAnchor4; run scripts/compile_circuits.sh')
  }
  const { vkAnchor3, vkAnchor4 } = anchorFile
  // One verifier per role count. bb's ZK verifier is too large for one contract; each ships two
  // external libraries to link, and the generated files suffix every name with the role count.
  const bidVerifierAddresses: Record<3 | 4, string> = { 3: '', 4: '' }
  for (const roles of [3, 4] as const) {
    const verifierSource = `contracts/verifiers/AuctionVerifier${roles}.sol`
    const libraries: Record<string, string> = {}
    for (const library of ['ZKTranscriptLib', 'RelationsLib']) {
      const deployed = await ethers.deployContract(`${verifierSource}:${library}${roles}`)
      await deployed.waitForDeployment()
      libraries[`project/${verifierSource}:${library}${roles}`] = await deployed.getAddress()
    }
    const bidVerifier = await ethers.deployContract(`${verifierSource}:AuctionVerifier${roles}`, { libraries })
    await bidVerifier.waitForDeployment()
    bidVerifierAddresses[roles] = await bidVerifier.getAddress()
    storeDeploymentArgs(
      { address: bidVerifierAddresses[roles], blockNumber: await ethers.provider.getBlockNumber() },
      `AuctionVerifier${roles}`,
      chain,
    )
  }

  // The allowlist gate is an example `IBidderGate`; an auction names it in its `customParams`.
  const allowlistGate = await ethers.deployContract('MerkleAllowlistGate')
  await allowlistGate.waitForDeployment()
  const allowlistGateAddress = await allowlistGate.getAddress()
  storeDeploymentArgs({ address: allowlistGateAddress, blockNumber: await ethers.provider.getBlockNumber() }, 'MerkleAllowlistGate', chain)

  const e3ProgramFactory = await ethers.getContractFactory(
    AuctionProgramFactory.abi,
    AuctionProgramFactory.linkBytecode({
      'npm/poseidon-solidity@0.0.5/PoseidonT3.sol:PoseidonT3': poseidonT3Address,
    }),
    owner,
  )
  const e3Program = await e3ProgramFactory.deploy(
    await interfold.getAddress(),
    await verifier.getAddress(),
    programId,
    bidVerifierAddresses[3],
    bidVerifierAddresses[4],
    vkAnchor3,
    vkAnchor4,
    dataAvailabilityVerifierAddress,
  )
  await e3Program.waitForDeployment()
  const programAddress = await e3Program.getAddress()
  const programDeployBlock = (await e3Program.deploymentTransaction()?.wait())?.blockNumber ?? (await ethers.provider.getBlockNumber())
  storeDeploymentArgs(
    {
      address: programAddress,
      blockNumber: programDeployBlock,
      constructorArgs: {
        interfold: await interfold.getAddress(),
        verifier: await verifier.getAddress(),
        imageId: programId,
        bidVerifier3: bidVerifierAddresses[3],
        bidVerifier4: bidVerifierAddresses[4],
        vkAnchor3,
        vkAnchor4,
        dataAvailabilityVerifier: dataAvailabilityVerifierAddress,
      },
    },
    'AuctionProgram',
    chain,
  )

  // Protocol wiring is owner-only. Without the owner key (a Safe on Sepolia), print the exact calls.
  const deferProtocolWiring = envFlag('DEFER_PROTOCOL_WIRING') === true
  const interfoldOwner = await interfold.owner()
  const signerIsOwner = interfoldOwner.toLowerCase() === ownerAddress.toLowerCase()
  const configuredVerifier = await interfold.getCiphertextVerifier(encryptionSchemeId)
  // One ciphertext verifier serves a scheme for every program on an Interfold, and applies to
  // future requests. On a shared deployment, replace it only on an explicit request.
  const replacesSharedVerifier =
    !isLocalChain &&
    configuredVerifier !== ethers.ZeroAddress &&
    configuredVerifier.toLowerCase() !== ciphertextVerifierAddress.toLowerCase() &&
    !envFlag('ALLOW_REPLACE_CIPHERTEXT_VERIFIER')
  let wiringComplete = false
  if (signerIsOwner && !deferProtocolWiring && !replacesSharedVerifier) {
    await (await interfold.setCiphertextVerifier(encryptionSchemeId, ciphertextVerifierAddress)).wait()
    await (await interfold.registerE3Program(programAddress)).wait()
    if (!(await interfold.e3Programs(programAddress))) {
      throw new Error(`AuctionProgram ${programAddress} was not enabled on Interfold ${interfoldAddress}`)
    }
    wiringComplete = true
  } else {
    const calls = [
      {
        function: 'setCiphertextVerifier',
        args: [encryptionSchemeId, ciphertextVerifierAddress],
        data: interfold.interface.encodeFunctionData('setCiphertextVerifier', [encryptionSchemeId, ciphertextVerifierAddress]),
      },
      {
        function: 'registerE3Program',
        args: [programAddress],
        data: interfold.interface.encodeFunctionData('registerE3Program', [programAddress]),
      },
    ]
    console.log(
      `\nProtocol wiring is not done: ${
        deferProtocolWiring
          ? 'DEFER_PROTOCOL_WIRING=true'
          : !signerIsOwner
            ? `the signer ${ownerAddress} is not the Interfold owner ${interfoldOwner}`
            : `Interfold already routes fhe.rs:BFV ciphertexts to ${configuredVerifier}; set ALLOW_REPLACE_CIPHERTEXT_VERIFIER=true to replace it`
      }.`,
    )
    console.log('The Interfold owner (a Safe batch) must send these transactions in order:')
    for (const call of calls) {
      console.log(JSON.stringify({ to: interfoldAddress, value: '0', ...call }, null, 2))
    }
  }

  console.log(
    `
      Deployed AuctionProgram at address: ${programAddress}
      Deployed the bid verifiers at addresses: ${bidVerifierAddresses[3]} (3 roles), ${bidVerifierAddresses[4]} (4 roles); VK anchors ${vkAnchor3}, ${vkAnchor4}
      Deployed MerkleAllowlistGate at address: ${allowlistGateAddress}
      Deployed ${unprovedTest ? 'local unproved test verifier' : 'OpenVmReceiptVerifier'} at address: ${await verifier.getAddress()}
      Deployed OpenVmBfvCiphertextVerifier at address: ${ciphertextVerifierAddress}
      Deployed ${useMockDataAvailability ? 'MockDataAvailabilityVerifier' : 'AvailVectorXDataAvailabilityVerifier'} at address: ${dataAvailabilityVerifierAddress}
      Protocol wiring: ${wiringComplete ? 'complete' : 'pending the Interfold owner'}
    `,
  )

  updateE3Config(chain, INTERFOLD_CONFIG_FILE, contractMapping)
}
