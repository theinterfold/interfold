// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { ciphernodeAdd, ciphernodeAdminAdd } from '@interfold/contracts/tasks/ciphernode'
import { cleanDeploymentsTask } from '@interfold/contracts/tasks/utils'
import dotenv from 'dotenv'

import hardhatEthersChaiMatchers from '@nomicfoundation/hardhat-ethers-chai-matchers'
import hardhatIgnitionEthers from '@nomicfoundation/hardhat-ignition-ethers'
import hardhatNetworkHelpers from '@nomicfoundation/hardhat-network-helpers'
import hardhatToolboxMochaEthersPlugin from '@nomicfoundation/hardhat-toolbox-mocha-ethers'
import hardhatTypechainPlugin from '@nomicfoundation/hardhat-typechain'

import type { HardhatUserConfig } from 'hardhat/config'

dotenv.config()

const mnemonic = process.env.MNEMONIC ?? 'test test test test test test test test test test test junk'
const privateKey = process.env.PRIVATE_KEY!
const rpcUrl = process.env.RPC_URL ?? 'http://localhost:8545'

const chainIds = {
  'arbitrum-mainnet': 42161,
  avalanche: 43114,
  bsc: 56,
  ganache: 1337,
  hardhat: 31337,
  mainnet: 1,
  'optimism-mainnet': 10,
  'polygon-mainnet': 137,
  'polygon-mumbai': 80001,
  sepolia: 11155111,
  goerli: 5,
}

function getChainConfig(chain: keyof typeof chainIds, apiUrl: string) {
  let accounts: [string] | { count: number; mnemonic: string; path: string }
  if (privateKey) {
    accounts = [privateKey]
  } else {
    accounts = {
      count: 10,
      mnemonic: mnemonic,
      path: "m/44'/60'/0'/0",
    }
  }

  return {
    accounts,
    chainId: chainIds[chain],
    url: rpcUrl,
    type: 'http' as const,
    chainType: 'l1' as const,
    blockExplorers: {
      etherscan: {
        apiUrl,
      },
    },
  }
}

const config: HardhatUserConfig = {
  tasks: [ciphernodeAdd, ciphernodeAdminAdd, cleanDeploymentsTask],
  plugins: [
    hardhatTypechainPlugin,
    hardhatEthersChaiMatchers,
    hardhatIgnitionEthers,
    hardhatNetworkHelpers,
    hardhatToolboxMochaEthersPlugin,
  ],
  typechain: {
    outDir: './types',
    tsNocheck: false,
  },
  paths: {
    sources: ['./contracts', './.interfold/generated/contracts'],
  },
  networks: {
    hardhat: {
      type: 'edr-simulated',
      chainType: 'l1',
    },
    localhost: {
      accounts: {
        mnemonic,
      },
      chainId: chainIds.hardhat,
      url: 'http://localhost:8545',
      type: 'http',
      chainType: 'l1',
      timeout: 60000,
    },
    ganache: {
      accounts: {
        mnemonic,
      },
      chainId: chainIds.ganache,
      url: 'http://localhost:8545',
      type: 'http',
    },
    arbitrum: getChainConfig('arbitrum-mainnet', process.env.ARBISCAN_API_KEY || ''),
    avalanche: getChainConfig('avalanche', process.env.SNOWTRACE_API_KEY || ''),
    bsc: getChainConfig('bsc', process.env.BSCSCAN_API_KEY || ''),
    mainnet: getChainConfig('mainnet', process.env.ETHERSCAN_API_KEY || ''),
    optimism: getChainConfig('optimism-mainnet', process.env.OPTIMISM_API_KEY || ''),
    'polygon-mainnet': getChainConfig('polygon-mainnet', process.env.POLYGONSCAN_API_KEY || ''),
    'polygon-mumbai': getChainConfig('polygon-mumbai', process.env.POLYGONSCAN_API_KEY || ''),
    sepolia: getChainConfig('sepolia', process.env.ETHERSCAN_API_KEY || ''),
    goerli: getChainConfig('goerli', process.env.ETHERSCAN_API_KEY || ''),
  },
  solidity: {
    npmFilesToBuild: [
      'poseidon-solidity/PoseidonT3.sol',
      '@openzeppelin/contracts/proxy/transparent/ProxyAdmin.sol',
      '@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol',
      '@interfold/contracts/contracts/lib/InterfoldPricing.sol',
      '@interfold/contracts/contracts/Interfold.sol',
      '@interfold/contracts/contracts/registry/CiphernodeRegistryOwnable.sol',
      '@interfold/contracts/contracts/registry/BondingRegistry.sol',
      '@interfold/contracts/contracts/slashing/SlashingManager.sol',
      '@interfold/contracts/contracts/E3RefundManager.sol',
      '@interfold/contracts/contracts/token/InterfoldToken.sol',
      '@interfold/contracts/contracts/token/InterfoldTicketToken.sol',
      '@interfold/contracts/contracts/verifiers/bfv/BfvDecryptionVerifier.sol',
      '@interfold/contracts/contracts/verifiers/bfv/BfvPkVerifier.sol',
      '@interfold/contracts/contracts/verifiers/bfv/honk/DkgAggregatorVerifier.sol',
      '@interfold/contracts/contracts/verifiers/bfv/honk/DecryptionAggregatorVerifier.sol',
      '@interfold/contracts/contracts/test/MockCiphernodeRegistry.sol',
      '@interfold/contracts/contracts/test/MockComputeProvider.sol',
      '@interfold/contracts/contracts/test/MockDecryptionVerifier.sol',
      '@interfold/contracts/contracts/test/MockE3Program.sol',
      '@interfold/contracts/contracts/test/MockPkVerifier.sol',
      '@interfold/contracts/contracts/test/MockSlashingVerifier.sol',
      '@interfold/contracts/contracts/test/MockStableToken.sol',
    ],
    compilers: [
      {
        version: '0.8.28',
        settings: {
          optimizer: {
            enabled: true,
            // Low runs shrinks deployment bytecode (EIP-170); higher runs favor runtime gas.
            runs: 100,
          },
          metadata: {
            bytecodeHash: 'none',
          },
        },
      },
    ],
  },
}

export default config
