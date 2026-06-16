// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
import hardhatEthersChaiMatchers from "@nomicfoundation/hardhat-ethers-chai-matchers";
import hardhatIgnitionEthers from "@nomicfoundation/hardhat-ignition-ethers";
import hardhatNetworkHelpers from "@nomicfoundation/hardhat-network-helpers";
import hardhatToolboxMochaEthersPlugin from "@nomicfoundation/hardhat-toolbox-mocha-ethers";
import hardhatTypechainPlugin from "@nomicfoundation/hardhat-typechain";
import hardhatVerify from "@nomicfoundation/hardhat-verify";
import dotenv from "dotenv";
import type { HardhatUserConfig } from "hardhat/config";

import {
  ciphernodeAdd,
  ciphernodeAdminAdd,
  ciphernodeMintTokens,
  ciphernodeRemove,
  updateSubmissionWindow,
} from "./tasks/ciphernode";
import {
  enableE3,
  getActiveAggregator,
  getCommitteePublicKey,
  getPlaintextOutput,
  publishCiphertext,
  publishCommittee,
  publishPlaintext,
  requestCommittee,
} from "./tasks/interfold";
import { publishInput, setMockProgramInterfold } from "./tasks/program";
import { cleanDeploymentsTask } from "./tasks/utils";

dotenv.config();

const mnemonic =
  process.env.MNEMONIC ??
  "test test test test test test test test test test test junk";
const privateKey = process.env.PRIVATE_KEY!;
const rpcUrl = process.env.RPC_URL ?? "http://localhost:8545";

const chainIds = {
  "arbitrum-mainnet": 42161,
  avalanche: 43114,
  bsc: 56,
  ganache: 1337,
  hardhat: 31337,
  mainnet: 1,
  "optimism-mainnet": 10,
  "polygon-mainnet": 137,
  "polygon-mumbai": 80001,
  sepolia: 11155111,
  goerli: 5,
};

function getChainConfig(chain: keyof typeof chainIds, apiUrl: string) {
  let accounts: [string] | { count: number; mnemonic: string; path: string };
  if (privateKey) {
    accounts = [privateKey];
  } else {
    accounts = {
      count: 10,
      mnemonic: mnemonic,
      path: "m/44'/60'/0'/0",
    };
  }

  return {
    accounts,
    chainId: chainIds[chain],
    url: rpcUrl,
    type: "http" as const,
    chainType: "l1" as const,
    blockExplorers: {
      etherscan: {
        apiUrl,
      },
    },
  };
}

const config: HardhatUserConfig = {
  plugins: [
    hardhatToolboxMochaEthersPlugin,
    hardhatTypechainPlugin,
    hardhatNetworkHelpers,
    hardhatIgnitionEthers,
    hardhatEthersChaiMatchers,
    hardhatVerify,
  ],
  tasks: [
    ciphernodeAdd,
    ciphernodeAdminAdd,
    ciphernodeMintTokens,
    ciphernodeRemove,
    requestCommittee,
    getCommitteePublicKey,
    getActiveAggregator,
    publishPlaintext,
    publishCiphertext,
    publishCommittee,
    getPlaintextOutput,
    publishInput,
    setMockProgramInterfold,
    enableE3,
    cleanDeploymentsTask,
    updateSubmissionWindow,
  ],
  networks: {
    hardhat: {
      chainId: chainIds.hardhat,
      type: "edr-simulated",
      chainType: "l1",
      // Honk aggregator verify.staticCall uses ~3–4M gas in normal runs. The 1B limit is
      // artificial Hardhat headroom (not a mainnet constraint) so BfvVkBindingIntegration
      // can set block + tx gas via HONK_VERIFY_GAS_LIMIT / networkHelpers.setBlockGasLimit.
      // Under --coverage those on-chain verifies are skipped (instrumented verifiers OOG).
      blockGasLimit: 1_000_000_000,
    },
    localhost: {
      accounts: {
        mnemonic,
      },
      chainId: chainIds.hardhat,
      url: "http://localhost:8545",
      type: "http",
      chainType: "l1",
      timeout: 60000,
    },
    ganache: {
      accounts: {
        mnemonic,
      },
      chainId: chainIds.ganache,
      url: "http://localhost:8545",
      type: "http",
      timeout: 60000,
    },
    arbitrum: getChainConfig(
      "arbitrum-mainnet",
      process.env.ARBISCAN_API_KEY || "",
    ),
    avalanche: getChainConfig("avalanche", process.env.SNOWTRACE_API_KEY || ""),
    bsc: getChainConfig("bsc", process.env.BSCSCAN_API_KEY || ""),
    mainnet: getChainConfig("mainnet", process.env.ETHERSCAN_API_KEY || ""),
    optimism: getChainConfig(
      "optimism-mainnet",
      process.env.OPTIMISM_API_KEY || "",
    ),
    "polygon-mainnet": getChainConfig(
      "polygon-mainnet",
      process.env.POLYGONSCAN_API_KEY || "",
    ),
    "polygon-mumbai": getChainConfig(
      "polygon-mumbai",
      process.env.POLYGONSCAN_API_KEY || "",
    ),
    sepolia: getChainConfig("sepolia", process.env.ETHERSCAN_API_KEY || ""),
    goerli: getChainConfig("goerli", process.env.ETHERSCAN_API_KEY || ""),
  },
  verify: {
    etherscan: {
      apiKey: process.env.ETHERSCAN_API_KEY || "",
    },
    blockscout: {
      enabled: false,
    },
  },
  paths: {
    artifacts: "./artifacts",
    cache: "./cache",
    sources: "./contracts",
    tests: "./test",
  },
  typechain: {
    outDir: "./types",
    tsNocheck: false,
  },
  solidity: {
    npmFilesToBuild: [
      "poseidon-solidity/PoseidonT3.sol",
      "@openzeppelin/contracts/proxy/transparent/ProxyAdmin.sol",
      "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol",
    ],
    compilers: [
      {
        version: "0.8.28",
        settings: {
          // H-27: Pin EVM target to `paris` so artifacts are portable across
          // chains that do not yet support post-Shanghai/Cancun opcodes (e.g.
          // PUSH0, MCOPY, TLOAD/TSTORE).
          evmVersion: "paris",
          optimizer: {
            enabled: true,
            runs: 1,
          },
          debug: {
            revertStrings: "strip",
          },
          metadata: {
            bytecodeHash: "none",
          },
          // H-22: emit storage layouts so `scripts/validateUpgrade.ts` can
          // snapshot and diff upgradeable contracts across releases.
          outputSelection: {
            "*": {
              "*": [
                "abi",
                "evm.bytecode",
                "evm.deployedBytecode",
                "evm.methodIdentifiers",
                "metadata",
                "storageLayout",
              ],
            },
          },
        },
      },
    ],
  },
};

export default config;
