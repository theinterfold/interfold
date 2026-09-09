// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
// Network selection, public client + contract addresses.
// Sepolia addresses sourced from packages/interfold-contracts/deployed_contracts.json,
// mainnet addresses from deployments/manifest.json (networks.mainnet).
//
// ABIs are imported from the canonical typechain factories in
// @interfold/contracts so they cannot drift from the deployed contracts.

import { createPublicClient, http, type Address, type Chain } from 'viem'
import { mainnet, sepolia } from 'viem/chains'
import {
  BondingRegistry__factory,
  CiphernodeRegistryOwnable__factory,
  Faucet__factory,
  Interfold__factory,
  InterfoldTicketToken__factory,
  InterfoldToken__factory,
} from '@interfold/contracts/types'

// E3 lifecycle stages — mirrors the Solidity `IInterfold.E3Stage` enum exactly.
// Defined locally (rather than imported from @interfold/sdk) so the dashboard
// has no dependency on the SDK's Rust/Noir build chain when deploying.
export enum E3Stage {
  None = 0,
  Requested = 1,
  CommitteeFinalized = 2,
  KeyPublished = 3,
  CiphertextReady = 4,
  Complete = 5,
  Failed = 6,
}

// Per-network deployment profile. `VITE_NETWORK` selects one; every value in it
// can then be overridden individually via the VITE_* variables below, so the
// dashboard can point at a custom deployment without code changes.
type NetworkProfile = {
  chain: Chain
  // Human-readable name used in UI copy ("Reading from Sepolia…").
  name: string
  // True for test networks. Gates test-only UI (the faucet card and its
  // "testnet deployment" copy) independently of the faucet address, so a stale
  // VITE_FAUCET_ADDRESS cannot surface testnet copy on a production network.
  testnet: boolean
  rpc: string
  explorer: string
  interfold: string
  ciphernodeRegistry: string
  crispProgram: string
  bondingRegistry: string
  // Empty string = no faucet on this network (hides the operator-guide card).
  faucet: string
  deployBlock: string
  // Fee token metadata for formatting escrowed fees/rewards. Hardcoded per
  // deployment (like the addresses) rather than read on-chain at runtime.
  feeSymbol: string
  feeDecimals: number
  // E3 timeout windows (seconds), from the deployment's getTimeoutConfig().
  computeWindow: string
  decryptionWindow: string
}

const NETWORKS: Record<string, NetworkProfile> = {
  sepolia: {
    chain: sepolia,
    name: 'Sepolia',
    testnet: true,
    rpc: 'https://ethereum-sepolia.publicnode.com',
    explorer: 'https://sepolia.etherscan.io',
    interfold: '0x3E856E24c7a95d0e04d387f847DA6FA9f6F6c20C',
    ciphernodeRegistry: '0x374F4542eC634d5437Dd65020781A9D9Df9c2AB8',
    crispProgram: '0x8654F380760c46857188097Fa0AD0bf995603124',
    bondingRegistry: '0x90250Dc48CBe109fFaA02AeAFbFBdbF12D7BD4d4',
    faucet: '0x6e281411C055BEEbD74bDFcB9aB095aa98907F85',
    // Earliest of the Interfold/CiphernodeRegistry/CRISPProgram deploy blocks
    // (CiphernodeRegistry) — a later value silently drops early registry events.
    deployBlock: '11508403',
    // MockUSDC on the Sepolia deployment.
    feeSymbol: 'USDC',
    feeDecimals: 6,
    computeWindow: '86400',
    decryptionWindow: '3600',
  },
  mainnet: {
    chain: mainnet,
    name: 'Ethereum mainnet',
    testnet: false,
    rpc: 'https://ethereum-rpc.publicnode.com',
    explorer: 'https://etherscan.io',
    interfold: '0x28cF63B459e6218C69EA97ea7D90541cf648c715',
    ciphernodeRegistry: '0xC927A5B2d8F68697bC28C0670df05178c93df2d7',
    // CRISP is not deployed on mainnet yet; MockE3Program fills the slot so the
    // poll views resolve until a real CRISP deployment replaces it via env.
    crispProgram: '0x4976E5E47852eFCe6851d35B95A1A2E19456F3D7',
    bondingRegistry: '0x0ec90465095C21830BEcED07e032809A2Bd2915F',
    // No faucet on mainnet.
    faucet: '',
    // All mainnet contracts were deployed in the same block.
    deployBlock: '25786403',
    // USDS (0xdC035D45…384F) on the mainnet deployment.
    feeSymbol: 'USDS',
    feeDecimals: 18,
    computeWindow: '604800',
    decryptionWindow: '21600',
  },
}

const env = ((import.meta as any).env ?? {}) as Record<string, string | undefined>
const envStr = (key: string, fallback: string): string => {
  const v = env[key]
  return v && v.trim() !== '' ? v.trim() : fallback
}

const NETWORK_KEY = envStr('VITE_NETWORK', 'sepolia').toLowerCase()
const NET = NETWORKS[NETWORK_KEY]
if (!NET) {
  throw new Error(`Unknown VITE_NETWORK "${NETWORK_KEY}" — expected one of: ${Object.keys(NETWORKS).join(', ')}`)
}

// The faucet is the one address that can be switched off, so it needs to tell an
// unset variable (use the network default) from an explicitly empty one (disable).
// Every other setting is resolved with `envStr`, which folds empty into the
// fallback and so can never yield the disabled state.
const faucetAddress = (): string => {
  const configured = env['VITE_FAUCET_ADDRESS']
  return configured === undefined ? NET.faucet : configured.trim()
}

const RPC_URL = envStr('VITE_RPC_URL', NET.rpc)

export const publicClient = createPublicClient({
  chain: NET.chain,
  transport: http(RPC_URL, { batch: true }),
})

export const CONTRACTS = {
  Interfold: envStr('VITE_INTERFOLD_ADDRESS', NET.interfold) as Address,
  CiphernodeRegistry: envStr('VITE_CIPHERNODE_REGISTRY_ADDRESS', NET.ciphernodeRegistry) as Address,
  CRISPProgram: envStr('VITE_CRISP_PROGRAM_ADDRESS', NET.crispProgram) as Address,
  // Operator-guide contracts. The bonding registry is the only address the guide
  // needs hardcoded — the ciphernode bond token, ticket wrapper, and ticket underlying
  // are all read back from it at runtime so they cannot drift.
  BondingRegistry: envStr('VITE_BONDING_REGISTRY_ADDRESS', NET.bondingRegistry) as Address,
  // Testnet-only convenience faucet (FOLD + fee token). The zero address or an
  // empty string disables the faucet card in the operator guide.
  Faucet: faucetAddress() as Address,
}

// The chain the dashboard writes to. Reads use `publicClient`; the operator guide
// refuses to send a transaction unless the wallet is on this chain.
export const CHAIN = NET.chain

// Human-readable network name for UI copy.
export const NETWORK_NAME = NET.name

// Whether the selected network is a test network. Test-only UI must gate on this
// as well as on the faucet address.
export const IS_TESTNET = NET.testnet

// Block explorer base URL for the selected network.
export const EXPLORER_URL = NET.explorer

// Fee token metadata for formatting escrowed fees/rewards.
export const FEE_TOKEN = {
  symbol: envStr('VITE_FEE_TOKEN_SYMBOL', NET.feeSymbol),
  decimals: Number(envStr('VITE_FEE_TOKEN_DECIMALS', String(NET.feeDecimals))),
}

// First block to scan from — lower bound for getLogs. This bounds queries against
// Interfold, CiphernodeRegistry and CRISPProgram, so it must be the earliest of
// those three deploy blocks: a later value would silently drop registry events
// emitted before Interfold was deployed.
export const DEPLOY_BLOCK = BigInt(envStr('VITE_DEPLOY_BLOCK', NET.deployBlock))

// E3 timeout windows (seconds), matching the deployment's timeoutConfig. Used to
// decide whether an E3 is still genuinely active vs. expired without completing.
export const TIMEOUTS = {
  computeWindow: Number(envStr('VITE_COMPUTE_WINDOW', NET.computeWindow)),
  decryptionWindow: Number(envStr('VITE_DECRYPTION_WINDOW', NET.decryptionWindow)),
}

export const interfoldAbi = Interfold__factory.abi
export const ciphernodeRegistryAbi = CiphernodeRegistryOwnable__factory.abi
export const bondingRegistryAbi = BondingRegistry__factory.abi
export const ticketTokenAbi = InterfoldTicketToken__factory.abi
export const ciphernodeBondTokenAbi = InterfoldToken__factory.abi
export const faucetAbi = Faucet__factory.abi
