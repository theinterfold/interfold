// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
// Network selection, public client + contract addresses. Profiles and the
// environment rules that select them live in ./networks.
//
// ABIs are imported from the canonical typechain factories in
// @interfold/contracts so they cannot drift from the deployed contracts.

import { createPublicClient, http, type Address } from 'viem'
import {
  BondingRegistry__factory,
  CiphernodeRegistryOwnable__factory,
  E3RefundManager__factory,
  Faucet__factory,
  Interfold__factory,
  InterfoldTicketToken__factory,
  InterfoldToken__factory,
} from '@interfold/contracts/types'
import { NETWORKS, overrideKey, selectNetwork, type Env, type Setting } from './networks'

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

// Failure reasons mirror the Solidity `IInterfold.FailureReason` enum.
// Keep this list in the same order as the contract ABI.
export enum FailureReason {
  None = 0,
  CommitteeFormationTimeout = 1,
  InsufficientCommitteeMembers = 2,
  DKGTimeout = 3,
  DKGInvalidShares = 4,
  NoInputsReceived = 5,
  ComputeTimeout = 6,
  ComputeProviderExpired = 7,
  ComputeProviderFailed = 8,
  RequesterCancelled = 9,
  DecryptionTimeout = 10,
  DecryptionInvalidShares = 11,
  VerificationFailed = 12,
}

// Vite inlines `import.meta.env` at build time. Node (tests) has none.
const env: Env = (import.meta as ImportMeta & { env?: Env }).env ?? {}

// The page's hostname picks the network (VITE_NETWORK_HOSTS), so one build can
// serve mainnet and testnet from different domains. Node (tests) has no window.
const NETWORK_KEY = selectNetwork(env, typeof window === 'undefined' ? undefined : window.location.hostname)
const NET = NETWORKS[NETWORK_KEY]

const envStr = (setting: Setting, fallback: string): string => {
  const v = env[overrideKey(NETWORK_KEY, setting)]
  return v && v.trim() !== '' ? v.trim() : fallback
}

// The faucet is the one address that can be switched off, so it needs to tell an
// unset variable (use the network default) from an explicitly empty one (disable).
// Every other setting is resolved with `envStr`, which folds empty into the
// fallback and so can never yield the disabled state.
const faucetAddress = (): string => {
  const configured = env[overrideKey(NETWORK_KEY, 'FAUCET_ADDRESS')]
  return configured === undefined ? NET.faucet : configured.trim()
}

const RPC_URL = envStr('RPC_URL', NET.rpc)

export const publicClient = createPublicClient({
  chain: NET.chain,
  transport: http(RPC_URL, { batch: true }),
})

export const CONTRACTS = {
  Interfold: envStr('INTERFOLD_ADDRESS', NET.interfold) as Address,
  CiphernodeRegistry: envStr('CIPHERNODE_REGISTRY_ADDRESS', NET.ciphernodeRegistry) as Address,
  CRISPProgram: envStr('CRISP_PROGRAM_ADDRESS', NET.crispProgram) as Address,
  // Operator-guide contracts. The bonding registry is the only address the guide
  // needs hardcoded — the ciphernode bond token, ticket wrapper, and ticket underlying
  // are all read back from it at runtime so they cannot drift.
  BondingRegistry: envStr('BONDING_REGISTRY_ADDRESS', NET.bondingRegistry) as Address,
  // Testnet-only convenience faucet (FOLD + fee token). The zero address or an
  // empty string disables the faucet card in the operator guide.
  Faucet: faucetAddress() as Address,
}

// Every CRISP program on the network: the current one, then the earlier deployments. An E3 of any of
// them is a CRISP poll.
export const CRISP_PROGRAMS: readonly Address[] = [CONTRACTS.CRISPProgram, ...(NET.previousCrispPrograms as readonly Address[])]

// The chain the dashboard writes to. Reads use `publicClient`; the operator guide
// refuses to send a transaction unless the wallet is on this chain.
export const CHAIN = NET.chain

// True on a test network. Test-only UI (the faucet) also requires it.
export const IS_TESTNET = CHAIN.testnet === true

// Human-readable network name for UI copy.
export const NETWORK_NAME = NET.name

// Block explorer base URL for the selected network.
export const EXPLORER_URL = NET.explorer

// Fee token metadata for formatting escrowed fees/rewards.
export const FEE_TOKEN = {
  symbol: envStr('FEE_TOKEN_SYMBOL', NET.feeSymbol),
  decimals: Number(envStr('FEE_TOKEN_DECIMALS', String(NET.feeDecimals))),
}

// First block to scan from — lower bound for getLogs. This bounds queries against
// Interfold, CiphernodeRegistry and CRISPProgram, so it must be the earliest of
// those three deploy blocks: a later value would silently drop registry events
// emitted before Interfold was deployed.
export const DEPLOY_BLOCK = BigInt(envStr('DEPLOY_BLOCK', NET.deployBlock))

// E3 timeout windows (seconds), matching the deployment's timeoutConfig. Used to
// decide whether an E3 is still genuinely active vs. expired without completing.
export const TIMEOUTS = {
  computeWindow: Number(envStr('COMPUTE_WINDOW', NET.computeWindow)),
  decryptionWindow: Number(envStr('DECRYPTION_WINDOW', NET.decryptionWindow)),
}

export const interfoldAbi = Interfold__factory.abi
export const ciphernodeRegistryAbi = CiphernodeRegistryOwnable__factory.abi
export const e3RefundManagerAbi = E3RefundManager__factory.abi
export const bondingRegistryAbi = BondingRegistry__factory.abi
export const ticketTokenAbi = InterfoldTicketToken__factory.abi
export const ciphernodeBondTokenAbi = InterfoldToken__factory.abi
export const faucetAbi = Faucet__factory.abi
