// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import 'dotenv/config'
import type { Address, Hex } from 'viem'

/** The live Sepolia deploy of the auction demo. */
export const DEPLOYMENT = {
  interfold: '0x0CdF132Be58dc57e1f45b39A403467c674c10b4B',
  ciphernodeRegistry: '0x3C114B193f1A66E6cFE88b2aE78B7027188f16F6',
  feeToken: '0x230616B4C2a6dc466D9e571F5e58bc73Fe6406E2',
  /** Gives the fee token (MockUSDC) to anyone who calls `faucet()`. */
  feeFaucet: '0xE4c5dC23B5F22c8913A11391ff3a9D6E22771221',
  /** The `AuctionProgram`. One program serves the three auction designs. */
  auctionProgram: '0xaca1cD626d5E788A1dA98AC0852c171944A6A773',
  /** The block in which the program was deployed: no event of the program is older. */
  auctionProgramBlock: 12020400n,
  /** The mask provider that the live demo server runs. */
  serverProvider: '0x761475d370e24C7f42a12d92913C805Ab929beE1',
  serverUrl: 'https://auction-testnet-server.theinterfold.com',
} as const satisfies Record<string, Address | bigint | string>

/** The least ETH that a generated second bidder gets. One bid costs about 6 M gas. */
export const BIDDER2_MIN_FUNDING_WEI = 5_000_000_000_000_000n

/** The gas that the funding of a generated second bidder covers: one bid (about 6 M) with a margin. */
export const BID_GAS_LIMIT = 7_000_000n

/** The minutes from the request to the end of the bid window. Key generation (about 8 min) and two proofs (2 to 5 min each) must fit in it. */
export const DEFAULT_WINDOW_MINUTES = 30

/** An error whose message tells the user what to do. The runner prints the message without a stack. */
export class ExampleError extends Error {}

export interface ExampleEnv {
  rpcUrl: string
  /** The creator and the first bidder. */
  creatorKey: Hex
  /** The second bidder, if the user gave a key. Otherwise the script makes and funds a key. */
  bidder2Key: Hex | undefined
  windowMinutes: number
}

function privateKeyFrom(name: string, value: string): Hex {
  const key = value.startsWith('0x') ? value : `0x${value}`
  if (!/^0x[0-9a-fA-F]{64}$/.test(key)) throw new ExampleError(`${name} must be 32 bytes of hex (64 characters, with or without 0x)`)
  return key as Hex
}

/** Read the settings of the example from the environment (and from `.env` in the working directory). */
export function loadEnv(): ExampleEnv {
  const rpcUrl = process.env.SEPOLIA_RPC_URL
  const creatorKey = process.env.PRIVATE_KEY
  const missing = [
    rpcUrl ? null : 'SEPOLIA_RPC_URL (an HTTPS Sepolia RPC endpoint)',
    creatorKey ? null : 'PRIVATE_KEY (a funded Sepolia account)',
  ].filter((entry) => entry !== null)
  if (missing.length > 0 || !rpcUrl || !creatorKey) {
    throw new ExampleError(`Set these environment variables, then run the example again:\n  ${missing.join('\n  ')}`)
  }
  if (!/^https?:\/\//.test(rpcUrl)) throw new ExampleError('SEPOLIA_RPC_URL must start with http:// or https://')
  const bidder2 = process.env.BIDDER2_PRIVATE_KEY
  if (bidder2 && privateKeyFrom('BIDDER2_PRIVATE_KEY', bidder2).toLowerCase() === privateKeyFrom('PRIVATE_KEY', creatorKey).toLowerCase()) {
    throw new ExampleError('BIDDER2_PRIVATE_KEY must differ from PRIVATE_KEY: the same key would update the first bid')
  }
  const minutes = process.env.WINDOW_MINUTES === undefined ? DEFAULT_WINDOW_MINUTES : Number(process.env.WINDOW_MINUTES)
  if (!Number.isInteger(minutes) || minutes < 15) throw new ExampleError('WINDOW_MINUTES must be a whole number of at least 15')
  return {
    rpcUrl,
    creatorKey: privateKeyFrom('PRIVATE_KEY', creatorKey),
    bidder2Key: bidder2 ? privateKeyFrom('BIDDER2_PRIVATE_KEY', bidder2) : undefined,
    windowMinutes: minutes,
  }
}
