// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

/**
 * The scenario driver of the private round. One scenario is one full round on the local stack: it
 * requests the round, deposits, proves and publishes real bids, waits for the compute and the
 * decryption, clears, runs every claim, and checks the creator withdrawals.
 *
 * Environment:
 *   ROUND_SCENARIO           sold_out | undersubscribed | not_met | all (default all)
 *   ROUND_BIDDERS            the bidders that bid, 2 to 12 (default: 5 for sold_out, 3 for the others).
 *                            One more account deposits and never bids, so a round has up to 13 depositors.
 *   ROUND_PROOF_CONCURRENCY  bid proofs at the same time (default 2). One proof takes 3-4 CPU minutes.
 *   ROUND_SKIP_SWEEP         set to 1 to skip the 30-day time jump and the sweep at the end of the last scenario.
 *   PRIVATE_ROUND_SERVER_URL the coordination server that relays (default http://localhost:8080).
 *
 * Every scenario computes the expected outcome in the clear with `plainOutcome`, and asserts that the
 * decoded output, the stored clearing and every payout of a claim agree with it. A failed assertion
 * prints the state of the scenario.
 */
import {
  InterfoldSDK,
  calculateInputWindow,
  DEFAULT_COMPUTE_PROVIDER_PARAMS,
  encodeComputeProviderParams,
  CommitteeSize,
  CommitteePublicKeyAssembler,
} from '@interfold/sdk'
import { InterfoldEventType, RegistryEventType } from '@interfold/sdk/events'
import { E3Stage } from '@interfold/sdk/contracts'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import {
  createWalletClient,
  type Account,
  type Address,
  type Hex,
  hexToBytes,
  hexToSignature,
  http,
  parseAbi,
  parseEventLogs,
  type WalletClient,
} from 'viem'
import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts'
import { anvil } from 'viem/chains'
import { beforeAll, describe, expect, it } from 'vitest'
import { PrivateRoundProgram__factory } from '../types/factories/contracts'
import {
  allocationOf,
  bidInputsHash,
  bidTypedData,
  claimClass,
  claimComparison,
  clearing as clearingOf,
  decodeOutput,
  encodeBidInput,
  encodeSaleParams,
  escrowOf,
  marginalRank,
  MAX_BIDS_PER_BIDDER,
  Outcome,
  plainOutcome,
  PRESET,
  roundParamsOf,
  supplyOf,
  type Allocation,
  type BidInput,
  type ClaimClass,
  type Clearing,
  type RoundSale,
} from '@interfold/private-round'
import { BidProver, ClaimProver, PARAM_SET, type PreparedBid } from '@interfold/private-round/prover'
import { advanceAnvilTime, sleep } from './anvil-helpers'

const DAY = 24 * 3600
const CLAIM_WINDOW = 30 * DAY

const registryReadAbi = parseAbi(['function sortitionSeed(uint256 e3Id) view returns (bool ready, uint256 seed)'])
const erc20Abi = parseAbi([
  'function mint(address to, uint256 amount)',
  'function approve(address spender, uint256 amount) returns (bool)',
  'function balanceOf(address owner) view returns (uint256)',
  'function nonces(address owner) view returns (uint256)',
  'function name() view returns (string)',
])

const CREATOR_KEY = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80'
// Anvil accounts 6-8. Accounts 1-5 are the ciphernodes' wallets. Account 9 is the server's relayer.
// The other bidders are fresh keys that the test funds with gas.
const FIXED_BIDDER_KEYS = [
  '0x92db14e403b83dfe3df233f83dfa3a0d7096f21ca9b0d6d6b8d88b2b4ec1564e',
  '0x4bbbf85ce3377467afe5d46f804f221813b2bb87f24d81f60f1fcdbf7cbf4356',
  '0xdbda1821b80551c9d65939329250298aa3472ba22feea921c0cf5d620ea67b97',
] as const
const SERVER_URL = process.env.PRIVATE_ROUND_SERVER_URL ?? 'http://localhost:8080'

const SALE_DECIMALS = 18
const SALE_UNIT = 10n ** BigInt(SALE_DECIMALS)
/** Payment-token base units (6 decimals) per whole sale token at the steps 0, 1, 2, ...: 1, 2, 3, ... USDC. */
const ladder = (levels: number): bigint[] => Array.from({ length: levels }, (_, step) => BigInt(step + 1) * 1_000_000n)

const SCENARIO_NAMES = ['sold_out', 'undersubscribed', 'not_met'] as const
type ScenarioName = (typeof SCENARIO_NAMES)[number]

/** The public parameters and the bids of one scenario. The bidder `i` is the `i`-th account that deposits. */
interface Scenario {
  name: ScenarioName
  levels: number
  /** The lot, in whole sale tokens. */
  lotTokens: bigint
  lots: number
  reserveStep: number
  minLots: number
  defaultBidders: number
  /** The final step of each bidder, by bidder index. Longer than 12: the scenario cycles the pattern. */
  steps: readonly number[]
  /** Bidders that bid a first bid, then update it to the step of `steps`: the first bid steps. */
  updates: Readonly<Record<number, number>>
  /** Bidders whose final bid publishes a mask that does not open its commitment: the program leaves them out. */
  dropped: readonly number[]
  /** Bidders whose final bid goes through the relayer. */
  relayed: readonly number[]
  /** The bidder that deposits with a permit through the relayer. */
  permitDepositor: number
  /** What the scenario shows, with the default number of bidders. */
  expected: Outcome
}

/**
 * - sold_out: 2 lots, minimum raise 1, reserve step 1. Bids 5, 4, 4, 2, 0: one bidder above the clearing
 *   step 4, two at it (the first one by deposit order gets the one lot that is left, the other gets the
 *   refund), one below it and one below the reserve. The marginal bidders register in reverse order, to show
 *   that the deposit order decides. With 3 or more bidders at the step, the last one does not register and gets the refund only.
 * - undersubscribed: 3 lots, minimum raise 2, reserve step 1. Bids 3, 1 and a dropped bidder: two
 *   bidders at or above the reserve, fewer than the 3 lots.
 * - not_met: 2 lots, minimum raise 2, reserve step 2. Only one bidder is at the reserve.
 */
const SCENARIOS: Record<ScenarioName, Scenario> = {
  sold_out: {
    name: 'sold_out',
    levels: 6,
    lotTokens: 10n,
    lots: 2,
    reserveStep: 1,
    minLots: 1,
    defaultBidders: 5,
    steps: [5, 4, 4, 2, 0, 4, 3, 1, 4, 2, 5, 3],
    updates: { 1: 1 },
    dropped: [],
    relayed: [1, 3],
    permitDepositor: 2,
    expected: Outcome.SoldOut,
  },
  undersubscribed: {
    name: 'undersubscribed',
    levels: 4,
    lotTokens: 10n,
    lots: 3,
    reserveStep: 1,
    minLots: 2,
    defaultBidders: 3,
    steps: [3, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    updates: {},
    dropped: [2],
    relayed: [1],
    permitDepositor: 0,
    expected: Outcome.Undersubscribed,
  },
  not_met: {
    name: 'not_met',
    levels: 4,
    lotTokens: 10n,
    lots: 2,
    reserveStep: 2,
    minLots: 2,
    defaultBidders: 3,
    steps: [3, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1],
    updates: {},
    dropped: [],
    relayed: [0],
    permitDepositor: 1,
    expected: Outcome.NotMet,
  },
}

function readDeployment(name: string): Address {
  const deployments = JSON.parse(readFileSync(fileURLToPath(new URL('../deployed_contracts.json', import.meta.url)), 'utf8')) as {
    localhost?: Record<string, { address?: Address }>
  }
  const address = deployments.localhost?.[name]?.address
  if (!address) throw new Error(`deployed_contracts.json has no localhost ${name}; run pnpm deploy`)
  return address
}

function getContractAddresses() {
  return {
    interfold: process.env.INTERFOLD_ADDRESS as Address,
    ciphernodeRegistry: process.env.REGISTRY_ADDRESS as Address,
    e3Program: process.env.E3_PROGRAM_ADDRESS as Address,
    feeToken: process.env.FEE_TOKEN_ADDRESS as Address,
    saleToken: readDeployment('MockSaleToken'),
    paymentToken: readDeployment('MockPaymentToken'),
  }
}

function integerFromEnv(name: string, fallback: number, min: number, max: number): number {
  const text = process.env[name]?.trim()
  if (!text) return fallback
  const value = Number(text)
  if (!Number.isInteger(value) || value < min || value > max)
    throw new Error(`${name} must be an integer in [${min}, ${max}], got "${text}"`)
  return value
}

function selectedScenarios(): ScenarioName[] {
  const text = process.env.ROUND_SCENARIO?.trim() || 'all'
  if (text === 'all') return [...SCENARIO_NAMES]
  if (!(SCENARIO_NAMES as readonly string[]).includes(text)) {
    throw new Error(`ROUND_SCENARIO must be ${[...SCENARIO_NAMES, 'all'].join(' | ')}, got "${text}"`)
  }
  return [text as ScenarioName]
}

const jsonReplacer = (_key: string, value: unknown) => (typeof value === 'bigint' ? value.toString() : value)

/** One published bid of the plan. */
interface BidPlan {
  bidder: number
  step: number
  version: number
  relayed: boolean
  /** The mask ciphertext is the one of another bid, so the bytes do not open the commitment. */
  unopened: boolean
}

/** What a scenario run knows. It prints when an assertion fails. */
interface RunState {
  scenario: string
  e3Id?: bigint
  params?: Record<string, unknown>
  bidders?: { index: number; address: Address; finalStep: number | null; countedVersion: number }[]
  plan?: BidPlan[]
  expected?: { outcome: string; step: number | null; counted: number }
  decoded?: unknown
  clearing?: unknown
  claims?: unknown[]
  note?: string
}

describe('Private round', () => {
  const contracts = getContractAddresses()
  const sdk = InterfoldSDK.create({
    contracts: {
      interfold: contracts.interfold,
      ciphernodeRegistry: contracts.ciphernodeRegistry,
      feeToken: contracts.feeToken,
    },
    rpcUrl: 'ws://localhost:8545',
    chain: anvil,
    thresholdBfvParamsPresetName: PRESET,
    privateKey: CREATOR_KEY,
  })
  const publicClient = sdk.getPublicClient()
  const transport = http('http://localhost:8545')
  const creatorAccount = privateKeyToAccount(CREATOR_KEY)
  const creator = creatorAccount.address
  const creatorWallet = createWalletClient({ account: creatorAccount, chain: anvil, transport })
  const program = { address: contracts.e3Program, abi: PrivateRoundProgram__factory.abi } as const
  const concurrency = integerFromEnv('ROUND_PROOF_CONCURRENCY', 2, 1, 8)
  const skipSweep = process.env.ROUND_SKIP_SWEEP === '1'
  const names = selectedScenarios()

  const committeeKeys = new Map<bigint, Uint8Array>()
  const plaintexts = new Map<bigint, string>()
  const assembler = new CommitteePublicKeyAssembler()

  const anvilRequest = publicClient.request as (args: { method: string; params: unknown[] }) => Promise<unknown>
  const send = async (wallet: WalletClient & { account: Account }, request: Parameters<typeof publicClient.simulateContract>[0]) => {
    const { request: prepared } = await publicClient.simulateContract({ ...request, account: wallet.account } as never)
    const hash = await wallet.writeContract(prepared as never)
    const receipt = await publicClient.waitForTransactionReceipt({ hash })
    expect(receipt.status).toBe('success')
    return receipt
  }
  const balanceOf = (token: Address, owner: Address) =>
    publicClient.readContract({ address: token, abi: erc20Abi, functionName: 'balanceOf', args: [owner] })
  const waitFor = async <T>(what: string, read: () => T | undefined, timeoutMs: number): Promise<T> => {
    const deadline = Date.now() + timeoutMs
    for (;;) {
      const value = read()
      if (value !== undefined) return value
      if (Date.now() > deadline) throw new Error(`Timed out after ${timeoutMs}ms waiting for ${what}`)
      await sleep(500)
    }
  }
  const blockTime = async () => (await publicClient.getBlock()).timestamp
  const warpTo = async (timestamp: bigint) => {
    const now = await blockTime()
    if (now <= timestamp) await advanceAnvilTime(publicClient, Number(timestamp - now + 1n))
  }

  beforeAll(async () => {
    await sdk.onInterfoldEvent(RegistryEventType.COMMITTEE_PUBLIC_KEY_CHUNK_PUBLISHED, async (event) => {
      const assembled = assembler.add(event.data)
      if (!assembled) return
      if (await sdk.validatePublicKeyCommitment(assembled.publicKey, hexToBytes(assembled.pkCommitment))) {
        committeeKeys.set(assembled.e3Id, assembled.publicKey)
      }
    })
    await sdk.onInterfoldEvent(InterfoldEventType.PLAINTEXT_OUTPUT_PUBLISHED, (event) => {
      plaintexts.set(event.data.e3Id, event.data.plaintextOutput)
    })
  })

  /** Proves the bids with at most `concurrency` proofs at a time. Each worker owns one prover (one SRS in memory). */
  async function proveAll(count: number, prove: (prover: BidProver, index: number) => Promise<PreparedBid>): Promise<PreparedBid[]> {
    const prepared = new Array<PreparedBid>(count)
    const provers = await Promise.all(Array.from({ length: Math.min(concurrency, count) }, () => BidProver.create()))
    try {
      let next = 0
      await Promise.all(
        provers.map(async (prover) => {
          for (;;) {
            const index = next++
            if (index >= count) return
            prepared[index] = await prove(prover, index)
          }
        }),
      )
    } finally {
      await Promise.all(provers.map((prover) => prover.destroy()))
    }
    return prepared
  }

  async function runScenario(scenario: Scenario, state: RunState, sweepAtEnd: boolean): Promise<void> {
    const bidderCount = integerFromEnv('ROUND_BIDDERS', scenario.defaultBidders, 2, 12)
    state.note = `${bidderCount} bidders and one depositor that never bids`

    // ----- The round and its expected outcome, in the clear.
    const prices = ladder(scenario.levels)
    const lot = scenario.lotTokens * SALE_UNIT
    const sale: RoundSale = {
      prices,
      lot,
      lots: scenario.lots,
      reserveStep: scenario.reserveStep,
      minLots: scenario.minLots,
      saleDecimals: SALE_DECIMALS,
    }
    const escrow = escrowOf(sale)
    const supply = supplyOf(sale)
    const roundParams = roundParamsOf(sale)
    const title = `Integration ${scenario.name}`

    // The bids in publication order. A bidder that updates publishes its first bid, then its final one.
    const plan: BidPlan[] = []
    for (let bidder = 0; bidder < bidderCount; bidder++) {
      const first = scenario.updates[bidder]
      if (first !== undefined) plan.push({ bidder, step: first, version: 1, relayed: false, unopened: false })
      plan.push({
        bidder,
        step: scenario.steps[bidder],
        version: first === undefined ? 1 : 2,
        relayed: scenario.relayed.includes(bidder),
        unopened: scenario.dropped.includes(bidder),
      })
    }
    state.plan = plan
    // The final counted bid of each bidder: the highest version that opens its commitment.
    const finalStep: (number | null)[] = Array.from({ length: bidderCount }, (_, bidder) => {
      const counted = plan.filter((bid) => bid.bidder === bidder && !bid.unopened)
      return counted.length === 0 ? null : counted[counted.length - 1].step
    })
    const countedVersion = (bidder: number) => plan.filter((bid) => bid.bidder === bidder && !bid.unopened).length
    const countedSteps = finalStep.filter((step): step is number => step !== null)
    const expected = plainOutcome({ ...roundParams, lots: scenario.lots }, countedSteps)
    state.expected = { outcome: Outcome[expected.outcome], step: expected.step, counted: countedSteps.length }
    state.params = {
      levels: scenario.levels,
      prices,
      lot,
      lots: scenario.lots,
      reserveStep: scenario.reserveStep,
      minLots: scenario.minLots,
      escrow,
      supply,
    }
    if (bidderCount === scenario.defaultBidders) {
      expect(expected.outcome, 'the scenario shows what it is named for').toBe(scenario.expected)
    }

    // ----- Accounts and money. The creator gets the supply, the bidders get the escrow, fresh keys get gas.
    const depositors = bidderCount + 1 // the last one never bids
    const keys: Hex[] = [...FIXED_BIDDER_KEYS]
    while (keys.length < depositors) keys.push(generatePrivateKey())
    const wallets = keys
      .slice(0, depositors)
      .map((key) => createWalletClient({ account: privateKeyToAccount(key), chain: anvil, transport }))
    const addresses = wallets.map((wallet) => wallet.account.address)
    const idler = bidderCount
    for (const address of addresses.slice(FIXED_BIDDER_KEYS.length)) {
      await anvilRequest({ method: 'anvil_setBalance', params: [address, '0x56BC75E2D63100000'] })
    }
    await send(creatorWallet, { address: contracts.saleToken, abi: erc20Abi, functionName: 'mint', args: [creator, supply] })
    await send(creatorWallet, { address: contracts.saleToken, abi: erc20Abi, functionName: 'approve', args: [contracts.e3Program, supply] })
    for (const address of addresses) {
      await send(creatorWallet, { address: contracts.paymentToken, abi: erc20Abi, functionName: 'mint', args: [address, escrow] })
    }
    state.bidders = addresses.map((address, index) => ({
      index,
      address,
      finalStep: index < bidderCount ? finalStep[index] : null,
      countedVersion: index < bidderCount ? countedVersion(index) : 0,
    }))

    // ----- Request.
    // One window: the key generation takes about ten minutes, then the proofs, then the compute.
    const inputWindow = await calculateInputWindow(publicClient, 4 * 3600, 300n)
    const requestParams = {
      committeeSize: CommitteeSize.Minimum,
      inputWindow,
      e3Program: contracts.e3Program,
      paramSet: PARAM_SET,
      computeProviderParams: encodeComputeProviderParams(DEFAULT_COMPUTE_PROVIDER_PARAMS, true),
      customParams: encodeSaleParams({
        prices,
        saleToken: contracts.saleToken,
        lot,
        lots: scenario.lots,
        reserveStep: scenario.reserveStep,
        minLots: scenario.minLots,
        paymentToken: contracts.paymentToken,
        title,
      }),
    }
    expect(await publicClient.readContract({ ...program, functionName: 'MAX_BIDS_PER_BIDDER' })).toBe(MAX_BIDS_PER_BIDDER)

    const balanceBeforeRequest = await balanceOf(contracts.saleToken, contracts.e3Program)
    await sdk.waitForTransaction(await sdk.approveFeeToken(await sdk.getE3Quote(requestParams)))
    const requested = await publicClient.waitForTransactionReceipt({ hash: await sdk.requestE3(requestParams) })
    const [created] = parseEventLogs({ abi: PrivateRoundProgram__factory.abi, logs: requested.logs, eventName: 'SaleCreated' })
    const e3Id = created.args.e3Id
    state.e3Id = e3Id
    expect(created.args).toMatchObject({
      creator,
      levels: scenario.levels,
      saleToken: contracts.saleToken,
      paymentToken: contracts.paymentToken,
      lot,
      lots: scenario.lots,
      reserveStep: scenario.reserveStep,
      minLots: scenario.minLots,
      escrow,
      title,
    })
    expect([...created.args.prices].slice(0, scenario.levels)).toEqual(prices)
    const onChain = await publicClient.readContract({ ...program, functionName: 'sale', args: [e3Id] })
    expect(onChain.slice(0, 1)).toEqual([scenario.levels])
    expect(onChain[5]).toBe(lot) // lot
    expect(onChain[6]).toBe(scenario.lots)
    expect(onChain[7]).toBe(scenario.reserveStep)
    expect(onChain[8]).toBe(scenario.minLots)
    expect(onChain[9]).toBe(supply)
    expect(onChain[10]).toBe(escrow)
    // The contract pulled the supply at the request.
    expect(await balanceOf(contracts.saleToken, contracts.e3Program)).toBe(balanceBeforeRequest + supply)
    console.log(`[${scenario.name}] requested E3 ${e3Id}`)

    for (const deadline = Date.now() + 30_000; ; await sleep(250)) {
      const [ready] = await publicClient.readContract({
        address: contracts.ciphernodeRegistry,
        abi: registryReadAbi,
        functionName: 'sortitionSeed',
        args: [e3Id],
      })
      if (ready) break
      if (Date.now() > deadline) throw new Error(`Registry did not accept randomness for E3 ${e3Id}`)
    }

    // ----- Deposits. They assign the bidder indices 0, 1, 2, ... in this order. One bidder deposits
    // with a permit that the server's relayer sends.
    const gateProof = '0x'
    for (const [i, wallet] of wallets.entries()) {
      if (i === scenario.permitDepositor) {
        const deadline = (await blockTime()) + 3600n
        const name = await publicClient.readContract({ address: contracts.paymentToken, abi: erc20Abi, functionName: 'name' })
        const nonce = await publicClient.readContract({
          address: contracts.paymentToken,
          abi: erc20Abi,
          functionName: 'nonces',
          args: [addresses[i]],
        })
        const signature = hexToSignature(
          await wallet.signTypedData({
            domain: { name, version: '1', chainId: anvil.id, verifyingContract: contracts.paymentToken },
            types: {
              Permit: [
                { name: 'owner', type: 'address' },
                { name: 'spender', type: 'address' },
                { name: 'value', type: 'uint256' },
                { name: 'nonce', type: 'uint256' },
                { name: 'deadline', type: 'uint256' },
              ],
            },
            primaryType: 'Permit',
            message: { owner: addresses[i], spender: contracts.e3Program, value: escrow, nonce, deadline },
          }),
        )
        const response = await fetch(`${SERVER_URL}/relay/deposit`, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({
            e3Id: e3Id.toString(),
            bidder: addresses[i],
            gateProof,
            deadline: deadline.toString(),
            v: Number(signature.v ?? BigInt(27 + (signature.yParity ?? 0))),
            r: signature.r,
            s: signature.s,
          }),
        })
        const body = (await response.json()) as { txHash?: Hex; error?: string }
        expect(body.error).toBeUndefined()
        const receipt = await publicClient.waitForTransactionReceipt({ hash: body.txHash! })
        expect(receipt.status).toBe('success')
        // The relayer sent it, not the bidder, and the bidder paid no gas.
        expect(receipt.from.toLowerCase()).not.toBe(addresses[i].toLowerCase())
        expect(await balanceOf(contracts.paymentToken, addresses[i])).toBe(0n)
      } else {
        await send(wallet, {
          address: contracts.paymentToken,
          abi: erc20Abi,
          functionName: 'approve',
          args: [contracts.e3Program, escrow],
        })
        await send(wallet, { ...program, functionName: 'deposit', args: [e3Id, gateProof] })
      }
      expect(await publicClient.readContract({ ...program, functionName: 'bidderIndex', args: [e3Id, addresses[i]] })).toBe(BigInt(i))
    }
    expect(await publicClient.readContract({ ...program, functionName: 'bidderCount', args: [e3Id] })).toBe(BigInt(depositors))
    // A second deposit of the same address is refused.
    await expect(
      publicClient.simulateContract({ ...program, functionName: 'deposit', args: [e3Id, gateProof], account: addresses[0] }),
    ).rejects.toThrow(/AlreadyDeposited/)
    console.log(`[${scenario.name}] ${depositors} deposits done`)

    const committeeKey = await waitFor(`the verified committee key of E3 ${e3Id}`, () => committeeKeys.get(e3Id), 45 * 60_000)
    expect(await sdk.getE3Stage(e3Id)).toBe(E3Stage.KeyPublished)
    console.log(`[${scenario.name}] committee key published`)

    // ----- Prove every bid first. A proof binds its bidder, index, version and the round parameters.
    const prepared = await proveAll(plan.length, async (prover, i) => {
      const bid = plan[i]
      const started = Date.now()
      const result = await prover.prove({
        level: bid.step,
        levels: scenario.levels,
        reserveStep: scenario.reserveStep,
        committeeKey,
        bidder: addresses[bid.bidder],
        e3Id,
        bidderIndex: bid.bidder,
        version: bid.version,
        onStep: (step) => console.log(`[${scenario.name}] bid ${i} (bidder ${bid.bidder}, v${bid.version}): ${step.kind}`),
      })
      console.log(
        `[${scenario.name}] proved bid ${i} (bidder ${bid.bidder}, step ${bid.step}) in ${Math.round((Date.now() - started) / 1000)}s`,
      )
      return result
    })

    // What each bid publishes. An unopened bid carries the mask bytes of another bid under its own
    // commitments: the contract accepts it (it cannot open a commitment), the program does not count it.
    const bidInput = (i: number): BidInput => {
      const { ciphertexts, ctCommitments, bidCommitment, proof } = prepared[i]
      const other = prepared[i === 0 ? 1 : 0]
      return {
        bidder: addresses[plan[i].bidder],
        ciphertexts: plan[i].unopened ? [ciphertexts[0], other.ciphertexts[1]] : ciphertexts,
        ctCommitments,
        bidCommitment,
        proof,
        gateProof,
        signature: '0x',
      }
    }
    const bidCountOf = (bidder: number) =>
      publicClient.readContract({ ...program, functionName: 'bidCount', args: [e3Id, addresses[bidder]] })
    const simulate = (input: BidInput, sender: Address) =>
      publicClient.simulateContract({ ...program, functionName: 'publishInput', args: [e3Id, encodeBidInput(input)], account: sender })
    const sign = async (input: BidInput, bidder: number) => {
      const version = Number(await bidCountOf(bidder)) + 1
      return wallets[bidder].signTypedData(
        bidTypedData(
          anvil.id,
          contracts.e3Program,
          e3Id,
          addresses[bidder],
          version,
          bidInputsHash(input.ctCommitments, input.bidCommitment, input.ciphertexts),
        ),
      )
    }
    const relay = async (input: BidInput) => {
      const response = await fetch(`${SERVER_URL}/relay`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ e3Id: e3Id.toString(), data: encodeBidInput(input) }),
      })
      return { ok: response.ok, body: (await response.json()) as { txHash?: Hex; error?: string } }
    }

    // A bid needs a deposit: the creator has none.
    await expect(simulate({ ...bidInput(0), bidder: creator }, creator)).rejects.toThrow(/NotDeposited/)
    // Another account cannot send a direct bid for the bidder.
    await expect(simulate(bidInput(0), addresses[idler])).rejects.toThrow(/SenderNotBidder/)
    // A proof is bound to its bidder, index and version: another depositor cannot send it as its own bid.
    await expect(simulate({ ...bidInput(0), bidder: addresses[idler] }, addresses[idler])).rejects.toThrow(
      /InvalidBidProof|SumcheckFailed|ShpleminiFailed/,
    )

    for (const [i, bid] of plan.entries()) {
      const input = bidInput(i)
      const version = Number(await bidCountOf(bid.bidder)) + 1
      expect(version).toBe(bid.version)
      if (bid.relayed) {
        const relayed = { ...input, signature: await sign(input, bid.bidder) }
        const { ok, body } = await relay(relayed)
        expect(body.error).toBeUndefined()
        expect(ok).toBe(true)
        const receipt = await publicClient.waitForTransactionReceipt({ hash: body.txHash! })
        expect(receipt.status).toBe('success')
        expect(receipt.from.toLowerCase()).not.toBe(addresses[bid.bidder].toLowerCase())
        // The signature is for one version: the same signed bid no longer passes.
        const replay = await relay(relayed)
        expect(replay.ok).toBe(false)
        expect(replay.body.error).toMatch(/InvalidSignature/)
      } else {
        await send(wallets[bid.bidder], { ...program, functionName: 'publishInput', args: [e3Id, encodeBidInput(input)] })
      }
      expect(await bidCountOf(bid.bidder)).toBe(version)
      console.log(`[${scenario.name}] published bid ${i} of bidder ${bid.bidder}, version ${version}${bid.relayed ? ' (relayed)' : ''}`)
    }

    // One event per bid with two ciphertexts, the leaf of the first one, and two leaves per bid after the configuration.
    const submitted = await publicClient.getContractEvents({ ...program, eventName: 'BidSubmitted', args: { e3Id }, fromBlock: 0n })
    expect(submitted.map((event) => [event.args.bidder, event.args.version, event.args.index, Number(event.args.firstLeaf)])).toEqual(
      plan.map((bid, i) => [addresses[bid.bidder], bid.version, BigInt(bid.bidder), 1 + 2 * i]),
    )
    for (const event of submitted) {
      expect(event.args.ciphertexts).toHaveLength(2)
      expect(event.args.ctCommitments).toHaveLength(2)
    }
    const [, leaves] = await publicClient.readContract({ ...program, functionName: 'inputs', args: [e3Id] })
    expect(leaves).toBe(2 * plan.length + 1)

    await warpTo(inputWindow[1])
    console.log(`[${scenario.name}] closed the input window`)

    // ----- The output. The program counts the latest version of each bidder whose two ciphertexts open their commitments.
    const plaintextOutput = await waitFor(`the plaintext output of E3 ${e3Id}`, () => plaintexts.get(e3Id), 40 * 60_000)
    const bidCounts = Array.from({ length: 13 }, (_, index) => plan.filter((bid) => bid.bidder === index).length)
    const output = await decodeOutput(plaintextOutput, roundParams, bidCounts)
    state.decoded = output
    expect(output.reason).toBeNull()
    expect({ outcome: output.outcome, step: output.step }, 'decoded output against the plain outcome').toEqual(expected)
    expect(output.counted).toBe(countedSteps.length)
    expect(output.versions.slice(0, bidderCount)).toEqual(Array.from({ length: bidderCount }, (_, bidder) => countedVersion(bidder)))
    expect(output.versions.slice(bidderCount)).toEqual(Array.from({ length: 13 - bidderCount }, () => 0))

    // ----- The clearing: the contract, the SDK mirror and the plain outcome agree.
    const clearReceipt = await send(creatorWallet, { ...program, functionName: 'clear', args: [e3Id] })
    const [cleared] = parseEventLogs({ abi: PrivateRoundProgram__factory.abi, logs: clearReceipt.logs, eventName: 'SaleCleared' })
    const mirror: Clearing = clearingOf(sale, output)
    const view = await publicClient.readContract({ ...program, functionName: 'clearing', args: [e3Id] })
    const [isCleared, outcome, step, pStar, counted, phase1End, phase2End, claimDeadline, aboveClaimed0, registered0] = view
    state.clearing = { isCleared, outcome, step, pStar, counted, phase1End, phase2End, claimDeadline, aboveClaimed0, registered0, mirror }
    expect(isCleared).toBe(true)
    expect(outcome, 'on-chain outcome against the plain outcome').toBe(expected.outcome)
    expect(step).toBe(expected.step ?? 0)
    expect(pStar).toBe(mirror.pStar)
    expect(counted).toBe(BigInt(countedSteps.length))
    expect(cleared.args).toMatchObject({
      outcome: expected.outcome,
      step: expected.step ?? 0,
      pStar: mirror.pStar,
      counted: BigInt(countedSteps.length),
    })
    expect(aboveClaimed0).toBe(0n)
    expect(registered0).toBe(0n)
    const clearedAt = claimDeadline - BigInt(CLAIM_WINDOW)
    expect(phase1End).toBe(clearedAt + BigInt(2 * DAY))
    expect(phase2End).toBe(clearedAt + BigInt(4 * DAY))
    for (const bidder of [...Array(bidderCount).keys()]) {
      expect(await publicClient.readContract({ ...program, functionName: 'countedVersion', args: [e3Id, addresses[bidder]] })).toBe(
        countedVersion(bidder),
      )
    }
    expect(await publicClient.readContract({ ...program, functionName: 'countedVersion', args: [e3Id, addresses[idler]] })).toBe(0)
    console.log(`[${scenario.name}] cleared: ${Outcome[outcome]} at step ${step}, ${counted} counted`)

    // ----- The claims.
    const soldOut = mirror.outcome === Outcome.SoldOut
    const sells = soldOut || mirror.outcome === Outcome.Undersubscribed
    const claimProver = await ClaimProver.create()
    const claimLog: unknown[] = []
    state.claims = claimLog
    let paidTotal = 0n
    let tokensTotal = 0n
    let claimedCount = 0
    const marginalBidders: number[] = []
    const claimedAbove: number[] = []
    let tamperChecked = false

    /** The claim data of a depositor: a proof of the comparison with `k`, or empty when none is needed. */
    const claimData = async (bidder: number, overrideCmp?: 0 | 1 | 2): Promise<{ data: Hex; cmp: 0 | 1 | 2 | null }> => {
      const [proofNeeded, k] = await publicClient.readContract({
        ...program,
        functionName: 'claimRequirement',
        args: [e3Id, addresses[bidder]],
      })
      const step = bidder < bidderCount ? finalStep[bidder] : null
      const counted = bidder < bidderCount && countedVersion(bidder) > 0
      // The contract and the SDK agree on who needs a proof, and on k.
      expect(proofNeeded, `claimRequirement of bidder ${bidder}`).toBe(mirror.k !== null && counted)
      if (!proofNeeded) return { data: '0x', cmp: null }
      expect(k).toBe(mirror.k)
      const stored = await publicClient.readContract({
        ...program,
        functionName: 'bidCommitments',
        args: [e3Id, addresses[bidder], countedVersion(bidder)],
      })
      const bidIndex = plan.findIndex((bid) => bid.bidder === bidder && bid.version === countedVersion(bidder))
      const proved = await claimProver.prove({
        b: step as number,
        salt: prepared[bidIndex].salt,
        bidder: addresses[bidder],
        e3Id,
        bidCommitment: stored,
        k,
      })
      expect(proved.cmp).toBe(claimComparison(mirror, step as number))
      if (overrideCmp === undefined) return { data: proved.calldata, cmp: proved.cmp }
      // The cmp is a public input of the proof: a tampered value must fail the verifier.
      return { data: `0x${overrideCmp.toString(16).padStart(64, '0')}${proved.calldata.slice(66)}` as Hex, cmp: overrideCmp }
    }
    const claimRequest = (bidder: number, data: Hex) =>
      publicClient.simulateContract({ ...program, functionName: 'claim', args: [e3Id, addresses[bidder], data], account: creator })

    /** Sends a claim or a settlement, then checks the payout against the allocation and the balances. */
    const payOut = async (bidder: number, kind: 'claim' | 'settle', data: Hex, allocation: Allocation, cls: ClaimClass): Promise<void> => {
      const before = {
        sale: await balanceOf(contracts.saleToken, addresses[bidder]),
        payment: await balanceOf(contracts.paymentToken, addresses[bidder]),
      }
      // Anyone may send it; the funds go to the bidder.
      const receipt =
        kind === 'claim'
          ? await send(creatorWallet, { ...program, functionName: 'claim', args: [e3Id, addresses[bidder], data] })
          : await send(creatorWallet, { ...program, functionName: 'settleMarginal', args: [e3Id, addresses[bidder]] })
      const [claimed] = parseEventLogs({ abi: PrivateRoundProgram__factory.abi, logs: receipt.logs, eventName: 'Claimed' })
      claimLog.push({ bidder, kind, cls, allocation })
      expect(claimed.args, `Claimed event of bidder ${bidder}`).toMatchObject({ bidder: addresses[bidder], ...allocation })
      expect(await balanceOf(contracts.saleToken, addresses[bidder])).toBe(before.sale + allocation.tokens)
      expect(await balanceOf(contracts.paymentToken, addresses[bidder])).toBe(before.payment + allocation.refund)
      expect(allocation.paid + allocation.refund).toBe(escrow)
      expect(await publicClient.readContract({ ...program, functionName: 'claimed', args: [e3Id, addresses[bidder]] })).toBe(true)
      paidTotal += allocation.paid
      tokensTotal += allocation.tokens
      claimedCount++
      // A claim is paid once.
      await expect(claimRequest(bidder, data)).rejects.toThrow(/AlreadyClaimed/)
      console.log(
        `[${scenario.name}] bidder ${bidder}: ${cls}, ${allocation.tokens} tokens for ${allocation.paid}, refund ${allocation.refund}`,
      )
    }

    try {
      // Phase 1 (and every time in a round that sells nothing or is undersubscribed): full winners and refunds.
      for (const bidder of [...Array(bidderCount).keys()]) {
        const step = finalStep[bidder]
        const counted = step !== null
        const cmp = counted ? claimComparison(mirror, step) : null
        const cls = counted ? claimClass(mirror, cmp) : 'refund'
        if (cls === 'marginal') {
          marginalBidders.push(bidder)
          continue
        }
        const { data } = await claimData(bidder)
        if (!tamperChecked && cmp !== null) {
          tamperChecked = true
          // A bidder cannot turn its proof into a better outcome: the contract passes `cmp` to the verifier.
          const lie = (cmp === 2 ? 0 : 2) as 0 | 2
          const tampered = await claimData(bidder, lie)
          await expect(claimRequest(bidder, tampered.data)).rejects.toThrow(/InvalidClaimProof/)
        }
        if (cls === 'full' && soldOut) claimedAbove.push(bidder)
        await payOut(bidder, 'claim', data, allocationOf(sale, mirror, cls), cls)
      }
      // The idler never bids and never claims: its escrow stays in the contract until the sweep.
      if (!sells) {
        // Not met: the refund of a counted bidder needs no proof, and the contract has no marginal class.
        expect(marginalBidders).toEqual([])
      }

      const aboveExpected = soldOut ? countedSteps.filter((b) => b > (mirror.step as number)).length : 0
      expect(claimedAbove.length).toBe(aboveExpected)
      const afterPhase1 = await publicClient.readContract({ ...program, functionName: 'clearing', args: [e3Id] })
      expect(afterPhase1[8]).toBe(BigInt(claimedAbove.length))

      // Phase 2: the bidders at the clearing step register, and settle after the phase.
      if (soldOut && marginalBidders.length > 0) {
        // Registration is closed in phase 1.
        const first = await claimData(marginalBidders[0])
        await expect(claimRequest(marginalBidders[0], first.data)).rejects.toThrow(/MarginalPhaseNotOpen/)
        await warpTo(phase1End)
        // With three bidders at the step or more, the last one does not register: it forfeits the lot.
        const forfeiter = marginalBidders.length >= 3 ? marginalBidders[marginalBidders.length - 1] : null
        const registering = marginalBidders.filter((bidder) => bidder !== forfeiter)
        for (const bidder of [...registering].reverse()) {
          const { data, cmp } = await claimData(bidder)
          expect(cmp).toBe(1)
          const receipt = await send(creatorWallet, { ...program, functionName: 'claim', args: [e3Id, addresses[bidder], data] })
          expect(
            parseEventLogs({ abi: PrivateRoundProgram__factory.abi, logs: receipt.logs, eventName: 'MarginalRegistered' }),
          ).toHaveLength(1)
          expect(await publicClient.readContract({ ...program, functionName: 'registered', args: [e3Id, addresses[bidder]] })).toBe(true)
          // Registering is not a payout: the escrow stays locked and the bidder cannot register twice.
          expect(await publicClient.readContract({ ...program, functionName: 'claimed', args: [e3Id, addresses[bidder]] })).toBe(false)
          await expect(claimRequest(bidder, data)).rejects.toThrow(/AlreadyRegistered/)
          claimLog.push({ bidder, kind: 'register' })
        }
        const afterPhase2Start = await publicClient.readContract({ ...program, functionName: 'clearing', args: [e3Id] })
        expect(afterPhase2Start[9]).toBe(BigInt(registering.length))
        // The mask of the registrations has one bit for each registered bidder index.
        const mask = await publicClient.readContract({ ...program, functionName: 'marginalMask', args: [e3Id] })
        expect(mask).toBe(registering.reduce((bits, bidder) => bits | (1 << bidder), 0))
        // Settlement is closed until phase 2 ends.
        if (registering.length > 0) {
          await expect(
            publicClient.simulateContract({
              ...program,
              functionName: 'settleMarginal',
              args: [e3Id, addresses[registering[0]]],
              account: creator,
            }),
          ).rejects.toThrow(/SettlementNotOpen/)
        }
        await warpTo(phase2End)
        // The lots that phase 1 left go to the first registered bidders by deposit order, one whole lot each.
        const lotsLeft = scenario.lots - claimedAbove.length
        let filled = 0
        for (const bidder of registering) {
          const rank = marginalRank(registering, bidder)
          const allocation = allocationOf(sale, mirror, 'marginal', { aboveClaimed: claimedAbove.length, rank })
          expect(allocation.tokens, `bidder ${bidder} at rank ${rank} of ${lotsLeft} lots`).toBe(rank < lotsLeft ? lot : 0n)
          // The preview of the contract is the final allocation now.
          const [, tokens, paid, refund] = await publicClient.readContract({
            ...program,
            functionName: 'previewClaim',
            args: [e3Id, addresses[bidder], 1],
          })
          expect({ tokens, paid, refund }, 'preview of a registered marginal bidder').toEqual(allocation)
          // Settle in a different order than the deposits: the rank does not depend on it.
        }
        for (const bidder of [...registering].reverse()) {
          const rank = marginalRank(registering, bidder)
          const allocation = allocationOf(sale, mirror, 'marginal', { aboveClaimed: claimedAbove.length, rank })
          if (allocation.tokens > 0n) filled++
          await payOut(bidder, 'settle', '0x', allocation, 'marginal')
        }
        expect(filled).toBe(Math.min(lotsLeft, registering.length))
        if (forfeiter !== null) {
          // It did not register in phase 2: the proof of equality only earns the refund.
          const { data } = await claimData(forfeiter)
          await payOut(forfeiter, 'claim', data, allocationOf(sale, mirror, 'refund'), 'refund')
        }
      }

      expect(
        await publicClient.readContract({ ...program, functionName: 'claimed', args: [e3Id, addresses[idler]] }),
        'the idler did not claim',
      ).toBe(false)
      if (sells) {
        const lotsGiven = tokensTotal / lot
        expect(lotsGiven).toBeLessThanOrEqual(BigInt(scenario.lots))
        expect(tokensTotal).toBeLessThanOrEqual(supply)
      } else {
        expect(tokensTotal).toBe(0n)
        expect(paidTotal).toBe(0n)
      }
    } finally {
      await claimProver.destroy()
    }

    // ----- The creator.
    const paymentBefore = await balanceOf(contracts.paymentToken, creator)
    if (paidTotal > 0n) {
      await send(creatorWallet, { ...program, functionName: 'withdrawProceeds', args: [e3Id] })
      expect(await balanceOf(contracts.paymentToken, creator)).toBe(paymentBefore + paidTotal)
      expect(await publicClient.readContract({ ...program, functionName: 'proceedsAvailable', args: [e3Id] })).toBe(0n)
    } else {
      await expect(
        publicClient.simulateContract({ ...program, functionName: 'withdrawProceeds', args: [e3Id], account: creator }),
      ).rejects.toThrow(/NothingToWithdraw/)
    }
    let supplyTaken = false
    if (mirror.outcome === Outcome.NotMet || mirror.outcome === Outcome.Aborted) {
      // A round that sold nothing returns the whole supply, once.
      const saleBefore = await balanceOf(contracts.saleToken, creator)
      await send(creatorWallet, { ...program, functionName: 'withdrawSupply', args: [e3Id] })
      expect(await balanceOf(contracts.saleToken, creator)).toBe(saleBefore + supply)
      expect(await publicClient.readContract({ ...program, functionName: 'supplyReturned', args: [e3Id] })).toBe(true)
      await expect(
        publicClient.simulateContract({ ...program, functionName: 'withdrawSupply', args: [e3Id], account: creator }),
      ).rejects.toThrow(/NothingToWithdraw/)
      supplyTaken = true
    } else {
      await expect(
        publicClient.simulateContract({ ...program, functionName: 'withdrawSupply', args: [e3Id], account: creator }),
      ).rejects.toThrow(/SupplyNotWithdrawable/)
    }
    // Only the creator takes the funds.
    await expect(
      publicClient.simulateContract({ ...program, functionName: 'withdrawProceeds', args: [e3Id], account: addresses[0] }),
    ).rejects.toThrow(/NotCreator/)
    // The claim window is still open: no sweep yet.
    await expect(publicClient.simulateContract({ ...program, functionName: 'sweep', args: [e3Id], account: creator })).rejects.toThrow(
      /ClaimWindowOpen/,
    )

    if (sweepAtEnd && !skipSweep) {
      // Sweep: everything that nobody claimed. That is the lots that did not sell, and the escrow of the idler.
      await warpTo(claimDeadline)
      const saleBefore = await balanceOf(contracts.saleToken, creator)
      const payBefore = await balanceOf(contracts.paymentToken, creator)
      const expectedSale = supplyTaken ? 0n : supply - tokensTotal
      const expectedPayment = BigInt(depositors - claimedCount) * escrow
      const receipt = await send(creatorWallet, { ...program, functionName: 'sweep', args: [e3Id] })
      const [sweptEvent] = parseEventLogs({ abi: PrivateRoundProgram__factory.abi, logs: receipt.logs, eventName: 'Swept' })
      expect(sweptEvent.args).toMatchObject({ saleTokens: expectedSale, paymentTokens: expectedPayment })
      expect(await balanceOf(contracts.saleToken, creator)).toBe(saleBefore + expectedSale)
      expect(await balanceOf(contracts.paymentToken, creator)).toBe(payBefore + expectedPayment)
      expect(await publicClient.readContract({ ...program, functionName: 'swept', args: [e3Id] })).toBe(true)
      await expect(publicClient.simulateContract({ ...program, functionName: 'sweep', args: [e3Id], account: creator })).rejects.toThrow(
        /AlreadySwept/,
      )
    }
    console.log(`[${scenario.name}] done`)
  }

  for (const [position, name] of names.entries()) {
    it(
      `scenario ${name}`,
      async () => {
        const state: RunState = { scenario: name }
        try {
          await runScenario(SCENARIOS[name], state, position === names.length - 1)
        } catch (error) {
          console.error(`\n===== The scenario ${name} failed. State: =====\n${JSON.stringify(state, jsonReplacer, 2)}\n`)
          throw error
        }
      },
      3 * 60 * 60_000,
    )
  }
})
