// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

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
  http,
  parseAbi,
  parseEventLogs,
  type WalletClient,
} from 'viem'
import { privateKeyToAccount } from 'viem/accounts'
import { anvil } from 'viem/chains'
import { describe, expect, it } from 'vitest'
import { NegotiationProgram__factory } from '../types/factories/contracts'
import {
  decodeOutput,
  encodeNegotiationParams,
  encodeOfferInput,
  expectedOutcome,
  LEVELS,
  offerInputsHash,
  offerTypedData,
  priceAt,
  PRESET,
  randomShare,
  Role,
  type OfferInput,
  type Outcome,
} from '@interfold/negotiation'
import { OfferProver, PARAM_SET, type PreparedOffer } from '@interfold/negotiation/prover'
import { advanceAnvilTime, sleep } from './anvil-helpers'

const registryReadAbi = parseAbi(['function sortitionSeed(uint256 e3Id) view returns (bool ready, uint256 seed)'])

const CREATOR_KEY = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80'
// Anvil accounts 6 and 7. Accounts 1-5 are the ciphernodes' wallets. Account 9 is the server's relayer.
const SELLER_KEY = '0x92db14e403b83dfe3df233f83dfa3a0d7096f21ca9b0d6d6b8d88b2b4ec1564e'
const BUYER_KEY = '0x4bbbf85ce3377467afe5d46f804f221813b2bb87f24d81f60f1fcdbf7cbf4356'
const SERVER_URL = process.env.NEGOTIATION_SERVER_URL ?? 'http://localhost:8080'

// The price grid of every negotiation: 16 levels from 48, one unit apart. The price of the level `i` is 48 + i.
const MIN_PRICE = 48n
const STEP_PRICE = 1n

/**
 * The negotiations of one run, as `[seller step, buyer step]`. The order of the choice:
 * 1. `NEGOTIATION_CASES="2:12,5:3"`: exactly these negotiations.
 * 2. Else `NEGOTIATIONS=n`: the first negotiation has `SELLER_STEP` and `BUYER_STEP` (default 2 and 12), and
 *    the other `n - 1` have random steps. With no variable the run has one negotiation, 2 and 12.
 */
function negotiationCases(env: NodeJS.ProcessEnv): Array<[number, number]> {
  const step = (name: string, value: string | undefined): number => {
    const parsed = Number(value)
    if (!Number.isInteger(parsed) || parsed < 0 || parsed >= LEVELS)
      throw new Error(`${name} must be an integer in [0, ${LEVELS}), got ${value}`)
    return parsed
  }
  const explicit = env.NEGOTIATION_CASES?.trim()
  if (explicit) {
    return explicit.split(',').map((pair) => {
      const [seller, buyer] = pair.split(':')
      return [step('NEGOTIATION_CASES seller step', seller), step('NEGOTIATION_CASES buyer step', buyer)]
    })
  }
  const count = Number(env.NEGOTIATIONS ?? 1)
  if (!Number.isInteger(count) || count < 1) throw new Error(`NEGOTIATIONS must be a positive integer, got ${env.NEGOTIATIONS}`)
  const random = () => Math.floor(Math.random() * LEVELS)
  return [
    [step('SELLER_STEP', env.SELLER_STEP ?? '2'), step('BUYER_STEP', env.BUYER_STEP ?? '12')],
    ...Array.from({ length: count - 1 }, (): [number, number] => [random(), random()]),
  ]
}

const CASES = negotiationCases(process.env)
// How many offer proofs run at the same time. Each one loads its own copy of the proving key.
const PROOF_CONCURRENCY = Math.max(1, Number(process.env.PROOF_CONCURRENCY ?? 2))

/** One negotiation of the run. The shares are drawn here, so the test knows the exact outcome. */
interface Plan {
  sellerStep: number
  buyerStep: number
  sellerShare: number
  buyerShare: number
  e3Id?: bigint
}

/** Runs `task` after every earlier task of the same key. A wallet sends one transaction at a time, so its nonces never collide. */
const queues = new Map<string, Promise<unknown>>()
function serialized<T>(key: string, task: () => Promise<T>): Promise<T> {
  const run = (queues.get(key) ?? Promise.resolve()).then(() => task())
  queues.set(
    key,
    run.catch(() => undefined),
  )
  return run
}

/** A fixed set of offer provers. A task takes an idle one, or waits for one. */
class ProverPool {
  private readonly waiting: Array<(prover: OfferProver) => void> = []

  private constructor(
    private readonly idle: OfferProver[],
    private readonly all: readonly OfferProver[],
  ) {}

  static async create(size: number): Promise<ProverPool> {
    const provers = await Promise.all(Array.from({ length: size }, () => OfferProver.create()))
    return new ProverPool([...provers], provers)
  }

  async use<T>(task: (prover: OfferProver) => Promise<T>): Promise<T> {
    const prover = this.idle.pop() ?? (await new Promise<OfferProver>((resolve) => this.waiting.push(resolve)))
    try {
      return await task(prover)
    } finally {
      const next = this.waiting.shift()
      if (next) next(prover)
      else this.idle.push(prover)
    }
  }

  async destroy(): Promise<void> {
    await Promise.all(this.all.map((prover) => prover.destroy()))
  }
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
    e3Program: (process.env.E3_PROGRAM_ADDRESS as Address | undefined) ?? readDeployment('NegotiationProgram'),
    feeToken: process.env.FEE_TOKEN_ADDRESS as Address,
  }
}

describe('Sealed price negotiation', () => {
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
  const sellerWallet = createWalletClient({ account: privateKeyToAccount(SELLER_KEY), chain: anvil, transport })
  const buyerWallet = createWalletClient({ account: privateKeyToAccount(BUYER_KEY), chain: anvil, transport })
  const seller = sellerWallet.account.address
  const buyer = buyerWallet.account.address
  const program = { address: contracts.e3Program, abi: NegotiationProgram__factory.abi } as const

  const send = (wallet: WalletClient & { account: Account }, request: Parameters<typeof publicClient.simulateContract>[0]) =>
    serialized(wallet.account.address, async () => {
      const { request: prepared } = await publicClient.simulateContract({ ...request, account: wallet.account } as never)
      const hash = await wallet.writeContract(prepared as never)
      const receipt = await publicClient.waitForTransactionReceipt({ hash })
      expect(receipt.status).toBe('success')
      return receipt
    })

  it(
    'agrees on one price, or on no match, without revealing the private steps',
    async () => {
      const assembler = new CommitteePublicKeyAssembler()
      const committeeKeys = new Map<bigint, Uint8Array>()
      await sdk.onInterfoldEvent(RegistryEventType.COMMITTEE_PUBLIC_KEY_CHUNK_PUBLISHED, async (event) => {
        const assembled = assembler.add(event.data)
        if (!assembled) return
        if (await sdk.validatePublicKeyCommitment(assembled.publicKey, hexToBytes(assembled.pkCommitment))) {
          committeeKeys.set(assembled.e3Id, assembled.publicKey)
        }
      })
      const plaintexts = new Map<bigint, string>()
      await sdk.onInterfoldEvent(InterfoldEventType.PLAINTEXT_OUTPUT_PUBLISHED, (event) => {
        plaintexts.set(event.data.e3Id, event.data.plaintextOutput)
      })
      const waitFor = async <T>(what: string, read: () => T | undefined, timeoutMs: number): Promise<T> => {
        const deadline = Date.now() + timeoutMs
        for (;;) {
          const value = read()
          if (value !== undefined) return value
          if (Date.now() > deadline) throw new Error(`Timed out after ${timeoutMs}ms waiting for ${what}`)
          await sleep(500)
        }
      }

      const plans: Plan[] = CASES.map(([sellerStep, buyerStep]) => ({
        sellerStep,
        buyerStep,
        sellerShare: randomShare(),
        buyerShare: randomShare(),
      }))
      console.log(
        `Negotiations of this run: ${plans.map((plan) => `seller=${priceAt(MIN_PRICE, STEP_PRICE, plan.sellerStep)} buyer=${priceAt(MIN_PRICE, STEP_PRICE, plan.buyerStep)}`).join('; ')}`,
      )

      // One window for all negotiations. Their key generations run at the same time, so the window must leave
      // time for the slowest one, for every proof, and for the rounds of approve-and-request.
      const inputWindow = await calculateInputWindow(publicClient, (2 + plans.length) * 3600, 300n)
      const requestParams = {
        committeeSize: CommitteeSize.Minimum,
        inputWindow,
        e3Program: contracts.e3Program,
        paramSet: PARAM_SET,
        computeProviderParams: encodeComputeProviderParams(DEFAULT_COMPUTE_PROVIDER_PARAMS, true),
        customParams: encodeNegotiationParams({
          seller,
          buyer,
          levels: LEVELS,
          minPrice: MIN_PRICE,
          stepPrice: STEP_PRICE,
          title: 'Integration negotiation',
        }),
      }

      // Open every E3 first: the key generation of each takes minutes, and they run together.
      for (const plan of plans) {
        await sdk.waitForTransaction(await sdk.approveFeeToken(await sdk.getE3Quote(requestParams)))
        const requested = await publicClient.waitForTransactionReceipt({ hash: await sdk.requestE3(requestParams) })
        const [created] = parseEventLogs({ abi: NegotiationProgram__factory.abi, logs: requested.logs, eventName: 'NegotiationCreated' })
        plan.e3Id = created.args.e3Id
        expect(created.args).toMatchObject({
          creator,
          seller,
          buyer,
          levels: LEVELS,
          minPrice: MIN_PRICE,
          stepPrice: STEP_PRICE,
          title: 'Integration negotiation',
        })
        expect(await publicClient.readContract({ ...program, functionName: 'negotiation', args: [plan.e3Id] })).toEqual([
          creator,
          seller,
          buyer,
          LEVELS,
          MIN_PRICE,
          STEP_PRICE,
          'Integration negotiation',
        ])
        console.log(`Requested E3 ${plan.e3Id}`)
      }
      const e3Ids = plans.map((plan) => plan.e3Id!)
      for (const e3Id of e3Ids) {
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
      }

      const simulate = (e3Id: bigint, input: OfferInput, sender: Address) =>
        publicClient.simulateContract({ ...program, functionName: 'publishInput', args: [e3Id, encodeOfferInput(input)], account: sender })
      const relay = async (e3Id: bigint, input: OfferInput) => {
        const response = await fetch(`${SERVER_URL}/relay`, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ e3Id: e3Id.toString(), data: encodeOfferInput(input) }),
        })
        return { ok: response.ok, body: (await response.json()) as { txHash?: Hex; error?: string } }
      }
      const offerInput = (party: Address, prepared: PreparedOffer, signature: Hex): OfferInput => ({
        party,
        ciphertexts: prepared.ciphertexts,
        commitments: prepared.commitments,
        proof: prepared.proof,
        signature,
      })

      const pool = await ProverPool.create(PROOF_CONCURRENCY)
      try {
        // One pipeline for each negotiation: wait for its key, prove both offers, publish them. The seller
        // publishes directly. The buyer signs and the server's relayer sends the offer.
        await Promise.all(
          plans.map(async (plan, n) => {
            const e3Id = plan.e3Id!
            const committeeKey = await waitFor(`the verified committee key of E3 ${e3Id}`, () => committeeKeys.get(e3Id), 45 * 60_000)
            expect(await sdk.getE3Stage(e3Id)).toBe(E3Stage.KeyPublished)
            console.log(`Committee key published for E3 ${e3Id}`)

            const prove = (role: Role, step: number, share: number, party: Address) =>
              pool.use(async (prover) => {
                const started = Date.now()
                const prepared = await prover.prove({
                  role,
                  step,
                  share,
                  party,
                  levels: LEVELS,
                  committeeKey,
                  onStep: (progress) => console.log(`Negotiation ${n}, ${Role[role]}: ${progress.kind}`),
                })
                console.log(`Proved the ${Role[role]} offer of negotiation ${n} (E3 ${e3Id}) in ${Date.now() - started}ms`)
                return prepared
              })
            const [sellerOffer, buyerOffer] = await Promise.all([
              prove(Role.Seller, plan.sellerStep, plan.sellerShare, seller),
              prove(Role.Buyer, plan.buyerStep, plan.buyerShare, buyer),
            ])

            const sellerInput = offerInput(seller, sellerOffer, '0x')
            expect(await publicClient.readContract({ ...program, functionName: 'offerSubmitted', args: [e3Id, Role.Seller] })).toBe(false)
            // A stranger is no party. The proof is bound to the party, so the seller's offer cannot be sent in the stranger's name.
            await expect(simulate(e3Id, { ...sellerInput, party: creator }, creator)).rejects.toThrow(/NotAParty/)
            await send(sellerWallet, { ...program, functionName: 'publishInput', args: [e3Id, encodeOfferInput(sellerInput)] })
            expect(await publicClient.readContract({ ...program, functionName: 'offerSubmitted', args: [e3Id, Role.Seller] })).toBe(true)
            // Each role sends one offer.
            await expect(simulate(e3Id, sellerInput, seller)).rejects.toThrow(/AlreadySubmitted/)

            const signature = await buyerWallet.signTypedData(
              offerTypedData(anvil.id, contracts.e3Program, e3Id, buyer, offerInputsHash(buyerOffer.commitments, buyerOffer.ciphertexts)),
            )
            const buyerInput = offerInput(buyer, buyerOffer, signature)
            const { ok, body } = await serialized('relayer', () => relay(e3Id, buyerInput))
            expect(body.error).toBeUndefined()
            expect(ok).toBe(true)
            const receipt = await publicClient.waitForTransactionReceipt({ hash: body.txHash! })
            expect(receipt.status).toBe('success')
            // The relayer sent it, not the buyer, and the buyer paid no gas.
            expect(receipt.from.toLowerCase()).not.toBe(buyer.toLowerCase())
            expect(await publicClient.readContract({ ...program, functionName: 'offerSubmitted', args: [e3Id, Role.Buyer] })).toBe(true)
            console.log(`Published both offers of negotiation ${n} (E3 ${e3Id})`)
          }),
        )
      } finally {
        await pool.destroy()
      }

      // Three input leaves for each offer, after the configuration leaf.
      for (const e3Id of e3Ids) {
        const [, leaves] = await publicClient.readContract({ ...program, functionName: 'inputs', args: [e3Id] })
        expect(leaves).toBe(7)
        const submitted = await publicClient.getContractEvents({ ...program, eventName: 'OfferSubmitted', args: { e3Id }, fromBlock: 0n })
        expect(submitted.map((event) => [event.args.party, event.args.role])).toEqual([
          [seller, Role.Seller],
          [buyer, Role.Buyer],
        ])
      }

      const now = (await publicClient.getBlock()).timestamp
      if (now <= inputWindow[1]) await advanceAnvilTime(publicClient, Number(inputWindow[1] - now + 1n))
      console.log('Closed the input window')

      // Every output is public as soon as it is decrypted: anyone settles. The outcome is exact, because the test knows the shares.
      const results: Array<{ e3Id: bigint; seller: bigint; buyer: bigint; outcome: Outcome; price: bigint | null }> = []
      for (const [n, plan] of plans.entries()) {
        const e3Id = plan.e3Id!
        const plaintextOutput = await waitFor(`the plaintext output of E3 ${e3Id}`, () => plaintexts.get(e3Id), 25 * 60_000)
        const decoded = await decodeOutput(plaintextOutput)
        const expected = expectedOutcome(plan.sellerStep, plan.buyerStep, plan.sellerShare, plan.buyerShare)
        expect(decoded).toEqual(expected)
        // The price lies between the two private prices, or there is no match.
        if (plan.sellerStep > plan.buyerStep) expect(decoded).toEqual({ matched: false, step: null })
        else {
          expect(decoded.matched).toBe(true)
          expect(decoded.step).toBeGreaterThanOrEqual(plan.sellerStep)
          expect(decoded.step).toBeLessThanOrEqual(plan.buyerStep)
        }

        expect((await publicClient.readContract({ ...program, functionName: 'outcome', args: [e3Id] }))[0]).toBe(false)
        const settleReceipt = await send(creatorWallet, { ...program, functionName: 'settle', args: [e3Id] })
        const [settled] = parseEventLogs({ abi: NegotiationProgram__factory.abi, logs: settleReceipt.logs, eventName: 'Settled' })
        const price = decoded.step === null ? 0n : priceAt(MIN_PRICE, STEP_PRICE, decoded.step)
        expect(settled.args).toMatchObject({ e3Id, matched: decoded.matched, step: decoded.step ?? 0, price })
        expect(await publicClient.readContract({ ...program, functionName: 'outcome', args: [e3Id] })).toEqual([
          true,
          decoded.matched,
          decoded.step ?? 0,
          price,
        ])
        // A negotiation settles once.
        await expect(publicClient.simulateContract({ ...program, functionName: 'settle', args: [e3Id], account: creator })).rejects.toThrow(
          /AlreadySettled/,
        )

        results.push({
          e3Id,
          seller: priceAt(MIN_PRICE, STEP_PRICE, plan.sellerStep),
          buyer: priceAt(MIN_PRICE, STEP_PRICE, plan.buyerStep),
          outcome: decoded,
          price: decoded.matched ? price : null,
        })
        console.log(
          `NEGOTIATION ${e3Id} seller=${results[n].seller} buyer=${results[n].buyer} -> ${decoded.matched ? `price=${price}` : 'price=no match'}`,
        )
      }

      // The price of each negotiation, for a table of the distribution over many runs.
      console.log(
        `NEGOTIATION RESULTS ${JSON.stringify(results.map((result) => ({ e3Id: result.e3Id.toString(), seller: result.seller.toString(), buyer: result.buyer.toString(), price: result.price?.toString() ?? null })))}`,
      )
    },
    (4 + CASES.length) * 3600 * 1000,
  )
})
