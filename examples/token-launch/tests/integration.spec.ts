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
  hexToSignature,
  http,
  parseAbi,
  parseEventLogs,
  type WalletClient,
} from 'viem'
import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts'
import { anvil } from 'viem/chains'
import { describe, expect, it } from 'vitest'
import { TokenLaunchProgram__factory } from '../types/factories/contracts'
import {
  bidInputsHash,
  bidTypedData,
  ClaimTree,
  clearSale,
  configBytes,
  coarseProbeMask,
  countedBitmap,
  decodePlaintext,
  encodeBidInput,
  encodeClaimData,
  encodeLinkParams,
  encodeSaleParams,
  levelSum,
  PRESET,
  searchRound1,
  searchRound2,
  type Grid,
} from '@interfold/token-launch'
import { BidProver, ClaimProver, PARAM_SET, type PreparedBid } from '@interfold/token-launch/prover'
import { advanceAnvilTime, sleep } from './anvil-helpers'

const registryReadAbi = parseAbi(['function sortitionSeed(uint256 e3Id) view returns (bool ready, uint256 seed)'])
const erc20Abi = parseAbi([
  'function mint(address to, uint256 amount)',
  'function approve(address spender, uint256 amount) returns (bool)',
  'function balanceOf(address owner) view returns (uint256)',
  'function nonces(address owner) view returns (uint256)',
  'function name() view returns (string)',
])

const CREATOR_KEY = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80'
// Anvil accounts 6-8 hold gas for the two direct bidders. Accounts 1-5 are the ciphernodes' wallets.
// Account 9 is the server's relayer, which also sends `publishProbes`, `clear` and every claim.
const FIXED_BIDDER_KEYS = [
  '0x92db14e403b83dfe3df233f83dfa3a0d7096f21ca9b0d6d6b8d88b2b4ec1564e',
  '0x4bbbf85ce3377467afe5d46f804f221813b2bb87f24d81f60f1fcdbf7cbf4356',
  '0xdbda1821b80551c9d65939329250298aa3472ba22feea921c0cf5d620ea67b97',
] as const
const RELAYER = '0xa0Ee7A142d267C1f36714E4a8F75612F20a79720'
const SERVER_URL = process.env.TOKEN_LAUNCH_SERVER_URL ?? 'http://localhost:8080'

// ITokenLaunch.Phase.
const Phase = { Bidding: 1, Round1: 2, Probing: 3, Round2: 4, Clearable: 5, Cleared: 6, Aborted: 7, Failed: 8 } as const

/**
 * The sale. Prices are payment-token base units (6 decimals) per whole sale token (18 decimals): 1 to 8
 * USDC, one per step. A budget unit is 1 USDC. The supply is 30 tokens. A bid escrows one of two tiers,
 * 40 or 100 units.
 */
const LEVELS = 8
const PRICES = Array.from({ length: LEVELS }, (_, step) => BigInt(step + 1) * 1_000_000n)
const SALE_UNIT = 10n ** 18n
const BUDGET_UNIT = 1_000_000n
const TIERS = [40, 100]
const SUPPLY = 30n * SALE_UNIT
const GRID: Grid = { prices: PRICES, supply: SUPPLY, budgetUnit: BUDGET_UNIT, saleDecimals: 18 }

/**
 * The bids, in the order of their bid index (alice 0, bob 1, carol 2, dave 3).
 *
 * The budget sum of the bids with a step of at least `l` is F = [150, 150, 130, 130, 30, 30, 0, 0] for l = 0..7.
 * The over-demand test at level m asks F[m] * 1 USDC * 1 token > price[m-1] * 30 tokens, which is true for
 * m = 1, 2, 3 (150 > 30, 130 > 60, 130 > 90) and false from m = 4 (30 > 120 is false). The step is 3:
 * it is capped (130 >= 4 * 30), the price is 4 USDC, the bids above the step (alice, 30 USDC) buy 7.5
 * tokens, and the 22.5 tokens that remain go to the bids at the step, FIRST BID FIRST: bob (index 1)
 * could buy 10 tokens for 40 USDC and gets all 10; carol (index 2) could buy 15 and gets the remaining 12.5
 * for 50 USDC.
 *
 * - alice: step 5, budget 30, tier 0. Above the clearing step: a full winner.
 * - bob: step 3, budget 40, tier 0. At the clearing step: a marginal bidder. Relayed, with a permit.
 * - carol: step 3, budget 60, tier 1 (100 units). A marginal bidder with the larger escrow.
 * - dave: step 1, budget 20, tier 0. Below the clearing step: a loser. Relayed, with a permit, from
 *   an address that has no gas at all.
 *
 * The probe search reveals F at 4 levels only: round 1 at {2, 4, 6} (130, 30, 0) brackets the step in (2, 4),
 * and round 2 at {3} (130) fixes it. F[1], F[5] and F[7] stay hidden.
 */
interface Plan {
  name: string
  step: number
  budget: number
  tier: number
  /** Send it through `POST /relay` with the bidder's signature and a permit. */
  relayed?: true
}
const PLANS: readonly Plan[] = [
  { name: 'alice', step: 5, budget: 30, tier: 0 },
  { name: 'bob', step: 3, budget: 40, tier: 0, relayed: true },
  { name: 'carol', step: 3, budget: 60, tier: 1 },
  { name: 'dave', step: 1, budget: 20, tier: 0, relayed: true },
]

/** `F[l]` of the plans: the budget sum of the bids with a step of at least `l`. */
const CURVE = Array.from({ length: LEVELS }, (_, level) =>
  BigInt(PLANS.filter((plan) => plan.step >= level).reduce((sum, plan) => sum + plan.budget, 0)),
)
const sumsAt = (mask: number): bigint[] =>
  Array.from({ length: 16 }, (_, level) => (level < LEVELS && (mask & (1 << level)) !== 0 ? CURVE[level] : 0n))

// What the contract has to produce, worked out by hand above.
const EXPECTED = {
  lo: 2,
  hi: 4,
  probeMask1: 0b01010100,
  probeMask2: 0b00001000,
  kind: 1,
  step: 3,
  pStar: 4_000_000n,
  sold: SUPPLY,
  countedMask: 0b1111n,
  // `marginal`: the claim registers in the marginal window and the keeper pays it after the window.
  claims: [
    { tokens: 7_500_000_000_000_000_000n, paid: 30_000_000n, refund: 10_000_000n, cmp: 2, marginal: false },
    { tokens: 10_000_000_000_000_000_000n, paid: 40_000_000n, refund: 0n, cmp: 1, marginal: true },
    { tokens: 12_500_000_000_000_000_000n, paid: 50_000_000n, refund: 50_000_000n, cmp: 1, marginal: true },
    { tokens: 0n, paid: 0n, refund: 40_000_000n, cmp: 0, marginal: false },
  ],
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

describe('Token launch', () => {
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
  // The fourth bidder is a fresh key with no gas: its bid goes through the relayer.
  const bidders = [...FIXED_BIDDER_KEYS, generatePrivateKey()].map((key) =>
    createWalletClient({ account: privateKeyToAccount(key), chain: anvil, transport }),
  )
  const addresses = bidders.map((bidder) => bidder.account.address)
  const program = { address: contracts.e3Program, abi: TokenLaunchProgram__factory.abi } as const

  const send = async (wallet: WalletClient & { account: Account }, request: Parameters<typeof publicClient.simulateContract>[0]) => {
    const { request: prepared } = await publicClient.simulateContract({ ...request, account: wallet.account } as never)
    const hash = await wallet.writeContract(prepared as never)
    const receipt = await publicClient.waitForTransactionReceipt({ hash })
    expect(receipt.status).toBe('success')
    return receipt
  }
  const balanceOf = (token: Address, owner: Address) =>
    publicClient.readContract({ address: token, abi: erc20Abi, functionName: 'balanceOf', args: [owner] })
  const post = async (path: string, body: unknown) => {
    const response = await fetch(`${SERVER_URL}${path}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
    })
    return { ok: response.ok, body: (await response.json()) as { txHash?: Hex; error?: string } }
  }

  it(
    'sells tokens at one clearing price with a private budget and a private max price, and pays claims to fresh addresses',
    async () => {
      const started = Date.now()
      const marks: Array<[string, number]> = []
      const mark = (label: string, since = started) => {
        const seconds = (Date.now() - since) / 1000
        marks.push([label, seconds])
        console.log(`[${((Date.now() - started) / 1000).toFixed(1)} s] ${label}`)
        return seconds
      }

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
        console.log(`[${((Date.now() - started) / 1000).toFixed(1)} s] plaintext of E3 ${event.data.e3Id} published`)
      })
      const waitFor = async <T>(what: string, read: () => T | undefined | Promise<T | undefined>, timeoutMs: number): Promise<T> => {
        const deadline = Date.now() + timeoutMs
        for (;;) {
          const value = await read()
          if (value !== undefined) return value
          if (Date.now() > deadline) throw new Error(`Timed out after ${timeoutMs}ms waiting for ${what}`)
          await sleep(500)
        }
      }

      // Money. The creator gets the supply; each bidder gets the escrow of its tier. The fourth bidder has no gas.
      await send(creatorWallet, { address: contracts.saleToken, abi: erc20Abi, functionName: 'mint', args: [creator, SUPPLY] })
      await send(creatorWallet, {
        address: contracts.saleToken,
        abi: erc20Abi,
        functionName: 'approve',
        args: [contracts.e3Program, SUPPLY],
      })
      const escrowOf = (i: number) => BigInt(TIERS[PLANS[i].tier]) * BUDGET_UNIT
      // Every bidder holds the large tier, so that an escrow of the wrong tier fails at the proof and not at the balance.
      const funds = BigInt(TIERS.at(-1)!) * BUDGET_UNIT
      // A rerun on the same chain starts with the balances of the earlier runs.
      const programBefore = await balanceOf(contracts.paymentToken, contracts.e3Program)
      const before = await Promise.all(addresses.map((address) => balanceOf(contracts.paymentToken, address)))
      const leftoverOf = (i: number) => before[i] + funds - escrowOf(i)
      for (const address of addresses) {
        await send(creatorWallet, { address: contracts.paymentToken, abi: erc20Abi, functionName: 'mint', args: [address, funds] })
      }
      expect(await publicClient.getBalance({ address: addresses[3] })).toBe(0n)

      // Two requests with one input window: round 1 (its id is the sale id) and round 2. Both keys exist before the first bid.
      const inputWindow = await calculateInputWindow(publicClient, 2 * 3600, 300n)
      const baseRequest = {
        committeeSize: CommitteeSize.Minimum,
        inputWindow,
        e3Program: contracts.e3Program,
        paramSet: PARAM_SET,
        computeProviderParams: encodeComputeProviderParams(DEFAULT_COMPUTE_PROVIDER_PARAMS, true),
      }
      const request = async (customParams: Hex) => {
        const params = { ...baseRequest, customParams }
        await sdk.waitForTransaction(await sdk.approveFeeToken(await sdk.getE3Quote(params)))
        return publicClient.waitForTransactionReceipt({ hash: await sdk.requestE3(params) })
      }

      const requested1 = await request(
        encodeSaleParams({
          prices: PRICES,
          saleToken: contracts.saleToken,
          supply: SUPPLY,
          paymentToken: contracts.paymentToken,
          budgetUnit: BUDGET_UNIT,
          tiers: TIERS,
          title: 'Integration sale',
        }),
      )
      const [created] = parseEventLogs({ abi: TokenLaunchProgram__factory.abi, logs: requested1.logs, eventName: 'SaleCreated' })
      const saleId = created.args.saleId
      expect(created.args).toMatchObject({
        creator,
        levels: LEVELS,
        saleToken: contracts.saleToken,
        paymentToken: contracts.paymentToken,
        supply: SUPPLY,
        budgetUnit: BUDGET_UNIT,
        title: 'Integration sale',
      })
      expect(await publicClient.readContract({ ...program, functionName: 'phase', args: [saleId] })).toBe(Phase.Bidding)
      // The contract pulled the supply at the request.
      expect(await balanceOf(contracts.saleToken, contracts.e3Program)).toBeGreaterThanOrEqual(SUPPLY)

      const requested2 = await request(encodeLinkParams(saleId))
      const [linked] = parseEventLogs({ abi: TokenLaunchProgram__factory.abi, logs: requested2.logs, eventName: 'RoundTwoLinked' })
      const e3Id2 = linked.args.e3Id2
      expect(linked.args.saleId).toBe(saleId)
      expect(await publicClient.readContract({ ...program, functionName: 'roundTwo', args: [saleId] })).toBe(e3Id2)
      mark(`requested sale ${saleId} (round 1) and E3 ${e3Id2} (round 2)`)

      for (const e3Id of [saleId, e3Id2]) {
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

      const key1 = await waitFor(`the verified committee key of round 1 (E3 ${saleId})`, () => committeeKeys.get(saleId), 45 * 60_000)
      const key2 = await waitFor(`the verified committee key of round 2 (E3 ${e3Id2})`, () => committeeKeys.get(e3Id2), 45 * 60_000)
      expect(await sdk.getE3Stage(saleId)).toBe(E3Stage.KeyPublished)
      expect(await sdk.getE3Stage(e3Id2)).toBe(E3Stage.KeyPublished)
      mark('both committee keys published')

      // Prove every bid first. A proof binds its bidder, index, tier escrow and sale, so each bid is proven
      // for its own address and for the index that it will get.
      const prepared: PreparedBid[] = []
      const prover = await BidProver.create()
      try {
        for (const [i, plan] of PLANS.entries()) {
          const since = Date.now()
          prepared.push(
            await prover.prove({
              committeeKey1: key1,
              committeeKey2: key2,
              step: plan.step,
              budget: plan.budget,
              escrowUnits: TIERS[plan.tier],
              bidder: addresses[i],
              saleId,
              index: i,
              levels: LEVELS,
              onProgress: (step) => console.log(`Bid ${i}: ${step.kind}`),
            }),
          )
          mark(`proved the bid of ${plan.name} (step ${plan.step}, budget ${plan.budget}, tier ${plan.tier})`, since)
        }
      } finally {
        await prover.destroy()
      }

      const bidInput = (i: number) => ({ bidder: addresses[i], tier: PLANS[i].tier, ...prepared[i] })
      const inputsHashOf = (i: number) =>
        bidInputsHash(
          prepared[i].ctCommitment1,
          prepared[i].ctCommitment2,
          prepared[i].bidCommitment,
          prepared[i].ciphertext1,
          prepared[i].ciphertext2,
        )
      const publishData = (i: number) => encodeBidInput(bidInput(i))
      const simulate = (data: Hex, sender: Address) =>
        publicClient.simulateContract({ ...program, functionName: 'publishInput', args: [saleId, data], account: sender })

      // The first bidder approves more than its tier, so the next checks fail at the proof and not at the allowance.
      await send(bidders[0], {
        address: contracts.paymentToken,
        abi: erc20Abi,
        functionName: 'approve',
        args: [contracts.e3Program, BigInt(TIERS[1]) * BUDGET_UNIT],
      })
      // Another account cannot send a direct bid for the bidder.
      await expect(simulate(publishData(0), addresses[2])).rejects.toThrow(/SenderNotBidder/)
      // The escrow is bound by the proof: alice proved the small tier, and cannot escrow the large one under her proof.
      await expect(simulate(encodeBidInput({ ...bidInput(0), tier: 1 }), addresses[0])).rejects.toThrow(
        /InvalidBidProof|0x9fc3a218|0xa5d82e8a/,
      )
      // The proof is bound to the bidder: carol cannot send alice's bid as her own.
      await send(bidders[2], { address: contracts.paymentToken, abi: erc20Abi, functionName: 'approve', args: [contracts.e3Program, escrowOf(2)] })
      await expect(simulate(encodeBidInput({ ...bidInput(0), bidder: addresses[2] }), addresses[2])).rejects.toThrow(
        /InvalidBidProof|0x9fc3a218|0xa5d82e8a/,
      )

      const permitFor = async (i: number) => {
        const deadline = (await publicClient.getBlock()).timestamp + 3600n
        const name = await publicClient.readContract({ address: contracts.paymentToken, abi: erc20Abi, functionName: 'name' })
        const nonce = await publicClient.readContract({
          address: contracts.paymentToken,
          abi: erc20Abi,
          functionName: 'nonces',
          args: [addresses[i]],
        })
        const signature = hexToSignature(
          await bidders[i].signTypedData({
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
            message: { owner: addresses[i], spender: contracts.e3Program, value: escrowOf(i), nonce, deadline },
          }),
        )
        return { deadline, v: Number(signature.v ?? BigInt(27 + (signature.yParity ?? 0))), r: signature.r, s: signature.s }
      }

      // The bids, in the order of their indices. Direct: approve, then `publishInput`. Relayed: a signed bid and
      // a permit go to `POST /relay`, and the relayer pays the gas.
      const biddingStarted = Date.now()
      for (const [i, plan] of PLANS.entries()) {
        expect(await publicClient.readContract({ ...program, functionName: 'bidCount', args: [saleId] })).toBe(BigInt(i))
        if (plan.relayed) {
          const signature = await bidders[i].signTypedData(bidTypedData(anvil.id, contracts.e3Program, saleId, addresses[i], plan.tier, inputsHashOf(i)))
          const data = encodeBidInput({ ...bidInput(i), signature, permit: await permitFor(i) })
          const relayed = await post('/relay', { e3Id: saleId.toString(), data })
          expect(relayed.body.error).toBeUndefined()
          expect(relayed.ok).toBe(true)
          const receipt = await publicClient.waitForTransactionReceipt({ hash: relayed.body.txHash! })
          expect(receipt.status).toBe('success')
          // The relayer sent it: the bidder paid no gas.
          expect(receipt.from.toLowerCase()).toBe(RELAYER.toLowerCase())
          // A bid is accepted once per address.
          const again = await post('/relay', { e3Id: saleId.toString(), data })
          expect(again.ok).toBe(false)
          expect(again.body.error).toMatch(/AlreadyBid/)
        } else {
          await send(bidders[i], {
            address: contracts.paymentToken,
            abi: erc20Abi,
            functionName: 'approve',
            args: [contracts.e3Program, escrowOf(i)],
          })
          await send(bidders[i], { ...program, functionName: 'publishInput', args: [saleId, publishData(i)] })
        }
        expect(await balanceOf(contracts.paymentToken, addresses[i])).toBe(leftoverOf(i))
        console.log(`Published the bid of ${plan.name}${plan.relayed ? ' (relayed)' : ''}`)
      }
      mark('published 4 bids', biddingStarted)
      expect(await publicClient.getBalance({ address: addresses[3] })).toBe(0n)
      expect(await publicClient.readContract({ ...program, functionName: 'bidCount', args: [saleId] })).toBe(4n)
      const submitted = await publicClient.getContractEvents({ ...program, eventName: 'BidSubmitted', args: { saleId }, fromBlock: 0n })
      expect(submitted.map((event) => [event.args.bidder, event.args.index, event.args.tier])).toEqual(
        PLANS.map((plan, i) => [addresses[i], BigInt(i), plan.tier]),
      )
      // Every bid has two ciphertexts: one per round.
      for (const [i, event] of submitted.entries()) {
        expect(event.args).toMatchObject({ ciphertext1: prepared[i].ciphertext1, ciphertext2: prepared[i].ciphertext2 })
      }
      expect((await balanceOf(contracts.paymentToken, contracts.e3Program)) - programBefore).toBe(
        PLANS.reduce((sum, _, i) => sum + escrowOf(i), 0n),
      )

      // Close the input window of both rounds.
      const now = (await publicClient.getBlock()).timestamp
      if (now <= inputWindow[1]) await advanceAnvilTime(publicClient, Number(inputWindow[1] - now + 1n))
      const windowClosed = Date.now()
      mark('closed the input window')

      // Phases of the sale. The server computes round 1, the committee decrypts it and the keeper sends
      // `publishProbes`; then round 2 and `clear`.
      const seen: number[] = []
      const waitForPhase = (target: number, timeoutMs: number) =>
        waitFor(
          `the sale to reach phase ${target}`,
          async () => {
            const phase = Number(await publicClient.readContract({ ...program, functionName: 'phase', args: [saleId] }))
            if (seen.at(-1) !== phase) {
              seen.push(phase)
              console.log(`[${((Date.now() - started) / 1000).toFixed(1)} s] phase ${phase}`)
            }
            if (phase === Phase.Aborted || phase === Phase.Failed) throw new Error(`The sale reached the phase ${phase}`)
            return phase >= target ? phase : undefined
          },
          timeoutMs,
        )

      // Round 1.
      await waitFor(`the plaintext of round 1 (E3 ${saleId})`, () => plaintexts.get(saleId), 25 * 60_000)
      mark('round 1: computed and decrypted', windowClosed)
      const round1 = decodePlaintext(plaintexts.get(saleId)!, PLANS.length)
      // The output of round 1 is F at the three coarse levels and the counted flags. Every other cell is zero.
      const mask1 = coarseProbeMask(LEVELS)
      expect(mask1).toBe(EXPECTED.probeMask1)
      for (let level = 0; level < 16; level++) {
        const revealed = (mask1 & (1 << level)) !== 0
        expect(levelSum(round1.cells, level), `round 1, level ${level}`).toBe(revealed ? CURVE[level] : 0n)
      }
      expect(countedBitmap(round1.flagCells)).toBe(EXPECTED.countedMask)

      await waitForPhase(Phase.Round2, 10 * 60_000)
      mark('round 1: the keeper published the probes', windowClosed)
      const [probeEvent] = await publicClient.getContractEvents({ ...program, eventName: 'ProbesPublished', args: { saleId }, fromBlock: 0n })
      expect(probeEvent.args).toMatchObject({ saleId, e3Id2, lo: EXPECTED.lo, hi: EXPECTED.hi, probeMask2: EXPECTED.probeMask2 })
      expect(probeEvent.args.config).toBe(configBytes(2, LEVELS, EXPECTED.probeMask2))
      // The keeper sent it, not the test.
      expect((await publicClient.getTransaction({ hash: probeEvent.transactionHash })).from.toLowerCase()).toBe(RELAYER.toLowerCase())
      const mirror1 = searchRound1(GRID, sumsAt(mask1))
      expect(mirror1).toEqual({ valid: true, lo: EXPECTED.lo, hi: EXPECTED.hi, probeMask2: EXPECTED.probeMask2 })
      const [lo, hi, onChainMask1, onChainMask2, sums1] = await publicClient.readContract({ ...program, functionName: 'probeInfo', args: [saleId] })
      expect([lo, hi, onChainMask1, onChainMask2]).toEqual([EXPECTED.lo, EXPECTED.hi, EXPECTED.probeMask1, EXPECTED.probeMask2])
      expect([...sums1]).toEqual(sumsAt(mask1))

      // Round 2.
      await waitFor(`the plaintext of round 2 (E3 ${e3Id2})`, () => plaintexts.get(e3Id2), 25 * 60_000)
      mark('round 2: computed and decrypted', windowClosed)
      const round2 = decodePlaintext(plaintexts.get(e3Id2)!, PLANS.length)
      for (let level = 0; level < 16; level++) {
        const revealed = (EXPECTED.probeMask2 & (1 << level)) !== 0
        expect(levelSum(round2.cells, level), `round 2, level ${level}`).toBe(revealed ? CURVE[level] : 0n)
      }
      // Both rounds count the same bids.
      expect(countedBitmap(round2.flagCells)).toBe(countedBitmap(round1.flagCells))

      await waitForPhase(Phase.Cleared, 10 * 60_000)
      mark('round 2: the keeper cleared the sale', windowClosed)
      expect(seen).toEqual([...seen].sort((a, b) => a - b))
      expect(seen.at(-1)).toBe(Phase.Cleared)

      const [cleared] = await publicClient.getContractEvents({ ...program, eventName: 'SaleCleared', args: { saleId }, fromBlock: 0n })
      expect((await publicClient.getTransaction({ hash: cleared.transactionHash })).from.toLowerCase()).toBe(RELAYER.toLowerCase())
      expect(cleared.args).toMatchObject({
        kind: EXPECTED.kind,
        step: EXPECTED.step,
        pStar: EXPECTED.pStar,
        sold: EXPECTED.sold,
        countedMask: EXPECTED.countedMask,
      })
      // Only four of the seven interior levels were ever revealed, F[3] among them.
      const known = cleared.args.knownMask!
      for (const level of [2, 3, 4, 6]) expect(known & (1 << level), `level ${level} is known`).not.toBe(0)
      for (const level of [1, 5, 7]) expect(known & (1 << level), `level ${level} stays hidden`).toBe(0)
      expect(cleared.args.sums!.map((sum, level) => ((known & (1 << level)) !== 0 ? sum : 0n))).toEqual(
        CURVE.concat(Array(8).fill(0n)).map((sum, level) => ((known & (1 << level)) !== 0 ? sum : 0n)),
      )

      // The TypeScript mirror agrees with the contract and with the numbers worked out above.
      const sums2 = sumsAt(EXPECTED.probeMask2)
      const mirror2 = searchRound2(GRID, sumsAt(mask1), sums2, mirror1.lo, mirror1.probeMask2)
      expect(mirror2.valid).toBe(true)
      expect(mirror2.lstar).toBe(EXPECTED.step)
      const mirror = clearSale(GRID, mirror2.lstar, mirror2.sums)
      expect(mirror).toMatchObject({ kind: EXPECTED.kind, step: EXPECTED.step, pStar: EXPECTED.pStar, sold: EXPECTED.sold })
      const clearing = await publicClient.readContract({ ...program, functionName: 'clearing', args: [saleId] })
      expect(clearing).toMatchObject({
        cleared: true,
        kind: EXPECTED.kind,
        step: EXPECTED.step,
        pStar: EXPECTED.pStar,
        sold: EXPECTED.sold,
        countedMask: EXPECTED.countedMask,
        remaining: mirror.remaining,
      })
      // The marginal window is three days from the clearing.
      const clearedAt = (await publicClient.getBlock({ blockNumber: cleared.blockNumber })).timestamp
      expect(clearing.marginalDeadline).toBe(clearedAt + 3n * 86_400n)
      expect(clearing.remaining).toBe(22_500_000_000_000_000_000n)

      // The claim tree: the same root on chain and in the browser's mirror.
      const tree = ClaimTree.from(submitted.map((event) => BigInt(event.args.bidCommitment!)))
      expect(tree.root).toBe(clearing.root)
      expect(await publicClient.readContract({ ...program, functionName: 'claimRoot', args: [saleId] })).toBe(clearing.root)

      // The claims. Every bidder claims with a proof of its own and a FRESH recipient, through the relayer.
      // The winner and the loser are paid at once; nothing links their recipient to the bidder. A bid at the
      // clearing step (bob, carol) only REGISTERS in the marginal window: the proof shows its bid index, and
      // the keeper pays the registered claims, the first bid first, after the window.
      const claimProver = await ClaimProver.create()
      const recipients = PLANS.map(() => privateKeyToAccount(generatePrivateKey()).address)
      const marginalIndices = EXPECTED.claims.flatMap((claim, i) => (claim.marginal ? [i] : []))
      const claimsStarted = Date.now()
      try {
        for (const [i, plan] of PLANS.entries()) {
          const since = Date.now()
          const claim = await claimProver.prove({
            step: plan.step,
            budget: plan.budget,
            escrowUnits: TIERS[plan.tier],
            salt: prepared[i].salt,
            bidder: addresses[i],
            index: i,
            saleId,
            k: clearing.step,
            recipient: recipients[i],
            // Inside the marginal window the contract asks every claim for `reveal_index = 1`.
            revealIndex: true,
            root: clearing.root,
            countedMask: clearing.countedMask,
            path: tree.path(i).siblings,
          })
          mark(`proved the claim of ${plan.name}`, since)
          const expected = EXPECTED.claims[i]
          expect(claim.cmp).toBe(expected.cmp)
          expect(claim.indexPlusOne).toBe(expected.marginal ? i + 1 : 0)

          const claimData = (overrides: Partial<Parameters<typeof encodeClaimData>[0]> = {}) =>
            encodeClaimData({
              proof: claim.proof,
              nullifier: claim.nullifier,
              recipient: recipients[i],
              escrowUnits: TIERS[plan.tier],
              budgetUnits: claim.budgetUnits,
              cmp: claim.cmp,
              indexPlusOne: claim.indexPlusOne,
              ...overrides,
            })
          const data = claimData()
          // No byte of the claim names the bidder's address.
          expect(data.toLowerCase()).not.toContain(addresses[i].slice(2).toLowerCase())

          // The proof binds the recipient and the comparison: a relayer cannot redirect the payout or turn a loss into a win.
          const stolen = await post('/relay/claim', {
            saleId: saleId.toString(),
            data: claimData({ recipient: privateKeyToAccount(generatePrivateKey()).address }),
          })
          expect(stolen.ok).toBe(false)
          expect(stolen.body.error).toMatch(/InvalidClaimProof/)
          if (claim.cmp === 0) {
            const upgraded = await post('/relay/claim', { saleId: saleId.toString(), data: claimData({ cmp: 2, budgetUnits: plan.budget }) })
            expect(upgraded.ok).toBe(false)
            expect(upgraded.body.error).toMatch(/InvalidClaimProof/)
          }
          if (expected.marginal) {
            // The registered index is bound by the proof, and a marginal claim cannot hide it in the window.
            const moved = await post('/relay/claim', { saleId: saleId.toString(), data: claimData({ indexPlusOne: i === 1 ? 3 : 2 }) })
            expect(moved.ok).toBe(false)
            expect(moved.body.error).toMatch(/InvalidClaimProof/)
            const hidden = await post('/relay/claim', { saleId: saleId.toString(), data: claimData({ indexPlusOne: 0 }) })
            expect(hidden.ok).toBe(false)
            expect(hidden.body.error).toMatch(/InvalidClaim/)
          }

          expect(await balanceOf(contracts.saleToken, recipients[i])).toBe(0n)
          expect(await balanceOf(contracts.paymentToken, recipients[i])).toBe(0n)
          expect(await publicClient.getBalance({ address: recipients[i] })).toBe(0n)
          const relayed = await post('/relay/claim', { saleId: saleId.toString(), data })
          expect(relayed.body.error).toBeUndefined()
          expect(relayed.ok).toBe(true)
          const receipt = await publicClient.waitForTransactionReceipt({ hash: relayed.body.txHash! })
          expect(receipt.status).toBe('success')
          expect(receipt.from.toLowerCase()).toBe(RELAYER.toLowerCase())
          expect(await publicClient.readContract({ ...program, functionName: 'nullifierUsed', args: [saleId, claim.nullifier] })).toBe(true)

          if (expected.marginal) {
            const [registered] = parseEventLogs({ abi: TokenLaunchProgram__factory.abi, logs: receipt.logs, eventName: 'MarginalRegistered' })
            expect(registered.args).toEqual({ saleId, index: BigInt(i), budgetUnits: plan.budget, recipient: recipients[i] })
            expect(await publicClient.readContract({ ...program, functionName: 'marginalInfo', args: [saleId, BigInt(i)] })).toEqual([
              true,
              plan.budget,
              recipients[i],
              false,
            ])
            // Nothing is paid yet, and the preview shows what the first-bid-first fill will pay.
            expect(await balanceOf(contracts.saleToken, recipients[i])).toBe(0n)
            expect(await balanceOf(contracts.paymentToken, recipients[i])).toBe(0n)
            expect(await publicClient.readContract({ ...program, functionName: 'previewMarginal', args: [saleId, BigInt(i)] })).toEqual([
              expected.tokens,
              expected.paid,
              expected.refund,
            ])
            // A claim without the registration (after the window) is a forfeit: no tokens, the whole escrow back.
            expect(
              await publicClient.readContract({
                ...program,
                functionName: 'previewClaim',
                args: [saleId, claim.cmp, claim.budgetUnits, TIERS[plan.tier]],
              }),
            ).toEqual([0n, 0n, BigInt(TIERS[plan.tier]) * BUDGET_UNIT])
            console.log(`${plan.name}: marginal, registered bid ${i} (${expected.tokens} tokens for ${expected.paid} once the window ends)`)
          } else {
            const [event] = parseEventLogs({ abi: TokenLaunchProgram__factory.abi, logs: receipt.logs, eventName: 'Claimed' })
            expect(event.args).toEqual({
              saleId,
              nullifier: claim.nullifier,
              recipient: recipients[i],
              tokens: expected.tokens,
              paid: expected.paid,
              refund: expected.refund,
            })
            expect(
              await publicClient.readContract({
                ...program,
                functionName: 'previewClaim',
                args: [saleId, claim.cmp, claim.budgetUnits, TIERS[plan.tier]],
              }),
            ).toEqual([expected.tokens, expected.paid, expected.refund])
            // The tokens and the refund are at the fresh address. The bidder's address got nothing.
            expect(await balanceOf(contracts.saleToken, recipients[i])).toBe(expected.tokens)
            expect(await balanceOf(contracts.paymentToken, recipients[i])).toBe(expected.refund)
            console.log(
              `${plan.name}: ${['loser', 'marginal', 'winner'][claim.cmp]}, ${expected.tokens} tokens for ${expected.paid}, refund ${expected.refund}, to ${recipients[i]}`,
            )
          }
          expect(await balanceOf(contracts.saleToken, addresses[i])).toBe(0n)
          expect(await balanceOf(contracts.paymentToken, addresses[i])).toBe(leftoverOf(i))

          // A nullifier works once.
          const replay = await post('/relay/claim', { saleId: saleId.toString(), data })
          expect(replay.ok).toBe(false)
          expect(replay.body.error).toMatch(/NullifierUsed/)
        }
      } finally {
        await claimProver.destroy()
      }
      mark('claims: two paid, two registered', claimsStarted)

      // Nobody can pay a marginal claim while the window is open, the keeper included.
      await expect(
        publicClient.simulateContract({ ...program, functionName: 'payMarginal', args: [saleId, BigInt(marginalIndices[0])], account: creator }),
      ).rejects.toThrow(/MarginalWindowOpen/)

      // Time travel past the marginal deadline (three days). The keeper then pays each registered claim: the
      // first bid fills fully, the next takes the rest of the supply.
      const marginalClosed = Date.now()
      const latest = (await publicClient.getBlock()).timestamp
      await advanceAnvilTime(publicClient, Number(clearing.marginalDeadline - latest + 1n))
      await waitFor(
        'the keeper to pay the marginal claims',
        async () => {
          const infos = await Promise.all(
            marginalIndices.map((i) => publicClient.readContract({ ...program, functionName: 'marginalInfo', args: [saleId, BigInt(i)] })),
          )
          return infos.every(([, , , paid]) => paid) ? true : undefined
        },
        5 * 60_000,
      )
      mark('the keeper paid the marginal claims', marginalClosed)
      const paidEvents = await publicClient.getContractEvents({ ...program, eventName: 'MarginalPaid', args: { saleId }, fromBlock: 0n })
      expect(paidEvents).toHaveLength(marginalIndices.length)
      for (const i of marginalIndices) {
        const expected = EXPECTED.claims[i]
        const event = paidEvents.find((candidate) => candidate.args.index === BigInt(i))!
        expect(event.args).toEqual({
          saleId,
          index: BigInt(i),
          recipient: recipients[i],
          tokens: expected.tokens,
          paid: expected.paid,
          refund: expected.refund,
        })
        expect((await publicClient.getTransaction({ hash: event.transactionHash })).from.toLowerCase()).toBe(RELAYER.toLowerCase())
        expect(await balanceOf(contracts.saleToken, recipients[i])).toBe(expected.tokens)
        expect(await balanceOf(contracts.paymentToken, recipients[i])).toBe(expected.refund)
        // `payMarginal` pays once.
        await expect(
          publicClient.simulateContract({ ...program, functionName: 'payMarginal', args: [saleId, BigInt(i)], account: creator }),
        ).rejects.toThrow(/AlreadyPaid/)
      }

      const tokensTotal = EXPECTED.claims.reduce((sum, claim) => sum + claim.tokens, 0n)
      const paidTotal = EXPECTED.claims.reduce((sum, claim) => sum + claim.paid, 0n)
      expect(tokensTotal).toBe(EXPECTED.sold)
      expect(tokensTotal).toBeLessThanOrEqual(SUPPLY)
      expect(await publicClient.readContract({ ...program, functionName: 'proceedsAvailable', args: [saleId] })).toBe(paidTotal)
      mark('total')

      console.log('\nTimings (seconds)')
      for (const [label, seconds] of marks) console.log(`  ${seconds.toFixed(1).padStart(8)}  ${label}`)
    },
    120 * 60_000,
  )
})
