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
import { SealedCcaProgram__factory } from '../types/factories/contracts'
import {
  bidderOutcome,
  bidInputsHash,
  bidTypedData,
  clearing,
  decodeOutput,
  encodeBidInput,
  encodeSaleParams,
  expectedOutput,
  MAX_BIDS_PER_BIDDER,
  PRESET,
  type BidInput,
} from '@interfold/sealed-cca'
import { BidProver, ClaimProver, PARAM_SET, type PreparedBid } from '@interfold/sealed-cca/prover'
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
// Anvil accounts 6-8. Accounts 1-5 are the ciphernodes' wallets. Account 9 is the server's relayer.
// The fourth bidder is a fresh key that the test funds.
const FIXED_BIDDER_KEYS = [
  '0x92db14e403b83dfe3df233f83dfa3a0d7096f21ca9b0d6d6b8d88b2b4ec1564e',
  '0x4bbbf85ce3377467afe5d46f804f221813b2bb87f24d81f60f1fcdbf7cbf4356',
  '0xdbda1821b80551c9d65939329250298aa3472ba22feea921c0cf5d620ea67b97',
] as const
const SERVER_URL = process.env.SEALED_CCA_SERVER_URL ?? 'http://localhost:8080'

// The sale. Prices are payment-token base units (6 decimals) per whole sale token (18 decimals):
// 1, 2, 3 and 4 USDC. Every bid escrows 100 USDC and the supply is 50 tokens.
const SALE_UNIT = 10n ** 18n
const PRICES = [1_000_000n, 2_000_000n, 3_000_000n, 4_000_000n]
const ESCROW = 100_000_000n
const SUPPLY = 50n * SALE_UNIT

/**
 * The bids of the sale, in the order that the test publishes them. A bidder has the index of its
 * deposit: alice 0, bob 1, carol 2, dave 3.
 *
 * - alice bids the step 3 (4 USDC). She is above the clearing step: a full winner.
 * - bob first bids the step 0, then updates to the step 2. His version 2 counts. At the clearing
 *   step he is the one marginal bidder: he shares what the full winners leave.
 * - carol bids the step 0. She is a loser. She deposits with a permit and bids through the relayer.
 * - dave bids the step 1 with a ciphertext that does not open its commitment: the program leaves him
 *   out, and he is refunded in full without a proof.
 *
 * The demand is c = [3, 2, 2, 1]. The step 3 asks 1 * 100 USDC / 3 USDC = 33.3 tokens at most, which is
 * below the 50 tokens of supply, and the step 2 asks 2 * 100 / 2 = 100 tokens, above it: the sale
 * is capped at the step 2, and the price is 3 USDC.
 */
interface Plan {
  bidder: number
  step: number
  /** Send it through `POST /relay` with the bidder's signature. */
  relayed?: true
  /** Publish the bytes of another bid under this bid's commitment: they do not open it. */
  unopened?: true
}
const PLANS: readonly Plan[] = [
  { bidder: 0, step: 3 },
  { bidder: 1, step: 0 },
  { bidder: 1, step: 2, relayed: true },
  { bidder: 2, step: 0, relayed: true },
  { bidder: 3, step: 1, unopened: true },
]
const BIDDER_NAMES = ['alice', 'bob', 'carol', 'dave']
const LEVELS_OF_SALE = PRICES.length
const EXPECTED = { kind: 1, step: 2, pStar: 3_000_000n }

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

describe('Sealed CCA token sale', () => {
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
  const bidders = [...FIXED_BIDDER_KEYS, generatePrivateKey()].map((key) =>
    createWalletClient({ account: privateKeyToAccount(key), chain: anvil, transport }),
  )
  const addresses = bidders.map((bidder) => bidder.account.address)
  const program = { address: contracts.e3Program, abi: SealedCcaProgram__factory.abi } as const

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

  it(
    'sells tokens at one clearing price: a full winner, a marginal bidder, a loser and a dropped bidder',
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

      // Money. The creator gets the supply and the bidders get the escrow; the fourth bidder gets gas.
      await anvilRequest({ method: 'anvil_setBalance', params: [addresses[3], '0x56BC75E2D63100000'] })
      await send(creatorWallet, { address: contracts.saleToken, abi: erc20Abi, functionName: 'mint', args: [creator, SUPPLY] })
      await send(creatorWallet, {
        address: contracts.saleToken,
        abi: erc20Abi,
        functionName: 'approve',
        args: [contracts.e3Program, SUPPLY],
      })
      for (const address of addresses) {
        await send(creatorWallet, { address: contracts.paymentToken, abi: erc20Abi, functionName: 'mint', args: [address, ESCROW] })
      }

      // One window: the key generation takes about ten minutes, then four proofs, then the compute.
      const inputWindow = await calculateInputWindow(publicClient, 2 * 3600, 300n)
      const requestParams = {
        committeeSize: CommitteeSize.Minimum,
        inputWindow,
        e3Program: contracts.e3Program,
        paramSet: PARAM_SET,
        computeProviderParams: encodeComputeProviderParams(DEFAULT_COMPUTE_PROVIDER_PARAMS, true),
        customParams: encodeSaleParams({
          prices: PRICES,
          saleToken: contracts.saleToken,
          supply: SUPPLY,
          paymentToken: contracts.paymentToken,
          escrow: ESCROW,
          title: 'Integration sale',
        }),
      }
      expect(await publicClient.readContract({ ...program, functionName: 'MAX_BIDS_PER_BIDDER' })).toBe(MAX_BIDS_PER_BIDDER)

      await sdk.waitForTransaction(await sdk.approveFeeToken(await sdk.getE3Quote(requestParams)))
      const requested = await publicClient.waitForTransactionReceipt({ hash: await sdk.requestE3(requestParams) })
      const [created] = parseEventLogs({ abi: SealedCcaProgram__factory.abi, logs: requested.logs, eventName: 'SaleCreated' })
      const e3Id = created.args.e3Id
      expect(created.args).toMatchObject({
        creator,
        revealMode: 0,
        levels: LEVELS_OF_SALE,
        saleToken: contracts.saleToken,
        supply: SUPPLY,
        paymentToken: contracts.paymentToken,
        escrow: ESCROW,
        title: 'Integration sale',
      })
      // The contract pulled the supply at the request.
      expect(await balanceOf(contracts.saleToken, contracts.e3Program)).toBeGreaterThanOrEqual(SUPPLY)
      console.log(`Requested E3 ${e3Id}`)

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

      // Deposits assign the bidder indices: alice 0, bob 1, carol 2, dave 3. Carol deposits with a
      // permit, and the server's relayer sends it.
      const gateProof = '0x'
      for (const [i, wallet] of bidders.entries()) {
        if (i === 2) {
          const deadline = BigInt((await publicClient.getBlock()).timestamp) + 3600n
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
              message: { owner: addresses[i], spender: contracts.e3Program, value: ESCROW, nonce, deadline },
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
          // The relayer sent it, not carol, and she paid no gas.
          expect(receipt.from.toLowerCase()).not.toBe(addresses[i].toLowerCase())
          expect(await balanceOf(contracts.paymentToken, addresses[i])).toBe(0n)
        } else {
          await send(wallet, {
            address: contracts.paymentToken,
            abi: erc20Abi,
            functionName: 'approve',
            args: [contracts.e3Program, ESCROW],
          })
          await send(wallet, { ...program, functionName: 'deposit', args: [e3Id, gateProof] })
        }
        expect(await publicClient.readContract({ ...program, functionName: 'bidderIndex', args: [e3Id, addresses[i]] })).toBe(BigInt(i))
        console.log(`${BIDDER_NAMES[i]} deposited and has the index ${i}`)
      }
      expect(await publicClient.readContract({ ...program, functionName: 'bidderCount', args: [e3Id] })).toBe(4n)
      // A second deposit of the same address is refused, and so is a bid without a deposit.
      await expect(
        publicClient.simulateContract({ ...program, functionName: 'deposit', args: [e3Id, gateProof], account: addresses[0] }),
      ).rejects.toThrow(/AlreadyDeposited/)

      const committeeKey = await waitFor(`the verified committee key of E3 ${e3Id}`, () => committeeKeys.get(e3Id), 45 * 60_000)
      expect(await sdk.getE3Stage(e3Id)).toBe(E3Stage.KeyPublished)
      console.log(`Committee key published for E3 ${e3Id}`)

      // Prove every bid first. A proof binds its bidder, index and version, so each bid is proven
      // for its own address and for the version that it will get.
      const versionOf = (planIndex: number) =>
        PLANS.slice(0, planIndex + 1).filter((plan) => plan.bidder === PLANS[planIndex].bidder).length
      const prepared: PreparedBid[] = []
      const prover = await BidProver.create()
      try {
        for (const [i, plan] of PLANS.entries()) {
          const started = Date.now()
          prepared.push(
            await prover.prove(plan.step, LEVELS_OF_SALE, committeeKey, addresses[plan.bidder], e3Id, plan.bidder, versionOf(i), (step) =>
              console.log(`Bid ${i}: ${step.kind}`),
            ),
          )
          console.log(`Proved bid ${i} (${BIDDER_NAMES[plan.bidder]}, step ${plan.step}) in ${Date.now() - started}ms`)
        }
      } finally {
        await prover.destroy()
      }

      // What each bid publishes. An unopened bid carries the bytes of the first bid under its own
      // commitment, so the contract accepts it (it cannot open a commitment) and the program does not count it.
      const bidInput = (i: number): BidInput => {
        const { ciphertext, ctCommitment, bidCommitment, proof } = prepared[i]
        return {
          bidder: addresses[PLANS[i].bidder],
          ciphertext: PLANS[i].unopened ? prepared[0].ciphertext : ciphertext,
          ctCommitment,
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
        return bidders[bidder].signTypedData(
          bidTypedData(
            anvil.id,
            contracts.e3Program,
            e3Id,
            addresses[bidder],
            version,
            bidInputsHash(input.ctCommitment, input.bidCommitment, input.ciphertext),
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
      // A proof is bound to its bidder, index and version: bob cannot send alice's proof as his own bid.
      await expect(simulate({ ...bidInput(0), bidder: addresses[1] }, addresses[1])).rejects.toThrow(
        /InvalidBidProof|SumcheckFailed|ShpleminiFailed/,
      )
      // Another account cannot send a direct bid for the bidder.
      await expect(simulate(bidInput(0), addresses[2])).rejects.toThrow(/SenderNotBidder/)

      for (const [i, plan] of PLANS.entries()) {
        const input = bidInput(i)
        const version = Number(await bidCountOf(plan.bidder)) + 1
        expect(version).toBe(versionOf(i))
        if (plan.relayed) {
          const relayed = { ...input, signature: await sign(input, plan.bidder) }
          const { ok, body } = await relay(relayed)
          expect(body.error).toBeUndefined()
          expect(ok).toBe(true)
          const receipt = await publicClient.waitForTransactionReceipt({ hash: body.txHash! })
          expect(receipt.status).toBe('success')
          expect(receipt.from.toLowerCase()).not.toBe(addresses[plan.bidder].toLowerCase())
          // The signature is for one version: the same signed bid no longer passes.
          const replay = await relay(relayed)
          expect(replay.ok).toBe(false)
          expect(replay.body.error).toMatch(/InvalidSignature/)
        } else {
          await send(bidders[plan.bidder], { ...program, functionName: 'publishInput', args: [e3Id, encodeBidInput(input)] })
        }
        expect(await bidCountOf(plan.bidder)).toBe(version)
        console.log(`Published bid ${i} of ${BIDDER_NAMES[plan.bidder]}, version ${version}`)
      }

      // One event and one leaf per bid, and the event carries the bidder index of the deposit.
      const submitted = await publicClient.getContractEvents({ ...program, eventName: 'BidSubmitted', args: { e3Id }, fromBlock: 0n })
      expect(submitted.map((event) => [event.args.bidder, event.args.version, event.args.index])).toEqual(
        PLANS.map((plan, i) => [addresses[plan.bidder], versionOf(i), BigInt(plan.bidder)]),
      )
      const [, leaves] = await publicClient.readContract({ ...program, functionName: 'inputs', args: [e3Id] })
      expect(leaves).toBe(PLANS.length + 1)

      const now = (await publicClient.getBlock()).timestamp
      if (now <= inputWindow[1]) await advanceAnvilTime(publicClient, Number(inputWindow[1] - now + 1n))
      console.log('Closed the input window')

      // The program counts the latest version of each bidder whose bytes open their commitment.
      // alice v1, bob v2 and carol v1 count; dave's only bid does not open, so he is dropped.
      const counted = [
        { level: 3, bidderIndex: 0, version: 1 },
        { level: 2, bidderIndex: 1, version: 2 },
        { level: 0, bidderIndex: 2, version: 1 },
      ]
      const plaintextOutput = await waitFor(`the plaintext output of E3 ${e3Id}`, () => plaintexts.get(e3Id), 25 * 60_000)
      const output = await decodeOutput(plaintextOutput)
      expect(output).toEqual(expectedOutput(counted))
      expect(output.counts.slice(0, LEVELS_OF_SALE)).toEqual([3n, 2n, 2n, 1n])
      expect(output.counted.slice(0, 4)).toEqual([1, 2, 1, 0])

      // The clearing: the contract and the TypeScript mirror agree.
      const clearReceipt = await send(creatorWallet, { ...program, functionName: 'clear', args: [e3Id] })
      const [cleared] = parseEventLogs({ abi: SealedCcaProgram__factory.abi, logs: clearReceipt.logs, eventName: 'SaleCleared' })
      expect(cleared.args).toMatchObject({ kind: EXPECTED.kind, step: EXPECTED.step, pStar: EXPECTED.pStar })
      const mirror = clearing({ prices: PRICES, supply: SUPPLY, escrow: ESCROW, saleDecimals: 18 }, output.counts)
      expect(mirror).toMatchObject({ kind: 'capped', step: EXPECTED.step, pStar: EXPECTED.pStar })
      for (const [i, version] of [1, 2, 1, 0].entries()) {
        expect(await publicClient.readContract({ ...program, functionName: 'countedVersion', args: [e3Id, addresses[i]] })).toBe(version)
      }

      // The claims. Alice (full), bob (marginal) and carol (loser) prove the comparison of their step
      // with the clearing step; dave was dropped and claims without a proof.
      const steps = [3, 2, 0, 1]
      const salts = [prepared[0].salt, prepared[2].salt, prepared[3].salt]
      const claimProver = await ClaimProver.create()
      let paidTotal = 0n
      let soldTotal = 0n
      try {
        for (const bidder of [0, 1, 2, 3]) {
          const countedVersion = output.counted[bidder]
          const outcome = bidderOutcome(mirror, steps[bidder], countedVersion)
          const before = {
            sale: await balanceOf(contracts.saleToken, addresses[bidder]),
            payment: await balanceOf(contracts.paymentToken, addresses[bidder]),
          }
          let data: Hex = '0x'
          if (countedVersion !== 0) {
            const stored = await publicClient.readContract({
              ...program,
              functionName: 'bidCommitments',
              args: [e3Id, addresses[bidder], countedVersion],
            })
            const claim = await claimProver.prove({
              b: steps[bidder],
              salt: salts[bidder],
              bidder: addresses[bidder],
              e3Id,
              bidCommitment: stored,
              k: mirror.k!,
            })
            data = claim.calldata
            if (bidder === 2) {
              // The loser cannot turn her proof into a win: the contract passes `cmp` to the verifier.
              await expect(
                publicClient.simulateContract({
                  ...program,
                  functionName: 'claim',
                  args: [e3Id, addresses[bidder], `${data.slice(0, 2 + 63)}2${data.slice(2 + 64)}` as Hex],
                  account: creator,
                }),
              ).rejects.toThrow(/InvalidClaimProof/)
            }
          }
          // Anyone may send a claim; the funds go to the bidder.
          const receipt = await send(creatorWallet, { ...program, functionName: 'claim', args: [e3Id, addresses[bidder], data] })
          const [claimed] = parseEventLogs({ abi: SealedCcaProgram__factory.abi, logs: receipt.logs, eventName: 'Claimed' })
          expect(claimed.args).toMatchObject({
            bidder: addresses[bidder],
            tokens: outcome.tokens,
            paid: outcome.paid,
            refund: outcome.refund,
          })
          expect(await balanceOf(contracts.saleToken, addresses[bidder])).toBe(before.sale + outcome.tokens)
          expect(await balanceOf(contracts.paymentToken, addresses[bidder])).toBe(before.payment + outcome.refund)
          paidTotal += outcome.paid
          soldTotal += outcome.tokens
          console.log(`${BIDDER_NAMES[bidder]}: ${outcome.status}, ${outcome.tokens} tokens for ${outcome.paid}, refund ${outcome.refund}`)
          // A claim is paid once.
          await expect(
            publicClient.simulateContract({ ...program, functionName: 'claim', args: [e3Id, addresses[bidder], data], account: creator }),
          ).rejects.toThrow(/AlreadyClaimed/)
        }
      } finally {
        await claimProver.destroy()
      }
      expect(await publicClient.readContract({ ...program, functionName: 'claimed', args: [e3Id, addresses[3]] })).toBe(true)
      expect(soldTotal).toBe(mirror.sold)
      expect(soldTotal).toBeLessThanOrEqual(SUPPLY)
      expect(output.counted.slice(0, 4).map((version, i) => bidderOutcome(mirror, steps[i], version).status)).toEqual([
        'full',
        'marginal',
        'loser',
        'dropped',
      ])

      // The creator takes the payments and the tokens that were not sold.
      const paymentBefore = await balanceOf(contracts.paymentToken, creator)
      await send(creatorWallet, { ...program, functionName: 'withdrawProceeds', args: [e3Id] })
      expect(await balanceOf(contracts.paymentToken, creator)).toBe(paymentBefore + paidTotal)
      expect(paidTotal).toBe(mirror.proceeds)
      expect(await publicClient.readContract({ ...program, functionName: 'unsoldAmount', args: [e3Id] })).toBe(SUPPLY - soldTotal)
    },
    120 * 60_000,
  )
})
