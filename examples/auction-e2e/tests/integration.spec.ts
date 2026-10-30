// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import {
  InterfoldSDK,
  calculateInputWindow,
  computeCiphertextCommitment,
  DEFAULT_COMPUTE_PROVIDER_PARAMS,
  encodeComputeProviderParams,
  CommitteeSize,
  CommitteePublicKeyAssembler,
} from '@interfold/sdk'
import { InterfoldEventType, RegistryEventType } from '@interfold/sdk/events'
import { E3Stage } from '@interfold/sdk/contracts'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { createWalletClient, type Hex, hexToBytes, http, parseAbi, parseEventLogs, zeroAddress } from 'viem'
import { privateKeyToAccount } from 'viem/accounts'
import { anvil } from 'viem/chains'
import { describe, expect, it } from 'vitest'
import { publishBidInput } from './input'
import { AuctionProgram__factory } from '../types/factories/contracts'
import { MerkleAllowlistGate__factory } from '../types/factories/contracts/gates'
import { AuctionVerifier3__factory } from '../types/factories/contracts/verifiers/AuctionVerifier3.sol'
import {
  AuctionType,
  type BidInput,
  allowlistProof,
  allowlistRoot,
  bidInputsHash,
  bidTypedData,
  encodeAllowlistConfig,
  encodeAuctionParams,
  encodeBidInput,
  evenPrices,
  LEVELS,
  MAX_BIDDERS,
  MAX_BIDS_PER_BIDDER,
  PARAM_SET,
  PRESET,
  readPriceList,
  Role,
  rolesFor,
  selectBids,
  type SubmittedBid,
  toHex,
} from '@interfold/auction-core'
import type { PreparedBid } from '@interfold/auction-core/prover'
import * as firstPrice from '@interfold/auction-first-price'
import { createBidProver as createFirstPriceProver } from '@interfold/auction-first-price/prover'
import * as providerSecondPrice from '@interfold/auction-provider-second-price'
import { createBidProver as createProviderProver, type PreparedMask } from '@interfold/auction-provider-second-price/prover'
import * as qnrSecondPrice from '@interfold/auction-qnr-second-price'
import { createBidProver as createQnrProver } from '@interfold/auction-qnr-second-price/prover'
import { advanceAnvilTime, sleep } from './anvil-helpers'

/** The design package of each auction type. */
const DESIGNS = {
  [AuctionType.FirstPrice]: firstPrice,
  [AuctionType.ProviderSecondPrice]: providerSecondPrice,
  [AuctionType.QnrSecondPrice]: qnrSecondPrice,
}

const registryReadAbi = parseAbi(['function sortitionSeed(uint256 e3Id) view returns (bool ready, uint256 seed)'])

const CREATOR_KEY = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80'
// Anvil accounts 6-8. Accounts 1-5 are the ciphernodes' wallets. Account 9 is the server's relayer.
const BIDDER_KEYS = [
  '0x92db14e403b83dfe3df233f83dfa3a0d7096f21ca9b0d6d6b8d88b2b4ec1564e',
  '0x4bbbf85ce3377467afe5d46f804f221813b2bb87f24d81f60f1fcdbf7cbf4356',
  '0xdbda1821b80551c9d65939329250298aa3472ba22feea921c0cf5d620ea67b97',
] as const
const SERVER_URL = process.env.AUCTION_SERVER_URL ?? 'http://localhost:8080'

/** One bid, in the order that the test publishes the bids of its auction. */
interface BidPlan {
  /** The bidder, as an index into `BIDDER_KEYS`. */
  bidder: number
  level: number
  /** The bidder signs the bid and the server's relayer sends it. */
  relayed?: true
  /** The bidder publishes its `gt` bytes in the `mask` position, with the commitments of the proof. They do not open. */
  unopened?: true
  /** Send the prepared bid of the plan at this index again, as the next version of the bidder: no new proof. */
  resend?: number
}

interface AuctionCase {
  type: AuctionType
  title: string
  prices: readonly bigint[]
  bids: readonly BidPlan[]
  /** The bidders, as indices into `BIDDER_KEYS`, that the allowlist gate lets in. No gate if absent. */
  allowlist?: readonly number[]
  price: number
  /** The bidder, as an index into `BIDDER_KEYS`, that wins: on a tie, the tied bidder whose counted bid was published first. */
  winner: number
}

/**
 * One auction of each type, run at the same time, each with its own number of price steps. Every
 * bid is below the `levels` of its auction, and the top step of the shorter auctions is bid, so
 * the bid circuit's `b < levels` check is met at its edge.
 *
 * - First price (type 0): bidders 0 and 1 tie on step 9, so the winner is bidder 0, who bid first.
 *   The auction also covers the allowlist gate (bidders 0 to 2 are in, and the creator's account is
 *   rejected), a relayed bid (bidder 1 signs its bid and the server sends it) and bytes that do not
 *   open (bidder 2 bids step 11, the highest, but publishes bytes that do not open its commitments,
 *   so the result does not count it).
 * - Second price with mask providers (type 1): the creator is the only mask provider and sends its
 *   mask before bidding opens. The auction covers an update: bidder 0 bids step 14, which would
 *   win, then updates to step 5, so the result shows that the later version counts. It sends that
 *   update once more, as version 3, which reaches the limit of 3 bids.
 * - Second price without providers (type 2): bidders 0 and 1 tie on the top step of a 6-step
 *   auction, so the winner is the tied bidder whose counted bid was published first.
 *
 * Every encryption costs minutes of proving: 26 encryptions and 9 bid proofs and 1 mask proof in
 * all; `program/src/lib.rs` tests more ties and the other bidder counts against the FHE program
 * directly.
 */
// The second-price auction has all 16 steps with even prices; the other auctions have uneven or
// shorter lists. The program sees only steps, so the prices change nothing in the computation.
const UNEVEN_PRICES = [0n, 1n, 2n, 5n, 10n, 20n, 50n, 100n, 150n, 200n, 300n, 500n, 750n, 1000n, 2000n, 5000n]
const AUCTIONS: readonly AuctionCase[] = [
  {
    type: AuctionType.FirstPrice,
    title: 'First-price allowlist test',
    prices: UNEVEN_PRICES.slice(0, 12),
    bids: [
      { bidder: 0, level: 9 },
      { bidder: 1, level: 9, relayed: true },
      { bidder: 2, level: 11, unopened: true },
    ],
    allowlist: [0, 1, 2],
    winner: 0,
    price: 9,
  },
  {
    type: AuctionType.ProviderSecondPrice,
    title: 'Second-price mask-provider test',
    prices: evenPrices(0n, 100n, 16),
    bids: [
      { bidder: 0, level: 14 },
      { bidder: 1, level: 12 },
      { bidder: 2, level: 9 },
      { bidder: 0, level: 5 },
      { bidder: 0, level: 5, resend: 3 },
    ],
    winner: 1,
    price: 9,
  },
  {
    type: AuctionType.QnrSecondPrice,
    title: 'Second-price tie test',
    prices: evenPrices(10n, 10n, 6),
    bids: [
      { bidder: 0, level: 5 },
      { bidder: 1, level: 5 },
    ],
    winner: 0,
    price: 5,
  },
]

/** The `MerkleAllowlistGate` that `pnpm deploy` recorded for the local chain. */
function readGateAddress(): Hex {
  const deployments = JSON.parse(readFileSync(fileURLToPath(new URL('../deployed_contracts.json', import.meta.url)), 'utf8')) as {
    localhost?: { MerkleAllowlistGate?: { address?: Hex } }
  }
  const address = deployments.localhost?.MerkleAllowlistGate?.address
  if (!address) throw new Error('deployed_contracts.json has no localhost MerkleAllowlistGate; run pnpm deploy')
  return address
}

function getContractAddresses() {
  return {
    interfold: process.env.INTERFOLD_ADDRESS as `0x${string}`,
    ciphernodeRegistry: process.env.REGISTRY_ADDRESS as `0x${string}`,
    e3Program: process.env.E3_PROGRAM_ADDRESS as `0x${string}`,
    feeToken: process.env.FEE_TOKEN_ADDRESS as `0x${string}`,
    allowlistGate: readGateAddress(),
  }
}

describe('Sealed-bid auction', () => {
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
  const creatorAccount = privateKeyToAccount(CREATOR_KEY)
  const creator = creatorAccount.address
  const creatorWallet = createWalletClient({ account: creatorAccount, chain: anvil, transport: http('http://localhost:8545') })
  const bidders = BIDDER_KEYS.map((key) =>
    createWalletClient({ account: privateKeyToAccount(key), chain: anvil, transport: http('http://localhost:8545') }),
  )
  const program = { address: contracts.e3Program, abi: AuctionProgram__factory.abi } as const

  it(
    'finds the winner and the price of each auction type without decrypting any bid',
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

      const bidderAddresses = bidders.map((bidder) => bidder.account.address)
      const bidderIndex = (address: string) => bidderAddresses.findIndex((candidate) => candidate.toLowerCase() === address.toLowerCase())
      const allowlistMembers = (auction: AuctionCase) => (auction.allowlist ?? []).map((index) => bidderAddresses[index])
      // The creator is the only mask provider of the auction with mask providers.
      const providersOf = (auction: AuctionCase) => (auction.type === AuctionType.ProviderSecondPrice ? [creator] : [])

      // The three key generations take about 20 minutes together and the proofs about 40 more. All three
      // requests share one window, so its start leaves time for the three approve-and-request rounds.
      const inputWindow = await calculateInputWindow(publicClient, 3 * 3600, 300n)
      const requestParams = (auction: AuctionCase) => ({
        committeeSize: CommitteeSize.Minimum,
        inputWindow,
        e3Program: contracts.e3Program,
        paramSet: PARAM_SET,
        computeProviderParams: encodeComputeProviderParams(DEFAULT_COMPUTE_PROVIDER_PARAMS, true),
        customParams: auction.allowlist
          ? encodeAuctionParams(
              auction.type,
              auction.prices,
              auction.title,
              contracts.allowlistGate,
              encodeAllowlistConfig(allowlistMembers(auction)),
            )
          : encodeAuctionParams(auction.type, auction.prices, auction.title, zeroAddress, '0x', providersOf(auction)),
      })

      expect(await publicClient.readContract({ ...program, functionName: 'MAX_BIDS_PER_BIDDER' })).toBe(MAX_BIDS_PER_BIDDER)

      const e3Ids: bigint[] = []
      for (const auction of AUCTIONS) {
        const params = requestParams(auction)
        await sdk.waitForTransaction(await sdk.approveFeeToken(await sdk.getE3Quote(params)))
        const receipt = await publicClient.waitForTransactionReceipt({ hash: await sdk.requestE3(params) })
        const [created] = parseEventLogs({ abi: AuctionProgram__factory.abi, logs: receipt.logs, eventName: 'AuctionCreated' })
        // The contract keeps the unused steps at zero.
        const padded = [...auction.prices, ...Array.from({ length: LEVELS - auction.prices.length }, () => 0n)]
        const gate = auction.allowlist ? contracts.allowlistGate : zeroAddress
        expect(created.args).toMatchObject({
          creator,
          auctionType: auction.type,
          levels: auction.prices.length,
          prices: padded,
          title: auction.title,
          gate,
          gateConfig: auction.allowlist ? encodeAllowlistConfig(allowlistMembers(auction)) : '0x',
        })
        // The getter omits the price array: `(auctionType, levels, creator, title, gate)`.
        expect(await publicClient.readContract({ ...program, functionName: 'auctions', args: [created.args.e3Id] })).toEqual([
          auction.type,
          auction.prices.length,
          creator,
          auction.title,
          gate,
        ])
        const stored = await publicClient.readContract({ ...program, functionName: 'auctionPrices', args: [created.args.e3Id] })
        expect(stored).toEqual(padded)
        expect(readPriceList(auction.prices.length, stored)).toEqual(auction.prices)
        // The contract and `sdk/core/src/layout.ts` keep their own tables of the roles and the limit of a type.
        expect(await publicClient.readContract({ ...program, functionName: 'roleCount', args: [auction.type] })).toBe(
          rolesFor(auction.type).length,
        )
        expect(await publicClient.readContract({ ...program, functionName: 'maxBidders', args: [auction.type] })).toBe(MAX_BIDDERS)
        expect(await publicClient.readContract({ ...program, functionName: 'auctionProviders', args: [created.args.e3Id] })).toEqual(
          providersOf(auction),
        )
        if (auction.allowlist) {
          // The gate built its root on chain from the list; `sdk/core/src/allowlist.ts` builds the same root.
          const [set] = parseEventLogs({ abi: MerkleAllowlistGate__factory.abi, logs: receipt.logs, eventName: 'AllowlistSet' })
          expect(set.args).toMatchObject({
            program: contracts.e3Program,
            e3Id: created.args.e3Id,
            root: allowlistRoot(allowlistMembers(auction)),
          })
        }
        e3Ids.push(created.args.e3Id)
        console.log(`Requested E3 ${created.args.e3Id}: ${auction.title}`)
      }
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

      // l-BFV DKG with proof aggregation on param set 5 takes several minutes; the three run together.
      const committeeKeyOf: Uint8Array[] = []
      for (const e3Id of e3Ids) {
        // Three key generations run at the same time on one machine; each takes about ten minutes alone.
        committeeKeyOf.push(await waitFor(`the verified committee key of E3 ${e3Id}`, () => committeeKeys.get(e3Id), 45 * 60_000))
        expect(await sdk.getE3Stage(e3Id)).toBe(E3Stage.KeyPublished)
        console.log(`Committee key published for E3 ${e3Id}`)
      }

      // Prove every bid first: `prepared[auction][plan]`. A resent bid reuses the proof of its plan.
      // A proof binds its bidder, so each bid is proven for the address that will be its bidder.
      const prepared: PreparedBid[][] = AUCTIONS.map(() => [])
      let preparedMask: PreparedMask | undefined
      const providerAuction = AUCTIONS.findIndex((auction) => auction.type === AuctionType.ProviderSecondPrice)
      // One prover for each design, one at a time: every prover loads the SRS and takes much memory.
      for (const [a, auction] of AUCTIONS.entries()) {
        const providerProver = auction.type === AuctionType.ProviderSecondPrice ? await createProviderProver() : undefined
        const prover = providerProver ?? (await (auction.type === AuctionType.FirstPrice ? createFirstPriceProver : createQnrProver)())
        try {
          for (const [i, plan] of auction.bids.entries()) {
            if (plan.resend !== undefined) {
              prepared[a][i] = prepared[a][plan.resend]
              continue
            }
            const started = Date.now()
            prepared[a][i] = await prover.prove(
              plan.level,
              auction.prices.length,
              committeeKeyOf[a],
              bidderAddresses[plan.bidder],
              (step) => console.log(`Auction ${a}, bid ${i}: ${step.kind}${'role' in step ? ` of role ${step.role}` : ''}`),
            )
            console.log(`Proved bid ${i} of auction ${a} in ${Date.now() - started}ms`)
          }
          // The mask of the provider takes one encryption and one proof.
          if (providerProver) {
            preparedMask = await providerProver.proveMask(committeeKeyOf[providerAuction], creator, (step) =>
              console.log(`Auction ${providerAuction}, mask: ${step.kind}`),
            )
          }
        } finally {
          await prover.destroy()
        }
      }

      // What each bid publishes. An unopened bid carries its own `gt` bytes in the `mask` position,
      // under the commitments the proof covers, so the contract accepts it and the program does not count it.
      const bidInput = (a: number, i: number): BidInput => {
        const plan = AUCTIONS[a].bids[i]
        const { ciphertexts, commitments, proof } = prepared[a][i]
        const roles = rolesFor(AUCTIONS[a].type)
        const published = plan.unopened
          ? ciphertexts.map((ciphertext, r) => (roles[r] === Role.Mask ? ciphertexts[roles.indexOf(Role.Gt)] : ciphertext))
          : ciphertexts
        const members = allowlistMembers(AUCTIONS[a])
        return {
          bidder: bidderAddresses[plan.bidder],
          ciphertexts: published,
          commitments,
          proof,
          gateProof: AUCTIONS[a].allowlist ? allowlistProof(members, bidderAddresses[plan.bidder]) : '0x',
          signature: '0x',
        }
      }
      const bidCountOf = (a: number, bidder: number) =>
        publicClient.readContract({ ...program, functionName: 'bidCount', args: [e3Ids[a], bidderAddresses[bidder]] })

      // The bid verifier reverts on a bad proof; its errors decode with its ABI.
      const verifierErrors = AuctionVerifier3__factory.abi.filter((item) => item.type === 'error')
      const simulate = (a: number, input: BidInput, sender: { address: Hex }) =>
        publicClient.simulateContract({
          address: contracts.e3Program,
          abi: [...AuctionProgram__factory.abi, ...verifierErrors],
          functionName: 'publishInput',
          args: [e3Ids[a], encodeBidInput(input)],
          account: sender.address,
        })
      // The signature of the bidder, for the version the bid will get.
      const sign = async (a: number, input: BidInput, bidder: number) => {
        const version = Number(await bidCountOf(a, bidder)) + 1
        return bidders[bidder].signTypedData(
          bidTypedData(
            anvil.id,
            contracts.e3Program,
            e3Ids[a],
            bidderAddresses[bidder],
            version,
            bidInputsHash(input.commitments, input.ciphertexts),
          ),
        )
      }
      const relay = async (a: number, input: BidInput) => {
        const response = await fetch(`${SERVER_URL}/relay`, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ e3Id: e3Ids[a].toString(), data: encodeBidInput(input) }),
        })
        return { ok: response.ok, body: (await response.json()) as { txHash?: Hex; error?: string } }
      }

      const [first, provider, noProvider] = [0, 1, 2]
      expect(AUCTIONS.map((auction) => auction.type)).toEqual([
        AuctionType.FirstPrice,
        AuctionType.ProviderSecondPrice,
        AuctionType.QnrSecondPrice,
      ])

      // The program takes the number of ciphertexts of its type: a 3-role bid does not fit a 4-role auction.
      await expect(simulate(noProvider, { ...bidInput(first, 0), bidder: bidderAddresses[0] }, bidders[0].account)).rejects.toThrow(
        /InvalidBidShape/,
      )

      // A ciphertext is bound to its commitment: the right proof does not carry another ciphertext's.
      const genuine = bidInput(noProvider, 0)
      const forged = {
        ...genuine,
        commitments: [genuine.commitments[2], genuine.commitments[1], genuine.commitments[0], genuine.commitments[3]],
      }
      await expect(simulate(noProvider, forged, bidders[0].account)).rejects.toThrow(/SumcheckFailed|ShpleminiFailed/)

      // A proof is bound to its bidder: bidder 0's bid, copied by bidder 2 with its own address as the
      // bidder, fails verification, because the bidder is a public input of the proof.
      await expect(simulate(noProvider, { ...genuine, bidder: bidderAddresses[2] }, bidders[2].account)).rejects.toThrow(
        /SumcheckFailed|ShpleminiFailed/,
      )
      // Another account cannot send a direct bid for the bidder.
      await expect(simulate(noProvider, genuine, bidders[2].account)).rejects.toThrow(/SenderNotBidder/)

      // The allowlist: the creator is no member. Its own proof for its own address would be rejected as
      // well; a member's proof does not carry it.
      const allowlisted = bidInput(first, 0)
      await expect(simulate(first, { ...allowlisted, bidder: creator }, creatorAccount)).rejects.toThrow(/BidderNotEligible/)

      // A relayed bid: bidder 1 signs, the relayer sends. The signature covers the exact bytes, so
      // swapping two ciphertexts invalidates it.
      const relayedPlan = AUCTIONS[first].bids.findIndex((plan) => plan.relayed)
      const unsigned = bidInput(first, relayedPlan)
      const relayedBidder = AUCTIONS[first].bids[relayedPlan].bidder
      const signed = { ...unsigned, signature: await sign(first, unsigned, relayedBidder) }
      const swapped = { ...signed, ciphertexts: [signed.ciphertexts[1], signed.ciphertexts[0], ...signed.ciphertexts.slice(2)] }
      await expect(simulate(first, swapped, creatorAccount)).rejects.toThrow(/InvalidSignature/)
      // A signature of another account does not carry the bidder's bid.
      await expect(simulate(first, { ...unsigned, signature: await sign(first, unsigned, 2) }, creatorAccount)).rejects.toThrow(
        /InvalidSignature/,
      )

      // The auction with mask providers takes no bid until every provider has sent its mask.
      await expect(simulate(provider, bidInput(provider, 0), bidders[0].account)).rejects.toThrow(/MasksPending/)
      const sendMask = {
        address: contracts.e3Program,
        abi: AuctionProgram__factory.abi,
        functionName: 'publishInput',
        args: [
          e3Ids[provider],
          providerSecondPrice.encodeMaskInput({
            provider: creator,
            ciphertext: preparedMask!.ciphertext,
            commitment: preparedMask!.commitment,
            proof: preparedMask!.proof,
          }),
        ],
      } as const
      await sdk.waitForTransaction(await creatorWallet.writeContract({ ...sendMask, chain: anvil }))
      expect(await publicClient.readContract({ ...program, functionName: 'maskCount', args: [e3Ids[provider]] })).toBe(1n)
      expect(await publicClient.readContract({ ...program, functionName: 'maskSubmitted', args: [e3Ids[provider], creator] })).toBe(true)
      await expect(publicClient.simulateContract({ ...sendMask, account: creator })).rejects.toThrow(/MaskAlreadySubmitted/)

      for (const [a, auction] of AUCTIONS.entries()) {
        for (const [i, plan] of auction.bids.entries()) {
          const input = bidInput(a, i)
          const version = Number(await bidCountOf(a, plan.bidder)) + 1
          if (plan.relayed) {
            const relayed = { ...input, signature: await sign(a, input, plan.bidder) }
            const { ok, body } = await relay(a, relayed)
            expect(body.error).toBeUndefined()
            expect(ok).toBe(true)
            const receipt = await publicClient.waitForTransactionReceipt({ hash: body.txHash! })
            expect(receipt.status).toBe('success')
            // The relayer sent it, not the bidder.
            expect(receipt.from.toLowerCase()).not.toBe(bidderAddresses[plan.bidder].toLowerCase())
            // The signature is for one version: the same signed bid no longer passes.
            const replay = await relay(a, relayed)
            expect(replay.ok).toBe(false)
            expect(replay.body.error).toMatch(/InvalidSignature/)
          } else {
            await sdk.waitForTransaction(await publishBidInput(bidders[plan.bidder], e3Ids[a], input, contracts.e3Program))
          }
          expect(await bidCountOf(a, plan.bidder)).toBe(version)
          // The third bid of an address is its last.
          if (version === MAX_BIDS_PER_BIDDER) {
            await expect(simulate(a, input, bidders[plan.bidder].account)).rejects.toThrow(/TooManyBids/)
          }
        }

        // `bidderCount` counts addresses, not bids; `BidSubmitted` numbers the leaves after the config leaf.
        const distinctBidders = new Set(auction.bids.map((plan) => plan.bidder))
        expect(await publicClient.readContract({ ...program, functionName: 'bidderCount', args: [e3Ids[a]] })).toBe(
          BigInt(distinctBidders.size),
        )
        const roles = rolesFor(auction.type).length
        // The mask of the only provider is leaf 1 of the auction with mask providers, so its bids start at leaf 2.
        const masks = auction.type === AuctionType.ProviderSecondPrice ? 1 : 0
        const submitted = await publicClient.getContractEvents({
          ...program,
          eventName: 'BidSubmitted',
          args: { e3Id: e3Ids[a] },
          fromBlock: 0n,
        })
        expect(submitted.map((event) => event.args.firstIndex)).toEqual(auction.bids.map((_, i) => BigInt(1 + masks + roles * i)))
        expect(submitted.map((event) => event.args.version)).toEqual(
          auction.bids.map((plan, i) => auction.bids.slice(0, i + 1).filter((other) => other.bidder === plan.bidder).length),
        )
        const [, leaves] = await publicClient.readContract({ ...program, functionName: 'inputs', args: [e3Ids[a]] })
        expect(leaves).toBe(1 + masks + roles * auction.bids.length)
      }

      const now = (await publicClient.getBlock()).timestamp
      if (now <= inputWindow[1]) await advanceAnvilTime(publicClient, Number(inputWindow[1] - now + 1n))
      console.log('Closed the input windows')

      for (const [a, auction] of AUCTIONS.entries()) {
        // The program counts the latest version of each bidder whose bytes open their commitments. The
        // expectation comes from the plans: the latest plan of a bidder that is not `unopened`.
        const versionOfPlan = auction.bids.map(
          (plan, i) => auction.bids.slice(0, i + 1).filter((other) => other.bidder === plan.bidder).length,
        )
        const counted = [...new Set(auction.bids.map((plan) => plan.bidder))]
          .map((bidder) =>
            auction.bids
              .map((plan, i) => ({ plan, i }))
              .filter(({ plan }) => plan.bidder === bidder && !plan.unopened)
              .at(-1),
          )
          .filter((entry) => entry !== undefined)
          .sort((x, y) => x.i - y.i)

        const events = await publicClient.getContractEvents({
          ...program,
          eventName: 'BidSubmitted',
          args: { e3Id: e3Ids[a] },
          fromBlock: 0n,
        })
        const submitted: SubmittedBid[] = events.map((event) => ({
          bidder: event.args.bidder!,
          version: event.args.version!,
          firstIndex: Number(event.args.firstIndex),
          ciphertexts: [...event.args.ciphertexts!],
          commitments: [...event.args.commitments!],
        }))
        // `opens` is synchronous, so the commitments of all published bytes are computed first.
        const commitmentOf = new Map<Hex, string>()
        for (const bid of submitted) {
          for (const ciphertext of bid.ciphertexts) {
            if (!commitmentOf.has(ciphertext))
              commitmentOf.set(ciphertext, toHex(await computeCiphertextCommitment(hexToBytes(ciphertext), PRESET)))
          }
        }
        const selected = selectBids(submitted, (ciphertext, commitment) => commitmentOf.get(ciphertext) === commitment.toLowerCase())
        expect(selected.map(({ bidder, version }) => [bidderIndex(bidder), version])).toEqual(
          counted.map(({ plan, i }) => [plan.bidder, versionOfPlan[i]]),
        )
        // The bidder whose bytes do not open is dropped whole.
        const dropped = auction.bids.filter((plan) => plan.unopened).map((plan) => plan.bidder)
        for (const bidder of dropped) expect(selected.map((bid) => bidderIndex(bid.bidder))).not.toContain(bidder)
        const levels = counted.map(({ plan }) => plan.level)

        const plaintextOutput = await waitFor(`the plaintext output of E3 ${e3Ids[a]}`, () => plaintexts.get(e3Ids[a]), 25 * 60_000)
        // Bidder position `j` is the place of the `j`-th counted bid in leaf order.
        const result = await DESIGNS[auction.type].decodeResult(plaintextOutput, selected.length)
        console.log(
          `${auction.title}: winner bidder ${result.winner === null ? 'none' : bidderIndex(selected[result.winner].bidder)}, price ${result.price}`,
        )
        expect(result.unusedGroupsZero).toBe(true)
        const winnerPosition = selected.findIndex((bid) => bidderIndex(bid.bidder) === auction.winner)
        expect(result).toMatchObject({ winner: winnerPosition, price: auction.price })
        expect(DESIGNS[auction.type].expectedResult(levels)).toEqual({ winner: winnerPosition, price: auction.price })
      }
    },
    180 * 60_000,
  )
})
