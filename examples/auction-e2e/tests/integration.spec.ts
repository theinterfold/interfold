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
import { createWalletClient, hexToBytes, http, parseAbi, parseEventLogs } from 'viem'
import { privateKeyToAccount } from 'viem/accounts'
import { anvil } from 'viem/chains'
import { describe, expect, it } from 'vitest'
import { publishBidInput } from './input'
import { AuctionProgram__factory } from '../types/factories/contracts'
import { HonkVerifier__factory } from '../types/factories/contracts/verifiers/AuctionVerifier.sol'
import {
  AuctionType,
  decodeAuction,
  encodeAuctionParams,
  evenPrices,
  expectedAuction,
  expectedTieSet,
  FIRST_BID_LEAF,
  isRatioType,
  MAX_BIDDERS_BY_TYPE,
  Role,
  rolesFor,
} from '../shared/layout'
import { encodeBidInput, InputProver, newBidSecret, PARAM_SET, PRESET, type PreparedInput } from '../shared/prover'
import { advanceAnvilTime, sleep } from './anvil-helpers'

const registryReadAbi = parseAbi(['function sortitionSeed(uint256 e3Id) view returns (bool ready, uint256 seed)'])

const CREATOR_KEY = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80'
// Anvil accounts 6-8. Accounts 1-5 are the ciphernodes' wallets.
const BIDDER_KEYS = [
  '0x92db14e403b83dfe3df233f83dfa3a0d7096f21ca9b0d6d6b8d88b2b4ec1564e',
  '0x4bbbf85ce3377467afe5d46f804f221813b2bb87f24d81f60f1fcdbf7cbf4356',
  '0xdbda1821b80551c9d65939329250298aa3472ba22feea921c0cf5d620ea67b97',
] as const

interface AuctionCase {
  type: AuctionType
  title: string
  prices: readonly bigint[]
  bids: readonly number[]
  price: number
  /** The winner of a region auction, or of a ratio auction without a tie. */
  winner?: number
  /** The bidders of a ratio auction whose bid equals the price. */
  tieSet?: readonly number[]
}

/**
 * One auction of each type, run at the same time. The bids of the region auctions are distinct, so
 * their winner does not depend on the tie priority. The ratio first-price bids are distinct too.
 * The ratio second-price bids tie, so the winner is the member of the tie set that the random lane
 * picks. Every ciphertext costs minutes of proving, twenty-nine in all; `program/src/lib.rs` tests
 * more ties and the other bidder counts against the FHE program directly.
 */
// The second-price auction uses even steps; the first-price auction uses an uneven list. The
// program sees only levels, so the prices change nothing in the computation.
const UNEVEN_PRICES = [0n, 1n, 2n, 5n, 10n, 20n, 50n, 100n, 150n, 200n, 300n, 500n, 750n, 1000n, 2000n, 5000n]
const AUCTIONS: readonly AuctionCase[] = [
  { type: AuctionType.SecondPrice, title: 'Second-price test', prices: evenPrices(0n, 100n), bids: [5, 12, 9], winner: 1, price: 9 },
  { type: AuctionType.FirstPrice, title: 'First-price test', prices: UNEVEN_PRICES, bids: [6, 11], winner: 1, price: 11 },
  {
    type: AuctionType.RatioFirstPrice,
    title: 'Ratio first-price test',
    prices: UNEVEN_PRICES,
    bids: [4, 13],
    winner: 1,
    price: 13,
    tieSet: [1],
  },
  {
    type: AuctionType.RatioSecondPrice,
    title: 'Ratio second-price tie test',
    prices: evenPrices(10n, 10n),
    bids: [7, 7],
    price: 7,
    tieSet: [0, 1],
  },
]

function getContractAddresses() {
  return {
    interfold: process.env.INTERFOLD_ADDRESS as `0x${string}`,
    ciphernodeRegistry: process.env.REGISTRY_ADDRESS as `0x${string}`,
    e3Program: process.env.E3_PROGRAM_ADDRESS as `0x${string}`,
    feeToken: process.env.FEE_TOKEN_ADDRESS as `0x${string}`,
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
  const creator = privateKeyToAccount(CREATOR_KEY).address
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

      // The four key generations take about 26 minutes together and the proofs about 40 more. All four
      // requests share one window, so its start leaves time for the four approve-and-request rounds.
      const inputWindow = await calculateInputWindow(publicClient, 3 * 3600, 300n)
      const requestParams = (auction: AuctionCase) => ({
        committeeSize: CommitteeSize.Minimum,
        inputWindow,
        e3Program: contracts.e3Program,
        paramSet: PARAM_SET,
        computeProviderParams: encodeComputeProviderParams(DEFAULT_COMPUTE_PROVIDER_PARAMS, true),
        customParams: encodeAuctionParams(auction.type, auction.prices, auction.title),
      })

      const e3Ids: bigint[] = []
      for (const auction of AUCTIONS) {
        const params = requestParams(auction)
        await sdk.waitForTransaction(await sdk.approveFeeToken(await sdk.getE3Quote(params)))
        const receipt = await publicClient.waitForTransactionReceipt({ hash: await sdk.requestE3(params) })
        const [created] = parseEventLogs({ abi: AuctionProgram__factory.abi, logs: receipt.logs, eventName: 'AuctionCreated' })
        expect(created.args).toMatchObject({ creator, auctionType: auction.type, prices: auction.prices, title: auction.title })
        expect(await publicClient.readContract({ ...program, functionName: 'auctions', args: [created.args.e3Id] })).toEqual([
          auction.type,
          creator,
          auction.title,
        ])
        expect(await publicClient.readContract({ ...program, functionName: 'auctionPrices', args: [created.args.e3Id] })).toEqual(
          auction.prices,
        )
        // The contract and `shared/layout.ts` keep their own tables of the roles and the limit of a type.
        expect(await publicClient.readContract({ ...program, functionName: 'roleCount', args: [auction.type] })).toBe(
          rolesFor(auction.type).length,
        )
        expect(await publicClient.readContract({ ...program, functionName: 'maxBidders', args: [auction.type] })).toBe(
          MAX_BIDDERS_BY_TYPE[auction.type],
        )
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

      // l-BFV DKG with proof aggregation on param set 5 takes several minutes; the four run together.
      const committeeKeyOf: Uint8Array[] = []
      for (const e3Id of e3Ids) {
        // Four key generations run at the same time on one machine; each takes about ten minutes alone.
        committeeKeyOf.push(await waitFor(`the verified committee key of E3 ${e3Id}`, () => committeeKeys.get(e3Id), 45 * 60_000))
        expect(await sdk.getE3Stage(e3Id)).toBe(E3Stage.KeyPublished)
        console.log(`Committee key published for E3 ${e3Id}`)
      }

      // Prove every ciphertext first: `prepared[auction][bidder][role]`. A proof binds its sender.
      const prepared: PreparedInput[][][] = AUCTIONS.map((auction) => auction.bids.map(() => []))
      const prover = await InputProver.create()
      try {
        for (const [a, auction] of AUCTIONS.entries()) {
          for (const [bidder, bid] of auction.bids.entries()) {
            const secret = newBidSecret(bid)
            for (const role of rolesFor(auction.type)) {
              const started = Date.now()
              prepared[a][bidder][role] = await prover.prove(role, secret, committeeKeyOf[a], bidders[bidder].account.address)
              console.log(`Proved role ${role} of bidder ${bidder} in auction ${a} in ${Date.now() - started}ms`)
            }
          }
        }
      } finally {
        await prover.destroy()
      }

      const publish = async (a: number, bidder: number, role: number) =>
        sdk.waitForTransaction(await publishBidInput(bidders[bidder], e3Ids[a], prepared[a][bidder][role], contracts.e3Program))
      // The record verifier reverts on a bad proof; its errors decode with its ABI.
      const verifierErrors = HonkVerifier__factory.abi.filter((item) => item.type === 'error')
      const simulate = (a: number, input: PreparedInput, bidder: number) =>
        publicClient.simulateContract({
          address: contracts.e3Program,
          abi: [...AuctionProgram__factory.abi, ...verifierErrors],
          functionName: 'publishInput',
          args: [e3Ids[a], encodeBidInput(input)],
          account: bidders[bidder].account,
        })
      const submittedRoles = (a: number, bidder: number) =>
        publicClient.readContract({ ...program, functionName: 'submittedRoles', args: [e3Ids[a], bidders[bidder].account.address] })
      const ratioSecond = AUCTIONS.findIndex((auction) => auction.type === AuctionType.RatioSecondPrice)
      const ratioFirst = AUCTIONS.findIndex((auction) => auction.type === AuctionType.RatioFirstPrice)

      // Bidder 0 submits its first thermometer. A second thermometer that commits to another bid is
      // rejected: bidder 1's thermometer, sent from bidder 0's account, has another bid commitment.
      await publish(0, 0, 0)
      await expect(simulate(0, prepared[0][1][1], 0)).rejects.toThrow(/BidCommitmentMismatch/)
      expect(await submittedRoles(0, 0)).toBe(0b001)

      // A ciphertext is bound to its commitment: the right proof does not carry another ciphertext's.
      const forged = { ...prepared[0][0][1], ciphertextCommitment: prepared[0][0][2].ciphertextCommitment }
      await expect(simulate(0, forged, 0)).rejects.toThrow()

      // A proof is bound to its sender: bidder 0's published thermometer, copied by bidder 2, fails
      // verification, because the sender is a public input of the proof.
      await expect(simulate(0, prepared[0][0][0], 2)).rejects.toThrow(/SumcheckFailed/)

      // The pair mask exists only in the second-price ratio auction: the other types reject role 3
      // before they verify the proof.
      await expect(simulate(ratioFirst, prepared[ratioSecond][0][Role.PairMask], 0)).rejects.toThrow(/UnknownRole/)

      // Leaf order is the order in which the bidders complete, after the configuration leaf.
      await publish(0, 0, 1)
      await publish(0, 0, 2)
      for (const [a, auction] of AUCTIONS.entries()) {
        for (const bidder of auction.bids.keys()) {
          if (a === 0 && bidder === 0) continue
          for (const role of rolesFor(auction.type)) await publish(a, bidder, role)
        }
        expect(await publicClient.readContract({ ...program, functionName: 'linkedBidders', args: [e3Ids[a]] })).toBe(
          BigInt(auction.bids.length),
        )
        // A linked bidder has every role of its type: 7 for 3 roles, 15 for 4.
        expect(await submittedRoles(a, 0)).toBe((1 << rolesFor(auction.type).length) - 1)
        // Bidder `i` takes the leaves `1 + roles * i` on.
        const linked = await publicClient.getContractEvents({ ...program, eventName: 'BidLinked', args: { e3Id: e3Ids[a] }, fromBlock: 0n })
        expect(linked.map((event) => event.args.firstIndex)).toEqual(
          auction.bids.map((_, bidder) => BigInt(FIRST_BID_LEAF + rolesFor(auction.type).length * bidder)),
        )
      }

      const now = (await publicClient.getBlock()).timestamp
      if (now <= inputWindow[1]) await advanceAnvilTime(publicClient, Number(inputWindow[1] - now + 1n))
      console.log('Closed the input windows')

      for (const [a, auction] of AUCTIONS.entries()) {
        const plaintextOutput = await waitFor(`the plaintext output of E3 ${e3Ids[a]}`, () => plaintexts.get(e3Ids[a]), 25 * 60_000)
        const result = await decodeAuction(
          auction.type,
          plaintextOutput,
          prepared[a].map((inputs) => inputs[0].ciphertext),
        )
        if (result.kind === 'lane') {
          console.log(
            `${auction.title}: price ${result.price}, tie set ${result.tieSet.join(',')}, random ${result.random}, winner bidder ${result.winner}`,
          )
          expect(isRatioType(auction.type)).toBe(true)
          const { price, tieSet } = expectedTieSet(auction.type, auction.bids)
          expect({ price, tieSet }).toEqual({ price: auction.price, tieSet: auction.tieSet })
          expect(result).toMatchObject({ price, tieSet, copiesAgree: true })
          expect(result.random).not.toBeNull()
          // The winner is the member of the sorted tie set that the random lane picks.
          expect(result.winner).toBe(tieSet[result.random! % tieSet.length])
          if (auction.winner !== undefined) expect(result.winner).toBe(auction.winner)
          expect(result.lanes.filter((lane) => lane === 'result')).toHaveLength(1)
        } else {
          console.log(`${auction.title}: winner bidder ${result.winner}, price ${result.price}, priority ${result.priority.join(',')}`)
          expect(result.unusedGroupsZero).toBe(true)
          expect(result).toMatchObject({ winner: auction.winner, price: auction.price })
          expect(expectedAuction(auction.type, auction.bids, result.priority)).toEqual({ winner: auction.winner, price: auction.price })
        }
      }
    },
    180 * 60_000,
  )
})
