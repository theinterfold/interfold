// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import {
  CommitteePublicKeyAssembler,
  CommitteeSize,
  DEFAULT_COMPUTE_PROVIDER_PARAMS,
  InterfoldSDK,
  calculateInputWindow,
  computeCiphertextCommitment,
  encodeComputeProviderParams,
} from '@interfold/sdk'
import { E3Stage } from '@interfold/sdk/contracts'
import { InterfoldEventType, RegistryEventType } from '@interfold/sdk/events'
import {
  type Address,
  type Hex,
  bytesToHex,
  createWalletClient,
  erc20Abi,
  hexToBytes,
  http,
  parseAbi,
  parseEther,
  parseEventLogs,
  formatEther,
} from 'viem'
import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts'
import { sepolia } from 'viem/chains'
import {
  type AuctionType,
  PARAM_SET,
  PRESET,
  ROLE_LABELS,
  type RegionResult,
  type SubmittedBid,
  type BidInput,
  encodeBidInput,
  selectBids,
} from '@interfold/auction-core'
import type { BidStep, PreparedBid } from '@interfold/auction-core/prover'
import { AuctionProgram__factory } from '../../types/factories/contracts'
import { BID_GAS_LIMIT, BIDDER2_MIN_FUNDING_WEI, DEPLOYMENT, ExampleError, type ExampleEnv } from './config'
import { createLog, formatSeconds, sleep, waitFor } from './log'

/** The proving half of a design SDK: `createBidProver()` of `<design package>/prover`. */
export interface BidProver {
  prove(bid: number, levels: number, committeeKey: Uint8Array, bidder: Address, onStep?: (step: BidStep) => void): Promise<PreparedBid>
  destroy(): Promise<void>
}

/** The mask check of the provider design: `checkMasks` of `@interfold/auction-provider-second-price`. */
export type MaskChecker = (
  masks: readonly { provider: Address; index: number; ciphertext: Hex; commitment: Hex }[],
  providers: readonly Address[],
  opens: (ciphertext: Hex, commitment: Hex) => boolean,
) => { complete: boolean; missing: Address[]; invalid: Address[] }

/** What one example gives the runner: the design SDK and the auction to request. */
export interface AuctionExample {
  /** The design package, as one object: its `TYPE`, `design`, `decodeResult`, `expectedResult` and `createBidProver`. */
  kit: {
    TYPE: AuctionType
    design: { label: string }
    decodeResult(plaintextHex: string, bidders: number): Promise<RegionResult>
    expectedResult(bids: readonly number[]): { winner: number; price: number }
  }
  createBidProver: () => Promise<BidProver>
  /** The price of each step. */
  prices: bigint[]
  /** The `customParams` of the request, from the design's `encodeParams`. */
  customParams: Hex
  /** The step that each of the two bidders bids. The first bidder is the creator. */
  bids: readonly [number, number]
  /** Provider designs only: the providers whose masks must be in before the bidders bid. */
  providers?: { addresses: readonly Address[]; checkMasks: MaskChecker }
}

const faucetAbi = parseAbi(['function faucet() external'])

/** The `opens` function of `selectBids` and `checkMasks`: hash each ciphertext as the program does and compare. */
async function opensCommitment(ciphertexts: readonly Hex[]): Promise<(ciphertext: Hex, commitment: Hex) => boolean> {
  const recomputed = new Map<Hex, string>()
  for (const ciphertext of new Set(ciphertexts)) {
    try {
      recomputed.set(ciphertext, bytesToHex(await computeCiphertextCommitment(hexToBytes(ciphertext), PRESET)))
    } catch {
      // Bytes that are no ciphertext open no commitment.
    }
  }
  return (ciphertext, commitment) => recomputed.get(ciphertext) === commitment.toLowerCase()
}

/**
 * Run one auction on the live Sepolia deploy, from the request to the decoded result, and print a transcript.
 * The creator is bidder 1. Bidder 2 is `BIDDER2_PRIVATE_KEY`, or a new key that the creator funds and that sends the leftover back.
 */
export async function runAuction(example: AuctionExample, env: ExampleEnv): Promise<void> {
  const log = createLog()
  const { design } = example.kit
  const program = { address: DEPLOYMENT.auctionProgram, abi: AuctionProgram__factory.abi } as const

  const sdk = InterfoldSDK.create({
    contracts: { interfold: DEPLOYMENT.interfold, ciphernodeRegistry: DEPLOYMENT.ciphernodeRegistry, feeToken: DEPLOYMENT.feeToken },
    rpcUrl: env.rpcUrl,
    chain: sepolia,
    thresholdBfvParamsPresetName: PRESET,
    privateKey: env.creatorKey,
  })
  const publicClient = sdk.getPublicClient()
  const creator = privateKeyToAccount(env.creatorKey)
  const ownsBidder2 = env.bidder2Key === undefined
  const bidder2 = privateKeyToAccount(env.bidder2Key ?? generatePrivateKey())
  const wallets = [creator, bidder2].map((account) => createWalletClient({ account, chain: sepolia, transport: http(env.rpcUrl) }))
  const bidders = [creator.address, bidder2.address] as const
  const stepTimings = { keyGeneration: 0, proofs: [0, 0], resultLatency: 0 }

  console.log(`Auction design: ${design.label}`)
  console.log(`Program: ${DEPLOYMENT.auctionProgram} (Sepolia)`)
  console.log(`Bidder 1 (creator): ${bidders[0]}`)
  console.log(`Bidder 2${ownsBidder2 ? ' (new key, funded by the creator)' : ''}: ${bidders[1]}`)

  // Fund bidder 2 for one bid at twice the current fee: the bid is sent about 15 minutes later.
  const { maxFeePerGas } = await publicClient.estimateFeesPerGas()
  const byFee = 2n * maxFeePerGas * BID_GAS_LIMIT
  const bidder2Funding = byFee > BIDDER2_MIN_FUNDING_WEI ? byFee : BIDDER2_MIN_FUNDING_WEI
  const needed = ownsBidder2 ? bidder2Funding + parseEther('0.01') : parseEther('0.01')
  const balance = await publicClient.getBalance({ address: creator.address })
  if (balance < needed) {
    throw new ExampleError(
      `The creator ${creator.address} has ${formatEther(balance)} Sepolia ETH. This run needs at least ${formatEther(needed)} ETH.`,
    )
  }

  let fundedBidder2 = false
  try {
    // Listen before the request: the committee key and the result are events.
    const assembler = new CommitteePublicKeyAssembler()
    const committeeKeys = new Map<bigint, { key: Uint8Array; at: number }>()
    await sdk.onInterfoldEvent(RegistryEventType.COMMITTEE_PUBLIC_KEY_CHUNK_PUBLISHED, async (event) => {
      const assembled = assembler.add(event.data)
      if (!assembled) return
      if (await sdk.validatePublicKeyCommitment(assembled.publicKey, hexToBytes(assembled.pkCommitment))) {
        committeeKeys.set(assembled.e3Id, { key: assembled.publicKey, at: Date.now() })
      } else {
        log.say(`Ignored a committee key for E3 ${assembled.e3Id}: it does not match its commitment`)
      }
    })
    const plaintexts = new Map<bigint, { hex: string; at: number }>()
    await sdk.onInterfoldEvent(InterfoldEventType.PLAINTEXT_OUTPUT_PUBLISHED, (event) => {
      plaintexts.set(event.data.e3Id, { hex: event.data.plaintextOutput, at: Date.now() })
    })

    log.heading('1. Request the auction')
    if (ownsBidder2) {
      const hash = await wallets[0].sendTransaction({ to: bidder2.address, value: bidder2Funding })
      await publicClient.waitForTransactionReceipt({ hash })
      fundedBidder2 = true
      log.say(`Funded bidder 2 with ${formatEther(bidder2Funding)} ETH, tx ${hash}`)
    }
    // The window opens in 4 minutes, before the committee key is ready, and lasts `windowMinutes` from the request.
    const startBuffer = 240n
    const inputWindow = await calculateInputWindow(publicClient, env.windowMinutes * 60 - Number(startBuffer), startBuffer)
    const params = {
      committeeSize: CommitteeSize.Minimum,
      inputWindow,
      e3Program: DEPLOYMENT.auctionProgram,
      paramSet: PARAM_SET,
      computeProviderParams: encodeComputeProviderParams(DEFAULT_COMPUTE_PROVIDER_PARAMS, true),
      customParams: example.customParams,
    }
    // The quote depends on the block time, so it can rise between the quote and the request. Approve a
    // margin of 10 % and give the same amount as `maxFee`. The contract takes only the real fee.
    const quote = await sdk.getE3Quote(params)
    const maxFee = quote + quote / 10n
    const feeBalance = await publicClient.readContract({
      address: DEPLOYMENT.feeToken,
      abi: erc20Abi,
      functionName: 'balanceOf',
      args: [creator.address],
    })
    if (feeBalance < maxFee) {
      const hash = await wallets[0].writeContract({ address: DEPLOYMENT.feeFaucet, abi: faucetAbi, functionName: 'faucet' })
      await publicClient.waitForTransactionReceipt({ hash })
      log.say(`Fee token balance ${feeBalance} is below the fee ${maxFee}: took tokens from the faucet, tx ${hash}`)
    }
    const approveHash = await sdk.approveFeeToken(maxFee)
    await sdk.waitForTransaction(approveHash)
    // A lagging RPC node can serve the old allowance for a short time: wait until it shows the approval.
    await waitFor(
      'the fee approval to show on the RPC node',
      async () => {
        const allowance = await publicClient.readContract({
          address: DEPLOYMENT.feeToken,
          abi: erc20Abi,
          functionName: 'allowance',
          args: [creator.address, DEPLOYMENT.interfold],
        })
        return allowance >= maxFee ? allowance : undefined
      },
      60_000,
      1000,
    )
    log.say(`Approved a fee of at most ${maxFee} fee-token units (quote ${quote}), tx ${approveHash}`)

    // A load-balanced RPC endpoint can send the simulation of the request to a node that does not
    // have the approval yet. The call then reverts with ERC20InsufficientAllowance (0xfb8f41b2):
    // wait and try again.
    const requestHash = await waitFor(
      'an RPC node that has the fee approval',
      async () => {
        try {
          return await sdk.requestE3({ ...params, maxFee })
        } catch (error) {
          if (String(error).includes('0xfb8f41b2')) return undefined
          throw error
        }
      },
      60_000,
      3000,
    )
    const requestedAt = Date.now()
    const receipt = await publicClient.waitForTransactionReceipt({ hash: requestHash })
    const [created] = parseEventLogs({ abi: AuctionProgram__factory.abi, logs: receipt.logs, eventName: 'AuctionCreated' })
    if (!created) throw new Error(`Request ${requestHash} did not create an auction`)
    const e3Id = created.args.e3Id
    log.say(`Requested E3 ${e3Id}, tx ${requestHash}, block ${receipt.blockNumber}`)
    log.say(
      `Bid window: ${new Date(Number(inputWindow[0]) * 1000).toISOString()} to ${new Date(Number(inputWindow[1]) * 1000).toISOString()}`,
    )

    log.heading('2. Wait for the committee key')
    log.say('The committee runs distributed key generation. This takes about 8 minutes.')
    const committee = await waitFor(`the committee key of E3 ${e3Id}`, () => committeeKeys.get(e3Id), 30 * 60_000)
    stepTimings.keyGeneration = (committee.at - requestedAt) / 1000
    log.say(
      `Committee key published and verified after ${formatSeconds(stepTimings.keyGeneration)}; stage ${E3Stage[await sdk.getE3Stage(e3Id)]}`,
    )

    log.heading('3. Prove the bids')
    log.say('Each bid is encrypted to the committee key and proven in zero knowledge. This takes 2 to 5 minutes per bid.')
    const prover = await example.createBidProver()
    const prepared: PreparedBid[] = []
    try {
      for (const [index, level] of example.bids.entries()) {
        const started = Date.now()
        prepared.push(
          await prover.prove(level, example.prices.length, committee.key, bidders[index], (step) =>
            log.say(`  bidder ${index + 1}: ${step.kind}${'role' in step ? ` (${ROLE_LABELS[step.role]})` : ''}`),
          ),
        )
        stepTimings.proofs[index] = (Date.now() - started) / 1000
        log.say(`Bidder ${index + 1} proved a bid of step ${level} in ${formatSeconds(stepTimings.proofs[index])}`)
      }
    } finally {
      await prover.destroy()
    }

    const requestBlock = receipt.blockNumber
    if (example.providers) {
      log.heading('4. Wait for the mask providers')
      const { addresses, checkMasks } = example.providers
      log.say(`Providers: ${addresses.join(', ')}`)
      await waitFor(
        `the masks of the providers ${addresses.join(', ')}`,
        async () => {
          const events = await publicClient.getContractEvents({
            ...program,
            eventName: 'MaskSubmitted',
            args: { e3Id },
            fromBlock: requestBlock,
            strict: true,
          })
          const masks = events.map(({ args }) => ({
            provider: args.provider,
            index: Number(args.index),
            ciphertext: args.ciphertext,
            commitment: args.commitment,
          }))
          const status = checkMasks(masks, addresses, await opensCommitment(masks.map((mask) => mask.ciphertext)))
          if (status.invalid.length > 0) throw new Error(`The masks of ${status.invalid.join(', ')} do not open their commitments`)
          return status.complete ? status : undefined
        },
        15 * 60_000,
        5000,
      )
      log.say('Every provider mask is in; the bidders can bid')
    }

    log.heading(`${example.providers ? '5' : '4'}. Publish the bids`)
    for (const [index, bid] of prepared.entries()) {
      const input: BidInput = {
        bidder: bidders[index],
        ciphertexts: bid.ciphertexts,
        commitments: bid.commitments,
        proof: bid.proof,
        gateProof: '0x',
        signature: '0x',
      }
      const hash = await wallets[index].writeContract({
        ...program,
        functionName: 'publishInput',
        args: [e3Id, encodeBidInput(input)],
        chain: sepolia,
        account: wallets[index].account,
      })
      const bidReceipt = await publicClient.waitForTransactionReceipt({ hash })
      if (bidReceipt.status !== 'success') throw new Error(`The bid of bidder ${index + 1} reverted, tx ${hash}`)
      log.say(`Bidder ${index + 1} published its bid, tx ${hash}, gas ${bidReceipt.gasUsed}`)
    }

    log.heading(`${example.providers ? '6' : '5'}. Wait for the result`)
    const closeMs = Number(inputWindow[1]) * 1000
    log.say(`The bid window closes at ${new Date(closeMs).toISOString()}. The server then starts the encrypted computation.`)
    const plaintext = await waitFor(
      `the plaintext of E3 ${e3Id}`,
      () => plaintexts.get(e3Id),
      Math.max(closeMs - Date.now(), 0) + 25 * 60_000,
    )
    stepTimings.resultLatency = (plaintext.at - closeMs) / 1000
    log.say(`Plaintext output published ${formatSeconds(stepTimings.resultLatency)} after the window closed`)

    log.heading(`${example.providers ? '7' : '6'}. Decode the result`)
    const events = await publicClient.getContractEvents({
      ...program,
      eventName: 'BidSubmitted',
      args: { e3Id },
      fromBlock: requestBlock,
      strict: true,
    })
    const submitted: SubmittedBid[] = events
      .map(({ args }) => ({
        bidder: args.bidder,
        version: args.version,
        firstIndex: Number(args.firstIndex),
        ciphertexts: [...args.ciphertexts],
        commitments: [...args.commitments],
      }))
      .sort((a, b) => a.firstIndex - b.firstIndex)
    const opens = await opensCommitment(submitted.flatMap((bid) => bid.ciphertexts))
    const selected = selectBids(submitted, opens)
    const result = await example.kit.decodeResult(plaintext.hex, selected.length)
    const expected = example.kit.expectedResult(example.bids)
    const winnerBid = result.winner === null ? undefined : selected[result.winner]
    const winnerIndex = winnerBid ? bidders.findIndex((address) => address.toLowerCase() === winnerBid.bidder.toLowerCase()) : -1
    const price = result.price === null ? undefined : example.prices[result.price]

    console.log(`\nE3:       ${e3Id}`)
    console.log(`Design:   ${design.label}`)
    console.log(
      `Bids:     bidder 1 step ${example.bids[0]}, bidder 2 step ${example.bids[1]} (price of a step: ${example.prices.map(String).join(', ')})`,
    )
    console.log(
      `Decoded:  winner ${winnerBid ? `bidder ${winnerIndex + 1} ${winnerBid.bidder}` : 'none'}, step ${result.price ?? 'unreadable'}, price ${price ?? 'unreadable'}`,
    )
    console.log(`Expected: winner bidder ${expected.winner + 1}, step ${expected.price}, price ${example.prices[expected.price]}`)
    console.log(
      `Timings:  key generation ${formatSeconds(stepTimings.keyGeneration)}, proofs ${stepTimings.proofs.map(formatSeconds).join(' and ')}, result ${formatSeconds(stepTimings.resultLatency)} after the window closed, total ${formatSeconds(log.since())}`,
    )
    const matches = result.winner === expected.winner && result.price === expected.price
    console.log(matches ? 'Result matches the plaintext reference.' : 'MISMATCH: the decoded result differs from the plaintext reference.')
    if (!matches) process.exitCode = 1
  } finally {
    if (fundedBidder2) {
      // Send the leftover of the generated bidder back to the creator.
      try {
        const left = await publicClient.getBalance({ address: bidder2.address })
        const gasPrice = await publicClient.getGasPrice()
        const fee = gasPrice * 21_000n * 2n
        if (left > fee) {
          const hash = await wallets[1].sendTransaction({ to: creator.address, value: left - fee, gasPrice, gas: 21_000n })
          await publicClient.waitForTransactionReceipt({ hash })
          log.say(`Refunded ${formatEther(left - fee)} ETH from bidder 2 to the creator, tx ${hash}`)
        }
      } catch (error) {
        log.say(`Could not refund bidder 2 (${bidder2.address}): ${error instanceof Error ? error.message : String(error)}`)
      }
    }
    sdk.cleanup()
  }
}

/** Run an example. Print a failure as one clear line and set the exit code; end the process, because the SDK keeps timers alive. */
export async function runExample(main: () => Promise<void>): Promise<never> {
  try {
    await main()
  } catch (error) {
    if (error instanceof ExampleError) console.error(`\nError: ${error.message}`)
    else {
      // viem errors carry the request URL, which can hold an API key: print only the short message.
      const viemError = error as { shortMessage?: string; message?: string }
      console.error(`\nExample failed: ${viemError.shortMessage ?? viemError.message ?? String(error)}`)
    }
    process.exitCode = 1
  }
  await sleep(100)
  process.exit(process.exitCode ?? 0)
}
