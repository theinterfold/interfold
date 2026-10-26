// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import express, { NextFunction, Request, Response } from 'express'
import { CommitteePublicKeyAssembler, InterfoldSDK } from '@interfold/sdk'
import type { CiphertextOutputReference, CommitteePublicKeyChunkPublishedData } from '@interfold/sdk'
import { E3Stage } from '@interfold/sdk/contracts'
import { RegistryEventType } from '@interfold/sdk/events'
import { Interfold__factory } from '@interfold/contracts/types'
import { bytesToHex, createWalletClient, hexToBytes, http, keccak256, zeroAddress, type Hex } from 'viem'
import { privateKeyToAccount } from 'viem/accounts'
import { loadConfig, type ServerConfig } from './config'
import { callFheRunner } from './runner'
import { AvailabilityStore, AvailHelper } from './availability'
import { AvailPublicationRunner } from './publication'
import { ComputeScheduler } from './scheduler'
import { closedReason, computeWindowOpen, type E3Window } from './window'
import { getLogsChunked } from './logs'
import { TokenLaunchProgram__factory } from '../types/factories/contracts'
import { configBytes } from '../sdk/src/layout'
import { coarseProbeMask } from '../sdk/src/probes'
import { MIN_BIDDERS, opensCommitment, roundInputs, selectBids, type ProgramInputs, type SubmittedBid } from './inputs'
import { KIND_CAPPED } from '../sdk/src/clearing'
import { SaleKeeper, type KeeperCall } from './keeper'
import { keeperStep, roundTwoGate, SalePhase } from './phases'
import {
  parseRelayClaimRequest,
  parseRelayRequest,
  relayBid,
  relayClaim,
  RelayRequestError,
  RelayRevertError,
  sendFromRelayer,
} from './relay'

// The coordination server orchestrates the FHE runs automatically. A sale is two E3s: round 1 (its
// id is the sale id) and round 2. The server watches for each E3's committee to publish, schedules
// the compute for when the input window closes (round 2 also waits for the probes of round 1), and
// publishes the ciphertext output once the runner calls back. A keeper sends the calls that anyone may
// send: `publishProbes` after round 1 decrypts, `clear` after round 2 decrypts and, once the marginal
// window of a capped sale ends, `payMarginal` for each registered claim. All of
// this needs a trusted always-on backend (an operator key to publish output and a reachable HTTP
// callback URL a browser cannot provide), so it stays server-side.
//
// It is kept deliberately lean: the params and published inputs are read from
// chain on demand at run time rather than accumulated in memory, so there is no
// per-E3 session state or input-buffering to maintain. The WebSocket listener only sees new
// events, so on start the server scans the chain for E3s that a restart interrupted.

function loadConfigOrExit(): ServerConfig {
  try {
    return loadConfig()
  } catch (error) {
    console.error(`❌ Invalid configuration: ${error instanceof Error ? error.message : error}`)
    process.exit(1)
  }
}

const config = loadConfigOrExit()
const store = new AvailabilityStore(config.dataDirectory)

function createSdk(rpcUrl: string): InterfoldSDK {
  return InterfoldSDK.create({
    rpcUrl,
    privateKey: config.privateKey,
    contracts: {
      interfold: config.interfold,
      ciphernodeRegistry: config.registry,
      feeToken: config.feeToken,
    },
    chain: config.chain,
    thresholdBfvParamsPresetName: 'INSECURE_THRESHOLD_SIMD',
  })
}

// Reads and writes use the HTTP endpoint. The live listener uses the WebSocket endpoint when set.
const sdk = createSdk(config.rpcUrl)
const listenerSdk = config.wsRpcUrl ? createSdk(config.wsRpcUrl) : sdk
const program = { address: config.program, abi: TokenLaunchProgram__factory.abi } as const

// The server keeps no per-E3 state on disk except the Avail output records. In memory it holds the
// scheduler (E3s that wait for or run a compute, and their callback tokens), the E3s whose output
// this process is publishing right now, and one assembler of committee keys that both the live
// listener and the recovery scan feed. After a restart, recovery rebuilds all of it from the chain.
const committeeKeyAssembler = new CommitteePublicKeyAssembler()
const publishing = new Set<string>()
const CHAIN_TIME_POLL_INTERVAL_MS = 500
// Between the last blocks of a long wait, the server polls the chain clock at most once a minute.
const CHAIN_TIME_FAR_POLL_INTERVAL_MS = 60_000
// The largest callback body: a hex ciphertext of up to 1 MiB (the Avail limit) and its compute proof.
const CALLBACK_BODY_LIMIT = '8mb'
const MAX_OUTPUT_BYTES = 1024 * 1024

/** The stage, the input and compute deadlines and the chain time of an E3. */
async function readWindow(e3Id: bigint): Promise<E3Window & { inputDeadline: bigint }> {
  const publicClient = sdk.getPublicClient()
  const [stage, e3, deadlines, block] = await Promise.all([
    sdk.getE3Stage(e3Id),
    sdk.getE3(e3Id),
    publicClient.readContract({ address: config.interfold, abi: Interfold__factory.abi, functionName: 'getDeadlines', args: [e3Id] }),
    publicClient.getBlock(),
  ])
  return { stage, inputDeadline: e3.inputWindow[1], computeDeadline: deadlines.computeDeadline, now: block.timestamp }
}

/** Send `publishCiphertextOutput` and wait until it is mined. Throws unless the transaction succeeded. */
async function publishOutput(e3Id: bigint, reference: CiphertextOutputReference): Promise<`0x${string}`> {
  const hash = await sdk.publishCiphertextOutput(e3Id, reference)
  const receipt = await sdk.getPublicClient().waitForTransactionReceipt({ hash })
  if (receipt.status !== 'success') throw new Error(`publishCiphertextOutput of E3 ${e3Id} reverted in ${hash}`)
  return hash
}

const availPublications =
  config.dataAvailability.mode === 'avail'
    ? new AvailPublicationRunner({
        store,
        helper: new AvailHelper(config.dataAvailability, config.chain.id),
        getWindow: readWindow,
        publish: publishOutput,
        pollIntervalMs: config.dataAvailability.proofPollIntervalMs,
      })
    : undefined

async function waitForChainTimestamp(target: bigint): Promise<void> {
  const publicClient = sdk.getPublicClient()
  for (;;) {
    const remaining = target - (await publicClient.getBlock()).timestamp
    if (remaining <= 0n) return
    // Chain time follows wall time, so a far deadline needs no frequent polling.
    const wait = remaining > 30n ? Math.min(Number(remaining - 10n) * 1000, CHAIN_TIME_FAR_POLL_INTERVAL_MS) : CHAIN_TIME_POLL_INTERVAL_MS
    await new Promise((resolve) => setTimeout(resolve, wait))
  }
}

/** The round of a sale that an E3 is. Round 1 is the sale itself (its E3 id is the sale id). */
interface Round {
  saleId: bigint
  role: 1 | 2
}

const rounds = new Map<string, Round>()

/**
 * Which round of which sale an E3 is, or `undefined` when it is not an E3 of this program. The
 * answer never changes once the E3 is linked, so it is cached. A round 1 is an E3 that has a sale;
 * a round 2 is the `e3Id2` of a `RoundTwoLinked` event, which the program emits when it validates
 * the request.
 */
async function roundOf(e3Id: bigint): Promise<Round | undefined> {
  const key = e3Id.toString()
  const cached = rounds.get(key)
  if (cached) return cached
  const publicClient = sdk.getPublicClient()
  const e3 = await sdk.getE3(e3Id)
  if (e3.e3Program.toLowerCase() !== config.program.toLowerCase()) return undefined

  const sale = await publicClient.readContract({ ...program, functionName: 'getSale', args: [e3Id] }).catch(() => undefined)
  let round: Round | undefined
  if (sale && sale.creator !== zeroAddress) {
    round = { saleId: e3Id, role: 1 }
  } else {
    const [linked] = await getLogsChunked(
      (range) =>
        publicClient.getContractEvents({ ...program, eventName: 'RoundTwoLinked', args: { e3Id2: e3Id }, strict: true, ...range }),
      config.deployBlock,
      await publicClient.getBlockNumber(),
      config.logChunkSize,
    )
    if (linked) round = { saleId: linked.args.saleId, role: 2 }
  }
  if (round) rounds.set(key, round)
  return round
}

async function readPhase(saleId: bigint): Promise<SalePhase> {
  return Number(await sdk.getPublicClient().readContract({ ...program, functionName: 'phase', args: [saleId] })) as SalePhase
}

/**
 * The next call that the keeper sends for a sale. A capped sale has marginal claims: after the marginal
 * window the keeper pays each registered one, in the order of the registrations, until every one is
 * paid. The other kinds have no marginal claims, so a cleared sale of those kinds is done.
 */
async function nextKeeperCall(saleId: bigint): Promise<KeeperCall | 'wait' | 'done'> {
  const step = keeperStep(await readPhase(saleId))
  if (step === 'publishProbes' || step === 'clear') return { functionName: step, args: [saleId] }
  if (step !== 'settle') return step

  const publicClient = sdk.getPublicClient()
  const clearing = await publicClient.readContract({ ...program, functionName: 'clearing', args: [saleId] })
  if (clearing.kind !== KIND_CAPPED) return 'done'
  // `payMarginal` reverts up to and including the deadline, and a claim after it registers nothing.
  if ((await publicClient.getBlock()).timestamp <= clearing.marginalDeadline) return 'wait'

  const registered = await getLogsChunked(
    (range) => publicClient.getContractEvents({ ...program, eventName: 'MarginalRegistered', args: { saleId }, strict: true, ...range }),
    await saleCreatedBlock(saleId),
    await publicClient.getBlockNumber(),
    config.logChunkSize,
  )
  for (const { args } of registered) {
    const [, , , paid] = await publicClient.readContract({ ...program, functionName: 'marginalInfo', args: [saleId, args.index] })
    if (!paid) return { functionName: 'payMarginal', args: [saleId, args.index] }
  }
  return 'done'
}

// The block of each sale's `SaleCreated` log. `E3.requestBlock` is a timestamp, not a block
// number, so it cannot start a log scan. Every bid, probe and key chunk of a sale, and of its
// round 2, comes after this block.
const createdBlocks = new Map<string, bigint>()

/** The `SaleCreated` logs of `[from, to]`. */
async function scanSales(from: bigint, to: bigint): Promise<Array<{ saleId: bigint; blockNumber: bigint }>> {
  const publicClient = sdk.getPublicClient()
  const logs = await getLogsChunked(
    (range) => publicClient.getContractEvents({ ...program, eventName: 'SaleCreated', strict: true, ...range }),
    from,
    to,
    config.logChunkSize,
  )
  const sales = logs.map(({ args, blockNumber }) => ({ saleId: args.saleId, blockNumber }))
  for (const { saleId, blockNumber } of sales) createdBlocks.set(saleId.toString(), blockNumber)
  return sales
}

async function saleCreatedBlock(saleId: bigint): Promise<bigint> {
  const cached = createdBlocks.get(saleId.toString())
  if (cached !== undefined) return cached
  const publicClient = sdk.getPublicClient()
  const [log] = await getLogsChunked(
    (range) => publicClient.getContractEvents({ ...program, eventName: 'SaleCreated', args: { saleId }, strict: true, ...range }),
    config.deployBlock,
    await publicClient.getBlockNumber(),
    config.logChunkSize,
  )
  if (!log) throw new Error(`Sale ${saleId}: no SaleCreated event at or after block ${config.deployBlock}; check DEPLOY_BLOCK`)
  createdBlocks.set(saleId.toString(), log.blockNumber)
  return log.blockNumber
}

/**
 * Read the params and published inputs for an E3 from chain and forward them to
 * the FHE runner. Stateless: everything is fetched on demand.
 */
async function runProgram(e3Id: bigint, committeeKey: Uint8Array, callbackToken: string): Promise<'submitted' | 'skipped'> {
  const publicClient = sdk.getPublicClient()
  const round = await roundOf(e3Id)
  if (!round) throw new Error(`E3 ${e3Id} is not a round of a sale of ${config.program}`)
  const { saleId, role } = round

  // Look up the encoded params from the on-chain paramSetRegistry.
  const e3 = await sdk.getE3(e3Id)
  const e3ProgramParams = (await publicClient.readContract({
    address: config.interfold,
    abi: [
      {
        name: 'paramSetRegistry',
        type: 'function',
        stateMutability: 'view',
        inputs: [{ name: '', type: 'uint8' }],
        outputs: [{ name: '', type: 'bytes' }],
      },
    ],
    functionName: 'paramSetRegistry',
    args: [e3.paramSet],
  })) as string

  // Gather the inputs with one-shot log queries: no long-lived listeners, no in-memory input
  // buffer. `BidSubmitted` holds the bytes of every bid in both rounds. Every bid is a published
  // input, counted or not, because the input root covers all leaves. Leaf 0 is the config of the
  // round: round 1 has the coarse probe levels, round 2 the config that `ProbesPublished` carries.
  // Every input comes after the sale's creation, so the scans start at its `SaleCreated` block, in
  // chunks that a public RPC accepts.
  const fromBlock = await saleCreatedBlock(saleId)
  const toBlock = await publicClient.getBlockNumber()
  const [submitted, sale, leafCount, probes] = await Promise.all([
    getLogsChunked(
      (range) => publicClient.getContractEvents({ ...program, args: { saleId }, strict: true, eventName: 'BidSubmitted', ...range }),
      fromBlock,
      toBlock,
      config.logChunkSize,
    ),
    publicClient.readContract({ ...program, functionName: 'getSale', args: [saleId] }),
    publicClient.readContract({ ...program, functionName: 'inputs', args: [e3Id] }),
    role === 2
      ? getLogsChunked(
          (range) => publicClient.getContractEvents({ ...program, args: { saleId }, strict: true, eventName: 'ProbesPublished', ...range }),
          fromBlock,
          toBlock,
          config.logChunkSize,
        )
      : [],
  ])

  let config0: Hex
  if (role === 1) {
    config0 = configBytes(1, sale.levels, coarseProbeMask(sale.levels))
  } else {
    const [published] = probes
    if (!published) throw new Error(`E3 ${e3Id}: round 2 of sale ${saleId} has no ProbesPublished event`)
    config0 = published.args.config
  }

  const bids: SubmittedBid[] = submitted.map(({ args }) => ({
    bidder: args.bidder,
    index: Number(args.index),
    ciphertext: role === 1 ? args.ciphertext1 : args.ciphertext2,
    commitment: role === 1 ? args.ctCommitment1 : args.ctCommitment2,
  }))
  // The config and one leaf per bid. A missing or an extra event would give a root that the program rejects.
  const [, leaves] = leafCount
  if (Number(leaves) !== bids.length + 1) {
    throw new Error(
      `E3 ${e3Id}: the contract holds ${leaves} input(s) but ${bids.length} bid event(s) were read; check LOG_CHUNK_SIZE and DEPLOY_BLOCK`,
    )
  }
  let inputs: ProgramInputs
  try {
    inputs = roundInputs(config0, bids)
  } catch (error) {
    throw new Error(`E3 ${e3Id}: ${error instanceof Error ? error.message : error}`)
  }

  // The contract cannot check that published bytes open their commitments; the program does, and
  // leaves a bid that does not open out of the computation. Apply the same rule here, to know
  // whether there is a sale to run.
  const counted = selectBids(bids, await opensCommitment(bids))
  console.log(`📊 Processing E3 ${e3Id} (round ${role} of sale ${saleId}): ${bids.length} bid(s), ${counted.length} counted`)

  // The program needs one counted bid at least: the output is the sum of the counted bids.
  if (counted.length < MIN_BIDDERS) {
    console.log(`⏭️  Skipping E3 ${e3Id}: ${counted.length} bid(s) that open their commitment, a sale needs ${MIN_BIDDERS}`)
    return 'skipped'
  }

  console.log(`🔄 Calling FHE runner for E3 ${e3Id}...`)
  await callFheRunner(
    e3Id,
    {
      chainId: await publicClient.getChainId(),
      interfoldAddress: config.interfold,
      encryptionSchemeId: e3.encryptionSchemeId,
      committeePublicKeyHash: e3.committeePublicKey,
    },
    e3ProgramParams,
    // The l-BFV relinearization key travels in the committee key; the program needs it.
    bytesToHex(committeeKey),
    inputs,
    // The runner posts its result to this URL verbatim. The token is the only credential of the callback.
    { runnerUrl: config.programRunnerUrl, callbackUrl: `${config.callbackUrl}/callback/${e3Id}/${callbackToken}` },
  )
  console.log(`✅ E3 ${e3Id} sent to FHE runner - awaiting callback`)
  return 'submitted'
}

const scheduler = new ComputeScheduler({
  getWindow: readWindow,
  waitForChainTime: waitForChainTimestamp,
  submit: runProgram,
  // Round 1 runs when its window closes. Round 2 also needs `publishProbes`, which puts its config in place.
  gate: async (e3Id) => {
    const round = await roundOf(e3Id)
    if (!round) return 'never'
    return round.role === 1 ? 'ready' : roundTwoGate(await readPhase(round.saleId))
  },
})

/**
 * Schedule the compute once the transported key matches the commitment accepted with the DKG
 * proof. Both the live listener and the recovery scan feed chunks here. An E3 of another program
 * on the same Interfold is not ours to run.
 */
async function handleKeyChunk(chunk: CommitteePublicKeyChunkPublishedData): Promise<void> {
  try {
    const assembled = committeeKeyAssembler.add(chunk)
    if (!assembled) return
    const round = await roundOf(assembled.e3Id)
    if (!round) {
      committeeKeyAssembler.clear(assembled.e3Id)
      return
    }
    const isBoundKey = await sdk.validatePublicKeyCommitment(assembled.publicKey, hexToBytes(assembled.pkCommitment))
    if (!isBoundKey) {
      console.warn(`Ignored committee public-key candidate for E3 ${assembled.e3Id}: commitment mismatch`)
      return
    }
    committeeKeyAssembler.clear(assembled.e3Id)
    if (!scheduler.isScheduled(assembled.e3Id)) console.log(`🎯 Committee published for E3 ${assembled.e3Id} (round ${round.role} of sale ${round.saleId})`)
    scheduler.schedule(assembled.e3Id, assembled.publicKey)
  } catch (error) {
    console.error('Failed to process a committee public-key chunk:', error)
  }
}

async function setupEventListeners() {
  console.log('📡 Setting up event listeners...')
  await listenerSdk.onInterfoldEvent(RegistryEventType.COMMITTEE_PUBLIC_KEY_CHUNK_PUBLISHED, (event) => handleKeyChunk(event.data))
  console.log('✅ Event listeners set up successfully')
}

/**
 * The listener only sees new events. After a restart, find the rounds whose committee key is
 * published but whose output is not, rebuild each key from the historical chunk events and
 * schedule the compute. Rounds whose output is already on its way through Avail resume that
 * publication instead. Run it after the listener subscribed: the scan then covers every block up
 * to `latest` and the listener every later one, and the shared assembler ignores a repeated chunk.
 * The keeper needs no recovery: it reads the phase of every sale from the chain.
 */
async function recoverE3s() {
  const publicClient = sdk.getPublicClient()
  const latest = await publicClient.getBlockNumber()
  console.log(`🔎 Scanning blocks ${config.deployBlock}-${latest} for sales to recover...`)

  const sales = await scanSales(config.deployBlock, latest)

  // E3s that wait for their compute: the key is published, no output is, and the compute window is
  // open. An E3 before that stage will publish its key to the live listener. A sale has two E3s.
  const waiting = new Set<string>()
  let from = latest
  for (const { saleId, blockNumber } of sales) {
    const roundTwo = await publicClient.readContract({ ...program, functionName: 'roundTwo', args: [saleId] })
    for (const e3Id of roundTwo === 0n ? [saleId] : [saleId, roundTwo]) {
      const key = e3Id.toString()
      if (waiting.has(key)) continue
      const window = await readWindow(e3Id)
      if (!computeWindowOpen(window)) {
        if (window.stage === E3Stage.KeyPublished) console.log(`⏭️  E3 ${e3Id} is not recovered: ${closedReason(window)}`)
        continue
      }
      if (await store.readRecord(e3Id)) continue // The output exists; the Avail publication resumes it.
      waiting.add(key)
      if (blockNumber < from) from = blockNumber
    }
  }
  if (waiting.size === 0) {
    console.log('🔎 No sale waits for its compute')
    return
  }

  const chunks = await getLogsChunked(
    async (range) => {
      const logs = await sdk.getHistoricalEvents(RegistryEventType.COMMITTEE_PUBLIC_KEY_CHUNK_PUBLISHED, range.fromBlock, range.toBlock)
      return logs.map((log) => (log as unknown as { args: CommitteePublicKeyChunkPublishedData }).args)
    },
    from,
    latest,
    config.logChunkSize,
  )
  for (const chunk of chunks) {
    if (waiting.has(chunk.e3Id.toString())) await handleKeyChunk(chunk)
  }
  for (const key of waiting) {
    if (!scheduler.isScheduled(BigInt(key)))
      console.warn(`E3 ${key} has a published committee key, but no valid key could be rebuilt from the events`)
  }
}

function isValidHexString(value: string): value is `0x${string}` {
  return value.startsWith('0x') && /^0x[a-fA-F0-9]*$/.test(value)
}

/** Reject a callback that lacks the token of the run in progress, before it reads or stores anything. */
type CallbackRequest = Request<{ e3Id: string; token: string }>

function authenticateCallback(req: CallbackRequest, res: Response, next: NextFunction) {
  const { e3Id, token } = req.params
  if (!/^\d+$/.test(e3Id) || !scheduler.authorize(BigInt(e3Id), token)) {
    res.status(401).json({ error: 'Unauthorized' })
    return
  }
  next()
}

async function handleCallback(req: CallbackRequest, res: Response) {
  const e3Id = BigInt(req.params.e3Id)
  const key = e3Id.toString()
  let claimed = false
  try {
    const body = req.body ?? {}
    if (String(body.e3_id) !== key) {
      res.status(400).json({ error: 'e3_id does not match the callback URL' })
      return
    }

    if (body.status === 'failed') {
      scheduler.failed(e3Id, typeof body.error === 'string' ? body.error : 'no reason given')
      res.json({ status: 'retrying', e3_id: key })
      return
    }

    const { ciphertext, ciphertext_commitment, proof } = body
    if (!ciphertext || !ciphertext_commitment || !proof) {
      res.status(400).json({ error: 'Missing required fields: ciphertext, ciphertext_commitment, proof' })
      return
    }
    if (!isValidHexString(ciphertext) || !isValidHexString(ciphertext_commitment) || !isValidHexString(proof)) {
      res.status(400).json({ error: 'ciphertext, ciphertext_commitment, and proof must be valid hex strings' })
      return
    }
    if (publishing.has(key)) {
      res.json({ status: 'ignored', e3_id: key, reason: 'output is already being published' })
      return
    }
    publishing.add(key)
    claimed = true

    // Interfold takes one output per E3, in the KeyPublished stage and before the compute deadline.
    // A late or repeated callback must not publish again.
    const window = await readWindow(e3Id)
    if (!computeWindowOpen(window)) {
      const reason = closedReason(window)
      console.log(`⏭️  Ignoring the output of E3 ${e3Id}: ${reason}`)
      scheduler.completed(e3Id)
      res.json({ status: 'ignored', e3_id: key, reason })
      return
    }

    console.log(`🔄 Publishing output for E3 ${e3Id}...`)
    const ciphertextBytes = Buffer.from(ciphertext.slice(2), 'hex')
    const contentHash = keccak256(ciphertext)

    if (availPublications) {
      if (ciphertextBytes.length > MAX_OUTPUT_BYTES) {
        res.status(413).json({ error: `The output is larger than ${MAX_OUTPUT_BYTES} bytes, the Avail limit` })
        return
      }
      // Do not spend Avail funds on an output that Ethereum would reject.
      try {
        await sdk.getPublicClient().readContract({
          ...program,
          functionName: 'verify',
          args: [e3Id, contentHash, ciphertext_commitment, proof],
        })
      } catch (error) {
        console.error(`❌ The program rejects the output of E3 ${e3Id}:`, error instanceof Error ? error.message : error)
        res.status(422).json({ error: 'The program rejects the output' })
        return
      }
      await store.storeObject(contentHash, ciphertextBytes)
      // Avail finalizes in minutes and the VectorX proof takes hours, so accept the output now and
      // publish it in the background. The record on disk survives a restart.
      const { created } = await store.createRecord(
        { e3Id: key, contentHash, ciphertextCommitment: ciphertext_commitment, computeProof: proof },
        ciphertextBytes,
      )
      if (!created) console.log(`E3 ${e3Id} already has an output on its way to Avail; keeping it`)
      availPublications.start(e3Id)
      scheduler.completed(e3Id)
      res.status(202).json({ status: 'accepted', e3_id: key })
      return
    }

    await store.storeObject(contentHash, ciphertextBytes)
    await publishOutput(e3Id, {
      contentHash,
      ciphertextCommitment: ciphertext_commitment,
      computeProof: proof,
      // The local program verifies raw bytes as a deterministic mock receipt.
      availabilityProof: ciphertext,
    })
    scheduler.completed(e3Id)
    console.log(`✅ Successfully completed E3 ${e3Id}`)
    res.json({ status: 'success', e3_id: key })
  } catch (error) {
    console.error('❌ Callback processing failed:', error)
    res.status(500).json({ error: 'Internal server error' })
  } finally {
    if (claimed) publishing.delete(key)
  }
}

const RELAY_BODY_LIMIT = '2mb'

// The relayer account, if configured. It is not the operator account, so a flood of relayed calls
// cannot drain the funds that publish outputs. It sends the bids, the claims and the keeper calls.
const relayer = config.relayerPrivateKey
  ? createWalletClient({ account: privateKeyToAccount(config.relayerPrivateKey), chain: config.chain, transport: http(config.rpcUrl) })
  : undefined

// Anyone may send `publishProbes(saleId)`, `clear(saleId)` and `payMarginal(saleId, index)`; the keeper
// sends them when the chain allows them. Each tick it reads every open sale, so a restart loses nothing.
let nextSaleScan = config.deployBlock
const keeper = new SaleKeeper({
  discover: async () => {
    const latest = await sdk.getPublicClient().getBlockNumber()
    if (nextSaleScan > latest) return []
    const sales = await scanSales(nextSaleScan, latest)
    nextSaleScan = latest + 1n
    return sales.map(({ saleId }) => saleId)
  },
  next: nextKeeperCall,
  send: (call) => sendFromRelayer(sdk.getPublicClient(), relayer!, config.program, call),
})

/** The relay endpoint carries no credential, so any page may call it. */
function allowAnyOrigin(req: Request, res: Response, next: NextFunction) {
  res.set({
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'content-type',
  })
  if (req.method === 'OPTIONS') {
    res.sendStatus(204)
    return
  }
  next()
}

/** Turns a relay failure into the HTTP answer: 400 for a bad body, 422 for a revert, 500 for anything else. */
function answerRelayError(res: Response, error: unknown) {
  if (error instanceof RelayRequestError) {
    res.status(400).json({ error: error.message })
  } else if (error instanceof RelayRevertError) {
    res.status(422).json({ error: error.message })
  } else {
    console.error('❌ Relay failed:', error)
    res.status(500).json({ error: 'Internal server error' })
  }
}

/**
 * `POST /relay { e3Id, data }` sends `publishInput(e3Id, data)` from the relayer account; `e3Id` is
 * the sale id. It answers `{ txHash }` once the transaction is mined, or `{ error }` with the revert
 * reason. The program checks the signature, the escrow and the proof, so this checks nothing else.
 */
async function handleRelay(req: Request, res: Response) {
  if (!relayer) {
    res.status(503).json({ error: 'This server has no relayer: set RELAYER_PRIVATE_KEY' })
    return
  }
  try {
    const { e3Id, data } = parseRelayRequest(req.body)
    const txHash = await relayBid(sdk.getPublicClient(), relayer, config.program, e3Id, data)
    console.log(`📨 Relayed a bid to sale ${e3Id}: ${txHash}`)
    res.json({ txHash })
  } catch (error) {
    answerRelayError(res, error)
  }
}

/**
 * `POST /relay/claim { saleId, data }` sends `claim(saleId, data)` from the relayer account. The
 * claim names its recipient and the proof binds it, so a fresh address that has no gas can claim.
 * The answer is the same as the answer of `POST /relay`. The server logs the transaction only.
 */
async function handleRelayClaim(req: Request, res: Response) {
  if (!relayer) {
    res.status(503).json({ error: 'This server has no relayer: set RELAYER_PRIVATE_KEY' })
    return
  }
  try {
    const { saleId, data } = parseRelayClaimRequest(req.body)
    const txHash = await relayClaim(sdk.getPublicClient(), relayer, config.program, saleId, data)
    console.log(`📨 Relayed a claim of sale ${saleId}: ${txHash}`)
    res.json({ txHash })
  } catch (error) {
    answerRelayError(res, error)
  }
}

const app = express()

app.get('/health', (_req, res) => {
  res.json({ status: 'ok' })
})
// The authentication runs before the body parser, so an unauthorized caller makes the server read nothing.
app.post('/callback/:e3Id/:token', authenticateCallback, express.json({ limit: CALLBACK_BODY_LIMIT }), handleCallback)
// The relayer sends a signed bid, or a claim, for an address that has no gas. A browser at another origin calls it.
app.use('/relay', allowAnyOrigin)
app.post('/relay', express.json({ limit: RELAY_BODY_LIMIT }), handleRelay)
app.post('/relay/claim', express.json({ limit: RELAY_BODY_LIMIT }), handleRelayClaim)
app.get('/availability/objects/:contentHash', async (req, res) => {
  const contentHash = req.params.contentHash
  if (!/^0x[a-fA-F0-9]{64}$/.test(contentHash)) {
    res.status(400).json({ error: 'contentHash must be a 32-byte hex value' })
    return
  }
  try {
    const bytes = await store.readObject(contentHash)
    res.type('application/octet-stream').send(bytes)
  } catch {
    res.status(404).json({ error: 'Object not found' })
  }
})

async function startServer() {
  try {
    // Serve first: the runner's callback and the health check must not wait for the recovery scan.
    app.listen(config.port, '0.0.0.0', () => {
      console.log(
        `🚀 Interfold coordination server listening on port ${config.port} (chain ${config.chain.id}, ${config.dataAvailability.mode})`,
      )
    })
    // Listen before the scan, so no event slips between the two.
    await setupEventListeners()
    await recoverE3s()
    await availPublications?.resume()
    if (relayer) {
      keeper.start(config.keeperPollMs)
      console.log(`🔧 Keeper started: publishProbes, clear and payMarginal are sent from ${relayer.account.address}`)
    } else {
      console.warn('⚠️  No relayer key: the keeper is off, so publishProbes, clear and payMarginal must be sent by someone else')
    }
    console.log(`📡 Event listeners active`)
  } catch (error) {
    console.error('❌ Failed to start server:', error)
    process.exit(1)
  }
}

startServer().catch(console.error)
