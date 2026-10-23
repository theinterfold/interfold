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
import { bytesToHex, createWalletClient, hexToBytes, http, keccak256 } from 'viem'
import { privateKeyToAccount } from 'viem/accounts'
import { loadConfig, type ServerConfig } from './config'
import { callFheRunner } from './runner'
import { AvailabilityStore, AvailHelper } from './availability'
import { AvailPublicationRunner } from './publication'
import { ComputeScheduler } from './scheduler'
import { closedReason, computeWindowOpen, type E3Window } from './window'
import { getLogsChunked } from './logs'
import { AuctionProgram__factory } from '../types/factories/contracts'
import { AUCTION_TYPE_LABELS, isAuctionType, MIN_BIDDERS } from '../shared/layout'
import { selectBids, type SubmittedBid } from '../shared/selection'
import { auctionInputs, opensCommitment, type ProgramInputs } from './inputs'
import { parseRelayRequest, relayBid, RelayRequestError, RelayRevertError } from './relay'

// The coordination server orchestrates the FHE run automatically: it watches for
// each E3's committee to publish, schedules the compute for when the input window
// closes, and publishes the ciphertext output once the runner calls back. All of
// this needs a trusted always-on backend (an operator key to publish output and a
// reachable HTTP callback URL a browser cannot provide), so it stays server-side.
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

// The block of each auction's `AuctionCreated` log. `E3.requestBlock` is a timestamp, not a block
// number, so it cannot start a log scan. Every input and key chunk of an E3 comes after this block.
const createdBlocks = new Map<string, bigint>()

async function auctionCreatedBlock(e3Id: bigint): Promise<bigint> {
  const cached = createdBlocks.get(e3Id.toString())
  if (cached !== undefined) return cached
  const publicClient = sdk.getPublicClient()
  const logs = await getLogsChunked(
    (range) =>
      publicClient.getContractEvents({
        address: config.program,
        abi: AuctionProgram__factory.abi,
        eventName: 'AuctionCreated',
        args: { e3Id },
        strict: true,
        ...range,
      }),
    config.deployBlock,
    await publicClient.getBlockNumber(),
    config.logChunkSize,
  )
  const log = logs[0]
  if (!log) throw new Error(`E3 ${e3Id}: no AuctionCreated event at or after block ${config.deployBlock}; check DEPLOY_BLOCK`)
  createdBlocks.set(e3Id.toString(), log.blockNumber)
  return log.blockNumber
}

/**
 * Read the params and published inputs for an E3 from chain and forward them to
 * the FHE runner. Stateless: everything is fetched on demand.
 */
async function runProgram(e3Id: bigint, committeeKey: Uint8Array, callbackToken: string): Promise<'submitted' | 'skipped'> {
  const publicClient = sdk.getPublicClient()

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

  // Gather the inputs with one-shot log queries — no long-lived listeners, no in-memory input
  // buffer. `BidSubmitted` holds the bytes of every bid and the leaf of its first ciphertext. Every
  // bid is a published input, counted or not, because the input root covers all leaves. Leaf 0 is
  // the auction's configuration, which the contract inserted at request time. Every input comes
  // after the auction's creation, so the scans start at its `AuctionCreated` block, in chunks that
  // a public RPC accepts.
  const fromBlock = await auctionCreatedBlock(e3Id)
  const toBlock = await publicClient.getBlockNumber()
  const [submitted, auction] = await Promise.all([
    getLogsChunked(
      (range) =>
        publicClient.getContractEvents({
          address: config.program,
          abi: AuctionProgram__factory.abi,
          args: { e3Id },
          strict: true,
          eventName: 'BidSubmitted',
          ...range,
        }),
      fromBlock,
      toBlock,
      config.logChunkSize,
    ),
    publicClient.readContract({
      address: config.program,
      abi: AuctionProgram__factory.abi,
      functionName: 'auctions',
      args: [e3Id],
    }),
  ])
  const [auctionType] = auction
  if (!isAuctionType(auctionType)) throw new Error(`E3 ${e3Id}: unknown auction type ${auctionType}`)

  const bids: SubmittedBid[] = submitted.map(({ args }) => ({
    bidder: args.bidder,
    version: args.version,
    firstIndex: Number(args.firstIndex),
    ciphertexts: [...args.ciphertexts],
    commitments: [...args.commitments],
  }))
  let inputs: ProgramInputs
  try {
    inputs = auctionInputs(auctionType, bids)
  } catch (error) {
    throw new Error(`E3 ${e3Id}: ${error instanceof Error ? error.message : error}`)
  }

  // The contract cannot check that published bytes open their commitments; the program does, and
  // leaves a bid that does not open out of the computation. Apply the same rule here, to know
  // whether there is an auction to run.
  const counted = selectBids(bids, await opensCommitment(bids))
  console.log(
    `📊 Processing E3 ${e3Id} (${AUCTION_TYPE_LABELS[auctionType]}): ${bids.length} bid(s), ${counted.length} counted, ${inputs.ciphertexts.length} input(s)`,
  )

  // The program needs 2 bidders at least (the most is set by the contract); with fewer there is no auction to run.
  if (counted.length < MIN_BIDDERS) {
    console.log(
      `⏭️  Skipping E3 ${e3Id}: ${counted.length} bidder(s) with a bid that opens its commitments, an auction needs ${MIN_BIDDERS}`,
    )
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
})

/**
 * Schedule the compute once the transported key matches the commitment accepted with the DKG
 * proof. Both the live listener and the recovery scan feed chunks here.
 */
async function handleKeyChunk(chunk: CommitteePublicKeyChunkPublishedData): Promise<void> {
  try {
    const assembled = committeeKeyAssembler.add(chunk)
    if (!assembled) return
    const isBoundKey = await sdk.validatePublicKeyCommitment(assembled.publicKey, hexToBytes(assembled.pkCommitment))
    if (!isBoundKey) {
      console.warn(`Ignored committee public-key candidate for E3 ${assembled.e3Id}: commitment mismatch`)
      return
    }
    committeeKeyAssembler.clear(assembled.e3Id)
    if (!scheduler.isScheduled(assembled.e3Id)) console.log(`🎯 Committee published for E3 ${assembled.e3Id}`)
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
 * The listener only sees new events. After a restart, find the auctions whose committee key is
 * published but whose output is not, rebuild each key from the historical chunk events and
 * schedule the compute. Auctions whose output is already on its way through Avail resume that
 * publication instead. Run it after the listener subscribed: the scan then covers every block up
 * to `latest` and the listener every later one, and the shared assembler ignores a repeated chunk.
 */
async function recoverE3s() {
  const publicClient = sdk.getPublicClient()
  const latest = await publicClient.getBlockNumber()
  console.log(`🔎 Scanning blocks ${config.deployBlock}-${latest} for auctions to recover...`)

  const created = await getLogsChunked(
    (range) =>
      publicClient.getContractEvents({
        address: config.program,
        abi: AuctionProgram__factory.abi,
        eventName: 'AuctionCreated',
        strict: true,
        ...range,
      }),
    config.deployBlock,
    latest,
    config.logChunkSize,
  )

  // E3s that wait for their compute: the key is published, no output is, and the compute window is
  // open. An E3 before that stage will publish its key to the live listener.
  const waiting = new Set<string>()
  let from = latest
  for (const { args, blockNumber } of created) {
    const key = args.e3Id.toString()
    createdBlocks.set(key, blockNumber)
    if (waiting.has(key)) continue
    const window = await readWindow(args.e3Id)
    if (!computeWindowOpen(window)) {
      if (window.stage === E3Stage.KeyPublished) console.log(`⏭️  E3 ${args.e3Id} is not recovered: ${closedReason(window)}`)
      continue
    }
    if (await store.readRecord(args.e3Id)) continue // The output exists; the Avail publication resumes it.
    waiting.add(key)
    if (blockNumber < from) from = blockNumber
  }
  if (waiting.size === 0) {
    console.log('🔎 No auction waits for its compute')
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
          address: config.program,
          abi: AuctionProgram__factory.abi,
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

// The relayer account, if configured. It is not the operator account, so a flood of relayed bids
// cannot drain the funds that publish outputs.
const relayer = config.relayerPrivateKey
  ? createWalletClient({ account: privateKeyToAccount(config.relayerPrivateKey), chain: config.chain, transport: http(config.rpcUrl) })
  : undefined

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

/**
 * `POST /relay { e3Id, data }` sends `publishInput(e3Id, data)` from the relayer account. It answers
 * `{ txHash }` once the transaction is mined, or `{ error }` with the revert reason. The program
 * checks the signature, the gate and the proof, so this checks nothing else.
 */
async function handleRelay(req: Request, res: Response) {
  if (!relayer) {
    res.status(503).json({ error: 'This server has no relayer: set RELAYER_PRIVATE_KEY' })
    return
  }
  try {
    const { e3Id, data } = parseRelayRequest(req.body)
    const txHash = await relayBid(sdk.getPublicClient(), relayer, config.program, e3Id, data)
    console.log(`📨 Relayed a bid to E3 ${e3Id}: ${txHash}`)
    res.json({ txHash })
  } catch (error) {
    if (error instanceof RelayRequestError) {
      res.status(400).json({ error: error.message })
    } else if (error instanceof RelayRevertError) {
      res.status(422).json({ error: error.message })
    } else {
      console.error('❌ Relay failed:', error)
      res.status(500).json({ error: 'Internal server error' })
    }
  }
}

const app = express()

app.get('/health', (_req, res) => {
  res.json({ status: 'ok' })
})
// The authentication runs before the body parser, so an unauthorized caller makes the server read nothing.
app.post('/callback/:e3Id/:token', authenticateCallback, express.json({ limit: CALLBACK_BODY_LIMIT }), handleCallback)
// The relayer sends a signed bid for a bidder who has no gas. A browser at another origin calls it.
app.use('/relay', allowAnyOrigin)
app.post('/relay', express.json({ limit: RELAY_BODY_LIMIT }), handleRelay)
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
    console.log(`📡 Event listeners active`)
  } catch (error) {
    console.error('❌ Failed to start server:', error)
    process.exit(1)
  }
}

startServer().catch(console.error)
