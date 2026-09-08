// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import express, { Request, Response } from 'express'
import { CommitteePublicKeyAssembler, InterfoldSDK } from '@interfold/sdk'
import { RegistryEventType } from '@interfold/sdk/events'
import { hexToBytes, keccak256 } from 'viem'
import { hardhat } from 'viem/chains'
import { mkdir, readFile, rename, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { handleTestInteraction } from './testHandler'
import { getCheckedEnvVars } from './utils'
import { callFheRunner } from './runner'
import { MyProgram__factory } from '../types/factories/contracts'

// The coordination server orchestrates the FHE run automatically: it watches for
// each E3's committee to publish, schedules the compute for when the input window
// closes, and publishes the ciphertext output once the runner calls back. All of
// this needs a trusted always-on backend (an operator key to publish output and a
// reachable HTTP callback URL a browser cannot provide), so it stays server-side.
//
// It is kept deliberately lean: the params and published inputs are read from
// chain on demand at run time rather than accumulated in memory, so there is no
// per-E3 session state or input-buffering to maintain.

let sdkInstance: InterfoldSDK | null = null

async function createPrivateSDK(): Promise<InterfoldSDK> {
  if (sdkInstance) return sdkInstance

  const { PRIVATE_KEY, CIPHERNODE_REGISTRY_CONTRACT, INTERFOLD_CONTRACT, FEE_TOKEN_CONTRACT, RPC_URL } = getCheckedEnvVars()

  sdkInstance = InterfoldSDK.create({
    rpcUrl: RPC_URL,
    privateKey: PRIVATE_KEY as `0x${string}`,
    contracts: {
      interfold: INTERFOLD_CONTRACT as `0x${string}`,
      ciphernodeRegistry: CIPHERNODE_REGISTRY_CONTRACT as `0x${string}`,
      feeToken: FEE_TOKEN_CONTRACT as `0x${string}`,
    },
    chain: hardhat,
    thresholdBfvParamsPresetName: 'INSECURE_THRESHOLD_512',
  })

  return sdkInstance
}

// The only state the server keeps, purely for idempotency: E3s already scheduled
// (so repeated public-key candidates do not double-schedule) and E3s already
// submitted to the runner (so a run is not sent twice).
const scheduled = new Set<string>()
const inFlight = new Set<string>()
const CHAIN_TIME_POLL_INTERVAL_MS = 500
const DATA_AVAILABILITY_DIRECTORY = process.env.DATA_AVAILABILITY_DIRECTORY ?? '.interfold/data-availability'

async function storeAvailabilityObject(contentHash: `0x${string}`, bytes: Buffer): Promise<void> {
  await mkdir(DATA_AVAILABILITY_DIRECTORY, { recursive: true })
  const path = join(DATA_AVAILABILITY_DIRECTORY, contentHash.slice(2).toLowerCase())
  const temporaryPath = `${path}.${process.pid}.tmp`
  await writeFile(temporaryPath, bytes)
  await rename(temporaryPath, path)
}

async function waitForChainTimestamp(sdk: InterfoldSDK, target: bigint): Promise<void> {
  const publicClient = sdk.getPublicClient()
  while ((await publicClient.getBlock()).timestamp < target) {
    await new Promise((resolve) => setTimeout(resolve, CHAIN_TIME_POLL_INTERVAL_MS))
  }
}

/**
 * Read the params and published inputs for an E3 from chain and forward them to
 * the FHE runner. Stateless: everything is fetched on demand.
 */
async function runProgram(e3Id: bigint): Promise<void> {
  const key = e3Id.toString()

  if (inFlight.has(key)) {
    console.log(`⏭️  E3 ${e3Id} is already being processed, skipping`)
    return
  }

  const sdk = await createPrivateSDK()
  const publicClient = sdk.getPublicClient()
  const { INTERFOLD_CONTRACT, E3_PROGRAM_ADDRESS } = getCheckedEnvVars()

  // Look up the encoded params from the on-chain paramSetRegistry.
  const e3 = await sdk.getE3(e3Id)
  const e3ProgramParams = (await publicClient.readContract({
    address: INTERFOLD_CONTRACT as `0x${string}`,
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

  // Gather all inputs published for this E3 with a one-shot log query — no
  // long-lived listeners, no in-memory input buffer.
  const logs = await publicClient.getContractEvents({
    address: E3_PROGRAM_ADDRESS as `0x${string}`,
    abi: MyProgram__factory.abi,
    eventName: 'InputPublished',
    args: { e3Id },
    fromBlock: 0n,
  })

  const ciphertextInputs: Array<[string, number]> = logs.map((log) => [
    (log.args as { data: string }).data,
    Number((log.args as { index: bigint }).index),
  ])

  console.log(`📊 Processing E3 ${e3Id} with ${ciphertextInputs.length} input(s)`)

  if (ciphertextInputs.length <= 1) {
    console.log(`⏭️  Skipping E3 ${e3Id}: not enough inputs (${ciphertextInputs.length})`)
    return
  }

  try {
    inFlight.add(key)
    console.log(`🔄 Calling FHE runner for E3 ${e3Id}...`)
    await callFheRunner(
      e3Id,
      {
        chainId: await publicClient.getChainId(),
        interfoldAddress: INTERFOLD_CONTRACT,
        encryptionSchemeId: e3.encryptionSchemeId,
        committeePublicKeyHash: e3.committeePublicKey,
      },
      e3ProgramParams,
      ciphertextInputs,
    )
    console.log(`✅ E3 ${e3Id} sent to FHE runner - awaiting callback`)
  } catch (error) {
    // Allow a later retry if the runner submission failed.
    inFlight.delete(key)
    throw error
  }
}

/**
 * When a committee publishes for an E3, schedule the FHE run for the moment the
 * input window closes (or run immediately if it has already passed).
 */
async function scheduleE3(e3Id: bigint) {
  const key = e3Id.toString()

  if (scheduled.has(key)) return
  scheduled.add(key)

  const sdk = await createPrivateSDK()
  const publicClient = sdk.getPublicClient()

  const e3 = await sdk.getE3(e3Id)
  const expiration = e3.inputWindow[1]

  console.log(`🎯 Committee published for E3 ${e3Id}, input window closes at ${expiration}`)

  const run = () =>
    runProgram(e3Id).catch((error) => {
      console.error(`❌ Error processing E3 ${e3Id}:`, error)
    })

  if ((await publicClient.getBlock()).timestamp >= expiration) {
    console.log(`⚡ E3 ${e3Id} input window already closed, processing immediately...`)
    await run()
    return
  }

  console.log(`⏰ Waiting for E3 ${e3Id} input window to close on-chain...`)
  void waitForChainTimestamp(sdk, expiration)
    .then(run)
    .catch((error) => {
      console.error(`❌ Error while waiting for E3 ${e3Id} input window:`, error)
    })
}

async function setupEventListeners() {
  const sdk = await createPrivateSDK()
  const committeeKeyAssembler = new CommitteePublicKeyAssembler()

  console.log('📡 Setting up event listeners...')

  // Schedule computation only after the transported key matches the commitment
  // accepted with the DKG proof.
  await sdk.onInterfoldEvent(RegistryEventType.COMMITTEE_PUBLIC_KEY_CHUNK_PUBLISHED, async (event) => {
    try {
      const assembled = committeeKeyAssembler.add(event.data)
      if (!assembled) return

      const isBoundKey = await sdk.validatePublicKeyCommitment(assembled.publicKey, hexToBytes(assembled.pkCommitment))
      if (!isBoundKey) {
        console.warn(`Ignored committee public-key candidate for E3 ${assembled.e3Id}: commitment mismatch`)
        return
      }

      committeeKeyAssembler.clear(assembled.e3Id)
      await scheduleE3(assembled.e3Id)
    } catch (error) {
      console.error('Failed to process a committee public-key chunk:', error)
    }
  })

  console.log('✅ Event listeners set up successfully')
}

function isValidHexString(value: string): value is `0x${string}` {
  return value.startsWith('0x') && /^0x[a-fA-F0-9]*$/.test(value)
}

async function handleWebhookRequest(req: Request, res: Response) {
  try {
    console.log('📨 Webhook received:')

    const { e3_id, ciphertext, ciphertext_commitment, proof } = req.body
    if (e3_id === undefined || !ciphertext || !ciphertext_commitment || !proof) {
      console.error('Missing required fields: e3_id, ciphertext, ciphertext_commitment, proof')
      res.status(400).json({ error: 'Missing required fields: e3_id, ciphertext, ciphertext_commitment, proof' })
      return
    }

    if (!isValidHexString(ciphertext) || !isValidHexString(ciphertext_commitment) || !isValidHexString(proof)) {
      console.error('ciphertext, ciphertext_commitment, and proof must be valid hex strings')
      res.status(400).json({ error: 'ciphertext, ciphertext_commitment, and proof must be valid hex strings' })
      return
    }

    console.log(`🔄 Publishing output for E3 ${e3_id}...`)

    const ciphertextBytes = Buffer.from(ciphertext.slice(2), 'hex')
    const contentHash = keccak256(ciphertext)
    await storeAvailabilityObject(contentHash, ciphertextBytes)

    const sdk = await createPrivateSDK()
    await sdk.publishCiphertextOutput(BigInt(e3_id), {
      contentHash,
      ciphertextCommitment: ciphertext_commitment,
      computeProof: proof,
      // The local program verifies raw bytes as a deterministic mock receipt.
      availabilityProof: ciphertext,
    })

    inFlight.delete(e3_id.toString())
    console.log(`✅ Successfully completed E3 ${e3_id}`)

    res.json({ status: 'success', e3_id })
  } catch (error) {
    console.error('❌ Webhook processing failed:', error)
    res.status(500).json({ error: 'Internal server error' })
  }
}

const app = express()
app.use(express.json({ limit: '50mb' }))

app.post('/', handleWebhookRequest)
app.get('/availability/objects/:contentHash', async (req, res) => {
  const contentHash = req.params.contentHash
  if (!/^0x[a-fA-F0-9]{64}$/.test(contentHash)) {
    res.status(400).json({ error: 'contentHash must be a 32-byte hex value' })
    return
  }
  try {
    const bytes = await readFile(join(DATA_AVAILABILITY_DIRECTORY, contentHash.slice(2).toLowerCase()))
    res.type('application/octet-stream').send(bytes)
  } catch {
    res.status(404).json({ error: 'Object not found' })
  }
})

// This allows us to test interaction between server and program
// TEST_MODE=1 pnpm dev:server
if (process.env.TEST_MODE) {
  app.get('/test', handleTestInteraction)
}

async function startServer() {
  try {
    await setupEventListeners()

    const PORT = process.env.PORT ? parseInt(process.env.PORT) : 8080
    app.listen(PORT, '0.0.0.0', () => {
      console.log(`🚀 Interfold coordination server listening on port ${PORT}`)
      console.log(`📡 Event listeners active`)
    })
  } catch (error) {
    console.error('❌ Failed to start server:', error)
    process.exit(1)
  }
}

startServer().catch(console.error)
