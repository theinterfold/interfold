// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import express, { Request, Response } from 'express'
import { InterfoldSDK } from '@interfold/sdk'
import { RegistryEventType, type CommitteePublishedData } from '@interfold/sdk/events'
import { Log, PublicClient } from 'viem'
import { hardhat } from 'viem/chains'
import { handleTestInteraction } from './testHandler'
import { getCheckedEnvVars } from './utils'
import { callFheRunner } from './runner'
import { ProgramEventType, RawInputPublishedEvent } from './types'
import { MyProgram__factory } from '../types/factories/contracts'

interface E3Session {
  e3Id: bigint
  expiration: bigint
  paramSet?: number
  inputs: Array<{ data: string; index: bigint }>
  isProcessing: boolean
  isCompleted: boolean
}

const e3Sessions = new Map<string, E3Session>()

let sdkInstance: InterfoldSDK | null = null

async function createPrivateSDK() {
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

async function runProgram(e3Id: bigint): Promise<void> {
  const sessionKey = e3Id.toString()
  const session = e3Sessions.get(sessionKey)

  if (!session || session.isProcessing || session.isCompleted) {
    return
  }

  console.log(`📊 Processing E3 session ${e3Id} with ${session.inputs.length} inputs`)

  try {
    session.isProcessing = true

    if (session.inputs.length <= 1) {
      console.log(`⏭️  Skipping E3 ${e3Id}: not enough inputs (${session.inputs.length})`)
      session.isCompleted = true
      return
    }

    // Look up the encoded params from the on-chain paramSetRegistry
    const sdk = await createPrivateSDK()
    const e3Details = await sdk.getE3(e3Id)
    const paramSetId = e3Details.paramSet
    const publicClient = sdk.getPublicClient()
    const { INTERFOLD_CONTRACT } = getCheckedEnvVars()
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
      args: [paramSetId],
    })) as string

    const ciphertextInputs: Array<[string, number]> = session.inputs.map((input) => [input.data, Number(input.index)])

    console.log(`🔄 Calling FHE runner for E3 ${e3Id}...`)
    await callFheRunner(e3Id, e3ProgramParams, ciphertextInputs)

    console.log(`✅ E3 ${e3Id} sent to FHE runner - awaiting callback`)
  } catch (error) {
    console.error(`❌ Error processing E3 ${e3Id}:`, error)
    session.isProcessing = false
  }
}

function defer() {
  let resolve: () => void = () => {}
  let reject: (e?: any) => void = () => {}

  const promise = new Promise<void>((res, rej) => {
    resolve = res
    reject = rej
  })

  return {
    promise,
    resolve,
    reject,
  }
}

type Defer = ReturnType<typeof defer>

const currentlyActivating = new Map<bigint, Defer>()

function getActivationDefer(e3Id: bigint): Defer {
  let d = currentlyActivating.get(e3Id)
  if (!d) {
    const def = defer()
    currentlyActivating.set(e3Id, def)
    return def
  }
  return d
}

async function handleCommitteePublishedEvent(event: any) {
  const data = event.data as CommitteePublishedData
  const e3Id = data.e3Id

  const def = getActivationDefer(e3Id)

  const sdk = await createPrivateSDK()
  const publicClient = sdk.getPublicClient()

  console.log('📡 Fetching E3 data from contract...')
  const e3 = await sdk.getE3(e3Id)

  console.log('✅ Received E3 data from contract.')

  const expiration = e3.inputWindow[1]

  console.log(`🎯 Committee Published for: ${e3Id}, expiration: ${expiration}`)

  console.log(`📥 Setting up session for E3 ${e3Id}...`)

  if (!e3Sessions.has(e3Id.toString())) {
    e3Sessions.set(e3Id.toString(), {
      e3Id,
      paramSet: e3.paramSet,
      expiration,
      inputs: [],
      isProcessing: false,
      isCompleted: false,
    })

    def.resolve()
  }

  const currentTime = (await publicClient.getBlock()).timestamp
  const sleepSeconds = expiration > currentTime ? Number(expiration - currentTime) : 0

  if (sleepSeconds > 0) {
    console.log(`⏰ Scheduling E3 ${e3Id} processing in ${sleepSeconds} seconds...`)
    setTimeout(async () => {
      await runProgram(e3Id)
    }, sleepSeconds * 1000)
  } else {
    console.log(`⚡ E3 ${e3Id} already expired, processing immediately...`)
    await runProgram(e3Id)
  }
}

async function handleInputPublishedEvent(event: RawInputPublishedEvent) {
  const e3Id = event.args.e3Id

  console.log(`📝 Input Published for E3 ${e3Id}: index ${event.args.index}`)

  const sessionKey = e3Id.toString()

  // Ensure the session is available
  await getActivationDefer(e3Id).promise

  const session = e3Sessions.get(sessionKey)

  if (session) {
    session.inputs.push({
      data: event.args.data,
      index: event.args.index,
    })
    console.log(`📊 E3 ${e3Id} now has ${session.inputs.length} inputs`)
  } else {
    console.warn(`⚠️  Received input for unknown E3 session: ${e3Id}`)
  }
}

async function listenToInputPublishedEvents(publicClient: PublicClient, address: `0x${string}`, fromBlock: bigint) {
  publicClient.watchContractEvent({
    address,
    abi: MyProgram__factory.abi,
    eventName: ProgramEventType.INPUT_PUBLISHED,
    fromBlock,
    async onLogs(logs: Log[]) {
      for (let i = 0; i < logs.length; i++) {
        const log = logs[i]
        if (!log) {
          console.log('warning: Log was falsy when a log was expected!')
          break
        }
        const eventData = log as unknown as RawInputPublishedEvent
        await handleInputPublishedEvent(eventData)
      }
    },
  })
}

async function setupEventListeners() {
  const sdk = await createPrivateSDK()

  const { E3_PROGRAM_ADDRESS: PROGRAM_ADDRESS } = getCheckedEnvVars()

  console.log('📡 Setting up event listeners...')

  // we need to listen to CommitteePublished to know when an E3 is ready
  await sdk.onInterfoldEvent(RegistryEventType.COMMITTEE_PUBLISHED, handleCommitteePublishedEvent)

  await listenToInputPublishedEvents(sdk.getPublicClient(), PROGRAM_ADDRESS as `0x${string}`, 0n)

  console.log('✅ Event listeners set up successfully')
}

function isValidHexString(value: string): value is `0x${string}` {
  return value.startsWith('0x') && /^0x[a-fA-F0-9]*$/.test(value)
}

async function handleWebhookRequest(req: Request, res: Response) {
  try {
    console.log('📨 Webhook received:')

    const { e3_id, ciphertext, proof } = req.body
    if (e3_id === undefined || !ciphertext || !proof) {
      console.error('Missing required fields: e3_id, ciphertext, proof')

      res.status(400).json({ error: 'Missing required fields: e3_id, ciphertext, proof' })
      return
    }

    if (!isValidHexString(ciphertext) || !isValidHexString(proof)) {
      console.error('ciphertext and proof must be valid hex strings')
      res.status(400).json({ error: 'ciphertext and proof must be valid hex strings' })
      return
    }

    console.log(`🔄 Publishing output for E3 ${e3_id}...`)

    const sdk = await createPrivateSDK()
    await sdk.publishCiphertextOutput(BigInt(e3_id), ciphertext, proof)

    // Mark session as completed
    const sessionKey = e3_id.toString()
    const session = e3Sessions.get(sessionKey)
    if (session) {
      session.isCompleted = true
      session.isProcessing = false
      console.log(`✅ Successfully completed E3 ${e3_id}`)
    }

    res.json({ status: 'success', e3_id })
  } catch (error) {
    console.error('❌ Webhook processing failed:', error)
    res.status(500).json({ error: 'Internal server error' })
  }
}

function handleGetSessions(req: Request, res: Response) {
  const sessions = Array.from(e3Sessions.entries()).map(([key, session]) => ({
    e3Id: key,
    expiration: session.expiration.toString(),
    inputCount: session.inputs.length,
    isProcessing: session.isProcessing,
    isCompleted: session.isCompleted,
  }))
  res.json(sessions)
}

const app = express()
app.use(express.json({ limit: '50mb' }))

app.post('/', handleWebhookRequest)
app.get('/sessions', handleGetSessions)

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
      console.log(`🚀 Interfold Server listening on port ${PORT}`)
      console.log(`📡 Event listeners active`)
      console.log(`📊 Sessions: http://localhost:${PORT}/sessions`)
    })
  } catch (error) {
    console.error('❌ Failed to start server:', error)
    process.exit(1)
  }
}

startServer().catch(console.error)
