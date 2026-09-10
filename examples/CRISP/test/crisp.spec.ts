// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { ConsoleMessage, Page } from '@playwright/test'
import { testWithSynpress } from '@synthetixio/synpress'
import { MetaMask, metaMaskFixtures } from '@synthetixio/synpress/playwright'
import basicSetup from './wallet-setup/basic.setup'
import { execFileSync } from 'child_process'
import { readFileSync } from 'fs'
import { config } from 'dotenv'
import { Contract, JsonRpcProvider } from 'ethers'
import path from 'path'

const CLI = path.join(process.cwd(), 'target', 'debug', 'cli')

config({ path: path.join(process.cwd(), 'server', '.env') })
config({ path: path.join(process.cwd(), 'client', '.env') })

const RANDOMNESS_ACCEPTANCE_WAIT = 30_000
const DKG_READY_GRACE = 90_000
const VOTE_PUBLICATION_WAIT = 180_000
const E3_COMPLETION_WAIT = 180_000
const CRISP_APP_URL = 'http://localhost:3000/'
const E3_STAGE_COMPLETE = 5n
const E3_STAGE_FAILED = 6n
const REGISTRY_READ_ABI = [
  'function sortitionSeed(uint256 e3Id) view returns (bool ready, uint256 seed)',
  'function getCommitteeDeadline(uint256 e3Id) view returns (uint256)',
]
const INTERFOLD_READ_ABI = [
  'function getE3(uint256 e3Id) view returns ((uint256 seed,uint8 committeeSize,uint256 requestBlock,uint256[2] inputWindow,bytes32 encryptionSchemeId,address e3Program,uint8 paramSet,bytes customParams,address decryptionVerifier,address pkVerifier,bytes32 committeePublicKey,bytes32 ciphertextOutput,bytes plaintextOutput,address requester,bytes32 ciphertextCommitment) e3)',
  'function getE3Stage(uint256 e3Id) view returns (uint8 stage)',
]
const CRISP_READ_ABI = [
  'function getRoundData(uint256 e3Id) view returns (uint256 merkleRoot,bytes32 paramsHash,uint256 numOptions,uint8 creditMode,uint256 inputRoot,uint40 numberOfVotes)',
]

function crispTokenAddress(): string {
  const tokenAddress = process.env.VITE_CRISP_TOKEN
  if (!tokenAddress) {
    throw new Error('VITE_CRISP_TOKEN must be set (see client/.env after deploy)')
  }
  return tokenAddress
}

async function runCliInit(): Promise<string> {
  try {
    const output = execFileSync(CLI, ['init', '--token-address', crispTokenAddress(), '--balance-threshold', '1000'], { encoding: 'utf-8' })
    console.log('Command output:', output)
    const lines = output.trim().split('\n')
    const lastLine = lines[lines.length - 1].trim()
    if (!/^\d+$/.test(lastLine)) {
      throw new Error(`Failed to parse e3Id from CLI output: ${lastLine}`)
    }
    return lastLine
  } catch (error) {
    console.error('Error executing command:', error)
    throw error
  }
}

async function checkE3Ready(e3id: string): Promise<boolean> {
  try {
    const output = execFileSync(CLI, ['check-e3-ready', '--e3id', String(e3id)], {
      encoding: 'utf-8',
    })
    const lines = output.trim().split('\n')
    const lastLine = lines[lines.length - 1].trim()
    return lastLine === 'true'
  } catch (error) {
    log(`check-e3-ready failed for e3id=${e3id}: ${error}`)
    return false
  }
}

async function waitForE3Ready(e3id: string, maxWaitMs: number): Promise<void> {
  const startTime = Date.now()
  while (Date.now() - startTime < maxWaitMs) {
    const isActivated = await checkE3Ready(e3id)
    if (isActivated) {
      log(`E3 ${e3id} is ready`)
      return
    }
    await new Promise((resolve) => setTimeout(resolve, 5000))
  }
  throw new Error(`E3 ${e3id} was not ready within ${maxWaitMs}ms`)
}

async function committeeReadyTimeout(e3id: string): Promise<number> {
  const { provider, registry } = protocolReader()
  const [committeeDeadline, latestBlock] = await Promise.all([registry.getCommitteeDeadline(e3id), provider.getBlock('latest')])
  if (!latestBlock) throw new Error('Latest block is unavailable while deriving the committee wait')

  const submissionTimeRemaining = Math.max(0, Number(committeeDeadline) - latestBlock.timestamp) * 1000
  return submissionTimeRemaining + DKG_READY_GRACE
}

function protocolReader(): { provider: JsonRpcProvider; registry: Contract; interfold: Contract; crispProgram: Contract } {
  const deploymentsPath = path.join(process.cwd(), 'packages', 'crisp-contracts', 'deployed_contracts.json')
  const deployments = JSON.parse(readFileSync(deploymentsPath, 'utf8'))
  const local = deployments.localhost
  const registryAddress = local?.CiphernodeRegistryOwnable?.address
  const interfoldAddress = local?.Interfold?.address
  const crispProgramAddress = local?.CRISPProgram?.address
  if (!registryAddress) throw new Error(`CiphernodeRegistryOwnable is missing from ${deploymentsPath}`)
  if (!interfoldAddress) throw new Error(`Interfold is missing from ${deploymentsPath}`)
  if (!crispProgramAddress) throw new Error(`CRISPProgram is missing from ${deploymentsPath}`)

  const provider = new JsonRpcProvider('http://127.0.0.1:8545', 31337, { staticNetwork: true })
  return {
    provider,
    registry: new Contract(registryAddress, REGISTRY_READ_ABI, provider),
    interfold: new Contract(interfoldAddress, INTERFOLD_READ_ABI, provider),
    crispProgram: new Contract(crispProgramAddress, CRISP_READ_ABI, provider),
  }
}

async function waitForRandomnessAcceptance(e3id: string): Promise<void> {
  const { registry } = protocolReader()
  const deadline = Date.now() + RANDOMNESS_ACCEPTANCE_WAIT
  let lastError: unknown

  while (Date.now() < deadline) {
    try {
      const [ready] = await registry.sortitionSeed(e3id)
      if (ready) {
        log(`Registry accepted delayed randomness for E3 ${e3id}`)
        return
      }
    } catch (error) {
      lastError = error
    }
    await new Promise((resolve) => setTimeout(resolve, 250))
  }

  const detail = lastError ? ` Last RPC error: ${lastError}` : ''
  throw new Error(`Registry did not accept delayed randomness for E3 ${e3id} within ${RANDOMNESS_ACCEPTANCE_WAIT}ms.${detail}`)
}

async function waitForVotePublication(e3id: string): Promise<void> {
  const { crispProgram } = protocolReader()
  const deadline = Date.now() + VOTE_PUBLICATION_WAIT
  let lastError: unknown

  while (Date.now() < deadline) {
    try {
      const round = await crispProgram.getRoundData(e3id)
      if (BigInt(round.numberOfVotes) > 0n) {
        log(`CRISPProgram accepted a vote for E3 ${e3id}`)
        return
      }
    } catch (error) {
      lastError = error
    }
    await new Promise((resolve) => setTimeout(resolve, 500))
  }

  const detail = lastError ? ` Last RPC error: ${lastError}` : ''
  throw new Error(`CRISPProgram did not accept a vote for E3 ${e3id} within ${VOTE_PUBLICATION_WAIT}ms.${detail}`)
}

async function closeInputWindow(e3id: string): Promise<void> {
  const { provider, interfold } = protocolReader()
  const [e3, latestBlock] = await Promise.all([interfold.getE3(e3id), provider.getBlock('latest')])
  if (!latestBlock) throw new Error('Latest block is unavailable while closing the input window')

  const inputDeadline = Number(e3.inputWindow[1])
  const nextTimestamp = Math.max(latestBlock.timestamp + 1, inputDeadline + 1)
  await provider.send('evm_setNextBlockTimestamp', [nextTimestamp])
  await provider.send('evm_mine', [])
  log(`advanced Anvil to ${nextTimestamp}, after the E3 input deadline ${inputDeadline}`)
}

async function waitForE3Completion(e3id: string): Promise<void> {
  const { interfold } = protocolReader()
  const deadline = Date.now() + E3_COMPLETION_WAIT
  let lastStage: bigint | undefined
  let lastError: unknown

  while (Date.now() < deadline) {
    try {
      lastStage = BigInt(await interfold.getE3Stage(e3id))
      if (lastStage === E3_STAGE_COMPLETE) {
        log(`E3 ${e3id} completed`)
        return
      }
      if (lastStage === E3_STAGE_FAILED) throw new Error(`E3 ${e3id} failed before completion`)
    } catch (error) {
      if (error instanceof Error && error.message === `E3 ${e3id} failed before completion`) throw error
      lastError = error
    }
    await new Promise((resolve) => setTimeout(resolve, 1000))
  }

  const stage = lastStage === undefined ? 'unavailable' : lastStage.toString()
  const detail = lastError ? ` Last RPC error: ${lastError}` : ''
  throw new Error(`E3 ${e3id} did not complete within ${E3_COMPLETION_WAIT}ms. Last stage: ${stage}.${detail}`)
}

const test = testWithSynpress(metaMaskFixtures(basicSetup))
const { expect } = test

async function ensureHomePageLoaded(page: Page) {
  await page.goto(CRISP_APP_URL, { waitUntil: 'domcontentloaded' })
  await page.waitForLoadState('load')
  log(`opened CRISP at ${page.url()}`)
  await expect(page.getByText('Coercion-Resistant Impartial Selection Protocol')).toBeVisible({ timeout: 30_000 })
}

function log(msg: string) {
  console.log(`[playwright] ${msg}`)
}

// ConnectKit modal animations + app initialization (initialLoad/switchChain)
// can cause the MetaMask button to be detached from the DOM or the page to
// navigate while the modal is opening. Retry the whole flow up to 3 times.
// After reload, wagmi/ConnectKit reconnect and App.tsx switchChain can lag on CI.
// Wait until the demo poll is interactive and the wallet session is restored.
async function waitForDemoPollReady(page: Page) {
  await page.waitForLoadState('load')
  await expect(page.locator("[data-test-id='poll-button-0']")).toBeVisible({ timeout: 60_000 })
  await expect(page.locator('.tag.live')).toBeVisible({ timeout: 60_000 })
}

async function waitForWalletSession(page: Page) {
  log('waiting for wallet session...')
  await expect(page.locator('button:has-text("Connect Wallet")')).toHaveCount(0, { timeout: 60_000 })
  // ConnectKit shows a truncated address once wagmi isConnected; VoteManagement only
  // sets `user` from the same source, so this gates Cast → signMessage.
  await expect(page.locator('button').filter({ hasText: /^0x/i })).toBeVisible({ timeout: 60_000 })
  // Vote status fetch proves user.address + currentRoundId are wired in React context.
  await expect(page.locator('.tag').filter({ hasText: 'Checking' })).toHaveCount(0, { timeout: 90_000 })
  log('wallet session ready')
}

async function reconnectWalletIfNeeded(page: Page, metamask: MetaMask) {
  const connectWalletBtn = page.locator('button:has-text("Connect Wallet")')
  if (!(await connectWalletBtn.isVisible({ timeout: 3_000 }).catch(() => false))) return

  // Wagmi restores the persisted connector asynchronously after a reload. Give
  // it time to finish before opening a second connection request.
  const restored = await expect(connectWalletBtn)
    .toHaveCount(0, { timeout: 15_000 })
    .then(() => true)
    .catch(() => false)
  if (restored) {
    log('wallet session restored automatically')
    return
  }

  log('wallet disconnected — reconnecting...')
  const connectionRequested = await connectWalletWithRetry(page)
  if (connectionRequested) {
    await metamask.connectToDapp()
  }
}

async function castVoteWithSignature(page: Page, metamask: MetaMask) {
  for (let attempt = 1; attempt <= 3; attempt++) {
    try {
      log(`clicking first vote card (attempt ${attempt})...`)
      await page.locator("[data-test-id='poll-button-0']").click()

      const castBtn = page.locator('button:has-text("Cast")')
      await expect(castBtn).toBeEnabled({ timeout: 30_000 })

      log(`clicking Cast Vote (attempt ${attempt})...`)
      await castBtn.click()
      log(`confirming MetaMask signature request...`)
      await metamask.confirmSignature()
      return
    } catch (error) {
      if (attempt === 3) throw error
      log(`signature attempt ${attempt} failed, retrying...`)
      await page.keyboard.press('Escape').catch(() => {})
      await page.waitForTimeout(2_000)
    }
  }
}

async function connectWalletWithRetry(page: Page, maxAttempts = 3): Promise<boolean> {
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      await page.waitForLoadState('load')

      const connectWalletBtn = page.locator('button:has-text("Connect Wallet")')
      const metamaskBtn = page.locator('button:has-text("MetaMask")')

      if (!(await connectWalletBtn.isVisible().catch(() => false))) {
        return false
      }

      // Only open the modal if MetaMask option isn't already visible
      if (!(await metamaskBtn.isVisible().catch(() => false))) {
        log(`clicking Connect Wallet (attempt ${attempt})...`)
        try {
          await connectWalletBtn.click({ timeout: 10_000 })
        } catch (error) {
          // The persisted connector can finish restoring between the visibility
          // check and the click. In that case no connection request is needed.
          if (!(await connectWalletBtn.isVisible().catch(() => false))) {
            return false
          }
          throw error
        }
      }

      log(`clicking MetaMask (attempt ${attempt})...`)
      await metamaskBtn.click({ timeout: 15_000 })
      return true
    } catch (error) {
      if (attempt === maxAttempts) throw error
      log(`wallet connect attempt ${attempt} failed, retrying...`)
      // Dismiss any open modal before retrying
      await page.keyboard.press('Escape').catch(() => {})
      await page.waitForTimeout(2_000)
    }
  }

  return false
}

test('CRISP smoke test', async ({ context, metamaskPage, extensionId }) => {
  // The persistent browser's first page belongs to MetaMask. Create a separate
  // page so extension navigation cannot replace the CRISP application under test.
  const page = await context.newPage()

  page.on('console', (msg: ConsoleMessage) => {
    console.log(msg.text())
  })
  page.on('pageerror', (error) => {
    console.error(`[browser page error] ${error.stack || error.message}`)
  })

  log('============================================')
  log('      STARTING YOUR PLAYWRIGHT TEST!        ')
  log('============================================')
  const testStart = Date.now()

  log('Creating new Metamask...')
  const metamask = new MetaMask(context, metamaskPage, basicSetup.walletPassword, extensionId)

  log('runCliInit()...')
  const e3id = await runCliInit()
  log(`Got e3 id: ${e3id}`)
  await waitForRandomnessAcceptance(e3id)

  log(`ensureHomePageLoaded...`)
  await ensureHomePageLoaded(page)

  log(`connecting wallet via ConnectKit...`)
  const connectionRequested = await connectWalletWithRetry(page)
  if (connectionRequested) {
    log(`connecting to dapp...`)
    await metamask.connectToDapp()
  }
  log(`clicking try demo...`)
  await page.locator('a:has-text("Try the demo")').click()

  log(`waiting for E3 Committee being published...`)
  await waitForE3Ready(e3id, await committeeReadyTimeout(e3id))
  const DKG_DURATION = Date.now() - testStart
  log(`DKG duration: ${DKG_DURATION}ms`)
  log(`forcing page reload...`)
  await page.reload()
  await page.waitForLoadState('load')
  // The wallet fixture starts on localwallet, and reloading the application does
  // not change the wallet network. Opening the extension here steals focus from
  // the application while its round state is being restored.
  await page.bringToFront()
  await waitForDemoPollReady(page)
  await reconnectWalletIfNeeded(page, metamask)
  await waitForWalletSession(page)
  await castVoteWithSignature(page, metamask)
  await waitForVotePublication(e3id)
  await closeInputWindow(e3id)
  await waitForE3Completion(e3id)
  log(`clicking all polls button...`)
  await page.locator('a:has-text("All Polls")').click()
  log(`asserting that All polls page exists...`)
  await expect(page.locator('h1')).toHaveText('All polls')
  const pollResult = page.locator(`[data-test-id='poll-${e3id}-0']`)
  log(`asserting that result has 100% on the vote we clicked on...`)
  await expect(pollResult.locator("[data-test-id='poll-result-0'] .h2")).toHaveText('100%', { timeout: 60_000 })
  log(`asserting that result has 0% on the vote we did not click on...`)
  await expect(pollResult.locator("[data-test-id='poll-result-1'] .h2")).toHaveText('0%')

  log('============================================')
  log('        PLAYWRIGHT TEST IS COMPLETE         ')
  log('============================================')
})
