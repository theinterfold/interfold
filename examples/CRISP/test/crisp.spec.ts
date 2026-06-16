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
import { config } from 'dotenv'
import path from 'path'

const CLI = path.join(process.cwd(), 'target', 'debug', 'cli')

config({ path: path.join(process.cwd(), 'server', '.env') })
config({ path: path.join(process.cwd(), 'client', '.env') })

const E3_DURATION = parseInt(process.env.E3_DURATION as string, 10) * 1000
const OUTPUT_DECRYPTION_WAIT = 80_000 // A small buffer for decryption

function crispTokenAddress(): string {
  const tokenAddress = process.env.VITE_CRISP_TOKEN
  if (!tokenAddress) {
    throw new Error('VITE_CRISP_TOKEN must be set (see client/.env after deploy)')
  }
  return tokenAddress
}

async function runCliInit(): Promise<number> {
  try {
    const output = execFileSync(CLI, ['init', '--token-address', crispTokenAddress(), '--balance-threshold', '1000'], { encoding: 'utf-8' })
    console.log('Command output:', output)
    const lines = output.trim().split('\n')
    const lastLine = lines[lines.length - 1].trim()
    const e3Id = parseInt(lastLine, 10)
    if (isNaN(e3Id)) {
      throw new Error(`Failed to parse e3Id from CLI output: ${lastLine}`)
    }
    return e3Id
  } catch (error) {
    console.error('Error executing command:', error)
    throw error
  }
}

async function checkE3Ready(e3id: number): Promise<boolean> {
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

async function waitForE3Ready(e3id: number, maxWaitMs: number = E3_DURATION): Promise<void> {
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

const test = testWithSynpress(metaMaskFixtures(basicSetup))
const { expect } = test

async function ensureHomePageLoaded(page: Page) {
  return await expect(page.getByText('Coercion-Resistant Impartial Selection Protocol')).toBeVisible()
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
  await expect(page.locator('button:has-text("Connect Wallet")')).not.toBeVisible({ timeout: 60_000 })
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
  if (await connectWalletBtn.isVisible({ timeout: 3_000 }).catch(() => false)) {
    log('wallet disconnected — reconnecting...')
    await connectWalletWithRetry(page)
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

async function connectWalletWithRetry(page: Page, maxAttempts = 3) {
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      await page.waitForLoadState('load')

      const connectWalletBtn = page.locator('button:has-text("Connect Wallet")')
      const metamaskBtn = page.locator('button:has-text("MetaMask")')

      // Only open the modal if MetaMask option isn't already visible
      if (!(await metamaskBtn.isVisible().catch(() => false))) {
        log(`clicking Connect Wallet (attempt ${attempt})...`)
        await connectWalletBtn.click({ timeout: 10_000 })
      }

      log(`clicking MetaMask (attempt ${attempt})...`)
      await metamaskBtn.click({ timeout: 15_000 })
      return
    } catch (error) {
      if (attempt === maxAttempts) throw error
      log(`wallet connect attempt ${attempt} failed, retrying...`)
      // Dismiss any open modal before retrying
      await page.keyboard.press('Escape').catch(() => {})
      await page.waitForTimeout(2_000)
    }
  }
}

test('CRISP smoke test', async ({ context, page, metamaskPage, extensionId }) => {
  page.on('console', (msg: ConsoleMessage) => {
    console.log(msg.text())
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

  await page.goto('/', { waitUntil: 'domcontentloaded' })
  await page.waitForLoadState('load')

  log(`ensureHomePageLoaded...`)
  await ensureHomePageLoaded(page)

  log(`connecting wallet via ConnectKit...`)
  await connectWalletWithRetry(page)
  log(`connecting to dapp...`)
  await metamask.connectToDapp()
  log(`clicking try demo...`)
  await page.locator('a:has-text("Try the demo")').click()

  log(`waiting for E3 Committee being published...`)
  await waitForE3Ready(e3id)
  const DKG_DURATION = Date.now() - testStart
  log(`DKG duration: ${DKG_DURATION}ms`)
  log(`forcing page reload...`)
  const voteStatusReady = page.waitForResponse((resp) => resp.url().includes('/voting/status') && resp.ok(), { timeout: 120_000 })
  await page.reload()
  await page.waitForLoadState('load')
  log(`ensuring local anvil network after reload...`)
  await metamask.switchNetwork('localwallet')
  await reconnectWalletIfNeeded(page, metamask)
  await waitForDemoPollReady(page)
  await waitForWalletSession(page)
  await voteStatusReady.catch(() => {
    log('vote status response not observed (may have completed before listener)')
  })
  await castVoteWithSignature(page, metamask)
  const WAIT = E3_DURATION - DKG_DURATION + OUTPUT_DECRYPTION_WAIT
  log(`waiting ${WAIT}ms...`)
  await page.waitForTimeout(WAIT)
  log(`clicking all polls button...`)
  await page.locator('a:has-text("All Polls")').click()
  log(`asserting that All polls page exists...`)
  await expect(page.locator('h1')).toHaveText('All polls')
  log(`asserting that result has 100% on the vote we clicked on...`)
  await expect(page.locator("[data-test-id='poll-0-0'] [data-test-id='poll-result-0'] .h2")).toHaveText('100%')
  log(`asserting that result has 0% on the vote we did not click on...`)
  await expect(page.locator("[data-test-id='poll-0-0'] [data-test-id='poll-result-1'] .h2")).toHaveText('0%')

  log('============================================')
  log('        PLAYWRIGHT TEST IS COMPLETE         ')
  log('============================================')
})
