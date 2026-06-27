// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { useCallback, useEffect, useMemo, useState } from 'react'
import {
  BrowserProvider,
  Contract,
  JsonRpcProvider,
  decodeBytes32String,
  encodeBytes32String,
  formatEther,
  getAddress,
  id,
  isHexString,
  parseEther,
} from 'ethers'
import {
  Activity,
  ArrowUpRight,
  CheckCircle2,
  Clock3,
  Coins,
  ExternalLink,
  Gavel,
  KeyRound,
  Link2,
  LockKeyhole,
  RefreshCw,
  ShieldCheck,
  Timer,
  Wallet,
} from 'lucide-react'
import './App.css'

interface WalletProvider {
  request(args: { method: string; params?: unknown[] | Record<string, unknown> }): Promise<unknown>
  on?(event: 'accountsChanged' | 'chainChanged', listener: (...args: unknown[]) => void): void
  removeListener?(event: 'accountsChanged' | 'chainChanged', listener: (...args: unknown[]) => void): void
}

declare global {
  interface Window {
    ethereum?: WalletProvider
  }
}

interface AuctionConfig {
  currency: string
  tokensRecipient: string
  fundsRecipient: string
  startBlock: string
  endBlock: string
  claimBlock: string
  tickSpacing: string
  validationHook: string
  floorPrice: string
  requiredCurrencyRaised: string
  auctionStepsData: string
}

interface SaleDeployment {
  name: string
  chainId: number
  txHash: string
  blockNumber: number
  operator: string
  safe: string
  saleDeployer: string
  fold: string
  auction: string
  bondingRegistry: string
  bondingRegistryProxyAdmin?: string
  ccaFactory: string
  saleAmount: string
  saleLabel: string
  ccaVersion: string
  auctionConfig?: AuctionConfig
  testBidId?: string
  foldSchedule?: {
    ccaStart: string
    ccaEnd: string
    noMoreLocks: string
  }
  mockCcaFactory?: string
}

interface LockEntry {
  policyId: string
  amount: bigint
  queued: boolean
}

interface OnchainState {
  blockNumber: bigint
  blockTimestamp: bigint
  tokenSupply: bigint
  totalFoldSupply: bigint
  currencyRaised?: bigint
  isGraduated?: boolean
  tokensReceived?: boolean
  foldBalance: bigint
  lockedBalance: bigint
  transferableBalance: bigint
  totalBonded: bigint
  lockCount: bigint
  queuedLockCount: bigint
  locks: LockEntry[]
  owner?: string
  pendingOwner?: string
  tgeTimestamp?: bigint
  phase?: number
  roles: {
    admin: boolean
    minter: boolean
    lockManager: boolean
    whitelist: boolean
  }
}

interface BidRecord {
  id: string
  amount: string
  price: string
  txHash: string
}

interface Profile {
  id: string
  name: string
  account: string
  amount: string
  policyId: string
  label: string
}

interface EventRow {
  id: string
  source: 'FOLD' | 'CCA'
  title: string
  detail: string
  blockNumber: number
  txHash: string
}

interface EventLogLike {
  address?: string
  args?: EventArgs
  blockNumber: number | bigint
  fragment?: { name?: string }
  index?: number
  transactionHash: string
}

type EventArgs = Record<string, unknown>

interface SubmittedTx {
  hash: string
  wait(): Promise<unknown>
}

const ZERO = '0x0000000000000000000000000000000000000000'
const PENDING_POLICY = encodeBytes32String('PENDING')
const DEFAULT_PROFILE = {
  name: 'CCA tester',
  account: '',
  amount: '10',
  policyId: 'CCA_TEST',
  label: 'cca-test',
}

const AUCTION_ABI = [
  'function token() view returns (address)',
  'function totalSupply() view returns (uint128)',
  'function currency() view returns (address)',
  'function startBlock() view returns (uint64)',
  'function endBlock() view returns (uint64)',
  'function claimBlock() view returns (uint64)',
  'function tokensReceived() view returns (bool)',
  'function isGraduated() view returns (bool)',
  'function currencyRaised() view returns (uint256)',
  'function checkpoint() returns (tuple(uint256 clearingPrice,uint224 currencyRaisedAtClearingPriceQ96X7,uint256 cumulativeMpsPerPrice,uint24 cumulativeMps,uint64 prev,uint64 next))',
  'function bids(uint256 bidId) view returns (tuple(uint64 startBlock,uint24 startCumulativeMps,uint64 exitedBlock,uint256 maxPrice,address owner,uint256 amountQ96,uint256 tokensFilled))',
  'function submitBid(uint256 maxPrice,uint128 amount,address owner,bytes hookData) payable returns (uint256 bidId)',
  'function exitBid(uint256 bidId)',
  'function exitPartiallyFilledBid(uint256 bidId,uint64 lastFullyFilledCheckpointBlock,uint64 outbidBlock)',
  'function claimTokens(uint256 bidId)',
  'event BidSubmitted(uint256 indexed id,address indexed owner,uint256 price,uint256 amount)',
  'function bid() payable',
  'function claim() returns (uint256)',
]

const FOLD_ABI = [
  'function balanceOf(address account) view returns (uint256)',
  'function totalSupply() view returns (uint256)',
  'function lockCount(address account) view returns (uint256)',
  'function queuedLockCount(address account) view returns (uint256)',
  'function locks(address account,uint256 index) view returns (bytes32 policyId,uint256 amount)',
  'function queuedLocks(address account,uint256 index) view returns (bytes32 policyId,uint256 amount)',
  'function lockedBalanceOf(address account) view returns (uint256)',
  'function transferableBalanceOf(address account) view returns (uint256)',
  'function owner() view returns (address)',
  'function pendingOwner() view returns (address)',
  'function tgeTimestamp() view returns (uint64)',
  'function phase() view returns (uint8)',
  'function hasRole(bytes32 role,address account) view returns (bool)',
  'function createLockPolicy(bytes32 policyId,tuple(uint64 holdUntil,tuple(uint8 anchor,uint64 start,uint64 cliffDuration,uint64 vestDuration) unlock) policy)',
  'function linkClaim(address account,uint256 amount,bytes32 policyId)',
  'function mintAllocations(tuple(address recipient,uint256 amount,bytes32 policyId,bytes32 label)[] allocations)',
  'function setTransferWhitelisted(address account,bool whitelisted)',
  'function setClaimLockExempt(address account,bool exempt)',
  'function acceptOwnership()',
  'function tge()',
  'event AllocationMinted(address indexed recipient,uint256 amount,bytes32 indexed policyId,bytes32 indexed label)',
  'event PolicyDefined(bytes32 indexed policyId,tuple(uint64 holdUntil,tuple(uint8 anchor,uint64 start,uint64 cliffDuration,uint64 vestDuration) unlock) policy)',
  'event TransferWhitelistUpdated(address indexed account,bool whitelisted)',
  'event ClaimLockExemptUpdated(address indexed account,bool exempt)',
  'event ActiveLockUpdated(address indexed account,bytes32 indexed policyId,uint256 amount)',
  'event QueuedLockUpdated(address indexed account,bytes32 indexed policyId,uint256 amount)',
  'event ActiveLockRelinked(address indexed account,bytes32 indexed fromPolicyId,bytes32 indexed toPolicyId,uint256 amount)',
  'event TgeTriggered(uint64 timestamp)',
]

const BONDING_ABI = ['function totalBonded(address account) view returns (uint256)']

const PUBLIC_RPC: Record<number, string> = {
  1: 'https://ethereum-rpc.publicnode.com',
  11155111: 'https://ethereum-sepolia-rpc.publicnode.com',
}

const TOKEN_PHASES = ['Virtual', 'CCA', 'Cooldown', 'Live']
const VIEW_TABS = ['Overview', 'Auction', 'Token Lab', 'Events', 'Contracts'] as const

function shortAddress(value?: string): string {
  if (!value) return '-'
  return `${value.slice(0, 6)}...${value.slice(-4)}`
}

function explorerBase(chainId: number): string | undefined {
  if (chainId === 1) return 'https://etherscan.io'
  if (chainId === 11155111) return 'https://sepolia.etherscan.io'
  if (chainId === 8453) return 'https://basescan.org'
  if (chainId === 84532) return 'https://sepolia.basescan.org'
  return undefined
}

function explorerLink(chainId: number, type: 'address' | 'tx', value: string): string | undefined {
  const base = explorerBase(chainId)
  return base ? `${base}/${type}/${value}` : undefined
}

function formatTokenAmount(value?: bigint, digits = 4): string {
  if (value === undefined) return '-'
  const raw = formatEther(value)
  const [head, tail = ''] = raw.split('.')
  const trimmed = tail.slice(0, digits).replace(/0+$/, '')
  return trimmed ? `${head}.${trimmed}` : head
}

function formatDate(seconds?: string | bigint): string {
  if (seconds === undefined || seconds === '') return '-'
  const date = new Date(Number(seconds) * 1000)
  return Number.isNaN(date.getTime()) ? '-' : date.toLocaleString()
}

function normalizeAddress(value: string): string {
  return getAddress(value.trim())
}

function bytes32FromInput(value: string): string {
  const trimmed = value.trim()
  if (isHexString(trimmed, 32)) return trimmed
  return encodeBytes32String(trimmed)
}

function bytes32Label(value: string): string {
  try {
    const decoded = decodeBytes32String(value)
    return decoded || value
  } catch {
    return value
  }
}

function readableError(error: unknown): string {
  if (!(error instanceof Error)) return 'Transaction failed'
  const short = error.message.split('\n')[0]
  return short.length > 220 ? `${short.slice(0, 220)}...` : short
}

function defer(task: () => void): void {
  window.setTimeout(task, 0)
}

function ccaStatus(current: bigint | undefined, config?: AuctionConfig): string {
  if (!current || !config) return 'Loading'
  const start = BigInt(config.startBlock)
  const end = BigInt(config.endBlock)
  const claim = BigInt(config.claimBlock)
  if (current < start) return 'Scheduled'
  if (current <= end) return 'Live'
  if (current < claim) return 'Settling'
  return 'Claim Open'
}

function readBidRecords(key: string): BidRecord[] {
  try {
    const raw = localStorage.getItem(key)
    return raw ? (JSON.parse(raw) as BidRecord[]) : []
  } catch {
    return []
  }
}

function writeBidRecords(key: string, bids: BidRecord[]): void {
  localStorage.setItem(key, JSON.stringify(bids))
}

function readProfiles(key: string): Profile[] {
  try {
    const raw = localStorage.getItem(key)
    return raw ? (JSON.parse(raw) as Profile[]) : []
  } catch {
    return []
  }
}

function writeProfiles(key: string, profiles: Profile[]): void {
  localStorage.setItem(key, JSON.stringify(profiles))
}

async function fetchJson<T>(url: string): Promise<T> {
  const response = await fetch(url, { cache: 'no-store' })
  if (!response.ok) throw new Error(`${url} returned ${response.status}`)
  return (await response.json()) as T
}

function makeReadProvider(deployment?: SaleDeployment) {
  if (!deployment) return undefined
  const rpc = PUBLIC_RPC[deployment.chainId]
  if (rpc) return new JsonRpcProvider(rpc)
  if (window.ethereum) return new BrowserProvider(window.ethereum)
  return undefined
}

function useSaleDeployment() {
  const [deployment, setDeployment] = useState<SaleDeployment>()
  const [error, setError] = useState<string>()

  useEffect(() => {
    let alive = true
    fetchJson<SaleDeployment>('/sale/deployment.json')
      .then((value) => {
        if (!alive) return
        setDeployment(value)
        setError(undefined)
      })
      .catch((err: unknown) => {
        if (!alive) return
        setError(readableError(err))
      })
    return () => {
      alive = false
    }
  }, [])

  return { deployment, error }
}

function useWallet(deployment?: SaleDeployment) {
  const [account, setAccount] = useState<string>()
  const [chainId, setChainId] = useState<number>()
  const [provider, setProvider] = useState<BrowserProvider>()
  const [error, setError] = useState<string>()

  const refresh = useCallback(async () => {
    if (!window.ethereum) return
    const browserProvider = new BrowserProvider(window.ethereum)
    const [accounts, network] = await Promise.all([
      window.ethereum.request({ method: 'eth_accounts' }) as Promise<string[]>,
      browserProvider.getNetwork(),
    ])
    setProvider(browserProvider)
    setAccount(accounts[0] ? getAddress(accounts[0]) : undefined)
    setChainId(Number(network.chainId))
  }, [])

  useEffect(() => {
    defer(() => {
      void refresh()
    })
    if (!window.ethereum) return undefined
    const handleChange = () => {
      void refresh()
    }
    window.ethereum.on?.('accountsChanged', handleChange)
    window.ethereum.on?.('chainChanged', handleChange)
    return () => {
      window.ethereum?.removeListener?.('accountsChanged', handleChange)
      window.ethereum?.removeListener?.('chainChanged', handleChange)
    }
  }, [refresh])

  const connect = useCallback(async () => {
    if (!window.ethereum) {
      setError('Wallet not found')
      return
    }
    await window.ethereum.request({ method: 'eth_requestAccounts' })
    await refresh()
  }, [refresh])

  const switchNetwork = useCallback(async () => {
    if (!window.ethereum || !deployment) return
    await window.ethereum.request({
      method: 'wallet_switchEthereumChain',
      params: [{ chainId: `0x${deployment.chainId.toString(16)}` }],
    })
    await refresh()
  }, [deployment, refresh])

  return { account, chainId, provider, walletError: error, connect, switchNetwork }
}

export default function App() {
  const { deployment, error: manifestError } = useSaleDeployment()
  const { account, chainId, provider, walletError, connect, switchNetwork } = useWallet(deployment)
  const [view, setView] = useState<(typeof VIEW_TABS)[number]>('Overview')
  const [onchain, setOnchain] = useState<OnchainState>()
  const [events, setEvents] = useState<EventRow[]>([])
  const [bidAmount, setBidAmount] = useState('0.01')
  const [maxPrice, setMaxPrice] = useState('')
  const [selectedBidId, setSelectedBidId] = useState('')
  const [bids, setBids] = useState<BidRecord[]>([])
  const [profiles, setProfiles] = useState<Profile[]>([])
  const [profile, setProfile] = useState<Profile>({ ...DEFAULT_PROFILE, id: 'draft' })
  const [policy, setPolicy] = useState({
    policyId: 'CCA_TEST',
    holdUntil: '0',
    anchor: '1',
    start: '0',
    cliffDuration: '0',
    vestDuration: '3456000',
  })
  const [whitelistValue, setWhitelistValue] = useState(false)
  const [exemptValue, setExemptValue] = useState(false)
  const [busy, setBusy] = useState<string>()
  const [notice, setNotice] = useState<{ kind: 'ok' | 'bad'; message: string }>()

  const auctionConfig = deployment?.auctionConfig
  const readProvider = useMemo(() => makeReadProvider(deployment), [deployment])
  const isCorrectNetwork = Boolean(deployment && chainId === deployment.chainId)
  const status = ccaStatus(onchain?.blockNumber, auctionConfig)

  const defaultMaxPrice = useMemo(() => {
    if (!auctionConfig) return ''
    return (BigInt(auctionConfig.floorPrice) + BigInt(auctionConfig.tickSpacing)).toString()
  }, [auctionConfig])

  const bidStorageKey = useMemo(() => {
    if (!deployment || !account) return ''
    return `interfold:bids:${deployment.chainId}:${deployment.auction}:${account}`
  }, [account, deployment])

  const profileStorageKey = useMemo(() => {
    if (!deployment) return ''
    return `interfold:profiles:${deployment.chainId}:${deployment.fold}`
  }, [deployment])

  useEffect(() => {
    if (!maxPrice && defaultMaxPrice) {
      defer(() => setMaxPrice(defaultMaxPrice))
    }
  }, [defaultMaxPrice, maxPrice])

  useEffect(() => {
    defer(() => setBids(bidStorageKey ? readBidRecords(bidStorageKey) : []))
  }, [bidStorageKey])

  useEffect(() => {
    defer(() => {
      const saved = profileStorageKey ? readProfiles(profileStorageKey) : []
      setProfiles(saved)
      if (saved[0]) setProfile(saved[0])
    })
  }, [profileStorageKey])

  useEffect(() => {
    if (deployment?.testBidId && !selectedBidId) {
      defer(() => setSelectedBidId(deployment.testBidId ?? ''))
    }
  }, [deployment?.testBidId, selectedBidId])

  useEffect(() => {
    if (account && !profile.account) {
      defer(() => setProfile((current) => ({ ...current, account })))
    }
  }, [account, profile.account])

  const loadEvents = useCallback(async () => {
    if (!deployment || !readProvider) return
    const latest = await readProvider.getBlockNumber()
    const fromBlock = Math.max(deployment.blockNumber, latest - 100_000)
    const fold = new Contract(deployment.fold, FOLD_ABI, readProvider)
    const auction = new Contract(deployment.auction, AUCTION_ABI, readProvider)
    const foldEventNames = [
      'AllocationMinted',
      'PolicyDefined',
      'TransferWhitelistUpdated',
      'ClaimLockExemptUpdated',
      'ActiveLockUpdated',
      'QueuedLockUpdated',
      'ActiveLockRelinked',
      'TgeTriggered',
    ]
    const logs = (
      await Promise.all([
        ...foldEventNames.map((name) => fold.queryFilter(name, fromBlock, latest).catch(() => [])),
        auction.queryFilter('BidSubmitted', fromBlock, latest).catch(() => []),
      ])
    ).flat()

    const rows = logs
      .map((log: EventLogLike): EventRow => {
        const name = log.fragment?.name ?? 'Event'
        const source = log.address?.toLowerCase() === deployment.fold.toLowerCase() ? 'FOLD' : 'CCA'
        return {
          id: `${log.transactionHash}:${log.index}`,
          source,
          title: name,
          detail: describeEvent(name, log.args),
          blockNumber: Number(log.blockNumber),
          txHash: log.transactionHash,
        }
      })
      .sort((a, b) => b.blockNumber - a.blockNumber)
      .slice(0, 80)
    setEvents(rows)
  }, [deployment, readProvider])

  const loadOnchain = useCallback(async () => {
    if (!deployment || !readProvider) return
    const auction = new Contract(deployment.auction, AUCTION_ABI, readProvider)
    const fold = new Contract(deployment.fold, FOLD_ABI, readProvider)
    const bonding = new Contract(deployment.bondingRegistry, BONDING_ABI, readProvider)
    const blockNumber = BigInt(await readProvider.getBlockNumber())
    const latestBlock = await readProvider.getBlock('latest')
    const wallet = account ?? ZERO
    const [
      tokenSupply,
      totalFoldSupply,
      tokensReceived,
      currencyRaised,
      isGraduated,
      foldBalance,
      lockedBalance,
      transferableBalance,
      totalBonded,
      lockCount,
      queuedLockCount,
      owner,
      pendingOwner,
      tgeTimestamp,
      phase,
      admin,
      minter,
      lockManager,
      whitelist,
    ] = await Promise.all([
      auction.totalSupply() as Promise<bigint>,
      fold.totalSupply() as Promise<bigint>,
      auction.tokensReceived().catch(() => undefined) as Promise<boolean | undefined>,
      auction.currencyRaised().catch(() => undefined) as Promise<bigint | undefined>,
      auction.isGraduated().catch(() => undefined) as Promise<boolean | undefined>,
      account ? (fold.balanceOf(account) as Promise<bigint>) : Promise.resolve(0n),
      account ? (fold.lockedBalanceOf(account) as Promise<bigint>) : Promise.resolve(0n),
      account ? (fold.transferableBalanceOf(account) as Promise<bigint>) : Promise.resolve(0n),
      account ? (bonding.totalBonded(account) as Promise<bigint>) : Promise.resolve(0n),
      account ? (fold.lockCount(account) as Promise<bigint>) : Promise.resolve(0n),
      account ? (fold.queuedLockCount(account) as Promise<bigint>) : Promise.resolve(0n),
      fold.owner().catch(() => undefined) as Promise<string | undefined>,
      fold.pendingOwner().catch(() => undefined) as Promise<string | undefined>,
      fold.tgeTimestamp().catch(() => undefined) as Promise<bigint | undefined>,
      fold.phase().catch(() => undefined) as Promise<number | undefined>,
      account ? (fold.hasRole('0x0000000000000000000000000000000000000000000000000000000000000000', wallet) as Promise<boolean>) : Promise.resolve(false),
      account ? (fold.hasRole(id('MINTER_ROLE'), wallet) as Promise<boolean>) : Promise.resolve(false),
      account ? (fold.hasRole(id('LOCK_MANAGER_ROLE'), wallet) as Promise<boolean>) : Promise.resolve(false),
      account ? (fold.hasRole(id('WHITELIST_ROLE'), wallet) as Promise<boolean>) : Promise.resolve(false),
    ])

    const locks: LockEntry[] = []
    for (let index = 0n; index < lockCount && index < 8n; index++) {
      const entry = await fold.locks(wallet, index)
      locks.push({ policyId: String(entry.policyId), amount: BigInt(entry.amount), queued: false })
    }
    for (let index = 0n; index < queuedLockCount && index < 8n; index++) {
      const entry = await fold.queuedLocks(wallet, index)
      locks.push({ policyId: String(entry.policyId), amount: BigInt(entry.amount), queued: true })
    }

    setOnchain({
      blockNumber,
      blockTimestamp: BigInt(latestBlock?.timestamp ?? 0),
      tokenSupply,
      totalFoldSupply,
      currencyRaised,
      isGraduated,
      tokensReceived,
      foldBalance,
      lockedBalance,
      transferableBalance,
      totalBonded,
      lockCount,
      queuedLockCount,
      locks,
      owner,
      pendingOwner,
      tgeTimestamp,
      phase,
      roles: { admin, minter, lockManager, whitelist },
    })
  }, [account, deployment, readProvider])

  useEffect(() => {
    if (!deployment || !readProvider) return undefined
    defer(() => {
      void Promise.all([loadOnchain(), loadEvents()]).catch((error: unknown) =>
        setNotice({ kind: 'bad', message: readableError(error) }),
      )
    })
    const interval = window.setInterval(() => {
      void loadOnchain().catch(() => undefined)
      void loadEvents().catch(() => undefined)
    }, 12_000)
    return () => window.clearInterval(interval)
  }, [deployment, loadEvents, loadOnchain, readProvider])

  const signerContracts = useCallback(async () => {
    if (!provider || !deployment) throw new Error('Connect wallet first')
    if (!isCorrectNetwork) throw new Error('Switch wallet network first')
    const signer = await provider.getSigner()
    return {
      auction: new Contract(deployment.auction, AUCTION_ABI, signer),
      fold: new Contract(deployment.fold, FOLD_ABI, signer),
    }
  }, [deployment, isCorrectNetwork, provider])

  const runTx = useCallback(
    async (label: string, task: () => Promise<SubmittedTx>) => {
      setBusy(label)
      setNotice(undefined)
      try {
        const tx = await task()
        await tx.wait()
        setNotice({ kind: 'ok', message: `${label}: ${shortAddress(tx.hash)}` })
        await Promise.all([loadOnchain(), loadEvents()])
      } catch (error) {
        setNotice({ kind: 'bad', message: readableError(error) })
      } finally {
        setBusy(undefined)
      }
    },
    [loadEvents, loadOnchain],
  )

  const submitBid = useCallback(async () => {
    if (!deployment || !account || !auctionConfig) return
    await runTx('Bid submitted', async () => {
      const { auction } = await signerContracts()
      const amount = parseEther(bidAmount)
      const price = BigInt(maxPrice || defaultMaxPrice)
      const isEth = auctionConfig.currency.toUpperCase() === 'ETH' || auctionConfig.currency === ZERO
      const tx = await auction['submitBid(uint256,uint128,address,bytes)'](price, amount, account, '0x', {
        value: isEth ? amount : 0n,
      })
      const receipt = await tx.wait()
      const event = receipt.logs
        .map((log: { topics: readonly string[]; data: string }) => {
          try {
            return auction.interface.parseLog(log)
          } catch {
            return null
          }
        })
        .find((parsed: { name?: string } | null) => parsed?.name === 'BidSubmitted')
      const bidId = String(event?.args?.id ?? '')
      if (bidId) {
        const next = [{ id: bidId, amount: bidAmount, price: price.toString(), txHash: tx.hash }, ...bids]
        if (bidStorageKey) writeBidRecords(bidStorageKey, next)
        setBids(next)
        setSelectedBidId(bidId)
      }
      return { wait: async () => receipt, hash: tx.hash }
    })
  }, [account, auctionConfig, bidAmount, bidStorageKey, bids, defaultMaxPrice, deployment, maxPrice, runTx, signerContracts])

  const checkpoint = useCallback(async () => {
    await runTx('Checkpoint', async () => {
      const { auction } = await signerContracts()
      return auction.checkpoint()
    })
  }, [runTx, signerContracts])

  const exitBid = useCallback(async () => {
    if (!selectedBidId) return
    await runTx('Exit', async () => {
      const { auction } = await signerContracts()
      try {
        return await auction.exitBid(BigInt(selectedBidId))
      } catch {
        const bid = await auction.bids(BigInt(selectedBidId))
        return auction.exitPartiallyFilledBid(BigInt(selectedBidId), bid.startBlock, 0)
      }
    })
  }, [runTx, selectedBidId, signerContracts])

  const claimBid = useCallback(async () => {
    if (!selectedBidId) return
    await runTx('Claim', async () => {
      const { auction } = await signerContracts()
      return auction.claimTokens(BigInt(selectedBidId))
    })
  }, [runTx, selectedBidId, signerContracts])

  const saveProfile = useCallback(() => {
    if (!profileStorageKey) return
    const idValue = profile.id === 'draft' ? `${Date.now()}` : profile.id
    const nextProfile = { ...profile, id: idValue }
    const next = [nextProfile, ...profiles.filter((item) => item.id !== idValue)]
    setProfiles(next)
    setProfile(nextProfile)
    writeProfiles(profileStorageKey, next)
  }, [profile, profileStorageKey, profiles])

  const selectProfile = useCallback((next: Profile) => {
    setProfile(next)
    setPolicy((current) => ({ ...current, policyId: next.policyId }))
  }, [])

  const createLockPolicy = useCallback(async () => {
    await runTx('Policy', async () => {
      const { fold } = await signerContracts()
      return fold.createLockPolicy(bytes32FromInput(policy.policyId), {
        holdUntil: BigInt(policy.holdUntil || '0'),
        unlock: {
          anchor: Number(policy.anchor),
          start: BigInt(policy.start || '0'),
          cliffDuration: BigInt(policy.cliffDuration || '0'),
          vestDuration: BigInt(policy.vestDuration || '0'),
        },
      })
    })
  }, [policy, runTx, signerContracts])

  const mintAllocation = useCallback(async () => {
    await runTx('Mint allocation', async () => {
      const { fold } = await signerContracts()
      return fold.mintAllocations([
        {
          recipient: normalizeAddress(profile.account),
          amount: parseEther(profile.amount),
          policyId: bytes32FromInput(profile.policyId),
          label: bytes32FromInput(profile.label),
        },
      ])
    })
  }, [profile, runTx, signerContracts])

  const linkClaim = useCallback(async () => {
    await runTx('Link claim', async () => {
      const { fold } = await signerContracts()
      return fold.linkClaim(normalizeAddress(profile.account), parseEther(profile.amount), bytes32FromInput(profile.policyId))
    })
  }, [profile, runTx, signerContracts])

  const setWhitelisted = useCallback(async () => {
    await runTx('Whitelist', async () => {
      const { fold } = await signerContracts()
      return fold.setTransferWhitelisted(normalizeAddress(profile.account), whitelistValue)
    })
  }, [profile.account, runTx, signerContracts, whitelistValue])

  const setClaimExempt = useCallback(async () => {
    await runTx('Claim exemption', async () => {
      const { fold } = await signerContracts()
      return fold.setClaimLockExempt(normalizeAddress(profile.account), exemptValue)
    })
  }, [exemptValue, profile.account, runTx, signerContracts])

  const acceptOwnership = useCallback(async () => {
    await runTx('Accept ownership', async () => {
      const { fold } = await signerContracts()
      return fold.acceptOwnership()
    })
  }, [runTx, signerContracts])

  const triggerTge = useCallback(async () => {
    await runTx('TGE', async () => {
      const { fold } = await signerContracts()
      return fold.tge()
    })
  }, [runTx, signerContracts])

  if (manifestError) {
    return <LoadingState title='No sale manifest' detail={manifestError} />
  }

  if (!deployment) {
    return <LoadingState title='Loading Interfold CCA' detail='Reading /sale/deployment.json' />
  }

  return (
    <div className='page'>
      <header className='site-head'>
        <div className='site-head__inner'>
          <button className='wordmark' type='button' aria-label='Interfold CCA' onClick={() => setView('Overview')}>
            <span />
          </button>
          <span className='product-name'>CCA sale</span>
          <nav className='site-nav' aria-label='Sale views'>
            {VIEW_TABS.map((tab) => (
              <button
                key={tab}
                type='button'
                className={view === tab ? 'site-nav__link site-nav__link--on' : 'site-nav__link'}
                onClick={() => setView(tab)}
              >
                {tab}
              </button>
            ))}
          </nav>
          <div className='head-actions'>
            <StatusPill status={status} />
            <WalletButton
              account={account}
              chainId={chainId}
              targetChainId={deployment.chainId}
              onConnect={connect}
              onSwitch={switchNetwork}
            />
          </div>
        </div>
      </header>

      <main className='app-main'>
        <section className='view-intro'>
          <div>
            <p className='eyebrow'>
              <Gavel size={14} />
              FOLD continuous clearing auction
            </p>
            <h1>{deployment.name}</h1>
            <p>{networkLabel(deployment.chainId)} · {deployment.ccaVersion} · {deployment.saleLabel}</p>
          </div>
          <div className='identity-card'>
            <span>Foundation Safe</span>
            <strong className='mono'>{shortAddress(deployment.safe)}</strong>
            <span>{onchain?.owner?.toLowerCase() === deployment.safe.toLowerCase() ? 'Accepted owner' : 'Ownership pending or not accepted'}</span>
          </div>
        </section>

        <section className='metrics-grid'>
          <Metric label='Sale Supply' value={formatTokenAmount(BigInt(deployment.saleAmount))} note='FOLD in CCA' />
          <Metric label='Raised' value={formatTokenAmount(onchain?.currencyRaised)} note={auctionConfig?.currency ?? 'ETH'} />
          <Metric label='Wallet FOLD' value={formatTokenAmount(onchain?.foldBalance)} note={`${onchain?.lockCount ?? 0n} active locks`} />
          <Metric label='Token Phase' value={TOKEN_PHASES[onchain?.phase ?? 0] ?? '-'} note='timestamp clock' />
          <Metric label='Current Block' value={onchain?.blockNumber?.toString() ?? '-'} note='CCA block clock' />
        </section>

        {notice && <p className={notice.kind === 'bad' ? 'notice notice--bad' : 'notice'}>{notice.message}</p>}
        {walletError && <p className='notice notice--bad'>{walletError}</p>}

        {view === 'Overview' && (
          <OverviewView
            deployment={deployment}
            onchain={onchain}
            auctionConfig={auctionConfig}
            onRefresh={() => void Promise.all([loadOnchain(), loadEvents()])}
          />
        )}

        {view === 'Auction' && (
          <AuctionView
            deployment={deployment}
            auctionConfig={auctionConfig}
            status={status}
            bidAmount={bidAmount}
            setBidAmount={setBidAmount}
            maxPrice={maxPrice}
            setMaxPrice={setMaxPrice}
            selectedBidId={selectedBidId}
            setSelectedBidId={setSelectedBidId}
            bids={bids}
            busy={busy}
            account={account}
            isCorrectNetwork={isCorrectNetwork}
            onSubmitBid={() => void submitBid()}
            onCheckpoint={() => void checkpoint()}
            onExit={() => void exitBid()}
            onClaim={() => void claimBid()}
          />
        )}

        {view === 'Token Lab' && (
          <TokenLabView
            onchain={onchain}
            account={account}
            profile={profile}
            setProfile={setProfile}
            profiles={profiles}
            saveProfile={saveProfile}
            selectProfile={selectProfile}
            policy={policy}
            setPolicy={setPolicy}
            whitelistValue={whitelistValue}
            setWhitelistValue={setWhitelistValue}
            exemptValue={exemptValue}
            setExemptValue={setExemptValue}
            busy={busy}
            onCreatePolicy={() => void createLockPolicy()}
            onMintAllocation={() => void mintAllocation()}
            onLinkClaim={() => void linkClaim()}
            onWhitelist={() => void setWhitelisted()}
            onClaimExempt={() => void setClaimExempt()}
            onAcceptOwnership={() => void acceptOwnership()}
            onTge={() => void triggerTge()}
          />
        )}

        {view === 'Events' && <EventsView deployment={deployment} events={events} onRefresh={() => void loadEvents()} />}

        {view === 'Contracts' && <ContractsView deployment={deployment} onchain={onchain} />}
      </main>
    </div>
  )
}

function OverviewView({
  deployment,
  onchain,
  auctionConfig,
  onRefresh,
}: {
  deployment: SaleDeployment
  onchain?: OnchainState
  auctionConfig?: AuctionConfig
  onRefresh(): void
}) {
  return (
    <div className='view-stack'>
      <section className='mode-grid'>
        <div className='panel'>
          <div className='panel__head'>
            <div>
              <p className='section-kicker'>
                <Clock3 size={14} />
                FOLD token timestamps
              </p>
              <h2>{TOKEN_PHASES[onchain?.phase ?? 0] ?? '-'}</h2>
            </div>
            <button className='icon-button' type='button' onClick={onRefresh} title='Refresh'>
              <RefreshCw size={16} />
            </button>
          </div>
          <FlowRail
            steps={[
              { label: 'Virtual', value: `until ${formatDate(deployment.foldSchedule?.ccaStart)}` },
              { label: 'CCA', value: `${formatDate(deployment.foldSchedule?.ccaStart)} - ${formatDate(deployment.foldSchedule?.ccaEnd)}` },
              { label: 'Cooldown', value: '40 days after token CCA_END' },
              { label: 'Live', value: onchain?.tgeTimestamp ? formatDate(onchain.tgeTimestamp) : 'TGE not triggered' },
            ]}
            activeIndex={onchain?.phase ?? 0}
          />
          <dl className='data-list data-list--wide'>
            <DataItem label='Current timestamp' value={onchain?.blockTimestamp ? `${onchain.blockTimestamp} · ${formatDate(onchain.blockTimestamp)}` : '-'} />
            <DataItem label='No more locks' value={formatDate(deployment.foldSchedule?.noMoreLocks)} />
          </dl>
        </div>

        <div className='panel'>
          <div className='panel__head'>
            <div>
              <p className='section-kicker'>
                <Timer size={14} />
                CCA auction blocks
              </p>
              <h2>{ccaStatus(onchain?.blockNumber, auctionConfig)}</h2>
            </div>
          </div>
          <FlowRail
            steps={[
              { label: 'Scheduled', value: `before #${auctionConfig?.startBlock ?? '-'}` },
              { label: 'Live', value: `#${auctionConfig?.startBlock ?? '-'} - #${auctionConfig?.endBlock ?? '-'}` },
              { label: 'Settling', value: `until #${auctionConfig?.claimBlock ?? '-'}` },
              { label: 'Claim', value: `from #${auctionConfig?.claimBlock ?? '-'}` },
            ]}
            activeIndex={ccaStatusIndex(onchain?.blockNumber, auctionConfig)}
          />
          <dl className='data-list data-list--wide'>
            <DataItem label='Current block' value={onchain?.blockNumber?.toString() ?? '-'} />
            <DataItem label='Auction steps data' value={auctionConfig?.auctionStepsData ?? '-'} />
          </dl>
        </div>
      </section>

      <section className='overview-grid'>
        <div className='panel'>
          <div className='panel__head'>
            <div>
              <p className='section-kicker'>
                <LockKeyhole size={14} />
                Wallet FOLD
              </p>
              <h2>Balance and locks</h2>
            </div>
          </div>
          <div className='balance-grid'>
            <MiniStat label='Balance' value={formatTokenAmount(onchain?.foldBalance)} />
            <MiniStat label='Locked' value={formatTokenAmount(onchain?.lockedBalance)} />
            <MiniStat label='Transferable' value={formatTokenAmount(onchain?.transferableBalance)} />
            <MiniStat label='Bonded' value={formatTokenAmount(onchain?.totalBonded)} />
          </div>
          <LockList locks={onchain?.locks ?? []} />
        </div>

        <div className='panel'>
          <div className='panel__head'>
            <div>
              <p className='section-kicker'>
                <ShieldCheck size={14} />
                Control surface
              </p>
              <h2>Safe ownership</h2>
            </div>
          </div>
          <dl className='data-list data-list--wide'>
            <DataItem label='FOLD owner' value={shortAddress(onchain?.owner)} />
            <DataItem label='Pending owner' value={shortAddress(onchain?.pendingOwner)} />
            <DataItem label='Sale deployer' value={shortAddress(deployment.saleDeployer)} />
            <DataItem label='Operator' value={shortAddress(deployment.operator)} />
          </dl>
        </div>
      </section>
    </div>
  )
}

function AuctionView({
  deployment,
  auctionConfig,
  status,
  bidAmount,
  setBidAmount,
  maxPrice,
  setMaxPrice,
  selectedBidId,
  setSelectedBidId,
  bids,
  busy,
  account,
  isCorrectNetwork,
  onSubmitBid,
  onCheckpoint,
  onExit,
  onClaim,
}: {
  deployment: SaleDeployment
  auctionConfig?: AuctionConfig
  status: string
  bidAmount: string
  setBidAmount(value: string): void
  maxPrice: string
  setMaxPrice(value: string): void
  selectedBidId: string
  setSelectedBidId(value: string): void
  bids: BidRecord[]
  busy?: string
  account?: string
  isCorrectNetwork: boolean
  onSubmitBid(): void
  onCheckpoint(): void
  onExit(): void
  onClaim(): void
}) {
  return (
    <section className='workspace-grid'>
      <div className='panel'>
        <div className='panel__head'>
          <div>
            <p className='section-kicker'>
              <Coins size={14} />
              Auction order
            </p>
            <h2>{status}</h2>
          </div>
        </div>
        <div className='form-grid'>
          <Field label='Bid amount' value={bidAmount} setValue={setBidAmount} inputMode='decimal' suffix={auctionConfig?.currency ?? 'ETH'} />
          <Field label='Max price' value={maxPrice} setValue={setMaxPrice} inputMode='numeric' />
        </div>
        <button className='primary-button' type='button' disabled={!account || !isCorrectNetwork || Boolean(busy)} onClick={onSubmitBid}>
          <Coins size={16} />
          Submit bid
        </button>

        <div className='divider' />
        <div className='claim-row'>
          <Field label='Bid ID' value={selectedBidId} setValue={setSelectedBidId} inputMode='numeric' />
          <button type='button' disabled={!selectedBidId || Boolean(busy)} onClick={onCheckpoint}>
            <Activity size={15} />
            Checkpoint
          </button>
          <button type='button' disabled={!selectedBidId || Boolean(busy)} onClick={onExit}>
            <ArrowUpRight size={15} />
            Exit
          </button>
          <button type='button' disabled={!selectedBidId || Boolean(busy)} onClick={onClaim}>
            <CheckCircle2 size={15} />
            Claim
          </button>
        </div>
        <BidList bids={bids} selectedBidId={selectedBidId} setSelectedBidId={setSelectedBidId} chainId={deployment.chainId} />
      </div>

      <div className='panel'>
        <div className='panel__head'>
          <div>
            <p className='section-kicker'>
              <Timer size={14} />
              CCA parameters
            </p>
            <h2>Block schedule</h2>
          </div>
        </div>
        <dl className='data-list data-list--wide'>
          <DataItem label='Start block' value={auctionConfig?.startBlock ?? '-'} />
          <DataItem label='End block' value={auctionConfig?.endBlock ?? '-'} />
          <DataItem label='Claim block' value={auctionConfig?.claimBlock ?? '-'} />
          <DataItem label='Floor price' value={auctionConfig?.floorPrice ?? '-'} />
          <DataItem label='Tick spacing' value={auctionConfig?.tickSpacing ?? '-'} />
          <DataItem label='Currency' value={auctionConfig?.currency ?? '-'} />
        </dl>
      </div>
    </section>
  )
}

function TokenLabView({
  onchain,
  account,
  profile,
  setProfile,
  profiles,
  saveProfile,
  selectProfile,
  policy,
  setPolicy,
  whitelistValue,
  setWhitelistValue,
  exemptValue,
  setExemptValue,
  busy,
  onCreatePolicy,
  onMintAllocation,
  onLinkClaim,
  onWhitelist,
  onClaimExempt,
  onAcceptOwnership,
  onTge,
}: {
  onchain?: OnchainState
  account?: string
  profile: Profile
  setProfile(value: Profile | ((current: Profile) => Profile)): void
  profiles: Profile[]
  saveProfile(): void
  selectProfile(profile: Profile): void
  policy: Record<string, string>
  setPolicy(value: Record<string, string> | ((current: Record<string, string>) => Record<string, string>)): void
  whitelistValue: boolean
  setWhitelistValue(value: boolean): void
  exemptValue: boolean
  setExemptValue(value: boolean): void
  busy?: string
  onCreatePolicy(): void
  onMintAllocation(): void
  onLinkClaim(): void
  onWhitelist(): void
  onClaimExempt(): void
  onAcceptOwnership(): void
  onTge(): void
}) {
  return (
    <div className='view-stack'>
      <section className='role-strip'>
        <RolePill label='Connected' active={Boolean(account)} />
        <RolePill label='Admin' active={Boolean(onchain?.roles.admin)} />
        <RolePill label='Minter' active={Boolean(onchain?.roles.minter)} />
        <RolePill label='Lock manager' active={Boolean(onchain?.roles.lockManager)} />
        <RolePill label='Whitelist' active={Boolean(onchain?.roles.whitelist)} />
      </section>

      <section className='workspace-grid workspace-grid--wide'>
        <div className='panel'>
          <div className='panel__head'>
            <div>
              <p className='section-kicker'>
                <KeyRound size={14} />
                Profiles
              </p>
              <h2>Claims and allocations</h2>
            </div>
            <button type='button' onClick={saveProfile}>
              <CheckCircle2 size={15} />
              Save
            </button>
          </div>
          <div className='form-grid form-grid--three'>
            <Field label='Name' value={profile.name} setValue={(value) => setProfile((current) => ({ ...current, name: value }))} />
            <Field label='Account' value={profile.account} setValue={(value) => setProfile((current) => ({ ...current, account: value }))} />
            <Field label='Amount' value={profile.amount} setValue={(value) => setProfile((current) => ({ ...current, amount: value }))} inputMode='decimal' suffix='FOLD' />
            <Field label='Policy ID' value={profile.policyId} setValue={(value) => setProfile((current) => ({ ...current, policyId: value }))} />
            <Field label='Label' value={profile.label} setValue={(value) => setProfile((current) => ({ ...current, label: value }))} />
          </div>
          <div className='button-grid'>
            <button type='button' disabled={Boolean(busy)} onClick={onLinkClaim}>
              <Link2 size={15} />
              Link claim
            </button>
            <button type='button' disabled={Boolean(busy)} onClick={onMintAllocation}>
              <Coins size={15} />
              Mint allocation
            </button>
          </div>
          {profiles.length > 0 && (
            <div className='profile-list'>
              {profiles.map((item) => (
                <button key={item.id} type='button' className='profile-row' onClick={() => selectProfile(item)}>
                  <span>{item.name}</span>
                  <span className='mono'>{shortAddress(item.account)}</span>
                  <span>{item.amount} FOLD</span>
                </button>
              ))}
            </div>
          )}
        </div>

        <div className='panel'>
          <div className='panel__head'>
            <div>
              <p className='section-kicker'>
                <LockKeyhole size={14} />
                Vesting policy
              </p>
              <h2>Write-once lock</h2>
            </div>
          </div>
          <div className='form-grid form-grid--three'>
            <Field label='Policy ID' value={policy.policyId} setValue={(value) => setPolicy((current) => ({ ...current, policyId: value }))} />
            <Field label='Hold until' value={policy.holdUntil} setValue={(value) => setPolicy((current) => ({ ...current, holdUntil: value }))} inputMode='numeric' />
            <label>
              <span>Anchor</span>
              <select value={policy.anchor} onChange={(event) => setPolicy((current) => ({ ...current, anchor: event.target.value }))}>
                <option value='1'>TGE</option>
                <option value='0'>Absolute</option>
              </select>
            </label>
            <Field label='Absolute start' value={policy.start} setValue={(value) => setPolicy((current) => ({ ...current, start: value }))} inputMode='numeric' />
            <Field label='Cliff seconds' value={policy.cliffDuration} setValue={(value) => setPolicy((current) => ({ ...current, cliffDuration: value }))} inputMode='numeric' />
            <Field label='Vest seconds' value={policy.vestDuration} setValue={(value) => setPolicy((current) => ({ ...current, vestDuration: value }))} inputMode='numeric' />
          </div>
          <button className='primary-button' type='button' disabled={Boolean(busy)} onClick={onCreatePolicy}>
            <LockKeyhole size={16} />
            Create policy
          </button>
        </div>
      </section>

      <section className='workspace-grid workspace-grid--wide'>
        <div className='panel'>
          <div className='panel__head'>
            <div>
              <p className='section-kicker'>
                <ShieldCheck size={14} />
                Transfer controls
              </p>
              <h2>Whitelist and exemptions</h2>
            </div>
          </div>
          <div className='toggle-grid'>
            <label className='toggle-row'>
              <input type='checkbox' checked={whitelistValue} onChange={(event) => setWhitelistValue(event.target.checked)} />
              <span>Transfer whitelisted</span>
            </label>
            <button type='button' disabled={Boolean(busy)} onClick={onWhitelist}>
              <ShieldCheck size={15} />
              Set whitelist
            </button>
            <label className='toggle-row'>
              <input type='checkbox' checked={exemptValue} onChange={(event) => setExemptValue(event.target.checked)} />
              <span>Claim-lock exempt</span>
            </label>
            <button type='button' disabled={Boolean(busy)} onClick={onClaimExempt}>
              <ShieldCheck size={15} />
              Set exemption
            </button>
          </div>
        </div>

        <div className='panel'>
          <div className='panel__head'>
            <div>
              <p className='section-kicker'>
                <Activity size={14} />
                Launch actions
              </p>
              <h2>Ownership and TGE</h2>
            </div>
          </div>
          <div className='button-grid'>
            <button type='button' disabled={Boolean(busy)} onClick={onAcceptOwnership}>
              <CheckCircle2 size={15} />
              Accept ownership
            </button>
            <button type='button' disabled={Boolean(busy)} onClick={onTge}>
              <Activity size={15} />
              Trigger TGE
            </button>
          </div>
        </div>
      </section>
    </div>
  )
}

function EventsView({ deployment, events, onRefresh }: { deployment: SaleDeployment; events: EventRow[]; onRefresh(): void }) {
  return (
    <section className='panel'>
      <div className='panel__head'>
        <div>
          <p className='section-kicker'>
            <Activity size={14} />
            Event stream
          </p>
          <h2>FOLD and CCA activity</h2>
        </div>
        <button type='button' onClick={onRefresh}>
          <RefreshCw size={15} />
          Refresh
        </button>
      </div>
      <div className='event-list'>
        {events.length === 0 && <p className='muted'>No indexed events in the recent range.</p>}
        {events.map((event) => (
          <a
            key={event.id}
            className='event-row'
            href={explorerLink(deployment.chainId, 'tx', event.txHash)}
            target='_blank'
            rel='noreferrer'
          >
            <span className={`source-badge source-badge--${event.source.toLowerCase()}`}>{event.source}</span>
            <span>
              <strong>{event.title}</strong>
              <small>{event.detail}</small>
            </span>
            <span className='mono'>#{event.blockNumber}</span>
          </a>
        ))}
      </div>
    </section>
  )
}

function ContractsView({ deployment, onchain }: { deployment: SaleDeployment; onchain?: OnchainState }) {
  return (
    <section className='workspace-grid'>
      <div className='panel'>
        <div className='panel__head'>
          <div>
            <p className='section-kicker'>
              <ExternalLink size={14} />
              Contracts
            </p>
            <h2>Deployment addresses</h2>
          </div>
        </div>
        <AddressRow label='FOLD' chainId={deployment.chainId} value={deployment.fold} />
        <AddressRow label='CCA auction' chainId={deployment.chainId} value={deployment.auction} />
        <AddressRow label='Foundation Safe' chainId={deployment.chainId} value={deployment.safe} />
        <AddressRow label='Sale deployer' chainId={deployment.chainId} value={deployment.saleDeployer} />
        <AddressRow label='Bonding registry' chainId={deployment.chainId} value={deployment.bondingRegistry} />
        {deployment.bondingRegistryProxyAdmin && <AddressRow label='ProxyAdmin' chainId={deployment.chainId} value={deployment.bondingRegistryProxyAdmin} />}
        <AddressRow label='CCA factory' chainId={deployment.chainId} value={deployment.ccaFactory} />
        <AddressRow label='Deploy tx' chainId={deployment.chainId} value={deployment.txHash} tx />
      </div>
      <div className='panel'>
        <div className='panel__head'>
          <div>
            <p className='section-kicker'>
              <ShieldCheck size={14} />
              Ownership
            </p>
            <h2>Who controls what</h2>
          </div>
        </div>
        <dl className='data-list data-list--wide'>
          <DataItem label='Deployer wallet' value={`${shortAddress(deployment.operator)} · gas only`} />
          <DataItem label='FOLD owner' value={shortAddress(onchain?.owner)} />
          <DataItem label='Pending FOLD owner' value={shortAddress(onchain?.pendingOwner)} />
          <DataItem label='ProxyAdmin owner' value={shortAddress(deployment.safe)} />
          <DataItem label='Unsold tokens' value={shortAddress(deployment.auctionConfig?.tokensRecipient)} />
          <DataItem label='Funds recipient' value={shortAddress(deployment.auctionConfig?.fundsRecipient)} />
        </dl>
      </div>
    </section>
  )
}

function eventValue(args: EventArgs, key: string): unknown {
  return args[key]
}

function describeEvent(name: string, args?: EventArgs): string {
  if (!args) return ''
  if (name === 'BidSubmitted') {
    return `bid #${String(eventValue(args, 'id') ?? '-')} by ${shortAddress(String(eventValue(args, 'owner') ?? ''))} for ${formatTokenAmount(BigInt(String(eventValue(args, 'amount') ?? '0')))}`
  }
  if (name === 'AllocationMinted') {
    return `${formatTokenAmount(BigInt(String(eventValue(args, 'amount') ?? '0')))} to ${shortAddress(String(eventValue(args, 'recipient') ?? ''))} · ${bytes32Label(String(eventValue(args, 'policyId') ?? ''))}`
  }
  if (name === 'PolicyDefined') return bytes32Label(String(eventValue(args, 'policyId') ?? ''))
  if (name === 'ActiveLockUpdated' || name === 'QueuedLockUpdated') {
    return `${shortAddress(String(eventValue(args, 'account') ?? ''))} · ${bytes32Label(String(eventValue(args, 'policyId') ?? ''))} · ${formatTokenAmount(BigInt(String(eventValue(args, 'amount') ?? '0')))}`
  }
  if (name === 'TransferWhitelistUpdated') return `${shortAddress(String(eventValue(args, 'account') ?? ''))} · ${String(eventValue(args, 'whitelisted') ?? '-')}`
  if (name === 'ClaimLockExemptUpdated') return `${shortAddress(String(eventValue(args, 'account') ?? ''))} · ${String(eventValue(args, 'exempt') ?? '-')}`
  if (name === 'TgeTriggered') return formatDate(BigInt(String(eventValue(args, 'timestamp') ?? '0')))
  return Object.values(args)
    .filter((value) => typeof value !== 'function')
    .slice(0, 3)
    .map(String)
    .join(' · ')
}

function LoadingState({ title, detail }: { title: string; detail: string }) {
  return (
    <main className='loading-page'>
      <span className='loader-ring' />
      <h1>{title}</h1>
      <p>{detail}</p>
    </main>
  )
}

function StatusPill({ status }: { status: string }) {
  const waiting = status === 'Scheduled' || status === 'Settling' || status === 'Loading'
  return (
    <span className={waiting ? 'status-pill status-pill--waiting' : 'status-pill'}>
      <span />
      {status}
    </span>
  )
}

function WalletButton({
  account,
  chainId,
  targetChainId,
  onConnect,
  onSwitch,
}: {
  account?: string
  chainId?: number
  targetChainId: number
  onConnect(): Promise<void>
  onSwitch(): Promise<void>
}) {
  if (!account) {
    return (
      <button type='button' className='wallet-button' onClick={() => void onConnect()}>
        <Wallet size={15} />
        Connect
      </button>
    )
  }
  if (chainId !== targetChainId) {
    return (
      <button type='button' className='wallet-button' onClick={() => void onSwitch()}>
        <Wallet size={15} />
        Switch
      </button>
    )
  }
  return <span className='wallet-chip'>{shortAddress(account)}</span>
}

function Metric({ label, value, note }: { label: string; value: string; note: string }) {
  return (
    <div className='metric'>
      <span className='metric__label'>{label}</span>
      <strong className='metric__value'>{value}</strong>
      <span className='metric__note'>{note}</span>
    </div>
  )
}

function MiniStat({ label, value }: { label: string; value: string }) {
  return (
    <div className='mini-stat'>
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  )
}

function FlowRail({ steps, activeIndex }: { steps: Array<{ label: string; value: string }>; activeIndex: number }) {
  return (
    <div className='flow-rail'>
      {steps.map((step, index) => (
        <div key={step.label} className={index === activeIndex ? 'flow-step flow-step--active' : index < activeIndex ? 'flow-step flow-step--done' : 'flow-step'}>
          <span />
          <strong>{step.label}</strong>
          <small>{step.value}</small>
        </div>
      ))}
    </div>
  )
}

function ccaStatusIndex(current: bigint | undefined, config?: AuctionConfig): number {
  if (!current || !config) return 0
  if (current < BigInt(config.startBlock)) return 0
  if (current <= BigInt(config.endBlock)) return 1
  if (current < BigInt(config.claimBlock)) return 2
  return 3
}

function LockList({ locks }: { locks: LockEntry[] }) {
  if (locks.length === 0) return <p className='muted'>No lock entries for the connected wallet.</p>
  return (
    <div className='lock-list'>
      {locks.map((entry, index) => (
        <div className='lock-row' key={`${entry.policyId}:${index}`}>
          <span>{entry.queued ? 'Queued' : 'Active'}</span>
          <strong>{bytes32Label(entry.policyId) || (entry.policyId === PENDING_POLICY ? 'PENDING' : entry.policyId)}</strong>
          <span>{formatTokenAmount(entry.amount)} FOLD</span>
        </div>
      ))}
    </div>
  )
}

function BidList({
  bids,
  selectedBidId,
  setSelectedBidId,
  chainId,
}: {
  bids: BidRecord[]
  selectedBidId: string
  setSelectedBidId(value: string): void
  chainId: number
}) {
  if (bids.length === 0) return null
  return (
    <div className='bid-list'>
      {bids.map((bid) => (
        <button
          key={`${bid.id}:${bid.txHash}`}
          type='button'
          className={selectedBidId === bid.id ? 'bid-row bid-row--selected' : 'bid-row'}
          onClick={() => setSelectedBidId(bid.id)}
        >
          <span>#{bid.id}</span>
          <span>{bid.amount}</span>
          <a href={explorerLink(chainId, 'tx', bid.txHash)} target='_blank' rel='noreferrer' onClick={(event) => event.stopPropagation()}>
            {shortAddress(bid.txHash)}
          </a>
        </button>
      ))}
    </div>
  )
}

function Field({
  label,
  value,
  setValue,
  inputMode,
  suffix,
}: {
  label: string
  value: string
  setValue(value: string): void
  inputMode?: 'decimal' | 'numeric' | 'text'
  suffix?: string
}) {
  return (
    <label>
      <span>{label}</span>
      <div className='field-shell'>
        <input value={value} inputMode={inputMode} onChange={(event) => setValue(event.target.value)} />
        {suffix && <small>{suffix}</small>}
      </div>
    </label>
  )
}

function RolePill({ label, active }: { label: string; active: boolean }) {
  return <span className={active ? 'role-pill role-pill--on' : 'role-pill'}>{label}</span>
}

function AddressRow({ label, value, chainId, tx }: { label: string; value: string; chainId: number; tx?: boolean }) {
  const href = explorerLink(chainId, tx ? 'tx' : 'address', value)
  return (
    <div className='address-row'>
      <span>{label}</span>
      {href ? (
        <a href={href} target='_blank' rel='noreferrer' className='mono'>
          {shortAddress(value)}
          <ExternalLink size={12} />
        </a>
      ) : (
        <code>{shortAddress(value)}</code>
      )}
    </div>
  )
}

function DataItem({ label, value }: { label: string; value: string }) {
  return (
    <>
      <dt>{label}</dt>
      <dd>{value}</dd>
    </>
  )
}

function networkLabel(chainId: number): string {
  if (chainId === 1) return 'Ethereum mainnet'
  if (chainId === 11155111) return 'Sepolia'
  return `Chain ${chainId}`
}
