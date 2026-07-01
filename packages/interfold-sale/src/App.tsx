// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { useCallback, useEffect, useMemo, useState } from 'react'
import { BrowserProvider, Contract, JsonRpcProvider, id, parseEther, parseUnits } from 'ethers'
import { AUCTION_ABI, BONDING_ABI, ERC20_ABI, FOLD_ABI } from './abis'
import { DEFAULT_PROFILE, PUBLIC_RPC, ROUTES, ZERO } from './constants'
import { useSaleDeployment } from './hooks/useSaleDeployment'
import { useWallet } from './hooks/useWallet'
import { ccaStatus, decodeAuctionSchedule, predicateHookData, readCurrencyState } from './lib/auction'
import { describeEvent } from './lib/events'
import { bytes32FromInput, currencyAddress, normalizeAddress, readableError, shortAddress } from './lib/format'
import { routeFromPath, routePath } from './lib/routes'
import { defer, readBidRecords, readProfiles, writeBidRecords, writeProfiles } from './lib/storage'
import { LoadingState, StatusPill, WalletButton } from './components/ui'
import { AdminRoute } from './routes/AdminRoute'
import { AuctionRoute } from './routes/AuctionRoute'
import type { BidRecord, EventLogLike, EventRow, LockEntry, OnchainState, Profile, RouteName, SaleDeployment, SubmittedTx } from './types'
import './App.css'

function makeReadProvider(deployment?: SaleDeployment) {
  if (!deployment) return undefined
  const rpc = PUBLIC_RPC[deployment.chainId]
  if (rpc) return new JsonRpcProvider(rpc)
  if (window.ethereum) return new BrowserProvider(window.ethereum)
  return undefined
}

export default function App() {
  const { deployment, error: manifestError } = useSaleDeployment()
  const { account, chainId, provider, walletError, connect, switchNetwork } = useWallet(deployment)
  const [route, setRoute] = useState<RouteName>(() => routeFromPath())
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
  const scheduleSteps = useMemo(() => decodeAuctionSchedule(auctionConfig?.auctionStepsData), [auctionConfig?.auctionStepsData])
  const readProvider = useMemo(() => makeReadProvider(deployment), [deployment])
  const isCorrectNetwork = Boolean(deployment && chainId === deployment.chainId)
  const status = ccaStatus(onchain?.blockNumber, auctionConfig)

  const navigate = useCallback((nextRoute: RouteName) => {
    const nextPath = routePath(nextRoute)
    window.history.pushState({}, '', nextPath)
    setRoute(nextRoute)
  }, [])

  useEffect(() => {
    const onPopState = () => setRoute(routeFromPath())
    window.addEventListener('popstate', onPopState)
    return () => window.removeEventListener('popstate', onPopState)
  }, [])

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
    const rawCurrency = auctionConfig?.currency ?? (await auction.currency().catch(() => 'ETH'))
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
      currencyState,
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
      account
        ? (fold.hasRole('0x0000000000000000000000000000000000000000000000000000000000000000', wallet) as Promise<boolean>)
        : Promise.resolve(false),
      account ? (fold.hasRole(id('MINTER_ROLE'), wallet) as Promise<boolean>) : Promise.resolve(false),
      account ? (fold.hasRole(id('LOCK_MANAGER_ROLE'), wallet) as Promise<boolean>) : Promise.resolve(false),
      account ? (fold.hasRole(id('WHITELIST_ROLE'), wallet) as Promise<boolean>) : Promise.resolve(false),
      readCurrencyState(readProvider, rawCurrency, account),
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
      currencyBalance: currencyState.balance,
      currencyDecimals: currencyState.decimals,
      currencySymbol: currencyState.symbol,
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
  }, [account, auctionConfig?.currency, deployment, readProvider])

  useEffect(() => {
    if (!deployment || !readProvider) return undefined
    defer(() => {
      void Promise.all([loadOnchain(), loadEvents()]).catch((error: unknown) => setNotice({ kind: 'bad', message: readableError(error) }))
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
      signer,
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
      const { auction, signer } = await signerContracts()
      const currency = currencyAddress(auctionConfig.currency)
      const decimals = onchain?.currencyDecimals ?? 18
      const amount = parseUnits(bidAmount, decimals)
      const rawPrice = maxPrice || defaultMaxPrice
      if (!rawPrice) throw new Error('Limit price is required')
      const price = BigInt(rawPrice)
      const hookData = await predicateHookData(deployment, account)
      if (currency !== ZERO) {
        const token = new Contract(currency, ERC20_ABI, signer)
        const allowance = (await token.allowance(account, deployment.auction)) as bigint
        if (allowance < amount) {
          const approveTx = await token.approve(deployment.auction, amount)
          await approveTx.wait()
        }
      }
      const tx = await auction['submitBid(uint256,uint128,address,bytes)'](price, amount, account, hookData, {
        value: currency === ZERO ? amount : 0n,
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
  }, [
    account,
    auctionConfig,
    bidAmount,
    bidStorageKey,
    bids,
    defaultMaxPrice,
    deployment,
    maxPrice,
    onchain?.currencyDecimals,
    runTx,
    signerContracts,
  ])

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
          <button className='wordmark' type='button' aria-label='Interfold CCA' onClick={() => navigate('auction')}>
            <span />
          </button>
          <span className='product-name'>CCA sale</span>
          <nav className='site-nav' aria-label='Sale views'>
            {ROUTES.map((item) => (
              <button
                key={item.route}
                type='button'
                className={route === item.route ? 'site-nav__link site-nav__link--on' : 'site-nav__link'}
                onClick={() => navigate(item.route)}
              >
                {item.label}
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
        {notice && <p className={notice.kind === 'bad' ? 'notice notice--bad' : 'notice'}>{notice.message}</p>}
        {walletError && <p className='notice notice--bad'>{walletError}</p>}

        {route === 'auction' && (
          <AuctionRoute
            deployment={deployment}
            onchain={onchain}
            auctionConfig={auctionConfig}
            status={status}
            scheduleSteps={scheduleSteps}
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
            onConnect={() => void connect()}
            onSwitchNetwork={() => void switchNetwork()}
            onSubmitBid={() => void submitBid()}
            onCheckpoint={() => void checkpoint()}
            onExit={() => void exitBid()}
            onClaim={() => void claimBid()}
            events={events}
            onRefreshEvents={() => void loadEvents()}
          />
        )}

        {route === 'admin' && (
          <AdminRoute
            deployment={deployment}
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
            events={events}
            onRefreshEvents={() => void loadEvents()}
          />
        )}
      </main>
    </div>
  )
}
