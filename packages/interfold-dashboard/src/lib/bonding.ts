// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
// Bonding-registry reads and writes behind the ciphernode operator guide.
//
// Only the BondingRegistry address is configured. Every other address (ciphernode bond
// token, ticket wrapper, ticket underlying) is read back from the registry, so
// the guide follows the deployment instead of a hardcoded token list.

import { erc20Abi, isAddress, type Address, type WalletClient } from 'viem'
import { useCallback, useEffect, useRef, useState } from 'react'
import { CONTRACTS, bondingRegistryAbi, publicClient, ticketTokenAbi } from './chain'

const POLL_MS = 12_000

export const ZERO_ADDRESS = '0x0000000000000000000000000000000000000000' as Address

const registry = { address: CONTRACTS.BondingRegistry, abi: bondingRegistryAbi } as const

export type BondingConfig = {
  ciphernodeBondToken: Address
  ciphernodeBondSymbol: string
  ciphernodeBondDecimals: number
  /** ERC-20 wrapper that mints non-transferable tickets. Spender for the ticket purchase. */
  ticketToken: Address
  /** Asset actually paid for tickets (the wrapper's underlying). */
  ticketBase: Address
  ticketSymbol: string
  ticketDecimals: number
  /** Ciphernode bond required before an operator can register. */
  requiredCiphernodeBond: bigint
  /** Price of one ticket, in ticket-underlying units. */
  ticketPrice: bigint
  /** Tickets an operator must hold to become active. */
  minTicketBalance: bigint
  /** Seconds collateral stays queued after an unbond or deregistration. */
  exitDelay: bigint
}

export type OperatorStatus = {
  bondOwner: Address | null
  pendingBondOwner: Address | null
  ciphernodeBond: bigint
  ticketBalance: bigint
  availableTickets: bigint
  bonded: boolean
  registered: boolean
  active: boolean
  /**
   * Eligible for new committees at the latest block (`eligibilityAt`). Unlike `active`, this also
   * applies the admission cooldown and the admission policy. `null` when the read fails.
   */
  eligible: boolean | null
  exitInProgress: boolean
}

export type AccountFunds = {
  /** Ciphernode bond-token (FOLD) balance of the connected wallet. */
  ciphernodeBondBalance: bigint
  /** Ciphernode bond-token allowance granted to the bonding registry. */
  ciphernodeBondAllowance: bigint
  /** Ticket-underlying balance of the connected wallet. */
  ticketBaseBalance: bigint
  /** Ticket-underlying allowance granted to the ticket wrapper. */
  ticketBaseAllowance: bigint
}

export async function fetchBondingConfig(): Promise<BondingConfig> {
  const [ciphernodeBondToken, ticketToken, requiredCiphernodeBond, ticketPrice, minTicketBalance, exitDelay] = await Promise.all([
    (publicClient.readContract as any)({ ...registry, functionName: 'getCiphernodeBondToken' }) as Promise<Address>,
    (publicClient.readContract as any)({ ...registry, functionName: 'getTicketToken' }) as Promise<Address>,
    (publicClient.readContract as any)({ ...registry, functionName: 'requiredCiphernodeBond' }) as Promise<bigint>,
    (publicClient.readContract as any)({ ...registry, functionName: 'ticketPrice' }) as Promise<bigint>,
    (publicClient.readContract as any)({ ...registry, functionName: 'minTicketBalance' }) as Promise<bigint>,
    (publicClient.readContract as any)({ ...registry, functionName: 'exitDelay' }) as Promise<bigint>,
  ])

  const ticketBase = (await (publicClient.readContract as any)({
    address: ticketToken,
    abi: ticketTokenAbi,
    functionName: 'underlying',
  })) as Address

  const [ciphernodeBondSymbol, ciphernodeBondDecimals, ticketSymbol, ticketDecimals] = await Promise.all([
    tokenSymbol(ciphernodeBondToken, 'FOLD'),
    tokenDecimals(ciphernodeBondToken, 18),
    tokenSymbol(ticketBase, 'USDC'),
    tokenDecimals(ticketBase, 6),
  ])

  return {
    ciphernodeBondToken,
    ciphernodeBondSymbol,
    ciphernodeBondDecimals,
    ticketToken,
    ticketBase,
    ticketSymbol,
    ticketDecimals,
    requiredCiphernodeBond,
    ticketPrice,
    minTicketBalance,
    exitDelay: BigInt(exitDelay),
  }
}

// Symbol/decimals are cosmetic — a token that omits them must not break the guide.
async function tokenSymbol(token: Address, fallback: string): Promise<string> {
  try {
    return (await (publicClient.readContract as any)({ address: token, abi: erc20Abi, functionName: 'symbol' })) as string
  } catch {
    return fallback
  }
}

async function tokenDecimals(token: Address, fallback: number): Promise<number> {
  try {
    return Number(await (publicClient.readContract as any)({ address: token, abi: erc20Abi, functionName: 'decimals' }))
  } catch {
    return fallback
  }
}

// Never rejects: a failed read makes only the eligibility unknown, not the whole status.
async function fetchEligibility(operator: Address): Promise<boolean | null> {
  try {
    const block = await publicClient.getBlock()
    const [eligible] = (await (publicClient.readContract as any)({
      ...registry,
      functionName: 'eligibilityAt',
      args: [operator, block.timestamp],
    })) as [boolean, bigint]
    return eligible
  } catch {
    return null
  }
}

export async function fetchOperatorStatus(operator: Address): Promise<OperatorStatus> {
  const eligibility = fetchEligibility(operator)
  const [bondOwner, pendingBondOwner, ciphernodeBond, ticketBalance, availableTickets, bonded, registered, active, exitInProgress] =
    await Promise.all([
      (publicClient.readContract as any)({ ...registry, functionName: 'bondOwnerOf', args: [operator] }) as Promise<Address>,
      (publicClient.readContract as any)({ ...registry, functionName: 'pendingBondOwnerOf', args: [operator] }) as Promise<Address>,
      (publicClient.readContract as any)({ ...registry, functionName: 'getCiphernodeBond', args: [operator] }) as Promise<bigint>,
      (publicClient.readContract as any)({ ...registry, functionName: 'getTicketBalance', args: [operator] }) as Promise<bigint>,
      (publicClient.readContract as any)({ ...registry, functionName: 'availableTickets', args: [operator] }) as Promise<bigint>,
      (publicClient.readContract as any)({ ...registry, functionName: 'isCiphernodeBonded', args: [operator] }) as Promise<boolean>,
      (publicClient.readContract as any)({ ...registry, functionName: 'isRegistered', args: [operator] }) as Promise<boolean>,
      (publicClient.readContract as any)({ ...registry, functionName: 'isActive', args: [operator] }) as Promise<boolean>,
      (publicClient.readContract as any)({ ...registry, functionName: 'hasExitInProgress', args: [operator] }) as Promise<boolean>,
    ])

  return {
    bondOwner: bondOwner === ZERO_ADDRESS ? null : bondOwner,
    pendingBondOwner: pendingBondOwner === ZERO_ADDRESS ? null : pendingBondOwner,
    ciphernodeBond,
    ticketBalance,
    availableTickets,
    bonded,
    registered,
    active,
    eligible: await eligibility,
    exitInProgress,
  }
}

export async function fetchAccountFunds(account: Address, config: BondingConfig): Promise<AccountFunds> {
  const [ciphernodeBondBalance, ciphernodeBondAllowance, ticketBaseBalance, ticketBaseAllowance] = await Promise.all([
    (publicClient.readContract as any)({ address: config.ciphernodeBondToken, abi: erc20Abi, functionName: 'balanceOf', args: [account] }),
    (publicClient.readContract as any)({
      address: config.ciphernodeBondToken,
      abi: erc20Abi,
      functionName: 'allowance',
      args: [account, CONTRACTS.BondingRegistry],
    }),
    (publicClient.readContract as any)({ address: config.ticketBase, abi: erc20Abi, functionName: 'balanceOf', args: [account] }),
    (publicClient.readContract as any)({
      address: config.ticketBase,
      abi: erc20Abi,
      functionName: 'allowance',
      args: [account, config.ticketToken],
    }),
  ])
  return {
    ciphernodeBondBalance: ciphernodeBondBalance as bigint,
    ciphernodeBondAllowance: ciphernodeBondAllowance as bigint,
    ticketBaseBalance: ticketBaseBalance as bigint,
    ticketBaseAllowance: ticketBaseAllowance as bigint,
  }
}

export type BondingState = {
  config: BondingConfig | null
  status: OperatorStatus | null
  funds: AccountFunds | null
  loading: boolean
  error: Error | null
  /** Re-read everything immediately (call after a confirmed transaction). */
  refresh: () => void
}

/**
 * Poll the bonding registry for one operator key and one funding wallet.
 * `operator` and `account` are independent: the guide supports a hot operator
 * key whose collateral is controlled by a separate bond-owner wallet.
 */
export function useBonding(operator: string | null, account: Address | null): BondingState {
  const [config, setConfig] = useState<BondingConfig | null>(null)
  const [status, setStatus] = useState<OperatorStatus | null>(null)
  const [funds, setFunds] = useState<AccountFunds | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<Error | null>(null)
  const [nonce, setNonce] = useState(0)
  const configRef = useRef<BondingConfig | null>(null)

  const refresh = useCallback(() => setNonce((n) => n + 1), [])

  const validOperator = operator && isAddress(operator) ? (operator as Address) : null

  // Per-identity reads must not outlive the identity they belong to. The fetch
  // effect below only refills `status`/`funds` once the network answers, so
  // without this the panel keeps rendering the previous operator or account for
  // a full round trip. Clearing during render (not in an effect) drops the stale
  // values before the browser paints them. `config` is deployment-wide, so it
  // survives the switch and does not flash.
  const identity = `${validOperator ?? ''}|${account ?? ''}`
  const [loadedIdentity, setLoadedIdentity] = useState(identity)
  if (identity !== loadedIdentity) {
    setLoadedIdentity(identity)
    setStatus(null)
    setFunds(null)
    setError(null)
    setLoading(true)
  }

  useEffect(() => {
    let cancelled = false
    let inFlight = false

    const tick = async () => {
      if (inFlight) return
      inFlight = true
      try {
        const cfg = configRef.current ?? (await fetchBondingConfig())
        if (cancelled) return
        configRef.current = cfg
        setConfig(cfg)

        const [nextStatus, nextFunds] = await Promise.all([
          validOperator ? fetchOperatorStatus(validOperator) : Promise.resolve(null),
          account ? fetchAccountFunds(account, cfg) : Promise.resolve(null),
        ])
        if (cancelled) return
        setStatus(nextStatus)
        setFunds(nextFunds)
        setError(null)
      } catch (e: any) {
        if (!cancelled) setError(e)
      } finally {
        inFlight = false
        if (!cancelled) setLoading(false)
      }
    }

    void tick()
    const id = setInterval(tick, POLL_MS)
    return () => {
      cancelled = true
      clearInterval(id)
    }
  }, [validOperator, account, nonce])

  return { config, status, funds, loading, error, refresh }
}

/**
 * Simulate then send a contract write. Simulating first surfaces the registry's
 * typed revert (for example `NotBondOwner`) before the wallet prompt, instead of
 * letting the user sign a transaction that cannot succeed.
 */
export async function simulateAndWrite(
  client: WalletClient,
  account: Address,
  call: { address: Address; abi: readonly unknown[]; functionName: string; args: readonly unknown[] },
): Promise<`0x${string}`> {
  const { request } = await publicClient.simulateContract({
    account,
    address: call.address,
    abi: call.abi as any,
    functionName: call.functionName,
    args: call.args as any,
  })
  return client.writeContract(request as any)
}
