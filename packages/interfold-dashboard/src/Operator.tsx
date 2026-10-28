// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
// Ciphernode operator guide — an interactive walkthrough of the on-chain steps
// that take a ciphernode from "nothing" to "active in sortition":
// connect a wallet, authorize a bond owner, bond the ciphernode bond, register the node,
// then buy tickets.
//
// The operator key and the bond owner are separate addresses on purpose. The
// operator key is the hot key the node runs with; the bond owner is the wallet
// that funds and controls the collateral. They may be the same wallet, and the
// guide supports either arrangement.

import { useEffect, useMemo, useRef, useState, type ReactNode } from 'react'
import { erc20Abi, formatUnits, isAddress, parseUnits, type Address, type Hash } from 'viem'
import Loader from './Loader'
import {
  CHAIN,
  CONTRACTS,
  FEE_TOKEN,
  IS_TESTNET,
  NETWORK_NAME,
  bondingRegistryAbi,
  e3RefundManagerAbi,
  faucetAbi,
  interfoldAbi,
  ownerIdentityRegistryAbi,
} from './lib/chain'
import {
  PREVIEW_SERVICE,
  boundChainName,
  buildProofBundle,
  capacityWindowEnd,
  credentialEnd,
  dateInput,
  fetchIdentityPolicy,
  fetchOwnerAccount,
  fetchVerifierConfig,
  fmtDay,
  identityStatusText,
  outerEvmProof,
  parseDateInput,
  registrationDeadline,
  safeRegistrationBatch,
  type IdentityPolicy,
  type OwnerAccount,
  type ProofBundle,
  type VerifierConfig,
} from './lib/identity'
import { LINKS, explorerAddress, explorerTx } from './lib/links'
import { compactE3Id } from './lib/pollMeta'
import {
  CLAIM_STATES,
  claimPlan,
  fetchCommitteeSeats,
  fetchSeatStatuses,
  seatStageLabel,
  summarizeRewards,
  type CommitteeSeat,
  type SeatStatus,
} from './lib/rewards'
import { ZERO_ADDRESS, simulateAndWrite, useBonding, type BondingConfig, type OperatorStatus } from './lib/bonding'
import { confirmTx, useWallet, walletErrorMessage } from './lib/wallet'

const FAUCET_ENABLED = IS_TESTNET && CONTRACTS.Faucet !== ZERO_ADDRESS && CONTRACTS.Faucet.trim() !== ''

const shortAddr = (a: string): string => (a.length > 14 ? `${a.slice(0, 8)}…${a.slice(-6)}` : a)

const sameAddress = (a?: string | null, b?: string | null): boolean => Boolean(a && b && a.toLowerCase() === b.toLowerCase())

// Token amounts are shown at human scale; ticket counts are plain integers.
function fmtToken(value: bigint, decimals: number, symbol?: string): string {
  const asNumber = Number(formatUnits(value, decimals))
  const text = asNumber.toLocaleString(undefined, {
    maximumFractionDigits: asNumber >= 1000 ? 0 : 4,
  })
  return symbol ? `${text} ${symbol}` : text
}

function AddrLink({ address }: { address: string }) {
  return (
    <a className='hash' href={explorerAddress(address)} target='_blank' rel='noreferrer' title={address}>
      <span className='mono'>{shortAddr(address)}</span>
      <span className='hash__icon' aria-hidden='true'>
        ↗
      </span>
    </a>
  )
}

type StepState = 'done' | 'active' | 'todo'

function StepCard({
  num,
  title,
  lede,
  state,
  children,
}: {
  num: number
  title: string
  lede: string
  state: StepState
  children: ReactNode
}) {
  return (
    <section className={`opstep opstep--${state}`} aria-current={state === 'active' ? 'step' : undefined}>
      <div className='opstep__rail'>
        <span className='opstep__num'>{state === 'done' ? '✓' : num}</span>
      </div>
      <div className='opstep__body'>
        <header className='opstep__head'>
          <h3 className='opstep__title'>{title}</h3>
          <span className={`opstep__badge opstep__badge--${state}`}>
            {state === 'done' ? 'Complete' : state === 'active' ? 'Next' : 'Pending'}
          </span>
        </header>
        <p className='opstep__lede'>{lede}</p>
        <div className='opstep__content'>{children}</div>
      </div>
    </section>
  )
}

function Field({
  label,
  hint,
  value,
  onChange,
  placeholder,
  invalid,
  suffix,
}: {
  label: string
  hint?: ReactNode
  value: string
  onChange: (v: string) => void
  placeholder?: string
  invalid?: boolean
  suffix?: ReactNode
}) {
  return (
    <label className='opfield'>
      <span className='opfield__label'>{label}</span>
      <span className='opfield__control'>
        <input
          className={`opfield__input mono ${invalid ? 'opfield__input--bad' : ''}`}
          value={value}
          placeholder={placeholder}
          spellCheck={false}
          onChange={(e) => onChange(e.target.value)}
        />
        {suffix}
      </span>
      {hint && <span className='opfield__hint'>{hint}</span>}
    </label>
  )
}

function Note({ kind = 'info', children }: { kind?: 'info' | 'warn'; children: ReactNode }) {
  return (
    <div className={`opnote opnote--${kind}`}>
      <span className='opnote__dot' aria-hidden='true' />
      <span>{children}</span>
    </div>
  )
}

export default function Operator() {
  const wallet = useWallet()

  const [operatorInput, setOperatorInput] = useState('')
  const [bondOwnerInput, setBondOwnerInput] = useState('')
  const [bondAmountInput, setBondAmountInput] = useState('')
  const [ticketCountInput, setTicketCountInput] = useState('')

  // Default both address fields to the connected wallet — the single-wallet
  // setup is the common case, and either field can still be edited.
  useEffect(() => {
    if (!wallet.address) return
    setOperatorInput((v) => (v.trim() === '' ? wallet.address! : v))
    setBondOwnerInput((v) => (v.trim() === '' ? wallet.address! : v))
  }, [wallet.address])

  const operatorValid = isAddress(operatorInput.trim())
  const operator = operatorValid ? (operatorInput.trim() as Address) : null
  const bondOwnerValid = isAddress(bondOwnerInput.trim())

  const { config, status, funds, loading, error: readError, refresh } = useBonding(operator, wallet.address)

  // One in-flight write at a time, keyed so each button shows its own spinner.
  const [busy, setBusy] = useState<string | null>(null)
  const [txError, setTxError] = useState<{ key: string; message: string } | null>(null)
  const [lastTx, setLastTx] = useState<Hash | null>(null)

  const run = async (key: string, send: () => Promise<Hash>) => {
    setBusy(key)
    setTxError(null)
    try {
      const hash = await send()
      setLastTx(hash)
      await confirmTx(hash)
      refresh()
    } catch (e) {
      setTxError({ key, message: walletErrorMessage(e) })
    } finally {
      setBusy(null)
    }
  }

  const write = (call: { address: Address; abi: readonly unknown[]; functionName: string; args: readonly unknown[] }) => {
    if (!wallet.client || !wallet.address) throw new Error('Wallet not connected.')
    return simulateAndWrite(wallet.client, wallet.address, call)
  }

  // ─── Derived step completion ────────────────────────────────────────────
  const connected = Boolean(wallet.address) && wallet.onCorrectChain
  const bondOwnerSet = Boolean(status?.bondOwner)
  const isBondOwner = sameAddress(wallet.address, status?.bondOwner)
  const isOperatorWallet = sameAddress(wallet.address, operator)
  // Registration readiness must compare against the full `requiredCiphernodeBond`.
  // `status.bonded` is the registry's `isCiphernodeBonded()`, which only tests the
  // active-maintenance floor (`requiredCiphernodeBond * ciphernodeBondActiveBps`, 80% by
  // default). An operator between that floor and the full bond reads as
  // bonded, but `registerOperatorFor` still reverts with `NotCiphernodeBonded`.
  const bonded = Boolean(config && status && status.ciphernodeBond >= config.requiredCiphernodeBond)
  const registered = Boolean(status?.registered)
  const ticketed = Boolean(config && status && status.availableTickets >= config.minTicketBalance)

  // The identity panel follows the bond owner, not the connected wallet: `useBonding` clears the
  // status while a new wallet's reads load, and the panel must keep a finished proof meanwhile.
  const [ownerOf, setOwnerOf] = useState<{ operator: Address; owner: Address } | null>(null)
  if (operator && status?.bondOwner && (ownerOf?.operator !== operator || !sameAddress(ownerOf.owner, status.bondOwner))) {
    setOwnerOf({ operator, owner: status.bondOwner })
  }
  const identityOwner = operator && ownerOf?.operator === operator ? ownerOf.owner : null

  const stepDone = [connected, bondOwnerSet, bonded, registered, ticketed]
  const activeStep = stepDone.findIndex((d) => !d)
  const stateOf = (i: number): StepState => (stepDone[i] ? 'done' : i === activeStep ? 'active' : 'todo')

  // ─── Step 3 amounts ─────────────────────────────────────────────────────
  const shortfall = config && status ? bigMax(config.requiredCiphernodeBond - status.ciphernodeBond, 0n) : 0n
  useEffect(() => {
    if (!config) return
    setBondAmountInput((v) => (v.trim() === '' && shortfall > 0n ? formatUnits(shortfall, config.ciphernodeBondDecimals) : v))
  }, [config, shortfall])

  const bondAmount = useMemo(() => {
    if (!config) return null
    return parseAmount(bondAmountInput, config.ciphernodeBondDecimals)
  }, [bondAmountInput, config])

  // ─── Step 5 amounts ─────────────────────────────────────────────────────
  const ticketShortfall = config && status ? bigMax(config.minTicketBalance - status.availableTickets, 0n) : 0n
  useEffect(() => {
    if (!config) return
    setTicketCountInput((v) => (v.trim() === '' && ticketShortfall > 0n ? ticketShortfall.toString() : v))
  }, [config, ticketShortfall])

  const ticketCount = useMemo(() => {
    const trimmed = ticketCountInput.trim()
    if (!/^\d+$/.test(trimmed)) return null
    const n = BigInt(trimmed)
    return n > 0n ? n : null
  }, [ticketCountInput])
  const ticketCost = config && ticketCount ? ticketCount * config.ticketPrice : null

  const errFor = (key: string) => (txError?.key === key ? <Note kind='warn'>{txError.message}</Note> : null)
  const label = (key: string, idle: string) => (busy === key ? 'Confirming…' : idle)

  return (
    <div className='opguide'>
      {operator && (
        <CommitteeRewards
          operator={operator}
          wallet={connected ? wallet.address : null}
          busy={busy}
          // Each claim waits for the previous one, so its simulation sees the state after it.
          send={(key, calls) =>
            void run(key, async () => {
              for (const call of calls.slice(0, -1)) await confirmTx(await write(call))
              return write(calls[calls.length - 1])
            })
          }
          errFor={errFor}
        />
      )}

      <header className='opguide__head'>
        <div className='section__eyebrow'>Ciphernode operators</div>
        <h1 className='opguide__title'>Run a ciphernode on Interfold.</h1>
        <p className='opguide__lede'>
          Ciphernodes hold key shares for encrypted computations and are selected into committees by sortition. To take part, a node needs a
          bonded ciphernode bond and a ticket balance. This guide walks the on-chain setup step by step, against the live{' '}
          <a className='link-inline' href={explorerAddress(CONTRACTS.BondingRegistry)} target='_blank' rel='noreferrer'>
            bonding registry
          </a>
          .
        </p>
      </header>

      {readError && !config ? (
        <div className='emptystate'>
          <div className='emptystate__note'>
            <span className='emptystate__dot' aria-hidden='true' />
            <span>Couldn't reach the bonding registry. Retrying automatically…</span>
          </div>
        </div>
      ) : loading && !config ? (
        <Loader label='Loading bonding parameters' />
      ) : config ? (
        <>
          <ParameterStrip config={config} />

          {operator && status && <PositionPanel config={config} status={status} operator={operator} />}

          <div className='opsteps'>
            {/* ── 1. Connect ─────────────────────────────────────────── */}
            <StepCard
              num={1}
              title='Connect a wallet'
              lede='Every step below is a transaction. Connect the wallet that will fund the collateral.'
              state={stateOf(0)}
            >
              {!wallet.available ? (
                <Note kind='warn'>No Ethereum wallet detected in this browser. Install one, then reload this page.</Note>
              ) : !wallet.address ? (
                <>
                  <button className='btn btn--primary' onClick={() => void wallet.connect()} disabled={wallet.connecting}>
                    {wallet.connecting ? 'Connecting…' : 'Connect wallet'}
                  </button>
                  {wallet.error && <Note kind='warn'>{wallet.error}</Note>}
                </>
              ) : (
                <>
                  <dl className='dl'>
                    <dt>Connected</dt>
                    <dd>
                      <AddrLink address={wallet.address} />
                    </dd>
                    <dt>Network</dt>
                    <dd>{wallet.onCorrectChain ? NETWORK_NAME : `Wrong network (chain ${wallet.chainId ?? '—'})`}</dd>
                  </dl>
                  {!wallet.onCorrectChain && (
                    <>
                      <Note kind='warn'>Interfold is deployed on {NETWORK_NAME}. Switch networks to continue.</Note>
                      <button className='btn btn--primary' onClick={() => void wallet.switchChain()}>
                        Switch to {NETWORK_NAME}
                      </button>
                    </>
                  )}
                  {wallet.error && <Note kind='warn'>{wallet.error}</Note>}
                </>
              )}

              {FAUCET_ENABLED && connected && (
                <div className='opfaucet'>
                  <div>
                    <div className='opfaucet__title'>Testnet tokens</div>
                    <div className='opfaucet__sub'>
                      This is a testnet deployment. The faucet tops up {config.ciphernodeBondSymbol} for the ciphernode bond and{' '}
                      {config.ticketSymbol} for tickets.
                    </div>
                  </div>
                  <button
                    className='btn btn--ghost'
                    disabled={busy !== null}
                    onClick={() =>
                      void run('faucet', () => write({ address: CONTRACTS.Faucet, abi: faucetAbi, functionName: 'faucet', args: [] }))
                    }
                  >
                    {label('faucet', 'Get test tokens')}
                  </button>
                </div>
              )}
              {errFor('faucet')}
            </StepCard>

            {/* ── 2. Bond owner ──────────────────────────────────────── */}
            <StepCard
              num={2}
              title='Authorize the bond owner'
              lede='The operator key is the hot key your node runs with. The bond owner is the wallet that funds and controls its collateral — the same wallet, or a separate one you keep cold.'
              state={stateOf(1)}
            >
              <div className='opfields'>
                <Field
                  label='Operator key (the ciphernode address)'
                  value={operatorInput}
                  onChange={setOperatorInput}
                  placeholder='0x…'
                  invalid={operatorInput.trim() !== '' && !operatorValid}
                  hint={operatorInput.trim() !== '' && !operatorValid ? 'Not a valid address.' : 'The address your ciphernode signs with.'}
                  suffix={
                    wallet.address && !sameAddress(operatorInput, wallet.address) ? (
                      <button className='btn btn--sm btn--ghost' onClick={() => setOperatorInput(wallet.address!)}>
                        Use connected
                      </button>
                    ) : null
                  }
                />
                <Field
                  label='Bond owner (the funding wallet)'
                  value={bondOwnerInput}
                  onChange={setBondOwnerInput}
                  placeholder='0x…'
                  invalid={bondOwnerInput.trim() !== '' && !bondOwnerValid}
                  hint={
                    bondOwnerInput.trim() !== '' && !bondOwnerValid
                      ? 'Not a valid address.'
                      : 'May be the operator key itself. Only this wallet can bond, register, and buy tickets.'
                  }
                  suffix={
                    wallet.address && !sameAddress(bondOwnerInput, wallet.address) ? (
                      <button className='btn btn--sm btn--ghost' onClick={() => setBondOwnerInput(wallet.address!)}>
                        Use connected
                      </button>
                    ) : null
                  }
                />
              </div>

              {status?.bondOwner ? (
                <>
                  <dl className='dl'>
                    <dt>Bond owner on-chain</dt>
                    <dd>
                      <AddrLink address={status.bondOwner} />
                    </dd>
                  </dl>
                  {!isBondOwner && connected && (
                    <Note kind='warn'>
                      This operator's collateral is controlled by {shortAddr(status.bondOwner)}. Connect that wallet to complete the
                      remaining steps.
                    </Note>
                  )}
                  {status.pendingBondOwner && (
                    <Note>
                      A transfer to {shortAddr(status.pendingBondOwner)} is pending. That wallet must call{' '}
                      <code className='mono'>acceptBondOwner</code> to take over the position.
                    </Note>
                  )}
                </>
              ) : (
                <>
                  <Note>
                    <code className='mono'>setBondOwner</code> is sent by the operator key itself — it is how the node authorizes a wallet
                    to post collateral on its behalf.
                  </Note>
                  {connected && operatorValid && !isOperatorWallet && (
                    <Note kind='warn'>
                      Connect the operator wallet ({shortAddr(operatorInput.trim())}) to sign this step, then switch back to the bond owner
                      for the rest.
                    </Note>
                  )}
                  <button
                    className='btn btn--primary'
                    disabled={busy !== null || !connected || !operatorValid || !bondOwnerValid || !isOperatorWallet}
                    onClick={() =>
                      void run('setBondOwner', () =>
                        write({
                          address: CONTRACTS.BondingRegistry,
                          abi: bondingRegistryAbi,
                          functionName: 'setBondOwner',
                          args: [bondOwnerInput.trim() as Address],
                        }),
                      )
                    }
                  >
                    {label('setBondOwner', 'Authorize bond owner')}
                  </button>
                </>
              )}
              {errFor('setBondOwner')}
            </StepCard>

            {/* ── 3. Bond the ciphernode bond ────────────────────────────────── */}
            <StepCard
              num={3}
              title={`Bond the ${config.ciphernodeBondSymbol} ciphernode bond`}
              lede={`A ciphernode bond of ${fmtToken(config.requiredCiphernodeBond, config.ciphernodeBondDecimals, config.ciphernodeBondSymbol)} is the collateral that makes the node eligible to register. It is slashable, and unbonding is subject to the exit delay.`}
              state={stateOf(2)}
            >
              <dl className='dl'>
                <dt>Required bond</dt>
                <dd className='mono'>
                  {fmtToken(config.requiredCiphernodeBond, config.ciphernodeBondDecimals, config.ciphernodeBondSymbol)}
                </dd>
                <dt>Currently bonded</dt>
                <dd className='mono'>
                  {fmtToken(status?.ciphernodeBond ?? 0n, config.ciphernodeBondDecimals, config.ciphernodeBondSymbol)}
                </dd>
                <dt>Your wallet balance</dt>
                <dd className='mono'>
                  {fmtToken(funds?.ciphernodeBondBalance ?? 0n, config.ciphernodeBondDecimals, config.ciphernodeBondSymbol)}
                </dd>
              </dl>

              <Field
                label={`Amount to bond (${config.ciphernodeBondSymbol})`}
                value={bondAmountInput}
                onChange={setBondAmountInput}
                placeholder='0.0'
                invalid={bondAmountInput.trim() !== '' && bondAmount === null}
                hint={bondAmountInput.trim() !== '' && bondAmount === null ? 'Enter a positive number.' : undefined}
              />

              {bondAmount !== null && funds && bondAmount > funds.ciphernodeBondBalance && (
                <Note kind='warn'>
                  Not enough {config.ciphernodeBondSymbol} in the connected wallet.
                  {FAUCET_ENABLED ? ' Use the faucet in step 1.' : ''}
                </Note>
              )}

              <div className='opactions'>
                <button
                  className='btn btn--ghost'
                  disabled={
                    busy !== null ||
                    !connected ||
                    !isBondOwner ||
                    bondAmount === null ||
                    (funds?.ciphernodeBondAllowance ?? 0n) >= bondAmount
                  }
                  onClick={() =>
                    void run('approveCiphernodeBond', () =>
                      write({
                        address: config.ciphernodeBondToken,
                        abi: erc20Abi,
                        functionName: 'approve',
                        args: [CONTRACTS.BondingRegistry, bondAmount!],
                      }),
                    )
                  }
                >
                  {label(
                    'approveCiphernodeBond',
                    bondAmount !== null && (funds?.ciphernodeBondAllowance ?? 0n) >= bondAmount
                      ? `${config.ciphernodeBondSymbol} approved`
                      : `Approve ${config.ciphernodeBondSymbol}`,
                  )}
                </button>
                <button
                  className='btn btn--primary'
                  disabled={
                    busy !== null ||
                    !connected ||
                    !isBondOwner ||
                    !operator ||
                    bondAmount === null ||
                    (funds?.ciphernodeBondAllowance ?? 0n) < bondAmount
                  }
                  onClick={() =>
                    void run('bondCiphernode', () =>
                      write({
                        address: CONTRACTS.BondingRegistry,
                        abi: bondingRegistryAbi,
                        functionName: 'bondCiphernodeFor',
                        args: [operator!, bondAmount!],
                      }),
                    )
                  }
                >
                  {label('bondCiphernode', 'Bond FOLD')}
                </button>
              </div>
              {!bondOwnerSet && <Note>Complete step 2 first — the registry only accepts collateral from an authorized bond owner.</Note>}
              {errFor('approveCiphernodeBond')}
              {errFor('bondCiphernode')}
            </StepCard>

            {/* ── 4. Register ────────────────────────────────────────── */}
            <StepCard
              num={4}
              title='Register the ciphernode'
              lede='Registration adds the operator key to the ciphernode registry, making it a candidate for committee sortition.'
              state={stateOf(3)}
            >
              <dl className='dl'>
                <dt>Bonded for registration</dt>
                <dd>{bonded ? 'Yes' : 'Not yet — bond the full ciphernode bond first'}</dd>
                <dt>Registered</dt>
                <dd>{registered ? 'Yes' : 'No'}</dd>
              </dl>
              {status?.bonded && !bonded && (
                <Note kind='warn'>
                  This operator meets the active-maintenance threshold, but registration needs the full{' '}
                  {fmtToken(config.requiredCiphernodeBond, config.ciphernodeBondDecimals, config.ciphernodeBondSymbol)}. Bond{' '}
                  {fmtToken(shortfall, config.ciphernodeBondDecimals, config.ciphernodeBondSymbol)} more in step 3.
                </Note>
              )}
              {status?.exitInProgress && (
                <Note kind='warn'>
                  This operator has an exit in progress. Collateral must finish unwinding before it can register again.
                </Note>
              )}
              <button
                className='btn btn--primary'
                disabled={
                  busy !== null || !connected || !isBondOwner || !operator || !bonded || registered || Boolean(status?.exitInProgress)
                }
                onClick={() =>
                  void run('register', () =>
                    write({
                      address: CONTRACTS.BondingRegistry,
                      abi: bondingRegistryAbi,
                      functionName: 'registerOperatorFor',
                      args: [operator!],
                    }),
                  )
                }
              >
                {label('register', registered ? 'Registered' : 'Register ciphernode')}
              </button>
              {errFor('register')}
            </StepCard>

            {/* ── 5. Tickets ─────────────────────────────────────────── */}
            <StepCard
              num={5}
              title='Buy tickets'
              lede={`Tickets are the collateral that weights sortition. Each costs ${fmtToken(config.ticketPrice, config.ticketDecimals, config.ticketSymbol)}, and a node needs at least ${config.minTicketBalance.toString()} to go active.`}
              state={stateOf(4)}
            >
              <dl className='dl'>
                <dt>Ticket price</dt>
                <dd className='mono'>{fmtToken(config.ticketPrice, config.ticketDecimals, config.ticketSymbol)}</dd>
                <dt>Minimum to activate</dt>
                <dd className='mono'>{config.minTicketBalance.toString()}</dd>
                <dt>Tickets held</dt>
                <dd className='mono'>{(status?.availableTickets ?? 0n).toString()}</dd>
                <dt>Your wallet balance</dt>
                <dd className='mono'>{fmtToken(funds?.ticketBaseBalance ?? 0n, config.ticketDecimals, config.ticketSymbol)}</dd>
              </dl>

              <Field
                label='Number of tickets'
                value={ticketCountInput}
                onChange={setTicketCountInput}
                placeholder='0'
                invalid={ticketCountInput.trim() !== '' && ticketCount === null}
                hint={
                  ticketCount === null
                    ? 'Enter a whole number of tickets.'
                    : `Costs ${fmtToken(ticketCost!, config.ticketDecimals, config.ticketSymbol)}.`
                }
              />

              {ticketCost !== null && funds && ticketCost > funds.ticketBaseBalance && (
                <Note kind='warn'>
                  Not enough {config.ticketSymbol} in the connected wallet.
                  {FAUCET_ENABLED ? ' Use the faucet in step 1.' : ''}
                </Note>
              )}
              {!registered && <Note>Tickets can only be added to a registered operator. Complete step 4 first.</Note>}

              <div className='opactions'>
                <button
                  className='btn btn--ghost'
                  disabled={
                    busy !== null || !connected || !isBondOwner || ticketCost === null || (funds?.ticketBaseAllowance ?? 0n) >= ticketCost
                  }
                  onClick={() =>
                    void run('approveTickets', () =>
                      write({
                        address: config.ticketBase,
                        abi: erc20Abi,
                        functionName: 'approve',
                        args: [config.ticketToken, ticketCost!],
                      }),
                    )
                  }
                >
                  {label(
                    'approveTickets',
                    ticketCost !== null && (funds?.ticketBaseAllowance ?? 0n) >= ticketCost
                      ? `${config.ticketSymbol} approved`
                      : `Approve ${config.ticketSymbol}`,
                  )}
                </button>
                <button
                  className='btn btn--primary'
                  disabled={
                    busy !== null ||
                    !connected ||
                    !isBondOwner ||
                    !operator ||
                    !registered ||
                    ticketCost === null ||
                    (funds?.ticketBaseAllowance ?? 0n) < ticketCost
                  }
                  onClick={() =>
                    void run('buyTickets', () =>
                      write({
                        address: CONTRACTS.BondingRegistry,
                        abi: bondingRegistryAbi,
                        functionName: 'addTicketBalanceFor',
                        args: [operator!, ticketCost!],
                      }),
                    )
                  }
                >
                  {label('buyTickets', 'Buy tickets')}
                </button>
              </div>
              {errFor('approveTickets')}
              {errFor('buyTickets')}
            </StepCard>
          </div>

          {identityOwner && (
            <IdentityPanel
              key={identityOwner}
              owner={identityOwner}
              wallet={connected ? wallet.address : null}
              busy={busy}
              send={(key, call) => void run(key, () => write(call))}
              errFor={errFor}
            />
          )}

          {operator && status && (
            <ManagePosition
              config={config}
              status={status}
              operator={operator}
              wallet={connected ? wallet.address : null}
              busy={busy}
              send={(key, call) => void run(key, () => write(call))}
              errFor={errFor}
            />
          )}

          {lastTx && (
            <div className='optx'>
              Last transaction:{' '}
              <a className='hash' href={explorerTx(lastTx)} target='_blank' rel='noreferrer'>
                <span className='mono'>{shortAddr(lastTx)}</span>
                <span className='hash__icon' aria-hidden='true'>
                  ↗
                </span>
              </a>
            </div>
          )}

          <section className='opnext'>
            <div className='section__eyebrow'>After setup</div>
            <h3 className='opnext__title'>{status?.active ? 'This ciphernode is active.' : 'Run the node itself.'}</h3>
            <p className='opnext__body'>
              The on-chain position only makes the key eligible. The ciphernode software must be running with that same operator key so it
              can take part in key generation and decryption when sortition selects it. A registered node that fails to participate is
              slashable.
            </p>
            <div className='opnext__links'>
              <a className='btn btn--ghost' href={LINKS.docs} target='_blank' rel='noreferrer'>
                Documentation <span className='btn__arrow'>→</span>
              </a>
              <a className='btn btn--ghost' href={LINKS.repo} target='_blank' rel='noreferrer'>
                Node source <span className='btn__arrow'>→</span>
              </a>
            </div>
            <p className='opnext__body opnext__body--muted'>
              Winding down reverses these steps in <strong>Manage the position</strong>: <code className='mono'>deregisterOperatorFor</code>{' '}
              queues the collateral, and after the {formatDuration(config.exitDelay)} exit delay <code className='mono'>claimExitsFor</code>{' '}
              returns it to the bond owner.
            </p>
          </section>
        </>
      ) : null}
    </div>
  )
}

function ParameterStrip({ config }: { config: BondingConfig }) {
  const items: Array<[string, string]> = [
    ['Ciphernode bond', fmtToken(config.requiredCiphernodeBond, config.ciphernodeBondDecimals, config.ciphernodeBondSymbol)],
    ['Ticket price', fmtToken(config.ticketPrice, config.ticketDecimals, config.ticketSymbol)],
    ['Min. tickets', config.minTicketBalance.toString()],
    ['Exit delay', formatDuration(config.exitDelay)],
  ]
  return (
    <div className='insp-stats opparams'>
      {items.map(([k, v]) => (
        <div className='insp-stat' key={k}>
          <div className='insp-stat__label'>{k}</div>
          <div className='insp-stat__value mono'>{v}</div>
        </div>
      ))}
    </div>
  )
}

function PositionPanel({ config, status, operator }: { config: BondingConfig; status: OperatorStatus; operator: Address }) {
  const variant = status.active ? 'published' : status.registered ? 'open' : 'working'
  const label = status.active
    ? 'Active'
    : status.registered
      ? 'Registered · inactive'
      : status.bondOwner
        ? 'Setup in progress'
        : 'Not set up'
  return (
    <section className='opposition'>
      <header className='opposition__head'>
        <div>
          <div className='section__eyebrow'>Operator position</div>
          <div className='opposition__addr'>
            <AddrLink address={operator} />
          </div>
        </div>
        <span className={`stage-badge stage-badge--${variant}`}>
          <span className='stage-badge__dot' />
          <span>{label}</span>
        </span>
      </header>
      <dl className='dl'>
        <dt>Bond owner</dt>
        <dd>{status.bondOwner ? <AddrLink address={status.bondOwner} /> : <span className='dl__muted'>Not authorized</span>}</dd>
        <dt>Ciphernode bond</dt>
        <dd className='mono'>{fmtToken(status.ciphernodeBond, config.ciphernodeBondDecimals, config.ciphernodeBondSymbol)}</dd>
        <dt>Tickets</dt>
        <dd className='mono'>
          {status.availableTickets.toString()} <span className='insp-stat__of'>/ {config.minTicketBalance.toString()} required</span>
        </dd>
        <dt>Eligible for new committees</dt>
        <dd>{status.eligible === null ? <span className='dl__muted'>Unknown</span> : status.eligible ? 'Yes' : 'No'}</dd>
      </dl>
      {status.active && status.eligible === false && (
        <Note>Active, but not eligible for new committees yet. The admission cooldown or admission policy still applies.</Note>
      )}
    </section>
  )
}

type ContractCall = { address: Address; abi: readonly unknown[]; functionName: string; args: readonly unknown[] }

const MAX_UINT256 = (1n << 256n) - 1n

/** The position transactions that the connected wallet can send. The registry checks the same roles. */
export function positionActions(status: OperatorStatus, operator: Address, wallet: Address | null) {
  const isBondOwner = sameAddress(wallet, status.bondOwner)
  const open = !status.exitInProgress
  return {
    refresh: Boolean(wallet) && status.registered,
    burn: isBondOwner && open && status.registered && status.ticketBalance > 0n,
    unbond: isBondOwner && open && status.ciphernodeBond > 0n,
    deregister: (isBondOwner || sameAddress(wallet, operator)) && open && status.registered,
    // Anyone can claim tickets; only the bond owner can also claim the bond.
    claimAll: isBondOwner && (status.claimableTicket > 0n || status.claimableBond > 0n),
    claimTickets: Boolean(wallet) && !isBondOwner && status.claimableTicket > 0n,
    proposeOwner: isBondOwner,
    acceptOwner: sameAddress(wallet, status.pendingBondOwner),
  }
}

/** Ticket-token amount to burn for a whole number of tickets, or null when the balance does not cover it. */
export function ticketBurnAmount(input: string, ticketPrice: bigint, ticketBalance: bigint): bigint | null {
  const trimmed = input.trim()
  if (!/^\d+$/.test(trimmed)) return null
  const amount = BigInt(trimmed) * ticketPrice
  return amount > 0n && amount <= ticketBalance ? amount : null
}

/**
 * The CLI's position commands after setup: refresh the status, burn tickets, unbond, deregister,
 * claim exits, and transfer the bond owner. A node that runs without the CLI, such as a DAppNode
 * package, has no other way to send them.
 */
export function ManagePosition({
  config,
  status,
  operator,
  wallet,
  busy,
  send,
  errFor,
}: {
  config: BondingConfig
  status: OperatorStatus
  operator: Address
  wallet: Address | null
  busy: string | null
  send: (key: string, call: ContractCall) => void
  errFor: (key: string) => ReactNode
}) {
  const [ticketsInput, setTicketsInput] = useState('')
  const [unbondInput, setUnbondInput] = useState('')
  const [ownerInput, setOwnerInput] = useState('')

  const pending = status.pendingTicketExit > 0n || status.pendingBondExit > 0n
  if (!status.bondOwner && !status.registered && !pending) return null

  const can = positionActions(status, operator, wallet)
  const burnAmount = ticketBurnAmount(ticketsInput, config.ticketPrice, status.ticketBalance)
  const unbondAmount = parseAmount(unbondInput, config.ciphernodeBondDecimals)
  const unbondValid = unbondAmount !== null && unbondAmount <= status.ciphernodeBond
  const newOwner = isAddress(ownerInput.trim()) ? (ownerInput.trim() as Address) : null
  const label = (key: string, idle: string) => (busy === key ? 'Confirming…' : idle)
  const registry = (functionName: string, args: readonly unknown[]): ContractCall => ({
    address: CONTRACTS.BondingRegistry,
    abi: bondingRegistryAbi,
    functionName,
    args,
  })
  const tickets = (amount: bigint) => fmtToken(amount, config.ticketDecimals, config.ticketSymbol)
  const bond = (amount: bigint) => fmtToken(amount, config.ciphernodeBondDecimals, config.ciphernodeBondSymbol)

  return (
    <section className='opposition opmanage'>
      <div className='section__eyebrow'>Manage the position</div>
      <p className='opnext__body'>
        The same transactions as the <code className='mono'>interfold ciphernode</code> commands. Each one is simulated before the wallet
        prompt.
      </p>
      {!wallet && <Note>Connect the bond owner wallet, or the operator key to deregister, to send these transactions.</Note>}

      <div className='opmanage__group'>
        <h4 className='opmanage__title'>Refresh the status</h4>
        <p className='opmanage__text'>
          The registry recomputes the active state when collateral changes. Refresh it after another change, for example a node release that
          the node acknowledged.
        </p>
        <button
          className='btn btn--ghost'
          disabled={busy !== null || !can.refresh}
          onClick={() => send('refresh', registry('refreshOperatorStatus', [operator]))}
        >
          {label('refresh', 'Refresh status')}
        </button>
        {errFor('refresh')}
      </div>

      <div className='opmanage__group'>
        <h4 className='opmanage__title'>Burn tickets</h4>
        <Field
          label='Number of tickets to burn'
          value={ticketsInput}
          onChange={setTicketsInput}
          placeholder='0'
          invalid={ticketsInput.trim() !== '' && burnAmount === null}
          hint={
            burnAmount === null
              ? `${status.availableTickets.toString()} tickets held. The collateral returns after the exit delay.`
              : `Queues ${tickets(burnAmount)} for exit.`
          }
        />
        <button
          className='btn btn--ghost'
          disabled={busy !== null || !can.burn || burnAmount === null}
          onClick={() => send('burnTickets', registry('removeTicketBalanceFor', [operator, burnAmount!]))}
        >
          {label('burnTickets', 'Burn tickets')}
        </button>
        {errFor('burnTickets')}
      </div>

      <div className='opmanage__group'>
        <h4 className='opmanage__title'>Unbond {config.ciphernodeBondSymbol}</h4>
        <Field
          label={`Amount to unbond (${config.ciphernodeBondSymbol})`}
          value={unbondInput}
          onChange={setUnbondInput}
          placeholder='0.0'
          invalid={unbondInput.trim() !== '' && !unbondValid}
          hint={`${bond(status.ciphernodeBond)} bonded. A bond below the active-maintenance threshold makes the node inactive.`}
        />
        <button
          className='btn btn--ghost'
          disabled={busy !== null || !can.unbond || !unbondValid}
          onClick={() => send('unbond', registry('unbondCiphernodeFor', [operator, unbondAmount!]))}
        >
          {label('unbond', `Unbond ${config.ciphernodeBondSymbol}`)}
        </button>
        {errFor('unbond')}
      </div>

      <div className='opmanage__group'>
        <h4 className='opmanage__title'>Leave the network</h4>
        <p className='opmanage__text'>
          Deregistration queues the tickets and the bond for exit. Keep the node running until each E3 of its last committees completes or
          fails, then claim after the {formatDuration(config.exitDelay)} exit delay.
        </p>
        <button
          className='btn btn--ghost'
          disabled={busy !== null || !can.deregister}
          onClick={() => send('deregister', registry('deregisterOperatorFor', [operator]))}
        >
          {label('deregister', 'Deregister')}
        </button>
        {errFor('deregister')}
      </div>

      <div className='opmanage__group'>
        <h4 className='opmanage__title'>Claim exits</h4>
        <dl className='dl'>
          <dt>Queued</dt>
          <dd className='mono'>
            {tickets(status.pendingTicketExit)} · {bond(status.pendingBondExit)}
          </dd>
          <dt>Exit delay ended</dt>
          <dd className='mono'>
            {tickets(status.claimableTicket)} · {bond(status.claimableBond)}
          </dd>
        </dl>
        {status.exitInProgress && <Note>The exit delay of the deregistration has not ended.</Note>}
        <p className='opmanage__text'>
          An open slash proposal, or a committee of the operator that is not released yet, still holds a claim. The check before the wallet
          prompt shows it.
        </p>
        <div className='opactions'>
          <button
            className='btn btn--primary'
            disabled={busy !== null || !can.claimAll}
            onClick={() => send('claimAll', registry('claimExitsFor', [operator, MAX_UINT256, MAX_UINT256]))}
          >
            {label('claimAll', 'Claim to the bond owner')}
          </button>
          <button
            className='btn btn--ghost'
            disabled={busy !== null || !can.claimTickets}
            onClick={() => send('claimTickets', registry('claimExitsFor', [operator, MAX_UINT256, 0n]))}
          >
            {label('claimTickets', 'Claim tickets only')}
          </button>
        </div>
        {errFor('claimAll')}
        {errFor('claimTickets')}
      </div>

      <div className='opmanage__group'>
        <h4 className='opmanage__title'>Transfer the bond owner</h4>
        <Field
          label='New bond owner'
          value={ownerInput}
          onChange={setOwnerInput}
          placeholder='0x…'
          invalid={ownerInput.trim() !== '' && !newOwner}
          hint='The current bond owner proposes. The new wallet or Safe then accepts.'
        />
        <div className='opactions'>
          <button
            className='btn btn--ghost'
            disabled={busy !== null || !can.proposeOwner || !newOwner || sameAddress(newOwner, status.bondOwner)}
            onClick={() => send('proposeOwner', registry('proposeBondOwner', [operator, newOwner!]))}
          >
            {label('proposeOwner', 'Propose new owner')}
          </button>
          <button
            className='btn btn--ghost'
            disabled={busy !== null || !can.acceptOwner}
            onClick={() => send('acceptOwner', registry('acceptBondOwner', [operator]))}
          >
            {label('acceptOwner', 'Accept ownership')}
          </button>
        </div>
        {errFor('proposeOwner')}
        {errFor('acceptOwner')}
      </div>
    </section>
  )
}

/**
 * The rewards of the committees that selected the operator. Loads the seats once per operator, and
 * reads the claim states again after each transaction.
 */
function CommitteeRewards({
  operator,
  wallet,
  busy,
  send,
  errFor,
}: {
  operator: Address
  wallet: Address | null
  busy: string | null
  send: (key: string, calls: ContractCall[]) => void
  errFor: (key: string) => ReactNode
}) {
  const [reload, setReload] = useState(0)
  const [seats, setSeats] = useState<{ operator: Address; list: CommitteeSeat[] } | null>(null)
  // The operator whose read failed, so a failure never shows for another operator.
  const [failedFor, setFailedFor] = useState<Address | null>(null)
  // Kept with the seat list that it was read for, so another operator never shows these values.
  const [statuses, setStatuses] = useState<{ seats: CommitteeSeat[]; byE3: Map<bigint, SeatStatus> } | null>(null)

  useEffect(() => {
    let cancelled = false
    fetchCommitteeSeats(operator).then(
      (list) => {
        if (!cancelled) setSeats({ operator, list })
      },
      () => {
        if (!cancelled) setFailedFor(operator)
      },
    )
    return () => {
      cancelled = true
    }
  }, [operator, reload])

  // `busy` changes when a transaction settles, so a claim shows its new state.
  useEffect(() => {
    if (!seats) return
    let cancelled = false
    fetchSeatStatuses(seats.list).then(
      (next) => {
        if (!cancelled) setStatuses({ seats: seats.list, byE3: next })
      },
      () => {
        if (!cancelled) setFailedFor(seats.operator)
      },
    )
    return () => {
      cancelled = true
    }
  }, [seats, busy])

  const current = seats?.operator === operator ? seats.list : null
  return (
    <CommitteeRewardsView
      seats={current}
      statuses={current && statuses?.seats === current ? statuses.byE3 : null}
      loadFailed={failedFor === operator}
      wallet={wallet}
      busy={busy}
      onReload={() => {
        setFailedFor(null)
        setReload((n) => n + 1)
      }}
      send={send}
      errFor={errFor}
    />
  )
}

const CLAIM_KEY = 'claimRewards'
// One transaction key per E3, so each row shows its own spinner and error.
const processKey = (e3Id: bigint) => `process:${e3Id}`
const fee = (value: bigint) => fmtToken(value, FEE_TOKEN.decimals, FEE_TOKEN.symbol)

/**
 * The claimable total and its claim action, then the history of each committee seat. `seats` is null
 * while the seats load, and `statuses` while their claim states load.
 */
export function CommitteeRewardsView({
  seats,
  statuses,
  loadFailed,
  wallet,
  busy,
  onReload,
  send,
  errFor,
}: {
  seats: CommitteeSeat[] | null
  statuses: Map<bigint, SeatStatus> | null
  loadFailed: boolean
  wallet: Address | null
  busy: string | null
  onReload: () => void
  send: (key: string, calls: ContractCall[]) => void
  errFor: (key: string) => ReactNode
}) {
  return (
    <section className='opposition oprewards'>
      <div className='section__eyebrow'>Ciphernode / Rewards</div>
      <h3 className='oprewards__title'>E3 rewards</h3>
      <p className='opnext__body'>Rewards earned through this ciphernode's E3 committee participation.</p>

      {loadFailed ? (
        <>
          <Note kind='warn'>Could not read the rewards of this operator.</Note>
          <button className='btn btn--ghost' onClick={onReload}>
            Try again
          </button>
        </>
      ) : seats === null ? (
        <p className='opmanage__text'>Loading committees…</p>
      ) : seats.length === 0 ? (
        <p className='opmanage__text'>No committee has selected this operator yet.</p>
      ) : (
        <>
          <RewardsSummary seats={seats} statuses={statuses} wallet={wallet} busy={busy} send={send} />
          {errFor(CLAIM_KEY)}

          <h4 className='opmanage__title oprewards__history'>Committee history</h4>
          <div className='evlog-wrap'>
            <table className='evlog'>
              <thead>
                <tr>
                  <th>E3</th>
                  <th>Outcome</th>
                  <th className='evlog__num'>Reward</th>
                  <th>Claim status</th>
                </tr>
              </thead>
              <tbody>
                {seats.map((seat) => {
                  const status = statuses?.get(seat.e3Id)
                  const state = status && CLAIM_STATES[status.state]
                  return (
                    <tr key={seat.e3Id.toString()}>
                      <td className='mono' title={seat.e3Id.toString()}>
                        {compactE3Id(seat.e3Id)}
                      </td>
                      <td>{status ? seatStageLabel(status.stage) : '…'}</td>
                      <td className='evlog__num mono'>{status ? (status.amount === null ? '—' : fee(status.amount)) : '…'}</td>
                      <td>
                        {status && state ? (
                          <span className='oprewards__status'>
                            <span
                              className={`oprewards__state oprewards__state--${status.state}`}
                              title={`${state.reason} Recipient: ${seat.recipient}.`}
                            >
                              {state.label}
                            </span>
                            {status.state === 'needsProcessing' && wallet && (
                              <button
                                className='btn btn--sm btn--ghost'
                                disabled={busy !== null}
                                onClick={() =>
                                  send(processKey(seat.e3Id), [
                                    {
                                      address: CONTRACTS.Interfold,
                                      abi: interfoldAbi,
                                      functionName: 'processE3Failure',
                                      args: [seat.e3Id],
                                    },
                                  ])
                                }
                              >
                                {busy === processKey(seat.e3Id) ? 'Confirming…' : 'Process'}
                              </button>
                            )}
                          </span>
                        ) : (
                          '…'
                        )}
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
          {seats.map(({ e3Id }) => (
            <div key={e3Id.toString()}>{errFor(processKey(e3Id))}</div>
          ))}

          <details className='oprewards__about'>
            <summary>
              Rewards are assigned to the eligible recipient when each committee is finalized. Only that recipient can claim.
            </summary>
            <p>
              The recipient is the bond owner of the operator when the committee was finalized, or the operator key if it had no bond owner.
              A completed E3 pays each committee member a reward. A failed E3 pays its honest members compensation, after any wallet
              processes the failure. An open expulsion proposal against the operator holds its payment until the proposal resolves. An
              executed expulsion gives the share to the other members.
            </p>
            <p>Point to a claim status to see why it shows. The history covers the E3s of the current refund manager.</p>
          </details>
        </>
      )}
    </section>
  )
}

/** The claimable total, the claim action, and what stops a claim. */
function RewardsSummary({
  seats,
  statuses,
  wallet,
  busy,
  send,
}: {
  seats: CommitteeSeat[]
  statuses: Map<bigint, SeatStatus> | null
  wallet: Address | null
  busy: string | null
  send: (key: string, calls: ContractCall[]) => void
}) {
  const summary = statuses && summarizeRewards(statuses.values())
  const plan = statuses ? claimPlan(seats, statuses, wallet) : { rewards: [], compensation: [] }
  const calls: ContractCall[] = [
    ...(plan.rewards.length > 0
      ? [{ address: CONTRACTS.Interfold, abi: interfoldAbi, functionName: 'claimRewards', args: [plan.rewards] }]
      : []),
    ...plan.compensation.map(({ e3Id, operator, refundManager }) => ({
      address: refundManager,
      abi: e3RefundManagerAbi,
      functionName: 'claimHonestNodeReward',
      args: [e3Id, operator],
    })),
  ]
  const recipients = [...new Set(seats.map(({ recipient }) => recipient.toLowerCase()))]
  // The wallets that can claim what the connected wallet cannot.
  const claimers = [
    ...new Set(
      seats
        .filter(({ e3Id, recipient }) => statuses?.get(e3Id)?.state === 'claimable' && !sameAddress(recipient, wallet))
        .map(({ recipient }) => recipient),
    ),
  ]
  const extra = summary && [
    summary.claimed > 0n && `${fee(summary.claimed)} claimed`,
    summary.onHold > 0n && `${fee(summary.onHold)} on hold`,
  ]

  return (
    <>
      <div className='oprewards__summary'>
        <div>
          <div className='insp-stat__label'>Available to claim</div>
          <div className='oprewards__amount'>
            <span className='mono'>{summary ? fmtToken(summary.claimable, FEE_TOKEN.decimals) : '…'}</span>
            <span className='oprewards__unit'>{FEE_TOKEN.symbol}</span>
          </div>
          <div className='insp-stat__sub'>
            {summary
              ? [`${summary.claimableCount} ${summary.claimableCount === 1 ? 'reward' : 'rewards'} available`, ...(extra ?? [])]
                  .filter(Boolean)
                  .join(' · ')
              : 'Reading rewards…'}
          </div>
          <div className='insp-stat__sub oprewards__recipient'>
            Paid to {recipients.length === 1 ? <AddrLink address={seats[0].recipient} /> : `${recipients.length} wallets`}
          </div>
        </div>
        <div className='oprewards__claim'>
          <button className='btn btn--primary' disabled={busy !== null || calls.length === 0} onClick={() => send(CLAIM_KEY, calls)}>
            {busy === CLAIM_KEY ? 'Confirming…' : 'Claim rewards'}
          </button>
          {calls.length > 1 && <span className='insp-stat__sub'>{calls.length} transactions</span>}
        </div>
      </div>
      {claimers.length > 0 && (
        <Note>
          {claimers.length === 1 ? (
            <>
              Only <AddrLink address={claimers[0]} /> can claim {calls.length > 0 ? 'the other rewards' : 'these rewards'}.{' '}
              {wallet ? 'Connect that wallet.' : 'Connect it to claim.'}
            </>
          ) : (
            'Other wallets receive some of these rewards. Point to a claim status to see its recipient.'
          )}
        </Note>
      )}
      {summary && summary.needsProcessing > 0 && (
        <Note kind='warn'>
          {summary.needsProcessing === 1
            ? 'A failed E3 needs processing before its honest members can claim compensation. Any connected wallet can process it from the history.'
            : `${summary.needsProcessing} failed E3s need processing before their honest members can claim compensation. Any connected wallet can process them from the history.`}
        </Note>
      )}
    </>
  )
}

// ─── Bond-owner identity ──────────────────────────────────────────────────

/** The ZKPassport request of the identity panel. */
export type IdentityRequest =
  | { phase: 'idle' }
  | { phase: 'creating' }
  | { phase: 'waiting'; url: string; qr: string; received: boolean }
  | { phase: 'proving' }
  | { phase: 'ready'; bundle: ProofBundle }
  | { phase: 'failed'; message: string }

/** The proof settings: the deployed verifier's, or the planned ones before a deployment. */
export type IdentityService = {
  domain: string
  scope: string
  faceMatch: boolean
  /** 0 non-salted, 1 salted; null keeps the ZKPassport default. */
  nullifierType: number | null
  proofValidity: bigint
  maxValidity: bigint
}

const REGISTER_IDENTITY_KEY = 'registerIdentity'

function identityService(verifier: VerifierConfig | null, previewFaceMatch: boolean): IdentityService {
  return verifier
    ? {
        domain: verifier.domain,
        scope: verifier.scope,
        faceMatch: verifier.faceMatchRequired,
        nullifierType: verifier.nullifierType,
        proofValidity: verifier.proofValidity,
        maxValidity: verifier.maxValidity,
      }
    : {
        domain: PREVIEW_SERVICE.domain,
        scope: PREVIEW_SERVICE.scope,
        faceMatch: previewFaceMatch,
        nullifierType: null,
        proofValidity: PREVIEW_SERVICE.proofValidity,
        maxValidity: PREVIEW_SERVICE.maxValidity,
      }
}

function IdentityPanel({
  owner,
  wallet,
  busy,
  send,
  errFor,
}: {
  owner: Address
  wallet: Address | null
  busy: string | null
  send: (key: string, call: ContractCall) => void
  errFor: (key: string) => ReactNode
}) {
  const [reload, setReload] = useState(0)
  // undefined while loading; null when the network has no identity policy.
  const [policy, setPolicy] = useState<IdentityPolicy | null | undefined>(undefined)
  const [verifier, setVerifier] = useState<VerifierConfig | null>(null)
  // Kept with the owner that it was read for, so another owner never shows these values.
  const [account, setAccount] = useState<{ owner: Address; value: OwnerAccount } | null>(null)
  const [loadFailed, setLoadFailed] = useState(false)
  const [request, setRequest] = useState<IdentityRequest>({ phase: 'idle' })
  // null until the owner types a date.
  const [validUntilInput, setValidUntilInput] = useState<string | null>(null)
  const [previewFaceMatch, setPreviewFaceMatch] = useState(true)
  const cancelRequest = useRef<(() => void) | null>(null)
  // Each request gets a token. A callback of an older request changes nothing.
  const requestToken = useRef(0)

  useEffect(() => {
    let cancelled = false
    const load = async () => {
      const nextPolicy = await fetchIdentityPolicy()
      const nextVerifier = nextPolicy ? await fetchVerifierConfig(nextPolicy.registry) : null
      if (cancelled) return
      setPolicy(nextPolicy)
      setVerifier(nextVerifier)
    }
    load().catch(() => {
      if (!cancelled) setLoadFailed(true)
    })
    return () => {
      cancelled = true
    }
  }, [reload])

  // `busy` changes when a transaction settles, so a registration shows its new expiry.
  useEffect(() => {
    if (policy === undefined) return
    let cancelled = false
    fetchOwnerAccount(owner, policy?.registry ?? null).then(
      (value) => {
        if (!cancelled) setAccount({ owner, value })
      },
      () => {
        if (!cancelled) setLoadFailed(true)
      },
    )
    return () => {
      cancelled = true
    }
  }, [owner, policy, busy, reload])

  // A request binds one owner, and each owner has its own panel instance (keyed by owner).
  useEffect(
    () => () => {
      requestToken.current += 1
      cancelRequest.current?.()
      cancelRequest.current = null
    },
    [],
  )
  // A finished proof expires, so its view follows the clock while the page stays open.
  const [clock, setClock] = useState(() => BigInt(Math.floor(Date.now() / 1000)))
  useEffect(() => {
    if (request.phase !== 'ready') return undefined
    const id = setInterval(() => setClock(BigInt(Math.floor(Date.now() / 1000))), 30_000)
    return () => clearInterval(id)
  }, [request.phase])

  const service = identityService(verifier, previewFaceMatch)
  const loaded = account?.owner === owner ? account.value : null
  const current = loaded && clock > loaded.now ? { ...loaded, now: clock } : loaded
  // A published registry without a verifier keeps its credentials, but takes no registration.
  const registrationClosed = Boolean(policy) && verifier === null
  // Until the owner types a date, the field offers the longest credential that the verifier allows.
  const validUntilValue = validUntilInput ?? (current ? dateInput(current.now + service.maxValidity) : '')

  const create = async () => {
    const chain = boundChainName(CHAIN.id)
    const validUntil = parseDateInput(validUntilValue)
    if (!chain || validUntil === null) return
    cancelRequest.current?.()
    const token = ++requestToken.current
    const update = (next: IdentityRequest) => {
      if (requestToken.current === token) setRequest(next)
    }
    update({ phase: 'creating' })
    try {
      // The SDK is large, so it loads only when an owner asks for a proof.
      const [sdk, qrcode] = await Promise.all([import('@zkpassport/sdk'), import('qrcode')])
      const zkPassport = new sdk.ZKPassport(service.domain)
      const builder = await zkPassport.request({
        name: 'Interfold',
        purpose: 'Verify the bond owner of an Interfold ciphernode.',
        scope: service.scope,
        mode: 'compressed-evm',
        devMode: false,
        ...(service.nullifierType === null
          ? {}
          : { uniqueIdentifierType: service.nullifierType === 1 ? sdk.NullifierType.SALTED : sdk.NullifierType.NON_SALTED }),
      })
      let query = builder
        .gte('expiry_date', new Date(Number(validUntil) * 1000))
        .bind('user_address', owner)
        .bind('chain', chain)
      // The SDK requires strict FaceMatch for a salted identifier.
      if (service.faceMatch || service.nullifierType === 1) query = query.facematch('strict')
      const result = query.done()
      if (requestToken.current !== token) return zkPassport.cancelRequest(result.requestId)
      cancelRequest.current = () => zkPassport.cancelRequest(result.requestId)
      const qr = await qrcode.toDataURL(result.url, { margin: 1, width: 240 })
      update({ phase: 'waiting', url: result.url, qr, received: false })
      result.onRequestReceived(() => update({ phase: 'waiting', url: result.url, qr, received: true }))
      result.onGeneratingProof(() => update({ phase: 'proving' }))
      result.onSuccess((success) => {
        try {
          const outer = outerEvmProof(success.proofs)
          if (!outer) throw new Error('The app sent no EVM proof.')
          const params = zkPassport.getSolidityVerifierParameters({ proof: outer, scope: service.scope, devMode: false })
          update({
            phase: 'ready',
            bundle: buildProofBundle({ success, params, owner, chainId: CHAIN.id, faceMatch: service.faceMatch }),
          })
        } catch (e) {
          update({ phase: 'failed', message: walletErrorMessage(e) })
        }
      })
      result.onReject(() => update({ phase: 'failed', message: 'The request was rejected in the ZKPassport app.' }))
      result.onError((message) => update({ phase: 'failed', message }))
    } catch (e) {
      update({ phase: 'failed', message: walletErrorMessage(e) })
    }
  }

  return (
    <IdentityView
      owner={owner}
      policy={policy}
      verifier={verifier}
      account={current}
      loadFailed={loadFailed}
      service={service}
      validUntilInput={validUntilValue}
      onValidUntil={setValidUntilInput}
      previewFaceMatch={previewFaceMatch}
      onPreviewFaceMatch={setPreviewFaceMatch}
      request={request}
      registrationClosed={registrationClosed}
      canRegister={sameAddress(wallet, owner)}
      busy={busy}
      errFor={errFor}
      onReload={() => {
        setLoadFailed(false)
        setReload((n) => n + 1)
      }}
      onCreate={() => void create()}
      onCancel={() => {
        requestToken.current += 1
        cancelRequest.current?.()
        cancelRequest.current = null
        setRequest({ phase: 'idle' })
      }}
      onRegister={(bundle) =>
        send(REGISTER_IDENTITY_KEY, {
          address: policy!.registry,
          abi: ownerIdentityRegistryAbi,
          functionName: 'register',
          args: [bundle.evidence],
        })
      }
      onDownloadProof={(bundle) => downloadJson(`interfold-identity-proof-${owner}.json`, bundle)}
      onDownloadSafe={(bundle) => {
        if (BigInt(Math.floor(Date.now() / 1000)) > proofDeadline(bundle, service)) {
          setRequest({ phase: 'failed', message: 'The proof is too old to register. Create a new request.' })
          return
        }
        downloadJson(
          `interfold-identity-safe-${owner}.json`,
          safeRegistrationBatch(policy!.registry, owner, CHAIN.id, bundle.evidence, Date.now()),
        )
      }}
    />
  )
}

/**
 * The bond owner's credential, the ZKPassport request, and the registration. `policy` is undefined
 * while it loads and null when the network has no identity registry; `account` is null while it loads.
 */
export function IdentityView({
  owner,
  policy,
  verifier,
  account,
  loadFailed,
  service,
  validUntilInput,
  onValidUntil,
  previewFaceMatch,
  onPreviewFaceMatch,
  request,
  registrationClosed = false,
  canRegister,
  busy,
  errFor,
  onReload,
  onCreate,
  onCancel,
  onRegister,
  onDownloadProof,
  onDownloadSafe,
}: {
  owner: Address
  policy: IdentityPolicy | null | undefined
  verifier: VerifierConfig | null
  account: OwnerAccount | null
  loadFailed: boolean
  service: IdentityService
  validUntilInput: string
  onValidUntil: (value: string) => void
  previewFaceMatch: boolean
  onPreviewFaceMatch: (value: boolean) => void
  request: IdentityRequest
  /** The policy names a registry that has no verifier. */
  registrationClosed?: boolean
  canRegister: boolean
  busy: string | null
  errFor: (key: string) => ReactNode
  onReload: () => void
  onCreate: () => void
  onCancel: () => void
  onRegister: (bundle: ProofBundle) => void
  onDownloadProof: (bundle: ProofBundle) => void
  onDownloadSafe: (bundle: ProofBundle) => void
}) {
  const preview = policy === null
  const chain = boundChainName(CHAIN.id)
  const validUntil = parseDateInput(validUntilInput)
  const windowEnd = account ? capacityWindowEnd(account.now) : null
  const currentExpiry = account?.identity?.expiresAt ?? 0n
  // Capacity depends on credentials only while the policy requires them.
  const capacityApplies = Boolean(policy?.required)
  // The proof date is about now, so the credential would end on this date or at the verifier's cap.
  const plannedEnd = validUntil !== null && account ? credentialEnd(validUntil, account.now, service.maxValidity) : null
  const requesting = request.phase === 'creating' || request.phase === 'waiting' || request.phase === 'proving'

  return (
    <section className='opposition opidentity'>
      <div className='section__eyebrow'>Bond owner / Identity</div>
      <h3 className='oprewards__title'>Bond-owner identity</h3>
      <p className='opnext__body'>
        Governance can require each bond owner to prove one identity document with the ZKPassport app. The proof shows that the document is
        valid. It puts no personal data on chain. One owner may fund many operators.
      </p>

      {loadFailed ? (
        <>
          <Note kind='warn'>Could not read the identity registry.</Note>
          <button className='btn btn--ghost' onClick={onReload}>
            Try again
          </button>
        </>
      ) : policy === undefined || !account ? (
        <p className='opmanage__text'>Loading the identity status…</p>
      ) : (
        <>
          <dl className='dl'>
            <dt>Bond owner</dt>
            <dd>
              <AddrLink address={owner} />
              {account.isContract && <span className='dl__muted'> · contract wallet (Safe)</span>}
            </dd>
            <dt>Identity required</dt>
            <dd>
              {preview ? (
                <span className='dl__muted'>No identity registry on {NETWORK_NAME} yet</span>
              ) : policy.required ? (
                `Yes, since ${fmtDay(policy.timepoint)}`
              ) : (
                'Not yet'
              )}
            </dd>
            {!preview && (
              <>
                <dt>Credential</dt>
                <dd>{identityStatusText(account)}</dd>
              </>
            )}
          </dl>
          {capacityApplies && account.identity && account.identity.verifiedNow && windowEnd !== null && currentExpiry < windowEnd && (
            <Note kind='warn'>
              The credential ends before this 30-day window ends ({fmtDay(windowEnd)}), so this owner does not count toward request capacity
              in this window. Renew it.
            </Note>
          )}
          {preview && (
            <Note>
              You can still make a proof and download it. It uses the planned settings: domain{' '}
              <code className='mono'>{service.domain}</code>, scope <code className='mono'>{service.scope}</code>.
            </Note>
          )}

          {!chain ? (
            <Note kind='warn'>ZKPassport does not verify proofs on {NETWORK_NAME}.</Note>
          ) : registrationClosed ? (
            <Note>The identity registry has no verifier at the moment, so it takes no registration. Credentials it issued stay valid.</Note>
          ) : request.phase === 'ready' ? (
            <IdentityProof
              bundle={request.bundle}
              owner={owner}
              preview={preview}
              verifier={verifier}
              account={account}
              service={service}
              canRegister={canRegister}
              busy={busy}
              errFor={errFor}
              onRegister={onRegister}
              onDownloadProof={onDownloadProof}
              onDownloadSafe={onDownloadSafe}
              onRestart={onCancel}
            />
          ) : (
            <div className='opmanage__group'>
              <h4 className='opmanage__title'>{account.identity?.expiresAt ? 'Renew the credential' : 'Verify the owner'}</h4>
              <p className='opmanage__text'>
                Use a passport, ID card or residence permit with a chip, and a phone with NFC and the ZKPassport app. The proof is bound to
                this owner and to {NETWORK_NAME}.
              </p>
              <Field
                label='Document valid until (UTC date)'
                value={validUntilInput}
                onChange={onValidUntil}
                placeholder='YYYY-MM-DD'
                invalid={validUntilInput.trim() !== '' && validUntil === null}
                hint={`The document must be valid at least until this date. The credential ends on this date, or ${formatDuration(
                  service.maxValidity,
                )} after the proof, if that is earlier.`}
              />
              {capacityApplies && plannedEnd !== null && windowEnd !== null && plannedEnd < windowEnd && (
                <Note kind='warn'>
                  This date is before the end of the current 30-day window ({fmtDay(windowEnd)}). The owner would not count toward request
                  capacity in this window.
                </Note>
              )}
              {plannedEnd !== null && account.identity && plannedEnd < currentExpiry && (
                <Note kind='warn'>
                  Pick a date after the current expiry ({fmtDay(currentExpiry)}). A renewal cannot shorten the credential.
                </Note>
              )}
              {preview ? (
                <label className='opcheck'>
                  <input type='checkbox' checked={previewFaceMatch} onChange={(e) => onPreviewFaceMatch(e.target.checked)} />
                  <span>Require FaceMatch (a live face scan against the chip photo)</span>
                </label>
              ) : (
                service.faceMatch && <Note>The app also asks for a face scan (FaceMatch).</Note>
              )}

              {request.phase === 'waiting' ? (
                <div className='opidentity__request'>
                  <img className='opidentity__qr' src={request.qr} alt='ZKPassport request QR code' width={240} height={240} />
                  <div>
                    <p className='opmanage__text'>
                      {request.received
                        ? 'The request is open in the app. Check the site and the bound address, then approve it.'
                        : 'Scan this code with the ZKPassport app.'}
                    </p>
                    <a className='link-inline' href={request.url} target='_blank' rel='noreferrer'>
                      Open the request on this phone
                    </a>
                  </div>
                </div>
              ) : request.phase === 'proving' ? (
                <p className='opmanage__text'>The app is making the proof. This takes up to a minute.</p>
              ) : request.phase === 'failed' ? (
                <Note kind='warn'>{request.message}</Note>
              ) : null}

              <div className='opactions'>
                {requesting ? (
                  <button className='btn btn--ghost' onClick={onCancel}>
                    Cancel
                  </button>
                ) : (
                  <button className='btn btn--primary' disabled={validUntil === null} onClick={onCreate}>
                    {request.phase === 'failed' ? 'Try again' : 'Create ZKPassport request'}
                  </button>
                )}
              </div>
            </div>
          )}
        </>
      )}
    </section>
  )
}

/** A proof from the app: what the verifier will read from it, and the ways to register it. */
function IdentityProof({
  bundle,
  owner,
  preview,
  verifier,
  account,
  service,
  canRegister,
  busy,
  errFor,
  onRegister,
  onDownloadProof,
  onDownloadSafe,
  onRestart,
}: {
  bundle: ProofBundle
  owner: Address
  preview: boolean
  verifier: VerifierConfig | null
  account: OwnerAccount
  service: IdentityService
  canRegister: boolean
  busy: string | null
  errFor: (key: string) => ReactNode
  onRegister: (bundle: ProofBundle) => void
  onDownloadProof: (bundle: ProofBundle) => void
  onDownloadSafe: (bundle: ProofBundle) => void
  onRestart: () => void
}) {
  const validUntil = BigInt(bundle.validUntil)
  const proofDate = BigInt(bundle.proofDate)
  const ends = credentialEnd(validUntil, proofDate, service.maxValidity)
  const deadline = proofDeadline(bundle, service)
  // The panel requested this binding; a proof for another owner or chain would only revert.
  const bound = sameAddress(bundle.owner, owner) && bundle.chainId === CHAIN.id
  const versionMatches = !verifier || bundle.version.toLowerCase() === verifier.version.toLowerCase()
  const keyMatches =
    !verifier ||
    (bundle.nullifierType === verifier.nullifierType && bundle.oprfKeyHash.toLowerCase() === verifier.oprfKeyHash.toLowerCase())
  const expired = account.now > deadline
  const shortens = account.identity !== null && ends < account.identity.expiresAt
  const blocked = !bound || !versionMatches || !keyMatches || expired || shortens

  return (
    <div className='opmanage__group'>
      <h4 className='opmanage__title'>Proof ready</h4>
      <dl className='dl'>
        <dt>Bound to</dt>
        <dd>
          <AddrLink address={bundle.owner} /> on {NETWORK_NAME}
        </dd>
        <dt>Document valid until</dt>
        <dd>{fmtDay(validUntil)}</dd>
        <dt>Credential ends</dt>
        <dd>{fmtDay(ends)}</dd>
        <dt>Register before</dt>
        <dd>{fmtMoment(deadline)}</dd>
        <dt>Identifier type</dt>
        <dd>{bundle.nullifierType === 1 ? 'Salted' : 'Not salted'}</dd>
      </dl>
      {!bound && <Note kind='warn'>This proof is bound to another owner or network. Create a new request.</Note>}
      {!keyMatches && (
        <Note kind='warn'>The proof's identifier type or OPRF key differs from the verifier's. The verifier would reject it.</Note>
      )}
      {!versionMatches && (
        <Note kind='warn'>
          The app made the proof with another ZKPassport version than the verifier accepts. Governance must deploy a verifier for the new
          version first.
        </Note>
      )}
      {expired && <Note kind='warn'>The proof is too old to register. Create a new request.</Note>}
      {shortens && <Note kind='warn'>This proof ends before the current credential. A renewal cannot shorten it.</Note>}

      <div className='opactions'>
        {!preview && !account.isContract && (
          <button className='btn btn--primary' disabled={busy !== null || !canRegister || blocked} onClick={() => onRegister(bundle)}>
            {busy === REGISTER_IDENTITY_KEY ? 'Confirming…' : 'Register the identity'}
          </button>
        )}
        {!preview && account.isContract && (
          <button className='btn btn--primary' disabled={blocked} onClick={() => onDownloadSafe(bundle)}>
            Download the Safe transaction
          </button>
        )}
        <button className='btn btn--ghost' onClick={() => onDownloadProof(bundle)}>
          Download the proof (JSON)
        </button>
        <button className='btn btn--ghost' onClick={onRestart}>
          New request
        </button>
      </div>
      {errFor(REGISTER_IDENTITY_KEY)}
      {!preview && !account.isContract && !canRegister && <Note>Connect the bond-owner wallet {shortAddr(owner)} to register.</Note>}
      {!preview && account.isContract && (
        <Note>
          Load the file in the Safe Transaction Builder and execute it before {fmtMoment(deadline)}. The registration costs about 1.3
          million gas.
        </Note>
      )}
      {!preview && (
        <Note>
          The owner's operators count toward this window's request capacity after their next status refresh. Each node refreshes itself when
          a window starts; to count now, use <strong>Refresh the status</strong> in Manage the position.
        </Note>
      )}
    </div>
  )
}

/** The last moment that this proof can register under `service`. */
function proofDeadline(bundle: ProofBundle, service: IdentityService): bigint {
  const proofDate = BigInt(bundle.proofDate)
  return registrationDeadline(proofDate, service.proofValidity, credentialEnd(BigInt(bundle.validUntil), proofDate, service.maxValidity))
}

/** A Unix timestamp as a UTC date and time, to the minute. */
function fmtMoment(ts: bigint): string {
  return `${new Date(Number(ts) * 1000).toISOString().slice(0, 16).replace('T', ' ')} UTC`
}

function downloadJson(name: string, value: unknown) {
  const text = JSON.stringify(value, (_, v) => (typeof v === 'bigint' ? v.toString() : v), 2)
  const url = URL.createObjectURL(new Blob([text], { type: 'application/json' }))
  const link = document.createElement('a')
  link.href = url
  link.download = name
  link.click()
  URL.revokeObjectURL(url)
}

const bigMax = (a: bigint, b: bigint): bigint => (a > b ? a : b)

// Parse a user-typed decimal amount. Returns null for anything that isn't a
// positive number, so callers can keep their action disabled.
function parseAmount(input: string, decimals: number): bigint | null {
  const trimmed = input.trim()
  if (!/^\d*\.?\d*$/.test(trimmed) || trimmed === '' || trimmed === '.') return null
  try {
    const value = parseUnits(trimmed, decimals)
    return value > 0n ? value : null
  } catch {
    return null
  }
}

function formatDuration(seconds: bigint): string {
  const s = Number(seconds)
  if (s <= 0) return 'none'
  if (s % 86400 === 0) return `${s / 86400}d`
  if (s % 3600 === 0) return `${s / 3600}h`
  if (s % 60 === 0) return `${s / 60}m`
  return `${s}s`
}
