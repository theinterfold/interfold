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

import { useEffect, useMemo, useState, type ReactNode } from 'react'
import { erc20Abi, formatUnits, isAddress, parseUnits, type Address, type Hash } from 'viem'
import Loader from './Loader'
import { CONTRACTS, IS_TESTNET, NETWORK_NAME, bondingRegistryAbi, faucetAbi } from './lib/chain'
import { LINKS, explorerAddress, explorerTx } from './lib/links'
import { ZERO_ADDRESS, simulateAndWrite, useBonding, type BondingConfig, type OperatorStatus } from './lib/bonding'
import { confirmTx, useWallet, walletErrorMessage } from './lib/wallet'

// The faucet is testnet-only: a configured address is not enough, the selected
// network must be a test network too. Otherwise a VITE_FAUCET_ADDRESS left over
// from a testnet deployment shows "Testnet tokens" on mainnet.
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
              Winding down reverses these steps: <code className='mono'>deregisterOperatorFor</code> queues the collateral, and after the{' '}
              {formatDuration(config.exitDelay)} exit delay <code className='mono'>claimExitsFor</code> returns it to the bond owner.
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
      </dl>
    </section>
  )
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
