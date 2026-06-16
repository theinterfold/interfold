// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
// On-chain E3 fetchers — read events + view functions and assemble dashboard records.

import { CONTRACTS, DEPLOY_BLOCK, E3Stage, TIMEOUTS, ciphernodeRegistryAbi, interfoldAbi, publicClient } from './chain'

// Helper: pull a single named event ABI item out of the typechain bundle.
function eventAbi(abi: readonly any[], name: string): any {
  const item = abi.find((x) => x.type === 'event' && x.name === name)
  if (!item) throw new Error(`event ${name} not in ABI`)
  return item
}

const INTERFOLD_E3_REQUESTED = eventAbi(interfoldAbi as any, 'E3Requested')
const INTERFOLD_PLAINTEXT_PUBLISHED = eventAbi(interfoldAbi as any, 'PlaintextOutputPublished')
const INTERFOLD_REWARDS_DISTRIBUTED = eventAbi(interfoldAbi as any, 'RewardsDistributed')
// The Interfold E3StageChanged event is the reliable, program-agnostic signal for
// each lifecycle transition (the registry's CommitteePublished event signature
// has drifted from this package's ABI on the live deployment, so we don't use it).
const INTERFOLD_E3_STAGE_CHANGED = eventAbi(interfoldAbi as any, 'E3StageChanged')
const REGISTRY_COMMITTEE_REQUESTED = eventAbi(ciphernodeRegistryAbi as any, 'CommitteeRequested')
const REGISTRY_COMMITTEE_FINALIZED = eventAbi(ciphernodeRegistryAbi as any, 'SortitionCommitteeFinalized')

// CRISP votes are NOT published through Interfold (its IInterfold.InputPublished
// event is declared but never emitted). Each E3 program records its own inputs.
// CRISPProgram emits this on every accepted ballot; a re-vote reuses the same
// `index` (the vote's Merkle-tree leaf), so the true ballot count is the number
// of DISTINCT indexes, not the event count.
const CRISP_INPUT_PUBLISHED = {
  type: 'event',
  name: 'InputPublished',
  inputs: [
    { name: 'e3Id', type: 'uint256', indexed: true },
    { name: 'encryptedVote', type: 'bytes', indexed: false },
    { name: 'index', type: 'uint256', indexed: false },
  ],
} as const

// Public RPCs cap getLogs range. 9_500 keeps us safely under common 10k limits.
const LOG_CHUNK = 9_500n

// An E3 is a CRISP poll only if its program contract is the CRISPProgram.
// Other E3s on the same Interfold deployment run different programs and must not
// be presented as polls.
export function isCrispE3(e3Program: string): boolean {
  return e3Program.toLowerCase() === CONTRACTS.CRISPProgram.toLowerCase()
}

// Solidity E3Stage → 7-stage UI index used by STAGES in data.ts.
// UI stages: 0 Requested → 1 Committee Selected → 2 Keygen → 3 Input Window
//          → 4 Compute → 5 Decryption → 6 Published
export function solidityStageToUiIdx(stage: number, inputWindow: [bigint, bigint]): number {
  const now = BigInt(Math.floor(Date.now() / 1000))
  switch (stage) {
    case E3Stage.None:
    case E3Stage.Requested:
      return 0 // request placed, awaiting committee
    case E3Stage.CommitteeFinalized:
      return 2 // sortition done, DKG running
    case E3Stage.KeyPublished: {
      // Key is out — voting open until window close, then compute pending.
      if (inputWindow[1] !== 0n && now >= inputWindow[1]) return 4
      return 3
    }
    case E3Stage.CiphertextReady:
      return 5 // ciphertext produced, threshold decrypting
    case E3Stage.Complete:
      return 6
    case E3Stage.Failed:
      return 6 // distinct visual state handled separately
    default:
      return 0
  }
}

// Whether an E3 is genuinely still active right now. An E3 isn't active when:
//   - it's already Complete or Failed on-chain,
//   - it blew past its expected deadline (input close + compute + decryption windows)
//     without completing (chain hasn't formally marked it Failed yet), or
//   - for input-tracked programs (CRISP), its input window has closed without
//     a single ballot being submitted. The chain doesn't transition the stage
//     because there's nothing to compute; functionally it's a terminal no-op.
export function isE3Active(
  stage: number,
  inputWindowClose: bigint,
  opts: { e3Program?: string; ballotCount?: number; nowMs?: number } = {},
): boolean {
  if (stage === E3Stage.Complete || stage === E3Stage.Failed) return false
  if (inputWindowClose > 0n) {
    const now = BigInt(Math.floor((opts.nowMs ?? Date.now()) / 1000))
    if (now >= inputWindowClose) {
      // Input window has closed. For programs whose inputs we can observe, if
      // none arrived the round is effectively done.
      if (opts.e3Program && isCrispE3(opts.e3Program) && (opts.ballotCount ?? 0) === 0) return false
    }
    const deadline = inputWindowClose + BigInt(TIMEOUTS.computeWindow + TIMEOUTS.decryptionWindow)
    if (now > deadline) return false
  }
  return true
}

export type E3Summary = {
  id: bigint
  e3Program: `0x${string}`
  requester: `0x${string}`
  requestBlock: bigint
  requestTxHash: `0x${string}`
  inputWindow: [bigint, bigint]
  committeeSize: number
  stage: number // raw Solidity E3Stage enum
  ballotCount: number // distinct CRISP ballots (0 for non-CRISP / when not scanned)
}

export type E3FullDetails = E3Summary & {
  stage: number // raw Solidity enum
  uiStageIdx: number
  seed: bigint
  encryptionSchemeId: `0x${string}`
  committeePublicKey: `0x${string}`
  ciphertextOutput: `0x${string}`
  plaintextOutput: `0x${string}`
  requestedAt?: number // unix seconds (block.timestamp of the request)
  // Block number of the E3Requested log (distinct from `requestBlock` which on
  // this contract version is actually a Unix timestamp, not a block number).
  requestEventBlock?: bigint
  // From CiphernodeRegistry:
  committeeThreshold: [number, number] // [M, N]
  committeeMembers: `0x${string}`[]
  committeeFinalizedTx?: `0x${string}`
  committeeFinalizedAt?: number
  committeeFinalizedBlock?: bigint
  committeePublishedTx?: `0x${string}`
  committeePublishedAt?: number
  committeePublishedBlock?: bigint
  // Aggregated inputs. inputsTracked is true only for programs whose input
  // event we understand (CRISP); for other programs inputs aren't observable
  // from the dashboard, so ballotCount is 0 and inputsTracked is false.
  // ballotCount is the number of DISTINCT ballots (re-votes are not counted
  // twice). ballotEvents holds the raw on-chain events (incl. re-votes).
  inputsTracked: boolean
  ballotCount: number
  ballotEvents: Array<{
    blockNumber: bigint
    txHash: `0x${string}`
    index: bigint
    timestamp?: number
  }>
  resultTxHash?: `0x${string}`
  resultAt?: number
  resultBlock?: bigint
  // Fees, in fee-token base units (MockUSDC, 6 decimals). feeEscrowed is the
  // amount currently held for the E3 — note Interfold zeroes it on settlement or
  // refund, so a completed/refunded E3 reads 0. committeeReward is the real
  // total paid out to the committee (only known once RewardsDistributed fires).
  feeEscrowed: bigint
  committeeReward?: bigint
}

// Resolve unix timestamps for a (small, bounded) set of block numbers, deduped.
async function blockTimestamps(blocks: bigint[]): Promise<Map<string, number>> {
  const uniq = Array.from(new Set(blocks.filter((b) => b > 0n).map((b) => b.toString())))
  const entries = await Promise.all(
    uniq.map(async (s) => {
      try {
        const b = await publicClient.getBlock({ blockNumber: BigInt(s) })
        return [s, Number(b.timestamp)] as const
      } catch {
        return [s, 0] as const
      }
    }),
  )
  return new Map(entries)
}

async function getLogsChunked<T>(
  args: Omit<Parameters<typeof publicClient.getLogs>[0], 'fromBlock' | 'toBlock'>,
  from: bigint,
  to: bigint,
): Promise<T[]> {
  const out: any[] = []
  for (let start = from; start <= to; start += LOG_CHUNK + 1n) {
    const end = start + LOG_CHUNK > to ? to : start + LOG_CHUNK
    const logs = await publicClient.getLogs({ ...args, fromBlock: start, toBlock: end } as any)
    out.push(...logs)
  }
  return out as T[]
}

export async function fetchLatestBlock(): Promise<bigint> {
  return publicClient.getBlockNumber()
}

// ~24h of blocks at ~12s/block. Approximate window for the "last 24h" stat.
const BLOCKS_PER_DAY = 7200n

// Count CRISP ballots (InputPublished events) submitted in roughly the last 24h.
export async function fetchRecentBallotCount(): Promise<number> {
  const head = await fetchLatestBlock()
  const from = head > BLOCKS_PER_DAY + DEPLOY_BLOCK ? head - BLOCKS_PER_DAY : DEPLOY_BLOCK
  const logs = await getLogsChunked<any>({ address: CONTRACTS.CRISPProgram, event: CRISP_INPUT_PUBLISHED }, from, head)
  return logs.length
}

export type FetchE3Opts = {
  // CRISP poll view: only E3s whose program is the CRISPProgram.
  crispOnly?: boolean
  toBlock?: bigint
}

export async function fetchE3List(opts: FetchE3Opts = {}): Promise<E3Summary[]> {
  const { crispOnly = false, toBlock } = opts
  const head = toBlock ?? (await fetchLatestBlock())
  const logs = await getLogsChunked<any>(
    {
      address: CONTRACTS.Interfold,
      event: INTERFOLD_E3_REQUESTED,
    },
    DEPLOY_BLOCK,
    head,
  )

  const scoped = crispOnly ? logs.filter((log) => isCrispE3(log.args.e3.e3Program)) : logs

  const [stages, ballotCounts] = await Promise.all([
    // Current stage of each E3 in one multicall — lets the list show real status
    // (completed / failed / expired) rather than guessing.
    (publicClient.multicall as any)({
      contracts: scoped.map((log) => ({
        address: CONTRACTS.Interfold,
        abi: interfoldAbi,
        functionName: 'getE3Stage',
        args: [log.args.e3Id],
      })),
      allowFailure: true,
    }),
    // CRISP view: one scan of all ballots, grouped per E3 (distinct voteIndex),
    // so every history row shows its real count without a per-poll fetch.
    crispOnly ? fetchCrispBallotCounts(head) : Promise.resolve(new Map<string, number>()),
  ])

  const out: E3Summary[] = scoped.map((log, i) => {
    const { e3Id, e3 } = log.args
    const stageResult = stages[i]
    return {
      id: e3Id,
      e3Program: e3.e3Program,
      requester: e3.requester,
      requestBlock: e3.requestBlock,
      requestTxHash: log.transactionHash,
      inputWindow: [e3.inputWindow[0], e3.inputWindow[1]] as [bigint, bigint],
      committeeSize: Number(e3.committeeSize),
      stage: stageResult.status === 'success' ? Number(stageResult.result) : E3Stage.None,
      ballotCount: ballotCounts.get(e3Id.toString()) ?? 0,
    }
  })

  // Sort newest first.
  out.sort((a, b) => Number(b.requestBlock - a.requestBlock))
  return out
}

// Distinct ballot count per CRISP E3, from a single scan of all InputPublished
// events grouped by e3Id (re-votes reuse a voteIndex, so we count unique ones).
async function fetchCrispBallotCounts(head: bigint): Promise<Map<string, number>> {
  const inputs = await getLogsChunked<any>({ address: CONTRACTS.CRISPProgram, event: CRISP_INPUT_PUBLISHED }, DEPLOY_BLOCK, head)
  const byE3 = new Map<string, Set<string>>()
  for (const l of inputs) {
    const id = l.args.e3Id.toString()
    const set = byE3.get(id) ?? new Set<string>()
    set.add(l.args.index.toString())
    byE3.set(id, set)
  }
  return new Map(Array.from(byE3, ([id, set]) => [id, set.size]))
}

export async function fetchE3Details(e3Id: bigint, toBlock?: bigint): Promise<E3FullDetails> {
  const head = toBlock ?? (await fetchLatestBlock())

  // 1. Pull live E3 struct + stage + currently-escrowed fee.
  const [e3, stage, feeEscrowed] = await Promise.all([
    (publicClient.readContract as any)({
      address: CONTRACTS.Interfold,
      abi: interfoldAbi,
      functionName: 'getE3',
      args: [e3Id],
    }) as Promise<any>,
    (publicClient.readContract as any)({
      address: CONTRACTS.Interfold,
      abi: interfoldAbi,
      functionName: 'getE3Stage',
      args: [e3Id],
    }) as Promise<number>,
    (publicClient.readContract as any)({
      address: CONTRACTS.Interfold,
      abi: interfoldAbi,
      functionName: 'e3Payments',
      args: [e3Id],
    }).catch(() => 0n) as Promise<bigint>,
  ])

  // `e3.requestBlock` is misnamed: on this contract version it stores
  // `block.timestamp` (EIP-6372 timestamp clock), not a block number. Using it
  // as fromBlock would push the scan range past chain head and silently miss
  // every event. The first pass scans from DEPLOY_BLOCK; once we've found the
  // E3Requested log we tighten subsequent scans to its block number.

  // 2. Find the E3Requested tx for this id (for the inspector header).
  const requestLogs = await getLogsChunked<any>(
    {
      address: CONTRACTS.Interfold,
      event: INTERFOLD_E3_REQUESTED,
    },
    DEPLOY_BLOCK,
    head,
  )
  const requestLog = requestLogs.find((l: any) => l.args.e3Id === e3Id)
  const requestTxHash = (requestLog?.transactionHash ?? ('0x' as `0x${string}`)) as `0x${string}`
  // Nothing for this E3 can exist on chain before its E3Requested block, so
  // tighten the later scans (committee, inputs, result) to start there.
  const fromBlock: bigint = requestLog?.blockNumber ?? DEPLOY_BLOCK

  // 3. Committee data: requested (threshold/seed) + finalized (members) from the
  // registry; the key-publish moment from the Interfold E3StageChanged → KeyPublished
  // transition (the registry's CommitteePublished event has drifted from our ABI).
  const [requestedEvents, finalizedEvents, stageChanges] = await Promise.all([
    getLogsChunked<any>(
      {
        address: CONTRACTS.CiphernodeRegistry,
        event: REGISTRY_COMMITTEE_REQUESTED,
        args: { e3Id },
      } as any,
      fromBlock,
      head,
    ),
    getLogsChunked<any>(
      {
        address: CONTRACTS.CiphernodeRegistry,
        event: REGISTRY_COMMITTEE_FINALIZED,
        args: { e3Id },
      } as any,
      fromBlock,
      head,
    ),
    getLogsChunked<any>(
      {
        address: CONTRACTS.Interfold,
        event: INTERFOLD_E3_STAGE_CHANGED,
        args: { e3Id },
      } as any,
      fromBlock,
      head,
    ),
  ])

  const reqLog = requestedEvents[0]
  const finLog = finalizedEvents[0]
  // The key was published when the E3 transitioned into KeyPublished.
  const pubLog = stageChanges.find((l: any) => Number(l.args.newStage) === E3Stage.KeyPublished)

  const threshold: [number, number] = reqLog ? [Number(reqLog.args.threshold[0]), Number(reqLog.args.threshold[1])] : [0, 0]
  const members: `0x${string}`[] = (finLog?.args?.committee ?? []) as `0x${string}`[]

  // 4. Inputs + result + committee rewards.
  // Inputs come from the E3 program, not Interfold. We only understand CRISP's
  // event shape, so non-CRISP programs report no observable inputs.
  const inputsTracked = isCrispE3(e3.e3Program)
  const [inputs, results, rewards] = await Promise.all([
    inputsTracked
      ? getLogsChunked<any>(
          {
            address: CONTRACTS.CRISPProgram,
            event: CRISP_INPUT_PUBLISHED,
            args: { e3Id },
          } as any,
          fromBlock,
          head,
        )
      : Promise.resolve([] as any[]),
    getLogsChunked<any>(
      {
        address: CONTRACTS.Interfold,
        event: INTERFOLD_PLAINTEXT_PUBLISHED,
        args: { e3Id },
      } as any,
      fromBlock,
      head,
    ),
    getLogsChunked<any>(
      {
        address: CONTRACTS.Interfold,
        event: INTERFOLD_REWARDS_DISTRIBUTED,
        args: { e3Id },
      } as any,
      fromBlock,
      head,
    ),
  ])
  // Distinct ballots: re-votes reuse the same Merkle-leaf index, so dedupe.
  const ballotCount = inputsTracked ? new Set(inputs.map((l: any) => l.args.index.toString())).size : 0
  // Real committee reward total (sum of per-node amounts), once distributed.
  const committeeReward = rewards.length
    ? rewards.reduce((sum: bigint, log: any) => sum + (log.args.amounts as bigint[]).reduce((a, b) => a + b, 0n), 0n)
    : undefined
  const resultLog = results[0]

  // 5. Resolve block timestamps for the events we surface (bounded set: request,
  // committee finalize/publish, result, and the first/last few ballots).
  const shownBallots = inputs.slice(0, 6)
  if (inputs.length > 6) shownBallots.push(inputs[inputs.length - 1])
  const ts = await blockTimestamps(
    [finLog?.blockNumber, pubLog?.blockNumber, resultLog?.blockNumber, ...shownBallots.map((l: any) => l.blockNumber)].filter(
      (b): b is bigint => typeof b === 'bigint',
    ),
  )
  const at = (bn?: bigint) => (bn != null ? ts.get(bn.toString()) : undefined)
  // `e3.requestBlock` already IS a Unix timestamp on this contract version (the
  // field is misnamed — see fromBlock comment above), so we don't go to chain.
  const requestedAtTs = e3.requestBlock > 0n ? Number(e3.requestBlock) : undefined

  return {
    id: e3Id,
    e3Program: e3.e3Program,
    requester: e3.requester,
    requestBlock: e3.requestBlock,
    requestTxHash,
    requestedAt: requestedAtTs,
    requestEventBlock: requestLog?.blockNumber,
    inputWindow: [e3.inputWindow[0], e3.inputWindow[1]] as [bigint, bigint],
    committeeSize: Number(e3.committeeSize),
    stage,
    uiStageIdx: solidityStageToUiIdx(stage, [e3.inputWindow[0], e3.inputWindow[1]]),
    seed: e3.seed,
    encryptionSchemeId: e3.encryptionSchemeId,
    committeePublicKey: e3.committeePublicKey,
    ciphertextOutput: e3.ciphertextOutput,
    plaintextOutput: e3.plaintextOutput,
    committeeThreshold: threshold,
    committeeMembers: members,
    committeeFinalizedTx: finLog?.transactionHash,
    committeeFinalizedAt: at(finLog?.blockNumber),
    committeeFinalizedBlock: finLog?.blockNumber,
    committeePublishedTx: pubLog?.transactionHash,
    committeePublishedAt: at(pubLog?.blockNumber),
    committeePublishedBlock: pubLog?.blockNumber,
    inputsTracked,
    ballotCount,
    ballotEvents: inputs.map((l: any) => ({
      blockNumber: l.blockNumber,
      txHash: l.transactionHash,
      index: l.args.index,
      timestamp: at(l.blockNumber),
    })),
    resultTxHash: resultLog?.transactionHash,
    resultAt: at(resultLog?.blockNumber),
    resultBlock: resultLog?.blockNumber,
    feeEscrowed,
    committeeReward,
  }
}

// Decode CRISP tally from PlaintextOutputPublished bytes. CRISPProgram packs
// it as a uint64[] (per CRISPProgram.decodeTally). We surface the raw counts
// and let the UI label them by option index.
export function decodeCrispTally(plaintextOutput: `0x${string}`): number[] | null {
  if (!plaintextOutput || plaintextOutput === '0x' || plaintextOutput.length < 4) return null
  try {
    // The data is abi-encoded `bytes` → uint64[] inside. Lightweight decoder:
    // strip 0x, treat each 32-byte word as a uint256. The first word is offset,
    // second is length, then the data. We expect uint64 values one per word.
    const hex = plaintextOutput.slice(2)
    if (hex.length < 128) return null
    const lengthWord = hex.slice(64, 128)
    const len = parseInt(lengthWord, 16)
    if (!Number.isFinite(len) || len > 1024) return null
    const out: number[] = []
    for (let i = 0; i < len; i++) {
      const word = hex.slice(128 + i * 64, 128 + (i + 1) * 64)
      if (word.length !== 64) return null
      // Guard against silent precision loss converting a >2^53 word to a JS number.
      const v = BigInt('0x' + word)
      if (v > BigInt(Number.MAX_SAFE_INTEGER)) return null
      out.push(Number(v))
    }
    return out
  } catch {
    return null
  }
}
