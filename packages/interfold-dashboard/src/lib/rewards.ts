// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
// Committee seats, rewards, and failed-E3 compensation of one operator, behind the operator guide.
//
// When a committee is finalized, the refund manager emits one
// `RewardRecipientSnapshotted(e3Id, operator, recipient)` for each member. Its indexed operator topic
// lists every committee that selected an operator, and the wallet that receives the payments of that
// seat. Both payments are pull payments that only the recipient can claim:
// - A completed E3 pays a reward on the Interfold contract. `pendingReward(e3Id, recipient)` is the
//   amount that `claimReward(e3Id)` pays, and `RewardClaimed` records each claim.
// - A failed E3 pays compensation to honest members on the refund manager, after
//   `Interfold.processE3Failure(e3Id)` calculates the refund. `claimHonestNodeReward(e3Id, operator)`
//   pays it, and `RefundClaimed` records each claim. The contract has no view for that amount, so the
//   read simulates the claim from the recipient: the result is the amount, and the revert tells why
//   there is nothing to claim.
// `rewardStatus(e3Id, operator)` tells whether an open expulsion proposal holds the operator's payment,
// or an executed expulsion forfeited it.

import { BaseError, ContractFunctionRevertedError, getAbiItem, stringToHex, type Address } from 'viem'
import { CONTRACTS, DEPLOY_BLOCK, E3Stage, e3RefundManagerAbi, interfoldAbi, publicClient } from './chain'
import { getLogsChunked } from './e3'

const RECIPIENT_SNAPSHOTTED = getAbiItem({ abi: e3RefundManagerAbi, name: 'RewardRecipientSnapshotted' })
const REWARD_CLAIMED = getAbiItem({ abi: interfoldAbi, name: 'RewardClaimed' })
const REFUND_CLAIMED = getAbiItem({ abi: e3RefundManagerAbi, name: 'RefundClaimed' })
// `claimHonestNodeReward` emits this claim type. Requester refunds use another one.
const HONEST_NODE_CLAIM = stringToHex('HONEST_NODE', { size: 32 })

// viem types `readContract` and `simulateContract` on this client with a required
// `authorizationList`, so each call states its own result type. The ABIs still come from the
// typechain factories.
const readContract = publicClient.readContract as unknown as <T>(
  call:
    | {
        address: Address
        abi: typeof interfoldAbi
        functionName: 'e3RefundManager' | 'getE3Stage' | 'pendingReward'
        args?: readonly unknown[]
      }
    | {
        address: Address
        abi: typeof e3RefundManagerAbi
        functionName: 'getRefundDistribution' | 'rewardStatus' | 'operatorHeldRewards'
        args: readonly unknown[]
      },
) => Promise<T>
const simulateCompensationClaim = publicClient.simulateContract as unknown as (call: {
  account: Address
  address: Address
  abi: typeof e3RefundManagerAbi
  functionName: 'claimHonestNodeReward'
  args: readonly [bigint, Address]
}) => Promise<{ result: bigint }>

/**
 * One committee that selected the operator, the wallet that receives its payments, the refund manager
 * that recorded it, and the block of the record.
 */
export type CommitteeSeat = { e3Id: bigint; operator: Address; recipient: Address; refundManager: Address; block: bigint }

/** What the recipient of a seat can do with its payment. */
export type ClaimState =
  // The E3 has not finished.
  | 'inProgress'
  | 'claimable'
  | 'claimed'
  // An open expulsion proposal against the operator holds the payment.
  | 'onHold'
  // An executed expulsion gave the operator's share to the other members.
  | 'forfeited'
  // The E3 failed and nobody has sent `processE3Failure` yet.
  | 'needsProcessing'
  // The E3 failed and the operator was not an honest member.
  | 'notEligible'
  | 'noReward'

/**
 * `amount` is the claimable, claimed, or held amount, and null when the state has none. Claims are
 * recorded per recipient, so two seats of one recipient in one E3 both show the sum of its claims.
 */
export type SeatStatus = { stage: E3Stage; state: ClaimState; amount: bigint | null }

/**
 * Every committee that selected `operator`, newest first. The scan covers the current refund manager
 * of the Interfold contract, so it does not list E3s that an earlier refund manager recorded.
 */
export async function fetchCommitteeSeats(operator: Address): Promise<CommitteeSeat[]> {
  const [refundManager, head] = await Promise.all([
    readContract<Address>({ address: CONTRACTS.Interfold, abi: interfoldAbi, functionName: 'e3RefundManager' }),
    publicClient.getBlockNumber(),
  ])
  const logs = await getLogsChunked<{ blockNumber: bigint; args: { e3Id: bigint; operator: Address; recipient: Address } }>(
    { address: refundManager, event: RECIPIENT_SNAPSHOTTED, args: { operator } },
    DEPLOY_BLOCK,
    head,
  )
  return logs
    .map(({ blockNumber, args }) => ({
      e3Id: args.e3Id,
      operator: args.operator,
      recipient: args.recipient,
      refundManager,
      block: blockNumber,
    }))
    .reverse()
}

const claimKey = (e3Id: bigint, recipient: Address) => `${e3Id}:${recipient.toLowerCase()}`

/** The amount that each recipient of `seats` has claimed, keyed by `claimKey`. */
async function fetchClaimed(seats: CommitteeSeat[]): Promise<Map<string, bigint>> {
  const from = seats.reduce((min, { block }) => (block < min ? block : min), seats[0].block)
  const recipients = [...new Set(seats.map(({ recipient }) => recipient))]
  const head = await publicClient.getBlockNumber()
  type Claim = { args: { e3Id: bigint; account?: Address; claimant?: Address; amount: bigint; claimType?: `0x${string}` } }
  const [rewards, refunds] = await Promise.all([
    getLogsChunked<Claim>({ address: CONTRACTS.Interfold, event: REWARD_CLAIMED, args: { account: recipients } }, from, head),
    getLogsChunked<Claim>({ address: seats[0].refundManager, event: REFUND_CLAIMED, args: { claimant: recipients } }, from, head),
  ])
  const claimed = new Map<string, bigint>()
  const add = (e3Id: bigint, recipient: Address, amount: bigint) =>
    claimed.set(claimKey(e3Id, recipient), (claimed.get(claimKey(e3Id, recipient)) ?? 0n) + amount)
  for (const { args } of rewards) add(args.e3Id, args.account as Address, args.amount)
  for (const { args } of refunds) if (args.claimType === HONEST_NODE_CLAIM) add(args.e3Id, args.claimant as Address, args.amount)
  return claimed
}

/** The custom error of a contract revert, or null when `e` is not a revert. */
function revertName(e: unknown): string | null {
  if (!(e instanceof BaseError)) return null
  const revert = e.walk((cause) => cause instanceof ContractFunctionRevertedError)
  return revert instanceof ContractFunctionRevertedError ? (revert.data?.errorName ?? '') : null
}

async function fetchCompensation(seat: CommitteeSeat, claimed: bigint): Promise<Omit<SeatStatus, 'stage'>> {
  const distribution = await readContract<{ calculated: boolean }>({
    address: seat.refundManager,
    abi: e3RefundManagerAbi,
    functionName: 'getRefundDistribution',
    args: [seat.e3Id],
  })
  if (!distribution.calculated) return { state: 'needsProcessing', amount: null }
  try {
    const { result } = await simulateCompensationClaim({
      account: seat.recipient,
      address: seat.refundManager,
      abi: e3RefundManagerAbi,
      functionName: 'claimHonestNodeReward',
      args: [seat.e3Id, seat.operator],
    })
    if (result > 0n) return { state: 'claimable', amount: result }
  } catch (e) {
    const error = revertName(e)
    // Any other error (the RPC, for example) is not an answer, so it propagates.
    if (error === null) throw e
    if (error === 'NotHonestNode') return { state: 'notEligible', amount: null }
    if (error === 'AlreadyClaimed') return { state: 'claimed', amount: claimed > 0n ? claimed : null }
  }
  return claimed > 0n ? { state: 'claimed', amount: claimed } : { state: 'noReward', amount: null }
}

async function fetchReward(seat: CommitteeSeat, claimed: bigint): Promise<Omit<SeatStatus, 'stage'>> {
  const pending = await readContract<bigint>({
    address: CONTRACTS.Interfold,
    abi: interfoldAbi,
    functionName: 'pendingReward',
    args: [seat.e3Id, seat.recipient],
  })
  if (pending > 0n) return { state: 'claimable', amount: pending }
  return claimed > 0n ? { state: 'claimed', amount: claimed } : { state: 'noReward', amount: null }
}

/** The E3 stage and the claim state of each seat, keyed by E3 id. */
export async function fetchSeatStatuses(seats: CommitteeSeat[]): Promise<Map<bigint, SeatStatus>> {
  if (seats.length === 0) return new Map()
  const claimed = await fetchClaimed(seats)
  const entries = await Promise.all(
    seats.map(async (seat): Promise<[bigint, SeatStatus]> => {
      const [stage, [, held, excluded]] = await Promise.all([
        readContract<number>({ address: CONTRACTS.Interfold, abi: interfoldAbi, functionName: 'getE3Stage', args: [seat.e3Id] }),
        readContract<readonly [Address, boolean, boolean]>({
          address: seat.refundManager,
          abi: e3RefundManagerAbi,
          functionName: 'rewardStatus',
          args: [seat.e3Id, seat.operator],
        }),
      ])
      const status = async (): Promise<Omit<SeatStatus, 'stage'>> => {
        if (stage !== E3Stage.Complete && stage !== E3Stage.Failed) return { state: 'inProgress', amount: null }
        if (excluded) return { state: 'forfeited', amount: null }
        const claimedAmount = claimed.get(claimKey(seat.e3Id, seat.recipient)) ?? 0n
        if (stage === E3Stage.Failed) return held ? { state: 'onHold', amount: null } : fetchCompensation(seat, claimedAmount)
        if (!held) return fetchReward(seat, claimedAmount)
        const [heldSuccess] = await readContract<readonly [bigint, bigint]>({
          address: seat.refundManager,
          abi: e3RefundManagerAbi,
          functionName: 'operatorHeldRewards',
          args: [seat.e3Id, seat.operator],
        })
        return { state: 'onHold', amount: heldSuccess }
      }
      return [seat.e3Id, { stage, ...(await status()) }]
    }),
  )
  return new Map(entries)
}

const STAGE_LABELS: Record<E3Stage, string> = {
  [E3Stage.None]: 'Unknown',
  [E3Stage.Requested]: 'Requested',
  [E3Stage.CommitteeFinalized]: 'Key generation',
  [E3Stage.KeyPublished]: 'Accepting inputs',
  [E3Stage.CiphertextReady]: 'Decryption',
  [E3Stage.Complete]: 'Complete',
  [E3Stage.Failed]: 'Failed',
}

export function seatStageLabel(stage: E3Stage): string {
  return STAGE_LABELS[stage] ?? `Stage ${stage}`
}

/** The label of each claim state, and the reason it shows. */
export const CLAIM_STATES: Record<ClaimState, { label: string; reason: string }> = {
  inProgress: {
    label: 'In progress',
    reason: 'The E3 has not finished. A completed E3 pays a reward, and a failed E3 can pay compensation.',
  },
  claimable: { label: 'Claimable', reason: 'The recipient can claim this amount now.' },
  claimed: { label: 'Claimed', reason: 'The recipient claimed this payment.' },
  onHold: { label: 'On hold', reason: 'An open expulsion proposal against this operator holds the payment until the proposal resolves.' },
  forfeited: { label: 'Forfeited', reason: 'An executed expulsion of this operator gave its share to the other committee members.' },
  needsProcessing: {
    label: 'Needs processing',
    reason: 'The E3 failed. Any wallet can process the failure. After that, the honest members can claim compensation.',
  },
  notEligible: { label: 'Not eligible', reason: 'The operator was not an honest member of this failed E3, so it gets no compensation.' },
  noReward: { label: 'No reward', reason: 'This E3 assigned no payment to this operator.' },
}

/** The totals that lead the rewards section. */
export type RewardsSummary = { claimable: bigint; claimableCount: number; claimed: bigint; onHold: bigint; needsProcessing: number }

export function summarizeRewards(statuses: Iterable<SeatStatus>): RewardsSummary {
  const summary: RewardsSummary = { claimable: 0n, claimableCount: 0, claimed: 0n, onHold: 0n, needsProcessing: 0 }
  for (const { state, amount } of statuses) {
    if (state === 'claimable') {
      summary.claimable += amount ?? 0n
      summary.claimableCount++
    } else if (state === 'claimed') summary.claimed += amount ?? 0n
    else if (state === 'onHold') summary.onHold += amount ?? 0n
    else if (state === 'needsProcessing') summary.needsProcessing++
  }
  return summary
}

/**
 * The claims that `wallet` can send: one `claimRewards(e3Ids)` for the completed E3s, and one
 * `claimHonestNodeReward` for each failed E3. Only the recipient of a seat can claim it.
 */
export type ClaimPlan = { rewards: bigint[]; compensation: CommitteeSeat[] }

export function claimPlan(seats: CommitteeSeat[], statuses: Map<bigint, SeatStatus>, wallet: Address | null): ClaimPlan {
  const plan: ClaimPlan = { rewards: [], compensation: [] }
  if (!wallet) return plan
  for (const seat of seats) {
    const status = statuses.get(seat.e3Id)
    if (status?.state !== 'claimable' || seat.recipient.toLowerCase() !== wallet.toLowerCase()) continue
    if (status.stage === E3Stage.Failed) plan.compensation.push(seat)
    else plan.rewards.push(seat.e3Id)
  }
  return plan
}
