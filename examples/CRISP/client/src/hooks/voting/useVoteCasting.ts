// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { useState, useCallback, useEffect, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import { useSignTypedData, usePublicClient, useChainId, useWalletClient } from 'wagmi'
import { zeroHash } from 'viem'
import type { Address, Hex } from 'viem'
import { encodeSolidityProof, finishBallotProof, finishMaskProof, prepareBallot } from '@crisp-e3/sdk'
import { ciphertextCommitment, finishSafeBallotProof, ownersCommitment, withBallotParent } from '@crisp-e3/sdk'
import type { PreparedBallot, PrepareBallotInputs, SlotOwners } from '@crisp-e3/sdk'
import { ensureCircuits } from '@/utils/circuits'

import { useVoteManagementContext } from '@/context/voteManagement'
import { useNotificationAlertContext } from '@/context/NotificationAlert/NotificationAlert.context.tsx'
import { Poll } from '@/model/poll.model'
import { BroadcastVoteRequest, BroadcastVoteResponse, CensusMode, Vote, VoteStateLite, VotingRound } from '@/model/vote.model'
import { useInterfoldServer } from '../interfold/useInterfoldServer'
import { getRandomVoterToMask } from '@/utils/voters'
import { handleGenericError } from '@/utils/handle-generic-error'
import { NUM_OPTIONS } from '@/utils/constants'
import { ballotTypedData, getBallotAuthorization, getCrispProgramAddress, getCrispRoundConfig } from '@/utils/ballotDigest'
import { getRandomRegistrant, getVotingPower, isRegisteredIn } from '@/utils/onchainCensus'
import { submitInputCommitmentDirectly } from '@/utils/directVote'
import { txExplorerUrl } from '@/utils/methods'

const INTERFOLD_API = import.meta.env.VITE_INTERFOLD_API

/** How many registrants a random mask draws before it gives up on finding one with a ballot. */
const MAX_MASK_DRAWS = 8

interface PendingAvailabilityJob {
  jobId: string
  isMask: boolean
  /** A Safe vote, which is not the connected account's own vote. */
  isSafeVote?: boolean
  encodedProof?: string
}

const availabilityJobKey = (chainId: number, roundId: string, address: string): string => {
  return `crisp-availability-${chainId}-${roundId}-${address.toLowerCase()}`
}

const readAvailabilityJob = (key: string): PendingAvailabilityJob | undefined => {
  try {
    const stored = localStorage.getItem(key)
    if (!stored) return undefined
    const parsed: unknown = JSON.parse(stored)
    if (typeof parsed !== 'object' || parsed === null || !('jobId' in parsed) || typeof parsed.jobId !== 'string') return undefined
    return {
      jobId: parsed.jobId,
      isMask: 'isMask' in parsed && parsed.isMask === true,
      isSafeVote: 'isSafeVote' in parsed && parsed.isSafeVote === true,
      encodedProof: 'encodedProof' in parsed && typeof parsed.encodedProof === 'string' ? parsed.encodedProof : undefined,
    }
  } catch {
    return undefined
  }
}

const writeAvailabilityJob = (key: string, job: PendingAvailabilityJob): void => {
  try {
    localStorage.setItem(key, JSON.stringify(job))
  } catch {
    // Large secure ballots can exceed a browser's storage quota. Preserve the small server job
    // pointer when possible, even though a server-database loss would then need operator recovery.
    try {
      localStorage.setItem(key, JSON.stringify({ jobId: job.jobId, isMask: job.isMask, isSafeVote: job.isSafeVote }))
    } catch {
      // The durable server job remains valid. A browser with disabled storage cannot resume it
      // automatically after a reload.
    }
  }
}

const clearAvailabilityJob = (key: string): void => {
  try {
    localStorage.removeItem(key)
  } catch {
    // The item is already harmless after the server job reaches a terminal state.
  }
}

/// How often, and for how long, the client waits for the server to decide who sends a queued
/// commitment. The server worker can take minutes to reach a job when many jobs are pending.
const COMMITMENT_DECISION_POLL_MS = 10_000
const COMMITMENT_DECISION_WAIT_MS = 600_000

/// Wait until a `pending_commitment` job has a sender: the relay, or this wallet, which must then
/// send the commitment before its availability promise expires. Returns the first other view,
/// `null` when the server no longer has the job, or `undefined` when the wait ends or
/// `isCancelled` returns true.
const waitForCommitmentDecision = async (
  jobId: string,
  getVoteAvailability: (jobId: string) => Promise<BroadcastVoteResponse | null | undefined>,
  isCancelled: () => boolean,
): Promise<BroadcastVoteResponse | null | undefined> => {
  const deadline = Date.now() + COMMITMENT_DECISION_WAIT_MS
  while (!isCancelled()) {
    const view = await getVoteAvailability(jobId)
    if (view === null || (view && view.status !== 'pending_commitment')) return view
    if (Date.now() >= deadline) return undefined
    await new Promise((resolve) => setTimeout(resolve, COMMITMENT_DECISION_POLL_MS))
  }
  return undefined
}

/// The end of the slot's chain of usable entries, with the tree index the new input will name as
/// its parent. Not simply the newest entry published: one whose bytes do not reproduce its
/// commitment is never selected by the Secure Process and is never a valid parent, so the server
/// resolves the chain and answers with the entry that actually holds the slot.
const getSlotHead = async (e3Id: string, address: string): Promise<{ ciphertext: Uint8Array; index: number } | undefined> => {
  const response = await fetch(`${INTERFOLD_API}/state/previous-ciphertext`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ round_id: e3Id, address }),
  })

  if (response.status === 404) return undefined
  if (!response.ok) throw new Error(`Failed to fetch previous ciphertext: ${response.statusText}`)

  const body: unknown = await response.json()
  if (
    typeof body !== 'object' ||
    body === null ||
    !('ciphertext' in body) ||
    !Array.isArray(body.ciphertext) ||
    !body.ciphertext.every((value: unknown) => typeof value === 'number' && Number.isInteger(value) && value >= 0 && value <= 255)
  ) {
    throw new Error('Previous ciphertext response contains invalid bytes')
  }

  if (!('index' in body) || typeof body.index !== 'number' || !Number.isInteger(body.index) || body.index < 0) {
    throw new Error('Previous ciphertext response has no usable index')
  }

  return { ciphertext: new Uint8Array(body.ciphertext), index: body.index }
}

export type VotingStep = 'idle' | 'signing' | 'encrypting' | 'generating_proof' | 'broadcasting' | 'confirming' | 'complete' | 'error'

/**
 * Whose slot a mask is written to: a randomly drawn eligible slot, the caller's own, or a named
 * slot of an ONCHAIN round, such as a Safe the caller co-owns.
 */
export type MaskTarget = 'random' | 'self' | { slot: Address }

/**
 * A vote for a Safe, encrypted without the slot head and signed by its owners (`useSafeBallot`).
 * `castVoteWithProof` names the parent and proves it like any other input.
 */
export type SafeBallot = { prepared: PreparedBallot; slotOwners: SlotOwners; signatures: Hex[] }

export type CastVoteWithProof = (
  pollSelected: Poll | null,
  isAMask?: boolean,
  maskTarget?: MaskTarget,
  safeBallot?: SafeBallot,
) => Promise<void>

const extractCleanErrorMessage = (errorMessage: string | undefined): string => {
  if (!errorMessage) return 'Failed to broadcast the vote. Please try again.'

  if (errorMessage.includes('Internal error') || errorMessage.includes('-32603')) {
    return 'Transaction failed. The blockchain rejected the vote. Please try again.'
  }
  if (errorMessage.includes('insufficient funds')) {
    return 'Insufficient funds to process the transaction.'
  }
  if (errorMessage.includes('nonce')) {
    return 'Transaction conflict. Please try again.'
  }
  if (errorMessage.includes('gas')) {
    return 'Transaction failed due to gas issues. Please try again.'
  }
  if (errorMessage.includes('reverted')) {
    return 'Transaction was reverted by the contract.'
  }

  if (errorMessage.length > 100) {
    return 'Vote broadcast failed. Please try again.'
  }

  return errorMessage
}

interface VoteData {
  vote: Vote
  slotAddress: string
  balance: bigint
  signature: string
  messageHash: `0x${string}`
  error?: string
}

export const useVoteCasting = (customRoundState?: VoteStateLite | null, customVotingRound?: VotingRound | null) => {
  const {
    user,
    roundState: contextRoundState,
    votingRound: contextVotingRound,
    broadcastVote,
    setTxUrl,
    markVotedInRound,
    hasVotedInCurrentRound,
    getVoteAvailability,
  } = useVoteManagementContext()

  const roundState = customRoundState ?? contextRoundState
  const votingRound = customVotingRound ?? contextVotingRound

  const { signTypedDataAsync } = useSignTypedData()
  const publicClient = usePublicClient()
  const { data: walletClient } = useWalletClient()
  const chainId = useChainId()
  const { getEligibleVoters, getMerkleLeaves } = useInterfoldServer()
  const { showToast } = useNotificationAlertContext()
  const navigate = useNavigate()
  const [isVoting, setIsVoting] = useState<boolean>(false)
  const [isMasking, setIsMasking] = useState<boolean>(false)
  const [votingStep, setVotingStep] = useState<VotingStep>('idle')
  const [lastActiveStep, setLastActiveStep] = useState<VotingStep | null>(null)
  const [stepMessage, setStepMessage] = useState<string>('')
  const submissionInProgress = useRef(false)
  // A queued-commitment wait outlives the page that started it. Stop it on unmount, so that an
  // abandoned wait cannot open a wallet prompt or navigate from another page, and cannot run beside
  // the wait that a remounted page starts for the same job.
  const unmounted = useRef(false)
  useEffect(() => {
    unmounted.current = false
    return () => {
      unmounted.current = true
    }
  }, [])

  /**
   * Encrypt the ballot, have the voter sign the digest that binds it, then prove it.
   *
   * The order matters and cannot be rearranged: the digest commits to the ciphertext, so the
   * ballot has to exist before there is anything to sign. That is why signing happens here rather
   * than up front in `handleVote`.
   *
   * A mask follows the same path and carries the same digest — `publishInput` computes one for
   * every input regardless of branch, so a mask that skipped it would be rejected, and one that
   * looked different on chain would defeat the point of masking.
   *
   * The two census families differ only in how eligibility reaches the circuit. A Merkle round
   * proves membership of the census tree from `merkleLeaves`; an ONCHAIN round proves against the
   * voting power `CRISPProgram.votingPowerOf` reports, read from the same contract that will
   * verify the proof so the two cannot drift.
   */
  const handleProofGeneration = useCallback(
    async (
      vote: Vote,
      address: string,
      balance: bigint,
      isAMask: boolean,
      merkleLeaves: bigint[] | undefined,
      safeBallot?: SafeBallot,
    ): Promise<string | undefined> => {
      if (!votingRound) throw new Error('No voting round available for proof generation')
      if (!roundState) throw new Error('No round state available for proof generation')
      if (!publicClient) throw new Error('No RPC client available for proof generation')

      try {
        const publicKey = new Uint8Array(votingRound.pk_bytes)
        const head = await getSlotHead(votingRound.round_id, address)
        const e3Id = BigInt(votingRound.round_id)
        const slot = address as `0x${string}`
        const isOnchain = roundState.census_mode === CensusMode.Onchain

        const { crispProgram, paramSet } = await getCrispRoundConfig(publicClient, roundState.interfold_address as `0x${string}`, e3Id)

        const ballotBase = {
          vote,
          publicKey,
          slotAddress: address,
          isMaskVote: isAMask,
          numOptions: NUM_OPTIONS,
        } as const

        // Typed as the full input union: the head fields are optional-undefined in the SDK type,
        // so a ballot without them still satisfies it, and a plain `Omit` would collapse the
        // census discriminant.
        let ballot: PrepareBallotInputs
        if (isOnchain) {
          // The exact value `publishInput` will hand the circuit as public input 4.
          const votingPower = await getVotingPower(publicClient, crispProgram, e3Id, slot)
          if (safeBallot && votingPower.toString() !== safeBallot.prepared.circuitInputs.voting_power) {
            throw new Error('The Safe’s voting power changed since its owners signed. Prepare the ballot again.')
          }
          ballot = { ...ballotBase, censusMode: 'onchain', votingPower }
        } else {
          if (!merkleLeaves || merkleLeaves.length === 0) {
            throw new Error('No merkle leaves available for proof generation')
          }
          ballot = { ...ballotBase, censusMode: 'merkle', balance, merkleLeaves }
        }

        await ensureCircuits(paramSet)
        // The slot head is passed as a pair or not at all. A ciphertext without its index would be
        // proven against one entry and published against another, so the SDK types the two together
        // and this branches rather than spreading them as separate optional fields. A Safe vote was
        // encrypted before the head was read, so it names the parent now; see `withBallotParent`.
        const prepared = safeBallot
          ? withBallotParent(safeBallot.prepared, head && { index: head.index, commitment: ciphertextCommitment(head.ciphertext) })
          : await prepareBallot(head ? { ...ballot, previousCiphertext: head.ciphertext, previousIndex: head.index } : ballot)

        const authorization = await getBallotAuthorization(publicClient, crispProgram, e3Id, slot, prepared.ctCommitment)

        // A mask is not signed. The circuit skips the signature check on that branch, so the
        // placeholder the SDK supplies is enough. The owner commitment keeps a mask on a Safe slot
        // identical in its public inputs to a vote by the Safe.
        if (isAMask) {
          return encodeSolidityProof(await finishMaskProof(prepared, authorization.digest, authorization.ownersCommitment))
        }

        if (safeBallot) {
          if (authorization.ownersCommitment !== ownersCommitment(safeBallot.slotOwners)) {
            throw new Error('The Safe’s owners or threshold changed since its owners signed. Load the Safe and prepare again.')
          }
          return encodeSolidityProof(
            await finishSafeBallotProof(prepared, authorization.digest, safeBallot.slotOwners, safeBallot.signatures),
          )
        }

        if (authorization.safe) {
          throw new Error(
            'This account is a Safe, which cannot sign. Connect the wallet of one of its owners and use “Vote as a Safe” to collect the owner signatures.',
          )
        }

        setVotingStep('signing')
        setLastActiveStep('signing')
        setStepMessage('Please sign the ballot in your wallet...')

        const { domain, types, primaryType } = ballotTypedData(chainId, crispProgram)
        const signature = await signTypedDataAsync({
          domain,
          types,
          primaryType,
          message: { e3Id, slot, ciphertextCommitment: prepared.ctCommitment },
        })

        return encodeSolidityProof(await finishBallotProof(prepared, authorization.digest, signature))
      } catch (error) {
        // Logged and rethrown, not shown. `castVoteWithProof` already toasts what it catches, and
        // toasting here as well gave a rejected wallet prompt two notifications.
        const message = error instanceof Error ? error.message : String(error)
        handleGenericError('generateProof', error instanceof Error ? error : new Error(message))
        throw error
      }
    },
    [votingRound, roundState, publicClient, chainId, signTypedDataAsync],
  )

  const resetVotingState = useCallback(() => {
    setVotingStep('idle')
    setLastActiveStep(null)
    setStepMessage('')
    setIsVoting(false)
    setIsMasking(false)
  }, [])

  /**
   * Handles masking a vote, either of a random eligible slot or of the caller's own.
   *
   * Both targets matter for deniability, in different directions. Masking a random voter gives
   * *their* slot a later entry that might be their update. Masking your own slot is what makes
   * your own on-chain activity ambiguous: once self-masks are something people actually do, an
   * observer who sees your address write to your slot again cannot read it as "voted, then
   * updated" — it is just as plausibly "voted, then self-masked", or even two masks and no vote
   * at all. The circuit has always allowed it — the mask path checks slot eligibility, never who
   * submits — this only surfaces it.
   *
   * A Merkle round draws the target from the census the server built. An ONCHAIN round reads the
   * registrant list from the round's token instead — the server's list is discovered once at
   * round start, and a registry admits voters during the input window, so only the chain knows
   * who is maskable now.
   *
   * `ballotAuthorization` reverts for a Safe above the ballot caps, so it cannot be masked. The
   * random draw skips such slots, so that registered oversized Safes cannot make masks fail.
   */
  const handleMask = useCallback(
    async (target: MaskTarget): Promise<VoteData> => {
      if (!user || !roundState) {
        throw new Error('Cannot mask vote: Missing user or round state.')
      }

      const empty = {
        vote: [0, 0],
        balance: 0n,
        signature: '',
        messageHash: '' as `0x${string}`,
      }

      try {
        if (roundState.census_mode === CensusMode.Onchain) {
          if (!publicClient) throw new Error('No RPC client available for masking')

          // A named slot needs nothing but its address: the mask proves against the values
          // `ballotAuthorization` returns for it, and checks no signature.
          if (typeof target === 'object') return { ...empty, slotAddress: target.slot }

          if (target === 'self') {
            const registered = await isRegisteredIn(publicClient, roundState.token_address as Address, user.address as Address).catch(
              () => null,
            )
            if (registered === false) {
              throw new Error('You are not registered for this round, so your slot cannot be masked. Register first.')
            }

            // The balance is unused on the onchain path: the circuit takes voting power as a
            // public input, and `handleProofGeneration` reads it from the contract.
            return { ...empty, slotAddress: user.address }
          }

          const e3Id = BigInt(roundState.id)
          const { crispProgram } = await getCrispRoundConfig(publicClient, roundState.interfold_address as Address, e3Id)
          for (let draw = 0; draw < MAX_MASK_DRAWS; draw++) {
            const randomTarget = await getRandomRegistrant(publicClient, roundState.token_address as Address)
            if (!randomTarget) throw new Error('Nobody has registered in this round yet, so there is no slot to mask')
            // The ciphertext commitment does not change whether the slot has a ballot.
            const maskable = await getBallotAuthorization(publicClient, crispProgram, e3Id, randomTarget, zeroHash).then(
              () => true,
              () => false,
            )
            if (maskable) return { ...empty, slotAddress: randomTarget }
          }
          throw new Error('Could not find a slot to mask. Try again.')
        }

        if (typeof target === 'object') throw new Error('A named slot can be masked only in an on-chain round.')

        const eligibleVoters = await getEligibleVoters(roundState.id)

        if (!eligibleVoters || eligibleVoters.length === 0) {
          throw new Error('No eligible voters available for masking')
        }

        if (target === 'self') {
          // The census leaf is hash(address, balance), so a self-mask must prove against the
          // balance the census recorded, not a locally assumed one.
          const self = eligibleVoters.find((voter) => voter.address.toLowerCase() === user.address.toLowerCase())
          if (!self) {
            throw new Error("Your address is not in this round's census, so your slot cannot be masked.")
          }

          return {
            ...empty,
            slotAddress: self.address,
            balance: BigInt(self.balance),
          }
        }

        const randomVoterToMask = getRandomVoterToMask(eligibleVoters)

        return {
          ...empty,
          slotAddress: randomVoterToMask.address,
          balance: BigInt(randomVoterToMask.balance),
        }
      } catch (error) {
        return {
          ...empty,
          slotAddress: '',
          error: (error as Error).message,
        }
      }
    },
    [user, roundState, publicClient, getEligibleVoters],
  )

  /**
   * Handles the voting process including signing the message.
   */
  const handleVote = useCallback(
    async (pollSelected: Poll, slotAddress: string): Promise<VoteData> => {
      if (!roundState) {
        throw new Error('No round state available for voting')
      }

      // No signing here. The ballot digest commits to the ciphertext, so there is nothing to sign
      // until the vote has been encrypted — the wallet prompt now happens inside
      // `handleProofGeneration`.

      // vote is either 0 or 1, so we need to encode the vote accordingly.
      const balance = 1n
      const vote = pollSelected.value === 0 ? [Number(balance), 0] : [0, Number(balance)]

      return {
        signature: '',
        messageHash: '' as `0x${string}`,
        vote,
        slotAddress,
        balance,
      }
    },
    [roundState],
  )

  const castVoteWithProof: CastVoteWithProof = useCallback(
    async (pollSelected: Poll | null, isAMask: boolean = false, maskTarget: MaskTarget = 'random', safeBallot?: SafeBallot) => {
      if (!user || !roundState) {
        console.error('Cannot cast vote: Missing user or round state.')
        showToast({
          type: 'danger',
          message: 'Cannot cast vote. Ensure you are connected, and the round is active.',
          persistent: true,
        })
        return
      }

      // One account has one durable resume pointer per round. Do not let concurrent actions
      // replace that pointer before the first request records its job ID.
      if (submissionInProgress.current) return
      submissionInProgress.current = true

      const pendingJobKey = availabilityJobKey(chainId, roundState.id, user.address)

      const finishCommitment = async (
        response: BroadcastVoteResponse,
        operationIsMask: boolean,
        isSafeVote: boolean | undefined,
        afterRestage = false,
      ): Promise<boolean> => {
        if (response.status === 'failed_broadcast') {
          throw new Error(extractCleanErrorMessage(response.message ?? undefined))
        }

        if (response.status === 'pending_commitment') {
          setVotingStep('confirming')
          setStepMessage('Your proof is queued. Waiting for the server to send the commitment or to ask your wallet to send it...')
          const decided = response.job_id
            ? await waitForCommitmentDecision(response.job_id, getVoteAvailability, () => unmounted.current)
            : undefined
          // The page closed during the wait. Keep the job pointer so that the next action resumes it.
          if (unmounted.current) return false
          if (decided === null) {
            // The server lost the job while this page waited. Stage the stored bytes again once;
            // a second loss in the same action is left to the next one.
            const stored = readAvailabilityJob(pendingJobKey)
            if (!afterRestage && stored) return restagePendingJob(stored)
            throw new Error('The server lost the pending proof. Repeat the action to submit it again.')
          }
          if (decided) {
            if (decided.status === 'failed_broadcast') clearAvailabilityJob(pendingJobKey)
            return finishCommitment(decided, operationIsMask, isSafeVote, afterRestage)
          }

          setStepMessage('Your proof is still queued. Come back later and repeat the action to finish it.')
          showToast({
            type: 'success',
            message: 'Proof queued. Repeat the action later: your wallet may need to send the commitment.',
          })
          return false
        }

        let txHash: string | undefined = response.tx_hash ?? undefined
        if (response.status === 'ready_for_commitment') {
          if (!walletClient || !publicClient) {
            throw new Error('No wallet available to commit the vote proof')
          }

          setStepMessage('Please confirm the transaction in your wallet...')

          const e3Id = BigInt(roundState.id)
          const crispProgram = await getCrispProgramAddress(publicClient, roundState.interfold_address as `0x${string}`, e3Id)
          if (!response.encoded_proof) {
            throw new Error('Availability job is missing the input commitment payload')
          }
          // The page closed while the program address loaded. Keep the job pointer so that the next
          // action resumes it, and open no wallet prompt from a closed page.
          if (unmounted.current) return false
          txHash = await submitInputCommitmentDirectly(
            walletClient,
            publicClient,
            crispProgram,
            e3Id,
            response.encoded_proof as `0x${string}`,
          )
        }

        setVotingStep('complete')
        const finalized = response.status === 'success'
        setStepMessage(
          finalized
            ? `${operationIsMask ? 'Masking' : 'Vote'} finalized successfully!`
            : `${operationIsMask ? 'Masking' : 'Vote'} committed. Availability will finalize in the background.`,
        )

        const url = txHash ? txExplorerUrl(txHash) : undefined
        setTxUrl(url)

        if (!operationIsMask && !isSafeVote) markVotedInRound(roundState.id)

        showToast({
          type: 'success',
          message: finalized
            ? operationIsMask
              ? 'Slot masked successfully'
              : 'Vote finalized successfully!'
            : operationIsMask
              ? 'Mask committed. You can safely leave this page.'
              : 'Vote committed. You can safely leave this page.',
          linkUrl: url,
        })
        navigate(`/result/${roundState.id}/confirmation`)
        return true
      }

      // The server lost its job database. Re-stage the same bytes: a fresh ciphertext could leave
      // an earlier on-chain commitment unresolved and stop the complete round.
      const restagePendingJob = async (pendingJob: PendingAvailabilityJob): Promise<boolean> => {
        if (!pendingJob.encodedProof) {
          throw new Error('The server lost this legacy vote job. An operator must recover it before another vote is submitted.')
        }
        const restaged = await broadcastVote({ round_id: roundState.id, encoded_proof: pendingJob.encodedProof }, (jobId) =>
          writeAvailabilityJob(pendingJobKey, { ...pendingJob, jobId }),
        )
        if (!restaged) throw new Error('Could not restore the pending data-availability job.')
        if (restaged.status === 'failed_broadcast') clearAvailabilityJob(pendingJobKey)
        return finishCommitment(restaged, pendingJob.isMask, pendingJob.isSafeVote, true)
      }

      try {
        const pendingJob = readAvailabilityJob(pendingJobKey)
        // Following the earlier job can leave the page, and a Safe ballot lives only in the panel,
        // so refuse rather than lose the owners' signatures.
        if (pendingJob && safeBallot) {
          throw new Error('An earlier input from this account is still pending. Follow it with Cast or Mask, then submit the Safe vote.')
        }
        if (pendingJob) {
          setIsMasking(pendingJob.isMask)
          setIsVoting(!pendingJob.isMask)
          setVotingStep('broadcasting')
          setLastActiveStep('broadcasting')
          setStepMessage('Checking the durable vote job...')

          const resumed = await getVoteAvailability(pendingJob.jobId)
          if (resumed === null) {
            if (await restagePendingJob(pendingJob)) {
              clearAvailabilityJob(pendingJobKey)
            }
            return
          } else {
            if (!resumed) throw new Error('Could not read the pending data-availability job.')
            if (resumed.status === 'failed_broadcast') clearAvailabilityJob(pendingJobKey)
            if (await finishCommitment(resumed, pendingJob.isMask, pendingJob.isSafeVote)) {
              clearAvailabilityJob(pendingJobKey)
            }
            return
          }
        }

        if (!isAMask && !pollSelected && !safeBallot) {
          console.log('Cannot cast vote: Poll option not selected.')
          showToast({ type: 'danger', message: 'Please select a poll option first.' })
          return
        }

        let voteData

        const isOnchain = roundState.census_mode === CensusMode.Onchain

        if (isAMask) {
          setIsMasking(true)
          voteData = await handleMask(maskTarget)
        } else if (safeBallot) {
          setIsVoting(true)
          // The vote is already encrypted and signed; only the slot matters from here.
          voteData = {
            vote: [],
            slotAddress: safeBallot.prepared.circuitInputs.slot_address,
            balance: 0n,
            signature: '',
            messageHash: '0x',
          }
        } else {
          setIsVoting(true)

          // An unregistered voter's proof would only fail at the relay's simulation with an
          // opaque revert, so catch it here where the fix — registering — can be named. Best
          // effort: a round whose token is not a readable registry skips the check and lets the
          // relay's simulation be the arbiter.
          if (isOnchain && publicClient) {
            const registered = await isRegisteredIn(publicClient, roundState.token_address as Address, user.address as Address).catch(
              () => null,
            )
            if (registered === false) {
              throw new Error('You are not registered for this round. Register first, then vote.')
            }
          }

          voteData = await handleVote(pollSelected!, user.address)
        }

        if (voteData.error) {
          throw new Error(voteData.error)
        }

        // Step 2: Encrypting vote
        setVotingStep('encrypting')
        setLastActiveStep('encrypting')
        setStepMessage('')

        // A Merkle witness only exists for the census families that build a tree. An ONCHAIN
        // round has no census tree — eligibility is read from the token per input.
        const merkleLeaves = isOnchain ? undefined : await getMerkleLeaves(roundState.id)

        const encodedProof = await handleProofGeneration(
          voteData.vote,
          voteData.slotAddress,
          voteData.balance,
          isAMask,
          merkleLeaves?.map((s: string) => BigInt(`0x${s}`)),
          safeBallot,
        )

        if (!encodedProof) {
          throw new Error('Failed to encrypt vote.')
        }

        // Step 3: Generating proof
        setVotingStep('generating_proof')
        setLastActiveStep('generating_proof')

        // small delay for UX
        await new Promise((resolve) => setTimeout(resolve, 500))

        // Step 4: Broadcasting. The server either relays the commitment or answers
        // `ready_for_commitment`, and `finishCommitment` then sends it from the wallet.
        setVotingStep('broadcasting')
        setLastActiveStep('broadcasting')

        const voteRequest: BroadcastVoteRequest = {
          round_id: roundState.id,
          encoded_proof: encodedProof,
        }
        const isSafeVote = Boolean(safeBallot)
        const broadcastVoteResponse = await broadcastVote(voteRequest, (jobId) => {
          writeAvailabilityJob(pendingJobKey, { jobId, isMask: isAMask, isSafeVote, encodedProof })
        })

        if (!broadcastVoteResponse) {
          throw new Error('Received no response after publishing vote data.')
        }
        if (broadcastVoteResponse.status === 'failed_broadcast') clearAvailabilityJob(pendingJobKey)
        if (await finishCommitment(broadcastVoteResponse, isAMask, isSafeVote)) {
          clearAvailabilityJob(pendingJobKey)
        }
      } catch (error) {
        console.error('Vote processing failed:', error)
        // A page that closed during the action shows no toast on the page that is open now. A kept
        // job pointer lets the next action resume the job and report its state.
        if (unmounted.current) return
        setVotingStep('error')
        showToast({
          type: 'danger',
          message: `Vote failed: ${error instanceof Error ? error.message : String(error)}`,
          persistent: true,
        })
      } finally {
        submissionInProgress.current = false
        setIsVoting(false)
        setIsMasking(false)
      }
    },
    [
      user,
      roundState,
      publicClient,
      walletClient,
      broadcastVote,
      setTxUrl,
      showToast,
      navigate,
      handleProofGeneration,
      markVotedInRound,
      handleMask,
      handleVote,
      getMerkleLeaves,
      getVoteAvailability,
      chainId,
    ],
  )

  return {
    castVoteWithProof,
    isVoting,
    isMasking,
    votingStep,
    lastActiveStep,
    stepMessage,
    resetVotingState,
    hasVotedInCurrentRound,
  }
}
