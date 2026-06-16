// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { useState, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import { useSignMessage } from 'wagmi'
import { CrispSDK, encodeSolidityProof } from '@crisp-e3/sdk'

import { useVoteManagementContext } from '@/context/voteManagement'
import { useNotificationAlertContext } from '@/context/NotificationAlert/NotificationAlert.context.tsx'
import { Poll } from '@/model/poll.model'
import { BroadcastVoteRequest, Vote, VoteStateLite, VotingRound } from '@/model/vote.model'
import { hashMessage } from 'viem'
import { useInterfoldServer } from '../interfold/useInterfoldServer'
import { getRandomVoterToMask } from '@/utils/voters'
import { handleGenericError } from '@/utils/handle-generic-error'
import { NUM_OPTIONS } from '@/utils/constants'

const INTERFOLD_API = import.meta.env.VITE_INTERFOLD_API

export type VotingStep = 'idle' | 'signing' | 'encrypting' | 'generating_proof' | 'broadcasting' | 'confirming' | 'complete' | 'error'

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
  } = useVoteManagementContext()

  const roundState = customRoundState ?? contextRoundState
  const votingRound = customVotingRound ?? contextVotingRound

  const { signMessageAsync } = useSignMessage()
  const { getEligibleVoters, getMerkleLeaves } = useInterfoldServer()
  const { showToast } = useNotificationAlertContext()
  const navigate = useNavigate()
  const [isVoting, setIsVoting] = useState<boolean>(false)
  const [isMasking, setIsMasking] = useState<boolean>(false)
  const [votingStep, setVotingStep] = useState<VotingStep>('idle')
  const [lastActiveStep, setLastActiveStep] = useState<VotingStep | null>(null)
  const [stepMessage, setStepMessage] = useState<string>('')

  const handleProofGeneration = useCallback(
    async (
      vote: Vote,
      address: string,
      balance: bigint,
      signature: string,
      messageHash: `0x${string}`,
      isAMask: boolean,
      merkleLeaves: bigint[],
    ): Promise<string | undefined> => {
      if (!votingRound) throw new Error('No voting round available for proof generation')

      try {
        const sdk = new CrispSDK(INTERFOLD_API)
        const publicKey = new Uint8Array(votingRound.pk_bytes)

        const proof = isAMask
          ? await sdk.generateMaskVoteProof({
              e3Id: votingRound.round_id,
              publicKey,
              balance,
              slotAddress: address,
              merkleLeaves,
              numOptions: NUM_OPTIONS,
            })
          : await sdk.generateVoteProof({
              vote,
              e3Id: votingRound.round_id,
              publicKey,
              signature: signature as `0x${string}`,
              merkleLeaves,
              balance,
              messageHash,
              slotAddress: address,
            })

        return encodeSolidityProof(proof)
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error)
        showToast({ type: 'danger', message })
        handleGenericError('generateProof', error instanceof Error ? error : new Error(message))
        throw error
      }
    },
    [votingRound, showToast],
  )

  const resetVotingState = useCallback(() => {
    setVotingStep('idle')
    setLastActiveStep(null)
    setStepMessage('')
    setIsVoting(false)
    setIsMasking(false)
  }, [])

  /**
   * Handles masking a vote by selecting a random eligible voter.
   */
  const handleMask = useCallback(async (): Promise<VoteData> => {
    if (!user || !roundState) {
      throw new Error('Cannot mask vote: Missing user or round state.')
    }

    const eligibleVoters = await getEligibleVoters(roundState.id)

    if (!eligibleVoters || eligibleVoters.length === 0) {
      throw new Error('No eligible voters available for masking')
    }

    try {
      const randomVoterToMask = getRandomVoterToMask(eligibleVoters)

      return {
        vote: [0, 0],
        slotAddress: randomVoterToMask.address,
        balance: BigInt(randomVoterToMask.balance),
        signature: '',
        messageHash: '' as `0x${string}`,
      }
    } catch (error) {
      return {
        vote: [0, 0],
        slotAddress: '',
        balance: 0n,
        signature: '',
        messageHash: '' as `0x${string}`,
        error: (error as Error).message,
      }
    }
  }, [user, roundState, getEligibleVoters])

  /**
   * Handles the voting process including signing the message.
   */
  const handleVote = useCallback(
    async (pollSelected: Poll, slotAddress: string): Promise<VoteData> => {
      if (!roundState) {
        throw new Error('No round state available for voting')
      }

      // Step 1: Signing
      setVotingStep('signing')
      setLastActiveStep('signing')
      setStepMessage('Please sign the message in your wallet...')

      const message = `Vote for round ${roundState.id}`
      const messageHash = hashMessage(message)

      // vote is either 0 or 1, so we need to encode the vote accordingly.
      const balance = 1n
      const vote = pollSelected.value === 0 ? [Number(balance), 0] : [0, Number(balance)]

      let signature: string
      try {
        signature = await signMessageAsync({ message })
        return {
          signature,
          messageHash,
          vote,
          slotAddress,
          balance,
        }
      } catch (error) {
        console.log('User rejected signature or signing failed', error)
        resetVotingState()
        return {
          signature: '',
          messageHash: '' as `0x${string}`,
          vote: [0, 0],
          slotAddress: '',
          balance: 0n,
          error: 'User rejected signature or signing failed',
        }
      }
    },
    [roundState, signMessageAsync, resetVotingState],
  )

  const castVoteWithProof = useCallback(
    async (pollSelected: Poll | null, isAMask: boolean = false) => {
      if (!isAMask && !pollSelected) {
        console.log('Cannot cast vote: Poll option not selected.')
        showToast({ type: 'danger', message: 'Please select a poll option first.' })
        return
      }
      if (!user || !roundState) {
        console.error('Cannot cast vote: Missing user or round state.')
        showToast({
          type: 'danger',
          message: 'Cannot cast vote. Ensure you are connected, and the round is active.',
          persistent: true,
        })
        return
      }

      try {
        let voteData

        if (isAMask) {
          setIsMasking(true)
          voteData = await handleMask()
        } else {
          setIsVoting(true)
          voteData = await handleVote(pollSelected!, user.address)
        }

        if (voteData.error) {
          throw new Error(voteData.error)
        }

        // Step 2: Encrypting vote
        setVotingStep('encrypting')
        setLastActiveStep('encrypting')
        setStepMessage('')

        const merkleLeaves = await getMerkleLeaves(roundState.id)

        if (!merkleLeaves || merkleLeaves?.length === 0) {
          throw new Error('No merkle leaves available for proof generation')
        }

        const encodedProof = await handleProofGeneration(
          voteData.vote,
          voteData.slotAddress,
          voteData.balance,
          voteData.signature,
          voteData.messageHash,
          isAMask,
          merkleLeaves.map((s: string) => BigInt(`0x${s}`)),
        )

        if (!encodedProof) {
          throw new Error('Failed to encrypt vote.')
        }

        // Step 3: Generating proof
        setVotingStep('generating_proof')
        setLastActiveStep('generating_proof')

        // small delay for UX
        await new Promise((resolve) => setTimeout(resolve, 500))

        // Step 4: Broadcasting
        setVotingStep('broadcasting')
        setLastActiveStep('broadcasting')

        const voteRequest: BroadcastVoteRequest = {
          round_id: roundState.id,
          encoded_proof: encodedProof,
          address: voteData.slotAddress,
        }

        const broadcastVoteResponse = await broadcastVote(voteRequest)

        if (broadcastVoteResponse) {
          switch (broadcastVoteResponse.status) {
            case 'success': {
              setVotingStep('complete')
              setStepMessage(`${isAMask ? 'Masking' : 'Vote'} submitted successfully!'`)

              const url = `https://sepolia.etherscan.io/tx/${broadcastVoteResponse.tx_hash}`
              setTxUrl(url)

              if (!isAMask) markVotedInRound(roundState.id)

              const successMessage = isAMask
                ? 'Slot masked successfully'
                : broadcastVoteResponse.is_vote_update
                  ? 'Vote updated successfully!'
                  : 'Vote submitted successfully!'
              showToast({
                type: 'success',
                message: successMessage,
                linkUrl: url,
              })
              navigate(`/result/${roundState.id}/confirmation`)
              break
            }
            case 'failed_broadcast':
              setVotingStep('error')
              showToast({
                type: 'danger',
                message: extractCleanErrorMessage(broadcastVoteResponse.message),
                persistent: true,
              })
              break
            default:
              setVotingStep('error')
              showToast({
                type: 'danger',
                message: extractCleanErrorMessage(broadcastVoteResponse.message),
                persistent: true,
              })
              break
          }
        } else {
          throw new Error('Received no response after broadcasting vote.')
        }
      } catch (error) {
        setVotingStep('error')
        console.error('Vote processing failed:', error)
        showToast({
          type: 'danger',
          message: `Vote failed: ${error instanceof Error ? error.message : String(error)}`,
          persistent: true,
        })
      } finally {
        setIsVoting(false)
        setIsMasking(false)
      }
    },
    [
      user,
      roundState,
      broadcastVote,
      setTxUrl,
      showToast,
      navigate,
      handleProofGeneration,
      markVotedInRound,
      handleMask,
      handleVote,
      getMerkleLeaves,
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
