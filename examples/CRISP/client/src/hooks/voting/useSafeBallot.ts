// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { useCallback, useState } from 'react'
import { useChainId, usePublicClient, useSignTypedData } from 'wagmi'
import { BaseError, getAddress, isAddress, isHex, recoverAddress } from 'viem'
import type { Address, Hex } from 'viem'
import { prepareBallot } from '@crisp-e3/sdk'
import type { PreparedBallot } from '@crisp-e3/sdk'

import { useVoteManagementContext } from '@/context/voteManagement'
import { Poll } from '@/model/poll.model'
import { ensureCircuits } from '@/utils/circuits'
import { NUM_OPTIONS } from '@/utils/constants'
import { getCrispRoundConfig } from '@/utils/ballotDigest'
import { getVotingPower } from '@/utils/onchainCensus'
import { readSafeSlot, safeBallotTypedData, signRequestLink } from '@/utils/safeBallot'
import type { SafeSignRequest, SafeSlot } from '@/utils/safeBallot'
import type { CastVoteWithProof } from './useVoteCasting'

/** A ballot prepared for a Safe, waiting for its owners' signatures. */
type PendingSafeBallot = { prepared: PreparedBallot; request: SafeSignRequest; digest: Hex }

/**
 * Collect the signatures of several Safe owners for one ballot, then prove and submit it.
 *
 * The order is chosen so that nothing about a Safe vote differs from a mask to the CRISP server:
 *
 * 1. `prepare` encrypts the ballot with no slot head and builds the digest locally. It sends
 *    nothing to the CRISP server and calls nothing on the contract that names the ciphertext.
 * 2. The owners sign in their own wallets, from a link whose request stays in the URL fragment.
 * 3. `submit` hands the signed ballot to `castVoteWithProof`, which makes the same requests, in the
 *    same order, as for a mask, and names the parent only then (`withBallotParent`). However long
 *    the signing took, the server sees a normal input, and a mask that landed meanwhile cannot
 *    leave the vote on a stale parent.
 *
 * @param castVoteWithProof The page's own `useVoteCasting` function, so one step indicator, one
 * busy state and one resume pointer cover every input the page makes.
 */
export const useSafeBallot = (castVoteWithProof: CastVoteWithProof) => {
  const { user, roundState, votingRound } = useVoteManagementContext()
  const publicClient = usePublicClient()
  const chainId = useChainId()
  const { signTypedDataAsync } = useSignTypedData()

  const [safe, setSafe] = useState<SafeSlot | null>(null)
  const [pending, setPending] = useState<PendingSafeBallot | null>(null)
  const [signatures, setSignatures] = useState<Record<Address, Hex>>({})
  const [busy, setBusy] = useState<'loading' | 'preparing' | 'signing' | 'submitting' | 'masking' | null>(null)
  const [error, setError] = useState<string | null>(null)

  /** Run one step, showing its error. Resolves true when the step succeeded. */
  const run = useCallback(async (stage: NonNullable<typeof busy>, action: () => Promise<void>): Promise<boolean> => {
    setBusy(stage)
    setError(null)
    try {
      await action()
      return true
    } catch (e) {
      setError(e instanceof BaseError ? e.shortMessage : e instanceof Error ? e.message : String(e))
      return false
    } finally {
      setBusy(null)
    }
  }, [])

  const roundConfig = useCallback(async () => {
    if (!publicClient || !roundState) throw new Error('No active round.')
    return getCrispRoundConfig(publicClient, roundState.interfold_address as Address, BigInt(roundState.id))
  }, [publicClient, roundState])

  const loadSafe = useCallback(
    (address: string) =>
      run('loading', async () => {
        setSafe(null)
        setPending(null)
        setSignatures({})
        if (!isAddress(address)) throw new Error('Enter the address of the Safe.')
        if (!publicClient) throw new Error('No RPC client available.')
        const { crispProgram } = await roundConfig()
        setSafe(await readSafeSlot(publicClient, crispProgram, getAddress(address)))
      }),
    [run, publicClient, roundConfig],
  )

  const prepare = useCallback(
    (choice: Poll) =>
      run('preparing', async () => {
        if (!safe || !roundState || !votingRound || !publicClient) throw new Error('Load a Safe first.')
        setPending(null)
        setSignatures({})

        const e3Id = BigInt(roundState.id)
        const { crispProgram, paramSet } = await roundConfig()
        await ensureCircuits(paramSet)
        const votingPower = await getVotingPower(publicClient, crispProgram, e3Id, safe.address)
        if (votingPower === 0n) throw new Error('This Safe has no voting power in this round.')

        // No slot head: see `withBallotParent`. The parent is named when the vote is submitted.
        const prepared = await prepareBallot({
          censusMode: 'onchain',
          vote: choice.value === 0 ? [1, 0] : [0, 1],
          publicKey: new Uint8Array(votingRound.pk_bytes),
          votingPower,
          slotAddress: safe.address,
          isMaskVote: false,
          numOptions: NUM_OPTIONS,
        })
        const request: SafeSignRequest = {
          chainId,
          crispProgram,
          e3Id: roundState.id,
          safe: safe.address,
          ctCommitment: prepared.ctCommitment,
          owners: safe.owners,
          keyOwners: safe.keyOwners,
          threshold: safe.threshold,
          choice: choice.label,
        }
        setPending({ prepared, request, digest: safeBallotTypedData(request).digest })
      }),
    [run, safe, roundState, votingRound, publicClient, roundConfig, chainId],
  )

  const addSignature = useCallback(
    (signature: string) =>
      run('signing', async () => {
        if (!pending) throw new Error('Prepare the ballot first.')
        const trimmed = signature.trim()
        if (!isHex(trimmed) || trimmed.length !== 132) throw new Error('A signature is 65 bytes of hex, starting with 0x.')
        const signer = await recoverAddress({ hash: pending.digest, signature: trimmed })
        if (!pending.request.keyOwners.includes(signer)) {
          throw new Error(`This signature is by ${signer}, which is not an owner of the Safe, or it is over another ballot.`)
        }
        setSignatures((current) => ({ ...current, [signer]: trimmed }))
      }),
    [run, pending],
  )

  const signWithWallet = useCallback(
    () =>
      run('signing', async () => {
        if (!pending) throw new Error('Prepare the ballot first.')
        if (!user) throw new Error('Connect the wallet of one of the owners.')
        const account = getAddress(user.address)
        // An owner that is a contract, such as the Safe itself or a nested Safe connected through
        // WalletConnect, signs in its own app, which publishes the message. That would mark this
        // input as a vote, so only owners that sign with a key are asked.
        if (!pending.request.keyOwners.includes(account)) {
          throw new Error(
            pending.request.owners.includes(account)
              ? 'This owner is a contract and cannot sign a ballot. Connect the wallet of an owner that signs with a key.'
              : 'The connected wallet is not an owner of this Safe.',
          )
        }

        const signature = await signTypedDataAsync(safeBallotTypedData(pending.request).typedData)
        const signer = await recoverAddress({ hash: pending.digest, signature })
        if (signer !== account) throw new Error('The wallet signed something other than the ballot.')
        setSignatures((current) => ({ ...current, [signer]: signature }))
      }),
    [run, pending, user, signTypedDataAsync],
  )

  const submit = useCallback(
    () =>
      run('submitting', async () => {
        if (!pending) throw new Error('Prepare the ballot first.')
        const { owners, threshold } = pending.request
        if (Object.keys(signatures).length < threshold) throw new Error(`The Safe needs ${threshold} owner signatures.`)
        await castVoteWithProof(null, false, 'random', {
          prepared: pending.prepared,
          slotOwners: { owners, threshold },
          signatures: Object.values(signatures),
        })
      }),
    [run, pending, signatures, castVoteWithProof],
  )

  /** Mask the Safe's slot. Owners doing this is what makes their own writes to it ambiguous. */
  const maskSafe = useCallback(
    () =>
      run('masking', async () => {
        if (!safe) throw new Error('Load a Safe first.')
        await castVoteWithProof(null, true, { slot: safe.address })
      }),
    [run, safe, castVoteWithProof],
  )

  return {
    safe,
    pending,
    link: pending ? signRequestLink(pending.request) : null,
    signers: Object.keys(signatures) as Address[],
    busy,
    error,
    loadSafe,
    prepare,
    addSignature,
    signWithWallet,
    submit,
    maskSafe,
  }
}
