// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import React, { useState, useEffect, useRef } from 'react'
import { CalculatorIcon } from '@phosphor-icons/react'
import { bytesToHex, hexToBytes } from 'viem'
import type { CommitteePublicKeyChunkPublishedData } from '@interfold/sdk'
import CardContent from '../components/CardContent'
import Spinner from '../components/Spinner'
import ErrorDisplay from '../components/ErrorDisplay'
import { useWizard, WizardStep } from '../../context/WizardContext'
import {
  CommitteePublicKeyAssembler,
  encodeComputeProviderParams,
  DEFAULT_COMPUTE_PROVIDER_PARAMS,
  DEFAULT_E3_CONFIG,
  calculateInputWindow,
} from '@interfold/sdk'
import { getContractAddresses } from '@/utils/env-config'

/**
 * RequestComputation component - Second step in the Interfold wizard flow
 *
 * This component handles the request for an E3 computation from the Interfold network.
 * It provides feedback on the request process and displays the status of the request.
 */
const RequestComputation: React.FC = () => {
  const { e3State, setE3State, setLastTransactionHash, setCurrentStep, sdk } = useWizard()
  const { isInitialized, requestE3, onInterfoldEvent, off, InterfoldEventType, RegistryEventType } = sdk

  const contracts = getContractAddresses()

  const [isRequesting, setIsRequesting] = useState(false)
  const [requestError, setRequestError] = useState<any>(null)
  const [requestSuccess, setRequestSuccess] = useState(false)
  const [lastTransactionHash, setLocalTransactionHash] = useState<string | undefined>()
  const [showErrorDetails, setShowErrorDetails] = useState(false)
  const committeeKeyAssembler = useRef(new CommitteePublicKeyAssembler())

  // Set up event listeners for this step
  useEffect(() => {
    if (!isInitialized) return

    const handleE3Requested = (event: any) => {
      const { e3Id, e3 } = event.data
      setE3State((prev) => ({
        ...prev,
        id: e3Id,
        isRequested: true,
        expiresAt: e3.inputWindow?.[1] ?? null,
      }))
    }

    const handleCommitteeKeyChunk = async (event: { data: CommitteePublicKeyChunkPublishedData }) => {
      const { e3Id } = event.data
      if (e3State.id === null || e3Id !== e3State.id || !sdk.sdk) return

      try {
        const assembled = committeeKeyAssembler.current.add(event.data)
        if (!assembled) return

        const isBoundKey = await sdk.sdk.validatePublicKeyCommitment(assembled.publicKey, hexToBytes(assembled.pkCommitment))
        if (!isBoundKey) {
          console.warn(`Rejected committee public-key candidate for E3 ${e3Id}: commitment mismatch`)
          return
        }

        const publicKey = bytesToHex(assembled.publicKey)
        committeeKeyAssembler.current.clear(e3Id)
        setE3State((prev) => {
          if (prev.id !== null && e3Id === prev.id) {
            return {
              ...prev,
              isCommitteePublished: true,
              publicKey: publicKey as `0x${string}`,
            }
          }
          return prev
        })
      } catch (error) {
        console.warn(`Ignored invalid committee public-key chunk for E3 ${e3Id}:`, error)
      }
    }

    onInterfoldEvent(InterfoldEventType.E3_REQUESTED, handleE3Requested)
    onInterfoldEvent(RegistryEventType.COMMITTEE_PUBLIC_KEY_CHUNK_PUBLISHED, handleCommitteeKeyChunk)

    return () => {
      off(InterfoldEventType.E3_REQUESTED, handleE3Requested)
      off(RegistryEventType.COMMITTEE_PUBLIC_KEY_CHUNK_PUBLISHED, handleCommitteeKeyChunk)
    }
  }, [isInitialized, onInterfoldEvent, off, InterfoldEventType, RegistryEventType, setE3State, e3State.id, sdk.sdk])

  // Auto-advance to next step when committee publishes
  useEffect(() => {
    if (e3State.isCommitteePublished && e3State.publicKey) {
      setCurrentStep(WizardStep.ENTER_INPUTS)
    }
  }, [e3State.isCommitteePublished, e3State.publicKey, setCurrentStep])

  const handleRequestComputation = async () => {
    setIsRequesting(true)
    setRequestError(null)
    setRequestSuccess(false)

    // Reset E3 state
    setE3State({
      id: null,
      isRequested: false,
      isCommitteePublished: false,
      isCiphertextPublished: false,
      publicKey: null,
      expiresAt: null,
      plaintextOutput: null,
      hasPlaintextOutput: false,
    })

    try {
      if (!sdk.sdk) {
        throw new Error('SDK not initialized')
      }

      const committeeSize = DEFAULT_E3_CONFIG.committeeSize
      const publicClient = sdk.sdk.getPublicClient()

      const inputWindow = await calculateInputWindow(publicClient, 100) // 100 Seconds
      const computeProviderParams = encodeComputeProviderParams(DEFAULT_COMPUTE_PROVIDER_PARAMS)

      const requestParams = {
        committeeSize,
        inputWindow,
        e3Program: contracts.e3Program,
        paramSet: 0, // ParamSet.Insecure512
        computeProviderParams,
      }

      const fee = await sdk.sdk.getE3Quote(requestParams)
      const approveTx = await sdk.sdk.approveFeeToken(fee)
      await publicClient.waitForTransactionReceipt({ hash: approveTx })

      const hash = await requestE3(requestParams)

      setLocalTransactionHash(hash)
      setLastTransactionHash(hash)
      setRequestSuccess(true)
    } catch (error) {
      setRequestError(error)
      console.error('Error requesting computation:', error)
    } finally {
      setIsRequesting(false)
    }
  }

  return (
    <CardContent>
      <div className='space-y-6 text-center'>
        <div className='flex justify-center'>
          <CalculatorIcon size={48} className='text-accent-deep' />
        </div>
        <p className='eyebrow justify-center'>Step 2 · Request Computation</p>
        <div className='space-y-4'>
          <h3 className='text-2xl'>Request Encrypted Execution Environment</h3>
          <p className='leading-relaxed text-ink-3'>
            Request an E3 computation from Interfold's decentralized network. This initiates the selection of a Ciphernode Committee through
            cryptographic sortition, who will generate shared keys for securing your computation without any single point of trust.
          </p>
          <div className='note-accent text-left'>
            <strong className='font-semibold'>Process:</strong> Request E3 → Committee Selection via Sortition → Key Generation → Ready for
            Input
          </div>

          {/* E3 State Progress */}
          {e3State.id !== null && (
            <div className='space-y-3'>
              <div className='note-accent text-left'>
                <strong className='font-semibold'>✅ E3 ID:</strong> {String(e3State.id)}
                <br />
                <strong className='font-semibold'>Status:</strong> Computation requested
              </div>

              {e3State.isCommitteePublished && e3State.publicKey ? (
                <div className='note-accent text-left'>
                  <strong className='font-semibold'>🔑 Committee Published Public Key!</strong>
                  <br />
                  <strong className='font-semibold'>Public Key:</strong>{' '}
                  <span className='font-mono'>
                    {e3State.publicKey.slice(0, 20)}...{e3State.publicKey.slice(-10)}
                  </span>
                  <br />
                  Ready for encrypted input.
                </div>
              ) : (
                <div className='note-muted flex items-center gap-3 text-left'>
                  <Spinner size={20} />
                  <span>
                    <strong className='font-semibold text-ink-2'>Waiting for committee to publish public key…</strong> The computation
                    committee is being selected and will provide the public key shortly.
                  </span>
                </div>
              )}
            </div>
          )}

          {requestError && (
            <ErrorDisplay
              error={requestError}
              showDetails={showErrorDetails}
              onToggleDetails={() => setShowErrorDetails(!showErrorDetails)}
            />
          )}

          {requestSuccess && lastTransactionHash && (
            <div className='note-accent text-left'>
              <strong className='font-semibold'>✅ Transaction Successful!</strong>
              <br />
              Hash:{' '}
              <span className='font-mono'>
                {lastTransactionHash.slice(0, 10)}...{lastTransactionHash.slice(-8)}
              </span>
            </div>
          )}
        </div>

        {isRequesting && (
          <div className='mb-4 flex justify-center'>
            <Spinner />
          </div>
        )}

        <button onClick={handleRequestComputation} disabled={isRequesting || e3State.isRequested} className='btn-primary w-full'>
          {isRequesting
            ? 'Submitting to Blockchain...'
            : e3State.isRequested
              ? e3State.isCommitteePublished
                ? 'Committee Ready - Proceeding to Input!'
                : 'Waiting for Committee...'
              : 'Request E3 Computation (0.001 ETH)'}
        </button>
      </div>
    </CardContent>
  )
}

export default RequestComputation
