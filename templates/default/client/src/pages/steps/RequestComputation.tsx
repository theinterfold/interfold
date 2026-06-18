// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import React, { useState, useEffect } from 'react'
import { CalculatorIcon } from '@phosphor-icons/react'
import CardContent from '../components/CardContent'
import Spinner from '../components/Spinner'
import ErrorDisplay from '../components/ErrorDisplay'
import { useWizard, WizardStep } from '../../context/WizardContext'
import { encodeComputeProviderParams, DEFAULT_COMPUTE_PROVIDER_PARAMS, DEFAULT_E3_CONFIG, calculateInputWindow } from '@interfold/sdk'
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

    const handleCommitteePublished = (event: any) => {
      const { e3Id, publicKey } = event.data
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
    }

    onInterfoldEvent(InterfoldEventType.E3_REQUESTED, handleE3Requested)
    onInterfoldEvent(RegistryEventType.COMMITTEE_PUBLISHED, handleCommitteePublished)

    return () => {
      off(InterfoldEventType.E3_REQUESTED, handleE3Requested)
      off(RegistryEventType.COMMITTEE_PUBLISHED, handleCommitteePublished)
    }
  }, [isInitialized, onInterfoldEvent, off, InterfoldEventType, RegistryEventType, setE3State])

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
        proofAggregationEnabled: false,
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
          <CalculatorIcon size={48} className='text-interfold-400' />
        </div>
        <p className='text-base font-extrabold uppercase text-slate-600/50'>Step 2: Request Computation</p>
        <div className='space-y-4'>
          <h3 className='text-lg font-semibold text-slate-700'>Request Encrypted Execution Environment</h3>
          <p className='leading-relaxed text-slate-600'>
            Request an E3 computation from Interfold's decentralized network. This initiates the selection of a Ciphernode Committee through
            cryptographic sortition, who will generate shared keys for securing your computation without any single point of trust.
          </p>
          <div className='rounded-lg border border-blue-200 bg-blue-50 p-4'>
            <p className='text-sm text-slate-600'>
              <strong>Process:</strong> Request E3 → Committee Selection via Sortition → Key Generation → Ready for Input
            </p>
          </div>

          {/* E3 State Progress */}
          {e3State.id !== null && (
            <div className='space-y-3'>
              <div className='rounded-lg border border-green-200 bg-green-50 p-4'>
                <p className='text-sm text-slate-600'>
                  <strong>✅ E3 ID:</strong> {String(e3State.id)}
                  <br />
                  <strong>Status:</strong> Computation requested
                </p>
              </div>

              {e3State.isCommitteePublished && e3State.publicKey ? (
                <div className='rounded-lg border border-interfold-200 bg-interfold-50 p-4'>
                  <p className='text-sm text-slate-600'>
                    <strong>🔑 Committee Published Public Key!</strong>
                    <br />
                    <strong>Public Key:</strong> {e3State.publicKey.slice(0, 20)}...{e3State.publicKey.slice(-10)}
                    <br />
                    Ready for encrypted input.
                  </p>
                </div>
              ) : (
                <div className='rounded-lg border border-yellow-200 bg-yellow-50 p-4'>
                  <div className='flex flex-col items-center space-x-2'>
                    <Spinner size={20} />
                    <p className='text-sm text-slate-600'>
                      <strong>⏳ Waiting for committee to publish public key...</strong>
                      <br />
                      The computation committee is being selected and will provide the public key shortly.
                    </p>
                  </div>
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
            <div className='rounded-lg border border-green-200 bg-green-50 p-4'>
              <p className='text-sm text-green-600'>
                <strong>✅ Transaction Successful!</strong>
                <br />
                Hash: {lastTransactionHash.slice(0, 10)}...{lastTransactionHash.slice(-8)}
              </p>
            </div>
          )}
        </div>

        {isRequesting && (
          <div className='mb-4 flex justify-center'>
            <Spinner />
          </div>
        )}

        <button
          onClick={handleRequestComputation}
          disabled={isRequesting || e3State.isRequested}
          className='w-full rounded-lg bg-interfold-400 px-6 py-3 font-semibold text-slate-800 transition-all duration-200 hover:bg-interfold-300 hover:shadow-md disabled:cursor-not-allowed disabled:bg-slate-300 disabled:text-slate-500'
        >
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
