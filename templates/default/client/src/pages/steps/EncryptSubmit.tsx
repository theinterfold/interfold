// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import React, { useState, useEffect } from 'react'
import { LockIcon, CheckCircleIcon, WarningCircleIcon } from '@phosphor-icons/react'
import CardContent from '../components/CardContent'
import Spinner from '../components/Spinner'
import ErrorDisplay from '../components/ErrorDisplay'
import { useWizard, WizardStep } from '../../context/WizardContext'
import { decodePlaintextOutput } from '@interfold/sdk'

/**
 * EncryptSubmit component - Fourth step in the Interfold wizard flow
 *
 * This component handles the encryption and submission of user inputs to the E3.
 * It provides feedback on the encryption process and displays the status of the
 * submission to the E3.
 */
const EncryptSubmit: React.FC = () => {
  const { e3State, setE3State, setResult, setCurrentStep, inputPublishError, inputPublishSuccess, handleTryAgain, handleReset, sdk } =
    useWizard()
  const { isInitialized, onInterfoldEvent, off, InterfoldEventType } = sdk

  const [showErrorDetails, setShowErrorDetails] = useState(false)
  const [isExpired, setIsExpired] = useState(false)

  // Set up event listeners for this step
  useEffect(() => {
    if (!isInitialized) return

    const handleCiphertextOutput = (event: any) => {
      const { e3Id } = event.data
      setE3State((prev) => {
        if (prev.id !== null && e3Id === prev.id) {
          return { ...prev, isCiphertextPublished: true }
        }
        return prev
      })
    }

    const handlePlaintextOutput = (event: any) => {
      const { e3Id, plaintextOutput } = event.data
      setE3State((prev) => {
        if (prev.id !== null && e3Id === prev.id) {
          const decodedResult = decodePlaintextOutput(plaintextOutput)
          setResult(decodedResult)
          return {
            ...prev,
            plaintextOutput: plaintextOutput as string,
            hasPlaintextOutput: true,
          }
        }
        return prev
      })
    }

    onInterfoldEvent(InterfoldEventType.CIPHERTEXT_OUTPUT_PUBLISHED, handleCiphertextOutput)
    onInterfoldEvent(InterfoldEventType.PLAINTEXT_OUTPUT_PUBLISHED, handlePlaintextOutput)

    return () => {
      off(InterfoldEventType.CIPHERTEXT_OUTPUT_PUBLISHED, handleCiphertextOutput)
      off(InterfoldEventType.PLAINTEXT_OUTPUT_PUBLISHED, handlePlaintextOutput)
    }
  }, [isInitialized, onInterfoldEvent, off, InterfoldEventType, setE3State, setResult])

  // Check for E3 expiration
  useEffect(() => {
    if (!e3State.expiresAt || e3State.hasPlaintextOutput) return

    const checkExpiration = () => {
      const nowSeconds = BigInt(Math.floor(Date.now() / 1000))
      if (nowSeconds > e3State.expiresAt!) {
        setIsExpired(true)
      }
    }

    checkExpiration()
    const interval = setInterval(checkExpiration, 5000)
    return () => clearInterval(interval)
  }, [e3State.expiresAt, e3State.hasPlaintextOutput])

  // Auto-advance to results when output is available
  useEffect(() => {
    if (e3State.hasPlaintextOutput) {
      setCurrentStep(WizardStep.RESULTS)
    }
  }, [e3State.hasPlaintextOutput, setCurrentStep])

  // Progress steps for the computing phase
  const progressSteps = [
    { label: 'Inputs submitted', done: inputPublishSuccess },
    { label: 'FHE computation complete', done: e3State.isCiphertextPublished },
    { label: 'Committee decryption', done: e3State.hasPlaintextOutput },
  ]

  return (
    <CardContent>
      <div className='space-y-6 text-center'>
        <div className='flex justify-center'>
          <LockIcon size={48} className='text-interfold-400' />
        </div>
        <p className='text-base font-extrabold uppercase text-slate-600/50'>Step 4: Encrypting & Submitting</p>
        <div className='space-y-4'>
          <h3 className='text-lg font-semibold text-slate-700'>Secure Process Execution</h3>

          {isExpired && !e3State.hasPlaintextOutput && (
            <div className='space-y-4'>
              <div className='flex justify-center'>
                <WarningCircleIcon size={48} className='text-amber-500' />
              </div>
              <div role='alert' className='rounded-lg border border-amber-200 bg-amber-50 p-4'>
                <p className='text-sm text-amber-700'>
                  <strong>E3 Input Window Expired</strong>
                  <br />
                  The input deadline for this computation has passed. The computation may not have received enough inputs to produce a
                  result.
                </p>
              </div>
              <button
                onClick={handleReset}
                className='w-full rounded-lg bg-interfold-400 px-6 py-3 font-semibold text-slate-800 transition-all duration-200 hover:bg-interfold-300 hover:shadow-md'
              >
                Start New Computation
              </button>
            </div>
          )}

          {!isExpired && !inputPublishError && !inputPublishSuccess && (
            <div className='space-y-4'>
              <div className='flex justify-center'>
                <Spinner size={40} />
              </div>
              <p className='text-slate-600'>
                Your inputs are being encrypted to the committee's public key and submitted to the E3. The Compute Provider will execute the
                FHE computation over your encrypted data...
              </p>
              <div className='rounded-lg border border-blue-200 bg-blue-50 p-4'>
                <p className='text-sm text-slate-600'>
                  <strong>Process:</strong> Encrypt to Key → Submit to E3 → FHE Computation → Ciphertext Output
                </p>
              </div>
            </div>
          )}

          {inputPublishError && (
            <div className='space-y-4'>
              <ErrorDisplay
                error={inputPublishError}
                showDetails={showErrorDetails}
                onToggleDetails={() => setShowErrorDetails(!showErrorDetails)}
              />
              <button
                onClick={handleTryAgain}
                className='w-full rounded-lg bg-red-500 px-6 py-3 font-semibold text-white transition-all duration-200 hover:bg-red-600'
              >
                Try Again
              </button>
            </div>
          )}

          {!isExpired && inputPublishSuccess && (
            <div className='space-y-4'>
              <div className='flex justify-center'>
                <CheckCircleIcon size={48} className='text-green-500' />
              </div>

              {/* Progress tracker */}
              <div className='rounded-lg border border-slate-200 bg-slate-50 p-4'>
                <ul className='space-y-2 text-left'>
                  {progressSteps.map((step, i) => (
                    <li key={i} className='flex items-center gap-2 text-sm'>
                      {step.done ? <CheckCircleIcon size={18} className='flex-shrink-0 text-green-500' /> : <Spinner size={18} />}
                      <span className={step.done ? 'text-green-700' : 'text-slate-600'}>{step.label}</span>
                    </li>
                  ))}
                </ul>
              </div>

              {!e3State.isCiphertextPublished && (
                <div className='rounded-lg border border-yellow-200 bg-yellow-50 p-4'>
                  <p className='text-sm text-slate-600'>
                    The Compute Provider is executing the FHE computation over your encrypted inputs...
                  </p>
                </div>
              )}

              {e3State.isCiphertextPublished && !e3State.hasPlaintextOutput && (
                <div className='rounded-lg border border-yellow-200 bg-yellow-50 p-4'>
                  <p className='text-sm text-slate-600'>
                    Ciphertext output published. Waiting for the Ciphernode Committee to collectively decrypt the result...
                  </p>
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </CardContent>
  )
}

export default EncryptSubmit
