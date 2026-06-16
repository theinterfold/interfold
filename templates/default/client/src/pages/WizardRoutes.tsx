// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import React, { useMemo } from 'react'
import { Routes, Route, Navigate } from 'react-router-dom'
import {
  NumberSquareOneIcon,
  NumberSquareTwoIcon,
  NumberSquareThreeIcon,
  NumberSquareFourIcon,
  NumberSquareFiveIcon,
} from '@phosphor-icons/react'

// Step components
import ConnectWallet from './steps/ConnectWallet'
import RequestComputation from './steps/RequestComputation'
import EnterInputs from './steps/EnterInputs'
import EncryptSubmit from './steps/EncryptSubmit'
import Results from './steps/Results'
import EnvironmentError from './components/EnvironmentError'
import SDKErrorDisplay from './components/SDKErrorDisplay'
import StepIndicator from './components/StepIndicator'
import { useWizard, WizardStep } from '../context/WizardContext'
import { MISSING_ENV_VARS } from '@/utils/env-config'
import Navbar from './components/Navbar'

interface StepConfig {
  step: WizardStep
  path: string
  component: React.ComponentType
  icon: React.ComponentType<any>
}

// Steps are defined below as an array of objects.
// Each entry specifies the wizard step, URL path, component, and icon for that step.
const STEPS: StepConfig[] = [
  { step: WizardStep.CONNECT_WALLET, path: '/step1', component: ConnectWallet, icon: NumberSquareOneIcon },
  { step: WizardStep.REQUEST_COMPUTATION, path: '/step2', component: RequestComputation, icon: NumberSquareTwoIcon },
  { step: WizardStep.ENTER_INPUTS, path: '/step3', component: EnterInputs, icon: NumberSquareThreeIcon },
  { step: WizardStep.ENCRYPT_SUBMIT, path: '/step4', component: EncryptSubmit, icon: NumberSquareFourIcon },
  { step: WizardStep.RESULTS, path: '/step5', component: Results, icon: NumberSquareFiveIcon },
]

/**
 * WizardRoutes component that manages the multi-step wizard flow for Interfold E3.
 * Handles routing between wizard steps, displays step indicators, and manages
 * error states for environment configuration and SDK errors.
 *
 * Dynamically sets up routes for each wizard step, only rendering the component
 * for the current step and redirecting to the currentStep's route otherwise.
 * This enforces linear navigation through the wizard.
 */
const WizardRoutes: React.FC = () => {
  const { currentStep, sdk } = useWizard()

  // Memoize the current step path to avoid unnecessary recalculations.
  const currentStepPath = useMemo(() => `/step${currentStep}`, [currentStep])

  // Early returns for error states.
  if (MISSING_ENV_VARS.length > 0) {
    return <EnvironmentError missingVars={MISSING_ENV_VARS} />
  }

  if (sdk.error) {
    return <SDKErrorDisplay error={sdk.error} />
  }

  return (
    <div className='min-h-screen bg-white/80 text-slate-900 backdrop-blur-sm'>
      <Navbar />

      <div className='container mx-auto px-4 py-8'>
        <StepIndicator currentStep={currentStep} steps={STEPS} />

        <div className='mx-auto max-w-2xl'>
          <Routes>
            <Route path='/' element={<Navigate to={currentStepPath} replace />} />
            {STEPS.map(({ step, path, component: Component }) => (
              <Route key={path} path={path} element={currentStep === step ? <Component /> : <Navigate to={currentStepPath} replace />} />
            ))}
            {/* Catch-all route for any unknown paths */}
            <Route path='*' element={<Navigate to={currentStepPath} replace />} />
          </Routes>
        </div>
      </div>
    </div>
  )
}

export default WizardRoutes
