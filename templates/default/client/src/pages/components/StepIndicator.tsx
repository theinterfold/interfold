// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import React from 'react'
import { WizardStep } from '../../context/WizardContext'

interface StepConfig {
  step: WizardStep
  icon: React.ComponentType<any>
}

interface StepIndicatorProps {
  currentStep: WizardStep
  steps: StepConfig[]
}

const StepIndicator: React.FC<StepIndicatorProps> = React.memo(({ currentStep, steps }) => {
  return (
    <div className='mb-8 flex justify-center'>
      <div className='flex items-center space-x-2'>
        {steps.map(({ step, icon: IconComponent }, index) => {
          const isActive = currentStep >= step
          const isCompleted = currentStep > step

          return (
            <div key={step} className='flex items-center'>
              <div
                className={`flex h-10 w-10 items-center justify-center rounded-full border transition-all duration-200 ${
                  isActive ? 'border-interfold-400 bg-white/80 text-interfold-600' : 'border-slate-400 bg-white/80 text-slate-400'
                }`}
              >
                <IconComponent size={24} className={isActive ? 'text-interfold-500' : 'text-slate-400'} />
              </div>
              {index < steps.length - 1 && (
                <div className={`mx-2 h-0.5 w-8 transition-all duration-200 ${isCompleted ? 'bg-interfold-400' : 'bg-slate-300'}`} />
              )}
            </div>
          )
        })}
      </div>
    </div>
  )
})

export default StepIndicator
