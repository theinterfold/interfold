// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import React from 'react'
import { WarningIcon } from '@phosphor-icons/react'

interface EnvironmentErrorProps {
  missingVars: string[]
}

/** Shown instead of the app when a contract address is not configured. */
const EnvironmentError: React.FC<EnvironmentErrorProps> = ({ missingVars }) => (
  <div className='flex min-h-screen items-center justify-center p-4'>
    <div className='card w-full max-w-2xl space-y-6 !p-8'>
      <div className='flex items-center gap-3'>
        <WarningIcon size={28} className='text-danger' />
        <h1 className='h2'>Configuration required</h1>
      </div>
      <p className='text-ink-2'>These environment variables must be set before the app can run:</p>
      <ul className='space-y-2'>
        {missingVars.map((name) => (
          <li key={name}>
            <code className='addr bg-danger-tint px-2 py-1 text-danger'>{name}</code>
          </li>
        ))}
      </ul>
      <div className='note'>
        Start the stack with <code className='addr'>pnpm dev:frontend</code>, which exports them from the local deployment, or copy{' '}
        <code className='addr'>.env.example</code> to <code className='addr'>.env</code> in the client directory and fill them in. Then
        restart the dev server.
      </div>
      <button onClick={() => window.location.reload()} className='btn block'>
        Reload page
      </button>
    </div>
  </div>
)

export default EnvironmentError
