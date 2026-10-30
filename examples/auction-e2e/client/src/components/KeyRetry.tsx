// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import React from 'react'

/** The note that shows while the committee key is missing: it says what went wrong and offers a retry. */
export const KeyRetry: React.FC<{ error: string | null; onRetry: () => void }> = ({ error, onRetry }) =>
  error === null ? null : (
    <div role='alert' className='note bad flex flex-wrap items-center justify-between gap-3'>
      <span>Could not read the committee key: {error}</span>
      <button type='button' onClick={onRetry} className='btn ghost sm'>
        Try again
      </button>
    </div>
  )
