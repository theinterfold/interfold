// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import React, { useState } from 'react'
import { CheckIcon, CopyIcon } from '@phosphor-icons/react'
import { shortId } from '@/utils/format'

/** A long id in its short form, with the full value in the tooltip and a button to copy it. */
const CopyId: React.FC<{ id: bigint }> = ({ id }) => {
  const [state, setState] = useState<'idle' | 'copied' | 'failed'>('idle')
  const full = id.toString()
  return (
    <button
      type='button'
      title={full}
      aria-label={`Copy id ${full}`}
      className='id-chip'
      onClick={() => {
        const done = (next: 'copied' | 'failed') => {
          setState(next)
          setTimeout(() => setState('idle'), 2000)
        }
        navigator.clipboard.writeText(full).then(
          () => done('copied'),
          () => done('failed'),
        )
      }}
    >
      <span>{shortId(id)}</span>
      {state === 'copied' ? <CheckIcon size={14} aria-hidden /> : <CopyIcon size={14} aria-hidden />}
      <span className='sr-only' aria-live='polite'>
        {state === 'copied' ? 'Copied' : state === 'failed' ? 'Copy failed' : ''}
      </span>
    </button>
  )
}

export default CopyId
