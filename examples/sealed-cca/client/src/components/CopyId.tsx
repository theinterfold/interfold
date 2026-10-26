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
  const [copied, setCopied] = useState(false)
  const full = id.toString()
  return (
    <button
      type='button'
      title={full}
      aria-label={`Copy id ${full}`}
      className='id-chip'
      onClick={() => {
        void navigator.clipboard.writeText(full).then(() => {
          setCopied(true)
          setTimeout(() => setCopied(false), 2000)
        })
      }}
    >
      <span>{shortId(id)}</span>
      {copied ? <CheckIcon size={14} aria-hidden /> : <CopyIcon size={14} aria-hidden />}
      <span className='sr-only' aria-live='polite'>
        {copied ? 'Copied' : ''}
      </span>
    </button>
  )
}

export default CopyId
