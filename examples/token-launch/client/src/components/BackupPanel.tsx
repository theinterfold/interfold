// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import React, { useRef, useState } from 'react'
import type { UseSecrets } from '@/hooks/useSecrets'
import { formatError } from '@/utils/error-formatting'

/** Export and import of the bid secrets of one sale. The secret is the only way to claim. */
const BackupPanel: React.FC<{ secrets: UseSecrets }> = ({ secrets }) => {
  const input = useRef<HTMLInputElement>(null)
  const [message, setMessage] = useState<{ ok: boolean; text: string } | null>(null)

  const onFile = async (file: File | undefined) => {
    if (!file) return
    try {
      const count = await secrets.importFile(file)
      setMessage({ ok: true, text: `Imported ${count} bid ${count === 1 ? 'secret' : 'secrets'}.` })
    } catch (err) {
      setMessage({ ok: false, text: formatError(err) })
    } finally {
      if (input.current) input.current.value = ''
    }
  }

  return (
    <div className='space-y-3 border border-rule-strong bg-card p-4'>
      <p className='label !mb-0'>Bid secret backup</p>
      <p className='muted text-xs'>
        The secret of a bid is in this browser only. It is the only way to claim. If you lose it, you lose the tokens and the refund. Anyone
        who has the file can claim your bid. Keep it private.
      </p>
      <div className='flex flex-wrap gap-3'>
        <button type='button' onClick={secrets.exportFile} disabled={secrets.held.length === 0} className='btn sm'>
          Export backup file
        </button>
        <button type='button' onClick={() => input.current?.click()} className='btn ghost sm'>
          Import backup file
        </button>
        <input ref={input} type='file' accept='application/json,.json' hidden onChange={(event) => void onFile(event.target.files?.[0])} />
      </div>
      {message && <p className={`text-xs ${message.ok ? 'text-accent' : 'text-danger'}`}>{message.text}</p>}
    </div>
  )
}

export default BackupPanel
