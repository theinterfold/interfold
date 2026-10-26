// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import React, { useEffect, useRef, useState } from 'react'
import { ImageIcon } from '@phosphor-icons/react'
import { formatError } from '@/utils/error-formatting'
import { MAX_IMAGE_SIDE, PICKER_TYPES, prepareImage } from '@/utils/image'
import Spinner from './Spinner'

/** The optional picture of the create form: a file picker, a preview of the shrunk picture and a remove button. */
export const PictureField: React.FC<{ value: Blob | null; onChange: (value: Blob | null) => void; disabled: boolean }> = ({
  value,
  onChange,
  disabled,
}) => {
  const input = useRef<HTMLInputElement>(null)
  const [preparing, setPreparing] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [preview, setPreview] = useState<string | null>(null)

  useEffect(() => {
    if (!value) {
      setPreview(null)
      return
    }
    const url = URL.createObjectURL(value)
    setPreview(url)
    return () => URL.revokeObjectURL(url)
  }, [value])

  const choose = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0]
    // Reset the input, so that the same file can be chosen again after a remove or an error.
    event.target.value = ''
    if (!file) return
    setError(null)
    setPreparing(true)
    try {
      onChange(await prepareImage(file))
    } catch (err) {
      setError(formatError(err))
    } finally {
      setPreparing(false)
    }
  }

  return (
    <div>
      <p className='label'>Picture (optional)</p>
      <div className='flex items-center gap-4'>
        <div className='flex h-24 w-24 shrink-0 items-center justify-center overflow-hidden rounded border border-rule bg-surface-muted text-muted-2'>
          {preview ? <img src={preview} alt='Preview of the picture' className='h-full w-full object-cover' /> : <ImageIcon size={28} />}
        </div>
        <div className='min-w-0 space-y-2'>
          <input ref={input} type='file' accept={PICKER_TYPES.join(',')} className='hidden' onChange={(event) => void choose(event)} />
          <div className='flex flex-wrap items-center gap-2'>
            <button type='button' className='btn ghost sm' disabled={disabled || preparing} onClick={() => input.current?.click()}>
              {preparing ? (
                <>
                  <Spinner size={14} /> Preparing…
                </>
              ) : value ? (
                'Change picture'
              ) : (
                'Choose a picture'
              )}
            </button>
            {value && (
              <button type='button' className='btn ghost sm' disabled={disabled || preparing} onClick={() => onChange(null)}>
                Remove
              </button>
            )}
          </div>
          <p className='text-xs text-muted'>
            {value
              ? `${Math.max(1, Math.round(value.size / 1024))} KB after shrinking. Your wallet signs the upload once the negotiation is created.`
              : `PNG, JPEG or WebP. Your browser shrinks it to ${MAX_IMAGE_SIDE} px. The server stores it and anyone can see it.`}
          </p>
        </div>
      </div>
      {error && <p className='mt-1 text-xs text-negative'>{error}</p>}
    </div>
  )
}
