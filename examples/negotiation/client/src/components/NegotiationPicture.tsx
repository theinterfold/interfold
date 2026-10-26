// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import React, { useEffect, useRef, useState } from 'react'
import { ImageIcon } from '@phosphor-icons/react'
import { useWalletClient } from 'wagmi'
import { chain } from '@/utils/chain'
import { formatError } from '@/utils/error-formatting'
import { imageUrl, PICKER_TYPES, prepareImage, uploadImage } from '@/utils/image'
import Spinner from './Spinner'

export type PictureStatus = 'loading' | 'present' | 'none'

/**
 * Whether the server holds a picture of a negotiation, and its URL. The check loads the picture once, so
 * the `<img>` that shows it next finds it in the cache. `version` changes the URL after a replacement:
 * the earlier picture stays on screen until the new one has loaded.
 */
export function usePicture(e3Id: bigint | null, version?: number): { url: string | null; status: PictureStatus } {
  const [state, setState] = useState<{ e3Id: bigint | null; url: string | null; status: PictureStatus }>({
    e3Id: null,
    url: null,
    status: 'loading',
  })

  useEffect(() => {
    if (e3Id === null) return
    const url = imageUrl(e3Id, version)
    let cancelled = false
    const probe = new Image()
    // The page is cross-origin isolated: the server must answer with CORS for the picture to load.
    probe.crossOrigin = 'anonymous'
    probe.onload = () => {
      if (!cancelled) setState({ e3Id, url, status: 'present' })
    }
    probe.onerror = () => {
      if (!cancelled) setState({ e3Id, url: null, status: 'none' })
    }
    probe.src = url
    return () => {
      cancelled = true
    }
  }, [e3Id, version])

  // A state that belongs to another negotiation says nothing about this one.
  return state.e3Id === e3Id ? state : { url: null, status: 'loading' }
}

const FRAME = 'overflow-hidden rounded border border-rule bg-surface-muted'

/** A square picture of fixed size on a list row, or a placeholder of the same size: the row does not move when the picture loads. */
export const PictureThumb: React.FC<{ e3Id: bigint }> = ({ e3Id }) => {
  const { url, status } = usePicture(e3Id)
  return (
    <div className={`${FRAME} flex h-16 w-16 shrink-0 items-center justify-center text-muted-2`} aria-hidden>
      {status === 'present' && url ? (
        <img src={url} crossOrigin='anonymous' alt='' className='h-full w-full object-cover' />
      ) : (
        <ImageIcon size={24} />
      )}
    </div>
  )
}

/** The picture of a negotiation at full width, whole and not cropped. */
export const PictureHero: React.FC<{ url: string; title: string }> = ({ url, title }) => (
  <div className={`${FRAME} flex h-64 items-center justify-center sm:h-80 lg:h-[26rem]`}>
    <img src={url} crossOrigin='anonymous' alt={`Picture of ${title}`} className='h-full w-full object-contain' />
  </div>
)

const STEP_TEXT = {
  preparing: 'Preparing the picture…',
  signing: 'Sign the message in your wallet…',
  uploading: 'Uploading…',
} as const

/**
 * The creator's control to add or replace the picture of a negotiation. The wallet signs a message that
 * binds the bytes, and the server checks that the signer created the negotiation. It is also the retry of
 * an upload that failed when the negotiation was created.
 */
export const PictureControl: React.FC<{
  e3Id: bigint
  account: `0x${string}`
  hasPicture: boolean
  /** An error of the upload at creation, shown until the creator tries again. */
  initialError?: string
  onUploaded: () => void
}> = ({ e3Id, account, hasPicture, initialError, onUploaded }) => {
  const { data: walletClient } = useWalletClient({ chainId: chain.id })
  const input = useRef<HTMLInputElement>(null)
  const [step, setStep] = useState<keyof typeof STEP_TEXT | null>(null)
  const [error, setError] = useState<string | null>(initialError ?? null)

  const choose = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0]
    // Reset the input, so that the same file can be chosen again after an error.
    event.target.value = ''
    if (!file || !walletClient) return
    setError(null)
    try {
      setStep('preparing')
      const image = await prepareImage(file)
      await uploadImage(walletClient, account, e3Id, image, setStep)
      onUploaded()
    } catch (err) {
      setError(formatError(err))
    } finally {
      setStep(null)
    }
  }

  return (
    <div className='space-y-3'>
      <div className='flex flex-wrap items-center gap-3'>
        <input ref={input} type='file' accept={PICKER_TYPES.join(',')} className='hidden' onChange={(event) => void choose(event)} />
        <button type='button' className='btn ghost sm' disabled={step !== null || !walletClient} onClick={() => input.current?.click()}>
          {step ? (
            <>
              <Spinner size={14} /> {STEP_TEXT[step]}
            </>
          ) : hasPicture ? (
            'Replace picture'
          ) : (
            'Add picture'
          )}
        </button>
        {!hasPicture && step === null && (
          <span className='text-xs text-muted'>You created this negotiation, so only you can add a picture.</span>
        )}
      </div>
      {error && <div className='note bad'>The picture was not uploaded: {error}</div>}
    </div>
  )
}
