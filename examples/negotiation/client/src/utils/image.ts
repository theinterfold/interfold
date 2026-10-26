// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { type Address, getAddress, type WalletClient } from 'viem'
import { chain } from './chain'
import { getContractAddresses, SERVER_URL } from './env-config'

/** The server refuses a picture above this size (`MAX_IMAGE_BYTES` of `server/image.ts`). */
export const MAX_IMAGE_BYTES = 1024 * 1024
/** The long side of an uploaded picture, in pixels. */
export const MAX_IMAGE_SIDE = 1280
/** The file types the picker offers. The server accepts exactly these three; SVG is not one of them. */
export const PICKER_TYPES = ['image/png', 'image/jpeg', 'image/webp'] as const

/** The server header that carries the creator's signature (`IMAGE_SIGNATURE_HEADER` of `server/image.ts`). */
const SIGNATURE_HEADER = 'x-negotiation-image-signature'

/** Encoder settings in the order the client tries them: first the sharpest, then smaller and smaller. */
const QUALITIES = [0.86, 0.74, 0.6, 0.45] as const
const SHRINK_STEP = 0.75

/** The URL of the picture of a negotiation. `version` is a cache buster for a picture that the user just replaced. */
export function imageUrl(e3Id: bigint, version?: number): string {
  return `${SERVER_URL}/negotiations/${e3Id}/image${version ? `?v=${version}` : ''}`
}

/**
 * The text that the creator signs to upload a picture. It must equal `imageMessage` of
 * `server/image.ts` character for character: the server recovers the signer from it.
 */
export function imageMessage(e3Id: bigint, sha256: `0x${string}`, program: Address): string {
  return [
    'Interfold negotiation image',
    `chain: ${chain.id}`,
    `program: ${getAddress(program)}`,
    `e3Id: ${e3Id}`,
    `sha256: ${sha256}`,
  ].join('\n')
}

async function sha256Hex(bytes: ArrayBuffer): Promise<`0x${string}`> {
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes))
  return `0x${Array.from(digest, (byte) => byte.toString(16).padStart(2, '0')).join('')}`
}

function decode(file: Blob): Promise<HTMLImageElement> {
  const url = URL.createObjectURL(file)
  return new Promise<HTMLImageElement>((resolve, reject) => {
    const image = new Image()
    image.onload = () => resolve(image)
    image.onerror = () => reject(new Error('The browser cannot read this file as a picture.'))
    image.src = url
    // The decoded pixels stay valid after the URL is revoked, and the file is no longer needed.
  }).finally(() => URL.revokeObjectURL(url))
}

function encode(canvas: HTMLCanvasElement, type: string, quality: number): Promise<Blob | null> {
  return new Promise((resolve) => canvas.toBlob(resolve, type, quality))
}

/**
 * Downsize a picture to at most `MAX_IMAGE_SIDE` pixels on its long side and encode it as WebP, or as
 * JPEG where the browser cannot encode WebP. The result is at most `MAX_IMAGE_BYTES`: the encoder
 * lowers the quality and then the size until it fits. The canvas drops the metadata of the file, for
 * example the position of the camera.
 */
export async function prepareImage(file: File): Promise<Blob> {
  if (!(PICKER_TYPES as readonly string[]).includes(file.type)) throw new Error('Choose a PNG, JPEG or WebP picture.')
  const image = await decode(file)
  const longSide = Math.max(image.naturalWidth, image.naturalHeight)
  if (longSide === 0) throw new Error('The picture has no pixels.')

  let scale = Math.min(1, MAX_IMAGE_SIDE / longSide)
  const canvas = document.createElement('canvas')
  const context = canvas.getContext('2d')
  if (!context) throw new Error('This browser cannot resize pictures.')

  // Each round of the loop is a smaller scale. The first round at quality 0.86 usually fits.
  for (let round = 0; round < 8; round += 1) {
    canvas.width = Math.max(1, Math.round(image.naturalWidth * scale))
    canvas.height = Math.max(1, Math.round(image.naturalHeight * scale))
    // A JPEG has no alpha channel: a transparent pixel would turn black without a white ground.
    context.fillStyle = '#ffffff'
    context.fillRect(0, 0, canvas.width, canvas.height)
    context.drawImage(image, 0, 0, canvas.width, canvas.height)

    for (const quality of QUALITIES) {
      // A browser that cannot encode WebP returns a PNG, which is too large; ask for JPEG then.
      let blob = await encode(canvas, 'image/webp', quality)
      if (blob?.type !== 'image/webp') blob = await encode(canvas, 'image/jpeg', quality)
      if (blob && blob.size > 0 && blob.size <= MAX_IMAGE_BYTES) return blob
    }
    scale *= SHRINK_STEP
  }
  throw new Error('The picture is too large to shrink below 1 MiB.')
}

/** The message of a refusal by the server, or else the status. */
async function refusal(response: Response): Promise<string> {
  try {
    const body: unknown = await response.json()
    if (body && typeof body === 'object' && 'error' in body && typeof body.error === 'string') return body.error
  } catch {
    // The body is not JSON: the status below is all we have.
  }
  return `The server answered ${response.status}.`
}

/**
 * Upload the picture of a negotiation. The wallet signs a message that binds the chain, the program, the
 * negotiation and the hash of the bytes. The server accepts the picture only if the creator signed.
 *
 * @param onStep is called when the upload moves from the signature to the transfer.
 */
export async function uploadImage(
  walletClient: WalletClient,
  account: Address,
  e3Id: bigint,
  image: Blob,
  onStep?: (step: 'signing' | 'uploading') => void,
): Promise<void> {
  const bytes = await image.arrayBuffer()
  const sha256 = await sha256Hex(bytes)
  onStep?.('signing')
  const signature = await walletClient.signMessage({
    account,
    message: imageMessage(e3Id, sha256, getContractAddresses().e3Program),
  })
  onStep?.('uploading')
  let response: Response
  try {
    response = await fetch(imageUrl(e3Id), {
      method: 'PUT',
      headers: { 'content-type': image.type || 'application/octet-stream', [SIGNATURE_HEADER]: signature },
      body: bytes,
    })
  } catch {
    throw new Error(`Could not reach the negotiation server at ${SERVER_URL}.`)
  }
  if (!response.ok) throw new Error(await refusal(response))
}
