// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import express, { type NextFunction, type Request, type Response, type Router } from 'express'
import { createHash, randomUUID } from 'node:crypto'
import { mkdir, readFile, rename, rm, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { getAddress, isHex, recoverMessageAddress, type Address, type Hex } from 'viem'

/** The largest image the server stores. The client downsizes a picture to fit. */
export const MAX_IMAGE_BYTES = 1024 * 1024

/** The request header that carries the creator's signature (`personal_sign`, 65 bytes of hex). */
export const IMAGE_SIGNATURE_HEADER = 'x-auction-image-signature'

/** The id of an E3 is a `uint256`. */
const MAX_E3_ID = 2n ** 256n - 1n

export type ImageType = 'image/png' | 'image/jpeg' | 'image/webp'

const ascii = (bytes: Uint8Array, start: number, text: string): boolean =>
  bytes.length >= start + text.length && [...text].every((character, index) => bytes[start + index] === character.charCodeAt(0))

/**
 * The type of an image, read from its first bytes. The server never trusts a client content type.
 * It accepts PNG, JPEG and WebP only; SVG and every other format give `undefined`.
 */
export function detectImageType(bytes: Uint8Array): ImageType | undefined {
  if (bytes.length >= 8 && [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a].every((byte, index) => bytes[index] === byte)) {
    return 'image/png'
  }
  if (bytes.length >= 3 && bytes[0] === 0xff && bytes[1] === 0xd8 && bytes[2] === 0xff) return 'image/jpeg'
  if (ascii(bytes, 0, 'RIFF') && ascii(bytes, 8, 'WEBP')) return 'image/webp'
  return undefined
}

/** The SHA-256 of the bytes, as `0x` and 64 lowercase hex digits. */
export function sha256Hex(bytes: Uint8Array): Hex {
  return `0x${createHash('sha256').update(bytes).digest('hex')}`
}

/**
 * The text that the creator signs to upload a picture. It binds the chain, the program, the auction
 * and the exact bytes. The client builds the same text (`client/src/utils/image.ts`).
 */
export function imageMessage(fields: { chainId: number; program: Address; e3Id: bigint; sha256: Hex }): string {
  return [
    'Interfold auction image',
    `chain: ${fields.chainId}`,
    `program: ${getAddress(fields.program)}`,
    `e3Id: ${fields.e3Id}`,
    `sha256: ${fields.sha256}`,
  ].join('\n')
}

/** One image file for each E3 in a directory. A write replaces the file in one step. */
export class ImageStore {
  constructor(private readonly directory: string) {}

  private path(e3Id: bigint): string {
    return join(this.directory, `${e3Id}.img`)
  }

  async write(e3Id: bigint, bytes: Buffer): Promise<void> {
    await mkdir(this.directory, { recursive: true })
    const path = this.path(e3Id)
    // Two uploads for one E3 can overlap: each one has its own temporary file.
    const temporaryPath = `${path}.${randomUUID()}.tmp`
    try {
      await writeFile(temporaryPath, bytes)
      await rename(temporaryPath, path)
    } catch (error) {
      await rm(temporaryPath, { force: true })
      throw error
    }
  }

  async read(e3Id: bigint): Promise<Buffer | undefined> {
    try {
      return await readFile(this.path(e3Id))
    } catch (error) {
      if (error instanceof Error && 'code' in error && error.code === 'ENOENT') return undefined
      throw error
    }
  }
}

export interface ImageRouteOptions {
  chainId: number
  program: Address
  /** Where the image files live. */
  directory: string
  /** The creator of the auction on chain, or `undefined` if the program has no such auction. */
  readCreator: (e3Id: bigint) => Promise<Address | undefined>
}

/** `undefined` unless `text` is the decimal id of an E3. The result has no leading zeros. */
function parseE3Id(text: string): bigint | undefined {
  if (!/^\d{1,78}$/.test(text)) return undefined
  const value = BigInt(text)
  return value <= MAX_E3_ID ? value : undefined
}

/** Any page may read a picture, and the creator's page uploads one. The signature is the credential, not the origin. */
function allowAnyOrigin(req: Request, res: Response, next: NextFunction) {
  res.set({
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, PUT, OPTIONS',
    'Access-Control-Allow-Headers': `content-type, if-none-match, ${IMAGE_SIGNATURE_HEADER}`,
    'Access-Control-Expose-Headers': 'ETag',
    'Access-Control-Max-Age': '600',
  })
  if (req.method === 'OPTIONS') {
    res.sendStatus(204)
    return
  }
  next()
}

/**
 * `PUT /auctions/:e3Id/image` stores the picture of an auction and `GET` of the same path serves it.
 * A PUT carries the image bytes as its body and the creator's signature in `x-auction-image-signature`.
 * The creator is the `creator` of the auction on chain. The creator can replace the picture.
 */
export function imageRouter(options: ImageRouteOptions): Router {
  const { chainId, program, readCreator } = options
  const store = new ImageStore(options.directory)
  const router = express.Router()

  async function put(req: Request<{ e3Id: string }>, res: Response) {
    const e3Id = parseE3Id(req.params.e3Id)
    if (e3Id === undefined) {
      res.status(400).json({ error: 'e3Id must be a decimal string' })
      return
    }
    const body: unknown = req.body
    if (!Buffer.isBuffer(body) || body.length === 0) {
      res.status(400).json({ error: 'The body must be the image bytes' })
      return
    }
    if (detectImageType(body) === undefined) {
      res.status(415).json({ error: 'The image must be PNG, JPEG or WebP' })
      return
    }
    const signature = req.get(IMAGE_SIGNATURE_HEADER)
    if (!signature || !isHex(signature)) {
      res.status(400).json({ error: `The ${IMAGE_SIGNATURE_HEADER} header must be the signature in hex` })
      return
    }

    try {
      const creator = await readCreator(e3Id)
      if (creator === undefined) {
        res.status(404).json({ error: 'There is no such auction' })
        return
      }
      let signer: Address
      try {
        signer = await recoverMessageAddress({ message: imageMessage({ chainId, program, e3Id, sha256: sha256Hex(body) }), signature })
      } catch {
        res.status(400).json({ error: 'The signature is not valid' })
        return
      }
      // The message holds the hash of these exact bytes. A signature over other bytes recovers another address.
      if (signer.toLowerCase() !== creator.toLowerCase()) {
        res.status(403).json({ error: 'The signature is not from the creator of the auction, or it does not cover these bytes' })
        return
      }
      await store.write(e3Id, body)
      console.log(`🖼️ Stored the picture of E3 ${e3Id} (${body.length} bytes)`)
      res.status(204).end()
    } catch (error) {
      console.error(`❌ Could not store the picture of E3 ${e3Id}:`, error)
      res.status(500).json({ error: 'Internal server error' })
    }
  }

  async function get(req: Request<{ e3Id: string }>, res: Response) {
    const e3Id = parseE3Id(req.params.e3Id)
    if (e3Id === undefined) {
      res.status(400).json({ error: 'e3Id must be a decimal string' })
      return
    }
    try {
      const bytes = await store.read(e3Id)
      const type = bytes && detectImageType(bytes)
      if (!bytes || !type) {
        res.status(404).json({ error: 'There is no picture for this auction' })
        return
      }
      // The picture can be replaced: a cache keeps it for a minute and then asks again with the ETag.
      const etag = `"${sha256Hex(bytes).slice(2)}"`
      res.set({
        'X-Content-Type-Options': 'nosniff',
        'Cache-Control': 'public, max-age=60',
        // The client page is cross-origin isolated: it loads a cross-origin image only with this header or CORS.
        'Cross-Origin-Resource-Policy': 'cross-origin',
        'Content-Security-Policy': "default-src 'none'; sandbox",
        ETag: etag,
      })
      const candidates = (req.get('if-none-match') ?? '').split(',').map((candidate) => candidate.trim().replace(/^W\//, ''))
      if (candidates.includes(etag) || candidates.includes('*')) {
        res.status(304).end()
        return
      }
      res.type(type).send(bytes)
    } catch (error) {
      console.error(`❌ Could not read the picture of E3 ${e3Id}:`, error)
      res.status(500).json({ error: 'Internal server error' })
    }
  }

  router.use('/auctions/:e3Id/image', allowAnyOrigin)
  // The size limit applies to this route only. The parser rejects a larger body before it reads it all.
  router.put('/auctions/:e3Id/image', express.raw({ type: () => true, limit: MAX_IMAGE_BYTES }), put)
  router.get('/auctions/:e3Id/image', get)
  router.use('/auctions/:e3Id/image', (error: { status?: number; type?: string }, _req: Request, res: Response, next: NextFunction) => {
    if (error.type === 'entity.too.large') {
      res.status(413).json({ error: `The image must be at most ${MAX_IMAGE_BYTES} bytes` })
      return
    }
    if (typeof error.status === 'number' && error.status >= 400 && error.status < 500) {
      res.status(error.status).json({ error: 'The request body could not be read' })
      return
    }
    next(error)
  })

  return router
}
