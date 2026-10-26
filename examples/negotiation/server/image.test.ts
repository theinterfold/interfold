// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import express from 'express'
import type { Server } from 'node:http'
import { once } from 'node:events'
import { mkdtemp, readdir, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { promisify } from 'node:util'
import { join } from 'node:path'
import { type Address, type Hex } from 'viem'
import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts'
import { detectImageType, IMAGE_SIGNATURE_HEADER, imageMessage, imageRouter, MAX_IMAGE_BYTES, sha256Hex } from './image'

const CHAIN_ID = 11155111
const PROGRAM: Address = '0x2d37420ee09c10F833ECB254C40655b1e3664E82'
const EXISTING_E3 = 7n

const creator = privateKeyToAccount(generatePrivateKey())
const stranger = privateKeyToAccount(generatePrivateKey())

/** The first bytes of a PNG, a JPEG and a WebP file, then filler. The server reads the magic bytes only. */
const withMagic = (magic: number[], size = 64): Buffer => Buffer.concat([Buffer.from(magic), Buffer.alloc(size, 7)])
const png = (size?: number) => withMagic([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a], size)
const jpeg = (size?: number) => withMagic([0xff, 0xd8, 0xff, 0xe0], size)
const webp = () => Buffer.concat([Buffer.from('RIFF'), Buffer.from([0x10, 0, 0, 0]), Buffer.from('WEBPVP8 '), Buffer.alloc(32, 3)])
const svg = () => Buffer.from('<svg xmlns="http://www.w3.org/2000/svg" width="1" height="1"/>')

let server: Server
let directory: string
let base: string

beforeAll(async () => {
  directory = await mkdtemp(join(tmpdir(), 'negotiation-image-'))
  const app = express()
  app.use(
    imageRouter({
      chainId: CHAIN_ID,
      program: PROGRAM,
      directory,
      // Only E3 7 exists, and `creator` made it.
      readCreator: async (e3Id) => (e3Id === EXISTING_E3 ? creator.address : undefined),
    }),
  )
  server = app.listen(0, '127.0.0.1')
  await once(server, 'listening')
  const address = server.address()
  if (!address || typeof address === 'string') throw new Error('The test server has no port')
  base = `http://127.0.0.1:${address.port}`
})

afterAll(async () => {
  server.closeAllConnections()
  await promisify(server.close.bind(server))()
  await rm(directory, { recursive: true, force: true })
})

/** Sign the upload message of `signedBytes` with `account`. */
async function sign(account: typeof creator, e3Id: bigint, signedBytes: Buffer): Promise<Hex> {
  return account.signMessage({ message: imageMessage({ chainId: CHAIN_ID, program: PROGRAM, e3Id, sha256: sha256Hex(signedBytes) }) })
}

async function upload(e3Id: bigint, body: Buffer, signature: Hex | undefined, contentType = 'application/octet-stream') {
  const headers: Record<string, string> = { 'content-type': contentType }
  if (signature) headers[IMAGE_SIGNATURE_HEADER] = signature
  return fetch(`${base}/negotiations/${e3Id}/image`, { method: 'PUT', headers, body })
}

describe('detectImageType', () => {
  it('names PNG, JPEG and WebP by their magic bytes', () => {
    expect(detectImageType(png())).toBe('image/png')
    expect(detectImageType(jpeg())).toBe('image/jpeg')
    expect(detectImageType(webp())).toBe('image/webp')
  })

  it('refuses SVG, GIF, a RIFF file that is not WebP and short input', () => {
    expect(detectImageType(svg())).toBeUndefined()
    expect(detectImageType(Buffer.from('GIF89a...'))).toBeUndefined()
    expect(detectImageType(Buffer.concat([Buffer.from('RIFF'), Buffer.alloc(4), Buffer.from('WAVEfmt ')]))).toBeUndefined()
    expect(detectImageType(Buffer.from([0x89, 0x50]))).toBeUndefined()
    expect(detectImageType(Buffer.alloc(0))).toBeUndefined()
  })
})

describe('imageMessage', () => {
  it('binds the chain, the program, the negotiation and the hash, one to a line', () => {
    const sha256 = `0x${'ab'.repeat(32)}` as const
    // A lower-case program address gives the same text as the checksummed one.
    expect(imageMessage({ chainId: CHAIN_ID, program: PROGRAM.toLowerCase() as Address, e3Id: 12n, sha256 })).toBe(
      ['Interfold negotiation image', 'chain: 11155111', `program: ${PROGRAM}`, 'e3Id: 12', `sha256: ${sha256}`].join('\n'),
    )
  })
})

describe('PUT and GET /negotiations/:e3Id/image', () => {
  it('rejects a signature of another account than the creator', async () => {
    const bytes = png()
    const response = await upload(EXISTING_E3, bytes, await sign(stranger, EXISTING_E3, bytes))
    expect(response.status).toBe(403)
    expect((await fetch(`${base}/negotiations/${EXISTING_E3}/image`)).status).toBe(404)
  })

  it('rejects an upload for a negotiation that does not exist', async () => {
    const bytes = png()
    const response = await upload(99n, bytes, await sign(creator, 99n, bytes))
    expect(response.status).toBe(404)
  })

  it('rejects bytes that are not PNG, JPEG or WebP, whatever the content type says', async () => {
    const bad = [svg(), Buffer.from('GIF89a-not-allowed'), Buffer.from('plain text')]
    for (const bytes of bad) {
      const response = await upload(EXISTING_E3, bytes, await sign(creator, EXISTING_E3, bytes), 'image/png')
      expect(response.status).toBe(415)
    }
  })

  it('rejects a body above the limit and an empty body', async () => {
    const big = png(MAX_IMAGE_BYTES)
    expect((await upload(EXISTING_E3, big, await sign(creator, EXISTING_E3, big))).status).toBe(413)
    expect((await upload(EXISTING_E3, Buffer.alloc(0), undefined)).status).toBe(400)
  })

  it('accepts a body of exactly the limit', async () => {
    const edge = png(MAX_IMAGE_BYTES - 8)
    expect(edge.length).toBe(MAX_IMAGE_BYTES)
    expect((await upload(EXISTING_E3, edge, await sign(creator, EXISTING_E3, edge))).status).toBe(204)
  })

  it('rejects a signature over other bytes than the ones sent', async () => {
    const sent = png()
    const signedOther = jpeg()
    const response = await upload(EXISTING_E3, sent, await sign(creator, EXISTING_E3, signedOther))
    expect(response.status).toBe(403)
  })

  it('rejects a signature made for another negotiation of the same creator', async () => {
    const bytes = png()
    const response = await upload(EXISTING_E3, bytes, await sign(creator, 8n, bytes))
    expect(response.status).toBe(403)
  })

  it('rejects a missing or malformed signature and a bad e3Id', async () => {
    const bytes = png()
    expect((await upload(EXISTING_E3, bytes, undefined)).status).toBe(400)
    expect((await upload(EXISTING_E3, bytes, '0x1234')).status).toBe(400)
    const response = await fetch(`${base}/negotiations/abc/image`, { method: 'PUT', body: bytes })
    expect(response.status).toBe(400)
    expect((await fetch(`${base}/negotiations/abc/image`)).status).toBe(400)
  })

  it('stores a valid upload and serves the same bytes with the detected type', async () => {
    const bytes = jpeg(500)
    expect((await upload(EXISTING_E3, bytes, await sign(creator, EXISTING_E3, bytes), 'text/plain')).status).toBe(204)

    const response = await fetch(`${base}/negotiations/${EXISTING_E3}/image`)
    expect(response.status).toBe(200)
    expect(response.headers.get('content-type')).toBe('image/jpeg')
    expect(response.headers.get('x-content-type-options')).toBe('nosniff')
    expect(response.headers.get('cache-control')).toMatch(/max-age=\d+/)
    expect(response.headers.get('etag')).toBe(`"${sha256Hex(bytes).slice(2)}"`)
    expect(response.headers.get('access-control-allow-origin')).toBe('*')
    expect(Buffer.from(await response.arrayBuffer()).equals(bytes)).toBe(true)
  })

  it('answers 304 when the ETag matches', async () => {
    const bytes = png(100)
    await upload(EXISTING_E3, bytes, await sign(creator, EXISTING_E3, bytes))
    const first = await fetch(`${base}/negotiations/${EXISTING_E3}/image`)
    const second = await fetch(`${base}/negotiations/${EXISTING_E3}/image`, {
      headers: { 'if-none-match': first.headers.get('etag') ?? '' },
    })
    expect(second.status).toBe(304)
  })

  it('lets the creator replace the picture', async () => {
    const first = png(100)
    const second = webp()
    expect((await upload(EXISTING_E3, first, await sign(creator, EXISTING_E3, first))).status).toBe(204)
    expect((await upload(EXISTING_E3, second, await sign(creator, EXISTING_E3, second))).status).toBe(204)

    const response = await fetch(`${base}/negotiations/${EXISTING_E3}/image`)
    expect(response.headers.get('content-type')).toBe('image/webp')
    expect(Buffer.from(await response.arrayBuffer()).equals(second)).toBe(true)
  })

  it('keeps the earlier picture when a replacement is refused, and leaves no temporary file', async () => {
    const good = jpeg(200)
    await upload(EXISTING_E3, good, await sign(creator, EXISTING_E3, good))
    const bad = png(300)
    expect((await upload(EXISTING_E3, bad, await sign(stranger, EXISTING_E3, bad))).status).toBe(403)

    const response = await fetch(`${base}/negotiations/${EXISTING_E3}/image`)
    expect(Buffer.from(await response.arrayBuffer()).equals(good)).toBe(true)
    expect((await readdir(directory)).filter((name) => name.endsWith('.tmp'))).toEqual([])
  })

  it('answers the CORS preflight of an upload', async () => {
    const response = await fetch(`${base}/negotiations/${EXISTING_E3}/image`, { method: 'OPTIONS' })
    expect(response.status).toBe(204)
    expect(response.headers.get('access-control-allow-origin')).toBe('*')
    expect(response.headers.get('access-control-allow-methods')).toContain('PUT')
    expect(response.headers.get('access-control-allow-headers')).toContain(IMAGE_SIGNATURE_HEADER)
  })

  it('answers 404 for a negotiation without a picture', async () => {
    expect((await fetch(`${base}/negotiations/12345/image`)).status).toBe(404)
  })
})
