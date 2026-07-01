// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import type { IncomingMessage } from 'node:http'
import { defineConfig, type Plugin } from 'vite'
import react from '@vitejs/plugin-react'

async function readJson(req: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = []
  for await (const chunk of req) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk))
  }
  const raw = Buffer.concat(chunks).toString('utf8')
  return raw ? JSON.parse(raw) : {}
}

function predicateAttestationEndpoint(): Plugin {
  return {
    name: 'predicate-attestation-endpoint',
    configureServer(server) {
      server.middlewares.use('/api/predicate/attestation', async (req, res) => {
        if (req.method !== 'POST') {
          res.statusCode = 405
          res.end(JSON.stringify({ error: 'Method not allowed' }))
          return
        }

        const apiKey = process.env.PREDICATE_API_KEY
        if (!apiKey) {
          res.statusCode = 500
          res.end(JSON.stringify({ error: 'PREDICATE_API_KEY is not set' }))
          return
        }

        try {
          const body = (await readJson(req)) as {
            userAddress?: string
            contractAddress?: string
            chain?: string
          }
          const response = await fetch('https://api.predicate.io/v2/attestation', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'x-api-key': apiKey,
            },
            body: JSON.stringify({
              to: body.contractAddress,
              from: body.userAddress,
              chain: body.chain,
            }),
          })

          res.statusCode = response.status
          res.setHeader('Content-Type', 'application/json')
          res.end(await response.text())
        } catch (error) {
          const message = error instanceof Error ? error.message : String(error)
          res.statusCode = 500
          res.end(JSON.stringify({ error: message }))
        }
      })
    },
  }
}

// https://vite.dev/config/
export default defineConfig({
  plugins: [react(), predicateAttestationEndpoint()],
  build: {
    rollupOptions: {
      output: {
        manualChunks(id) {
          if (!id.includes('/node_modules/')) return undefined
          if (id.includes('/react/') || id.includes('/react-dom/')) return 'react'
          if (id.includes('/ethers/')) return 'wallet'
          if (id.includes('/framer-motion/')) return 'motion'
          return undefined
        },
      },
    },
  },
})
