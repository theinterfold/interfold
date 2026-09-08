// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
import { createServer } from 'node:http'
import { readFile } from 'node:fs/promises'
import path from 'node:path'

const directory = process.env.DATA_AVAILABILITY_DIRECTORY
const port = Number(process.env.PORT ?? '4000')

if (!directory) throw new Error('DATA_AVAILABILITY_DIRECTORY is required')
if (!Number.isInteger(port) || port <= 0 || port > 65_535) throw new Error('PORT is invalid')

const server = createServer(async (request, response) => {
  const pathname = new URL(request.url ?? '/', `http://${request.headers.host ?? 'localhost'}`).pathname

  if (request.method === 'GET' && pathname === '/health') {
    response.writeHead(200, { 'content-type': 'text/plain' })
    response.end('ok')
    return
  }

  const match = pathname.match(/^\/availability\/objects\/0x([a-fA-F0-9]{64})$/)
  if (request.method !== 'GET' || !match) {
    response.writeHead(404)
    response.end()
    return
  }

  try {
    const object = await readFile(path.join(directory, match[1].toLowerCase()))
    response.writeHead(200, {
      'content-length': object.length,
      'content-type': 'application/octet-stream',
    })
    response.end(object)
  } catch {
    response.writeHead(404)
    response.end()
  }
})

server.listen(port, '127.0.0.1', () => {
  console.log(`Mock data-availability server listening on 127.0.0.1:${port}`)
})

for (const signal of ['SIGINT', 'SIGTERM']) {
  process.on(signal, () => server.close(() => process.exit(0)))
}
