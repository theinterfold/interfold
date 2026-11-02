// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'
import { fileURLToPath } from 'node:url'

const root = fileURLToPath(new URL('../../../', import.meta.url))
const readConfig = (path) => JSON.parse(readFileSync(new URL(`../../../${path}`, import.meta.url), 'utf8'))
const initialize = JSON.stringify({
  jsonrpc: '2.0',
  id: 1,
  method: 'initialize',
  params: { protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 'test', version: '1.0.0' } },
})

for (const [name, command] of [
  ['OpenCode', readConfig('opencode.json').mcp.servers['interfold-docs'].command],
  [
    'MCP clients',
    [readConfig('.mcp.json').mcpServers['interfold-docs'].command, ...readConfig('.mcp.json').mcpServers['interfold-docs'].args],
  ],
]) {
  test(`${name} launcher returns an MCP initialize response without extra stdout`, () => {
    const result = spawnSync(command[0], command.slice(1), { cwd: root, input: `${initialize}\n`, encoding: 'utf8', timeout: 20000 })
    assert.ifError(result.error)
    assert.equal(result.status, 0, result.stderr)
    const messages = result.stdout
      .trim()
      .split('\n')
      .map((line) => JSON.parse(line))
    assert.equal(messages.length, 1)
    assert.equal(messages[0].id, 1)
    assert.equal(messages[0].result.serverInfo.name, 'interfold-docs')
  })
}
