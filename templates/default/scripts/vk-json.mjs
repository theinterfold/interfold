#!/usr/bin/env node
// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

/**
 * Writes `<name>.vk_recursive.json` next to each `<name>.vk_recursive` / `<name>.vk_recursive_hash`
 * pair named on the command line: the `noir-recursive-no-zk` key as bb.js's
 * `generateRecursiveProofArtifacts` returns it (`vkAsFields`, 32-byte chunks as hex, and `vkHash`).
 * bb.js recomputes the key from the bytecode on every call, so the SDK ships this file instead of
 * rebuilding each circuit once more per ballot.
 *
 * Usage: vk-json.mjs <path/to/name.vk_recursive>...
 */

import { readFileSync, writeFileSync } from 'node:fs'

for (const vkFile of process.argv.slice(2)) {
  const vk = readFileSync(vkFile)
  const vkAsFields = []
  for (let i = 0; i < vk.length; i += 32) vkAsFields.push(`0x${vk.subarray(i, i + 32).toString('hex')}`)
  const vkHash = `0x${readFileSync(`${vkFile}_hash`).toString('hex')}`
  writeFileSync(`${vkFile}.json`, `${JSON.stringify({ vkAsFields, vkHash })}\n`)
}
