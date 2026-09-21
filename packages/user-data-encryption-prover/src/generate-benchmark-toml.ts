#!/usr/bin/env tsx
// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { Barretenberg } from '@aztec/bb.js'
import type { CompiledCircuit } from '@noir-lang/noir_js'
import { readFileSync, writeFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

import { buildUserDataEncryptionTopLevelInputs, type UserDataEncryptionCircuitBundle, type UserDataEncryptionInputs } from './index'

type Options = {
  input: string
  preset: string
  committee: string
  outputRoot: string
}

const parseOptions = (): Options => {
  const values = new Map<string, string>()
  for (let index = 2; index < process.argv.length; index += 2) {
    const name = process.argv[index]
    const value = process.argv[index + 1]
    if (!name?.startsWith('--') || value === undefined) {
      throw new Error('Usage: generate-benchmark-toml.ts --input <json> --preset <name> --committee <name> --output-root <dir>')
    }
    values.set(name.slice(2), value)
  }

  const input = values.get('input')
  const preset = values.get('preset')
  const committee = values.get('committee')
  const outputRoot = values.get('output-root')
  if (!input || !preset || !committee || !outputRoot) {
    throw new Error('The input, preset, committee, and output-root options are required.')
  }
  return { input, preset, committee, outputRoot }
}

const CIRCUIT_NAMES = {
  ct0ChunkMain: 'ct0_chunk_main',
  ct0ChunkMainRoot: 'ct0_chunk_main_root',
  ct0PkCtCommit: 'ct0_pk_ct_commit',
  ct0ChunkGamma: 'ct0_chunk_gamma',
  ct0EvalChunkMain: 'ct0_eval_chunk_main',
  ct0EvalChunkMainRoot: 'ct0_eval_chunk_main_root',
  ct0EvalPkCt: 'ct0_eval_pk_ct',
  ct0EvalChunkIdentity: 'ct0_eval_chunk_identity',
  userDataEncryptionCt0: 'user_data_encryption_ct0',
  ct1ChunkMain: 'ct1_chunk_main',
  ct1ChunkMainRoot: 'ct1_chunk_main_root',
  ct1PkCtCommit: 'ct1_pk_ct_commit',
  ct1ChunkGamma: 'ct1_chunk_gamma',
  ct1EvalChunkMain: 'ct1_eval_chunk_main',
  ct1EvalChunkMainRoot: 'ct1_eval_chunk_main_root',
  ct1EvalPkCt: 'ct1_eval_pk_ct',
  ct1EvalChunkIdentity: 'ct1_eval_chunk_identity',
  userDataEncryptionCt1: 'user_data_encryption_ct1',
} as const

const loadCircuits = (preset: string, committee: string): UserDataEncryptionCircuitBundle => {
  const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '../../..')
  const root = resolve(repoRoot, 'dist', 'circuits', preset, committee, 'default', 'threshold')
  return Object.fromEntries(
    Object.entries(CIRCUIT_NAMES).map(([property, circuit]) => {
      const artifact = join(root, circuit, `${circuit}.json`)
      return [property, JSON.parse(readFileSync(artifact, 'utf8')) as CompiledCircuit]
    }),
  ) as UserDataEncryptionCircuitBundle
}

const tomlValue = (value: unknown): string => {
  if (typeof value === 'string') return JSON.stringify(value)
  if (typeof value === 'number' || typeof value === 'boolean') return String(value)
  if (Array.isArray(value)) return `[${value.map(tomlValue).join(', ')}]`
  if (value !== null && typeof value === 'object') {
    return `{ ${Object.entries(value)
      .map(([name, entry]) => `${name} = ${tomlValue(entry)}`)
      .join(', ')} }`
  }
  throw new Error(`Cannot encode TOML value: ${String(value)}`)
}

const toToml = (inputs: Record<string, unknown>): string =>
  `${Object.entries(inputs)
    .map(([name, value]) => `${name} = ${tomlValue(value)}`)
    .join('\n')}\n`

const main = async () => {
  const options = parseOptions()
  const inputs = JSON.parse(readFileSync(options.input, 'utf8')) as UserDataEncryptionInputs
  const circuits = loadCircuits(options.preset, options.committee)
  const api = await Barretenberg.new()
  try {
    await api.initSRSChonk(2 ** 21)
    const topLevel = await buildUserDataEncryptionTopLevelInputs(api, circuits, inputs)
    writeFileSync(join(options.outputRoot, 'user_data_encryption_ct0', 'Prover.toml'), toToml(topLevel.ct0))
    writeFileSync(join(options.outputRoot, 'user_data_encryption_ct1', 'Prover.toml'), toToml(topLevel.ct1))
  } finally {
    api.destroy()
  }
}

main().catch((error) => {
  console.error(error)
  process.exitCode = 1
})
