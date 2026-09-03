// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

// Stage the three compiled Noir circuits the client proves with into
// client/public/circuits so Vite serves them (CRISP's stage-preset step).
// Source: circuits/bin/threshold/target/<name>.json (nargo compile output).

import { copyFile, mkdir, stat } from 'node:fs/promises'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const here = path.dirname(fileURLToPath(import.meta.url))
const root = path.join(here, '..')
const interfold = path.join(root, '../..')
const src = path.join(interfold, 'circuits/bin/threshold/target')
const dst = path.join(root, 'client/public/circuits')

const NAMES = ['user_data_encryption_ckks_ct0_ps3', 'user_data_encryption_ckks_ct1_ps3', 'ckks_salary_validity_ps3']

await mkdir(dst, { recursive: true })
for (const name of NAMES) {
  const from = path.join(src, `${name}.json`)
  try {
    await stat(from)
  } catch {
    console.error(`missing ${from} — compile with: cd circuits/bin/threshold && nargo compile --package ${name}`)
    process.exit(1)
  }
  await copyFile(from, path.join(dst, `${name}.json`))
  console.log(`staged ${name}.json`)
}
