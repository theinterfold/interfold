// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { execa } from 'execa'
import { readFile, writeFile, rm } from 'fs/promises'
import replaceInFile from 'replace-in-file'

try {
  // Build WASM with web and node target - generates e3_wasm.js and e3_wasm_bg.wasm.
  await execa('wasm-pack', ['build', '--target=web', '--out-dir=dist/web', '--no-pack'])
  await execa('wasm-pack', ['build', '--target=nodejs', '--out-dir=dist/node', '--no-pack'])

  // Convert WASM binary to base64 for bundler compatibility.
  const wasmBinary = await readFile('./dist/web/e3_wasm_bg.wasm')
  const base64Src = `export default '${wasmBinary.toString('base64')}';\n`

  // Parallel cleanup and JS modification to prevent Next.js and other bundlers static analysis issues.
  await Promise.all([
    await Promise.all([
      rm('./dist/web/e3_wasm_bg.wasm', { force: true }),
      rm('./dist/web/e3_wasm_bg.wasm.d.ts', { force: true }),
      rm('./dist/web/.gitignore', { force: true }),
      rm('./dist/node/.gitignore', { force: true }),
    ]),
    replaceInFile({
      files: './dist/web/e3_wasm.js',
      from: /module_or_path\s*=\s*new URL\(['"]e3_wasm_bg\.wasm['"],\s*import\.meta\.url\);\s*/g,
      to: '/* wasm URL disabled: load via @interfold/wasm/init */\n',
    }),
    writeFile('./dist/web/e3_wasm_base64.js', base64Src),
  ])
} catch (error) {
  console.error(error)
  process.exit(1)
}
