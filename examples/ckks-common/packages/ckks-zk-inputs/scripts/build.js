// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

// Build recipe (mirrors crates/wasm + CRISP zk-inputs-wasm):
//   wasm-pack build --target=web    -> dist/web  (browser, wasm inlined as base64)
//   wasm-pack build --target=nodejs -> dist/node (node, loads the .wasm from disk)
// getrandom's wasm backend is selected by the crate's .cargo/config.toml
// (`--cfg getrandom_backend="wasm_js"`) + the `wasm_js` / `js` features.

import { execa } from 'execa'
import { readFile, writeFile, rm } from 'fs/promises'
import { resolve } from 'path'
import replaceInFile from 'replace-in-file'

const crate = resolve(process.cwd(), '../../crates/ckks-zk-inputs-wasm')
const dist = resolve(process.cwd(), 'dist')

try {
  await execa('wasm-pack', ['build', crate, '--target=web', `--out-dir=${dist}/web`, '--no-pack', '--out-name=index'], {
    stdio: 'inherit',
  })
  await execa('wasm-pack', ['build', crate, '--target=nodejs', `--out-dir=${dist}/node`, '--no-pack', '--out-name=index'], {
    stdio: 'inherit',
  })

  // Convert the web WASM binary to base64 for bundler compatibility.
  const wasmBinary = await readFile(`${dist}/web/index_bg.wasm`)
  const base64Src = `export default '${wasmBinary.toString('base64')}';\n`

  await Promise.all([
    rm(`${dist}/web/index_bg.wasm`, { force: true }),
    rm(`${dist}/web/index_bg.wasm.d.ts`, { force: true }),
    rm(`${dist}/web/.gitignore`, { force: true }),
    rm(`${dist}/node/.gitignore`, { force: true }),
    replaceInFile({
      files: `${dist}/web/index.js`,
      from: /module_or_path\s*=\s*new URL\(['"]index_bg\.wasm['"],\s*import\.meta\.url\);\s*/g,
      to: '/* wasm URL disabled: load via @interfold/ckks-zk-inputs/init */\n',
    }),
    writeFile(`${dist}/web/index_base64.js`, base64Src),
  ])
  console.log(`built dist/web (${(wasmBinary.length / 1024).toFixed(0)} KiB wasm, base64-inlined) + dist/node`)
} catch (error) {
  console.error(error)
  process.exit(1)
}
