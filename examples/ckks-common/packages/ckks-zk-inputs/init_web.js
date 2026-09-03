// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import * as bindgen from './dist/web/index.js'

let promise

export default async function initializeWasm() {
  promise ??= (async () => {
    const { default: base64 } = await import('./dist/web/index_base64.js')
    const binaryString = atob(base64)
    const bytes = new Uint8Array(binaryString.length)
    for (let i = 0; i < binaryString.length; i++) {
      bytes[i] = binaryString.charCodeAt(i)
    }
    bindgen.initSync({ module: bytes })
    return bindgen
  })()
  return promise
}
