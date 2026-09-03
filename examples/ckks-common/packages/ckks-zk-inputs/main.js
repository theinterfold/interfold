// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

// Universal entry: the web build with the wasm binary inlined as base64
// and instantiated synchronously at import time (works in browsers and in
// Node >= 18 alike; CRISP's crisp-zk-inputs uses the same pattern).

import { initSync } from './dist/web/index.js'
import base64 from './dist/web/index_base64.js'

const binaryString = atob(base64)
const len = binaryString.length
const bytes = new Uint8Array(len)

for (let i = 0; i < len; i++) {
  bytes[i] = binaryString.charCodeAt(i)
}

initSync({ module: bytes })

export * from './dist/web/index.js'
