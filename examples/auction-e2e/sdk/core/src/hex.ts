// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { type Hex } from 'viem'

export { bytesToHex } from 'viem'

/**
 * Encode bytes as a `0x`-prefixed lowercase hex string.
 *
 * @param bytes The bytes to encode.
 */
export function toHex(bytes: Uint8Array): Hex {
  let hex = '0x'
  for (const byte of bytes) hex += byte.toString(16).padStart(2, '0')
  return hex as Hex
}
