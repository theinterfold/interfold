// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { isAddress, type Address } from 'viem'
import { SERVER_URL } from './env-config'

/**
 * The address that the coordination server sends masks from (`GET <SERVER_URL>/provider`), or `null`
 * when the server has no mask provider key or cannot be reached. The create page offers it as a
 * mask provider; a creator can do without it.
 */
export async function fetchServerProvider(): Promise<Address | null> {
  try {
    const response = await fetch(`${SERVER_URL}/provider`)
    if (!response.ok) return null
    const body = (await response.json()) as { address?: unknown }
    return typeof body.address === 'string' && isAddress(body.address) ? body.address : null
  } catch {
    return null
  }
}
