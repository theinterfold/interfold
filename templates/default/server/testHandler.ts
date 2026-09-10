// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import payload from './payload.json'
import { callFheRunner } from './runner'

export async function handleTestInteraction() {
  const e3Id = BigInt(payload.e3_id)
  const params = payload.params
  const ciphertextInputs = payload.ciphertext_inputs as Array<[string, number]>
  await callFheRunner(
    e3Id,
    {
      chainId: Number(process.env.CHAIN_ID ?? 31_337),
      interfoldAddress: process.env.INTERFOLD_CONTRACT ?? '0x0000000000000000000000000000000000000000',
      encryptionSchemeId: process.env.ENCRYPTION_SCHEME_ID ?? `0x${'00'.repeat(32)}`,
      committeePublicKeyHash: process.env.COMMITTEE_PUBLIC_KEY_HASH ?? `0x${'00'.repeat(32)}`,
    },
    params,
    ciphertextInputs,
  )
}
