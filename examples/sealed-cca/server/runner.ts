// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import type { ProgramInputs } from './inputs'

export interface ComputeDomain {
  chainId: number
  interfoldAddress: string
  encryptionSchemeId: string
  committeePublicKeyHash: string
}

export interface RunnerEndpoints {
  /** The base URL of the program runner. */
  runnerUrl: string
  /** The URL that the runner posts its result to. It carries the secret token of this run. */
  callbackUrl: string
}

/**
 * Sends the round to the program runner. `inputs` holds every published input, in leaf order. Its
 * commitments, bidders and versions go as `input_commitments`, `input_slots` and `input_parents`,
 * which the runner packs into the metadata of each leaf.
 */
export async function callFheRunner(
  e3Id: bigint,
  domain: ComputeDomain,
  params: string,
  committeePublicKey: string,
  inputs: ProgramInputs,
  { runnerUrl, callbackUrl }: RunnerEndpoints,
): Promise<void> {
  const payload = {
    e3_id: e3Id.toString(),
    chain_id: domain.chainId,
    interfold_address: domain.interfoldAddress,
    encryption_scheme_id: domain.encryptionSchemeId,
    committee_public_key_hash: domain.committeePublicKeyHash,
    params,
    committee_public_key: committeePublicKey,
    ciphertext_inputs: inputs.ciphertexts,
    input_commitments: inputs.commitments,
    input_slots: inputs.slots,
    input_parents: inputs.parents,
    callback_url: callbackUrl,
  }
  console.log(`Submitting E3 ${e3Id} to FHE runner with ${inputs.ciphertexts.length} ciphertext input(s)`)

  const response = await fetch(`${runnerUrl}/run_compute`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(payload),
  })

  if (!response.ok) {
    throw new Error(`FHE Runner failed: ${response.status} ${response.statusText}`)
  }

  const result = await response.json()
  console.log(`✓ FHE Runner accepted E3 ${e3Id}:`, result)
}
