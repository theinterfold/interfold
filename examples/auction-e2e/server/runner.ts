// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

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

export async function callFheRunner(
  e3Id: bigint,
  domain: ComputeDomain,
  params: string,
  committeePublicKey: string,
  ciphertextInputs: Array<[string, number]>,
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
    ciphertext_inputs: ciphertextInputs,
    callback_url: callbackUrl,
  }
  console.log(`Submitting E3 ${e3Id} to FHE runner with ${ciphertextInputs.length} ciphertext input(s)`)

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
