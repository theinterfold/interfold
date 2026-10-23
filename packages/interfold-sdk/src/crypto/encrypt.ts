// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import initializeWasm from '@interfold/wasm/init'
import {
  bfv_encrypt_number,
  bfv_encrypt_vector,
  bfv_encrypt_vector_simd,
  generate_public_key,
  bfv_verifiable_encrypt_number,
  bfv_verifiable_encrypt_vector,
  bfv_verifiable_encrypt_vector_simd,
  compute_ct_commitment,
  compute_pk_commitment,
  open_lbfv_key_envelope,
  get_bfv_params,
} from '@interfold/wasm'
import { generateProof } from './user-data-encryption'
import type {
  BfvParams,
  EncryptedValueAndPublicInputs,
  LbfvKeyEnvelopeOpening,
  ThresholdBfvParamsPresetName,
  VerifiableEncryptionResult,
} from './types'

async function resolveParams(presetName: ThresholdBfvParamsPresetName): Promise<BfvParams> {
  await initializeWasm()
  const params = get_bfv_params(presetName)
  return {
    degree: Number(params.degree),
    plaintextModulus: params.plaintext_modulus as bigint,
    moduli: params.moduli as bigint[],
    error1Variance: params.error1_variance,
  }
}

/**
 * How a vector is packed into a plaintext.
 * - `'poly'` (default): `data[i]` is the coefficient of `X^i`.
 * - `'simd'`: `data[i]` is slot `i`, so ciphertext operations act on all slots at once. The preset's
 *   plaintext modulus must be prime and 1 mod 2N, as for `INSECURE_THRESHOLD_SIMD`.
 */
export type VectorEncoding = 'poly' | 'simd'

export interface VectorEncryptOptions {
  encoding?: VectorEncoding
}

function resolveEncoding(options: VectorEncryptOptions | undefined): VectorEncoding {
  const encoding = options?.encoding ?? 'poly'
  if (encoding !== 'poly' && encoding !== 'simd') {
    throw new Error(`Unsupported vector encoding: ${String(encoding)}`)
  }
  return encoding
}

export async function getThresholdBfvParamsSet(presetName: ThresholdBfvParamsPresetName): Promise<BfvParams> {
  return resolveParams(presetName)
}

export async function generatePublicKey(presetName: ThresholdBfvParamsPresetName): Promise<Uint8Array> {
  const params = await resolveParams(presetName)
  return generate_public_key(params.degree, params.plaintextModulus, BigUint64Array.from(params.moduli))
}

export async function computePublicKeyCommitment(pk: Uint8Array, presetName: ThresholdBfvParamsPresetName): Promise<Uint8Array> {
  const params = await resolveParams(presetName)
  return compute_pk_commitment(pk, params.degree, params.plaintextModulus, BigUint64Array.from(params.moduli))
}

/** Open an l-BFV committee key's on-chain commitment; throws for a plain BFV key. */
export async function openLbfvKeyEnvelope(pk: Uint8Array, presetName: ThresholdBfvParamsPresetName): Promise<LbfvKeyEnvelopeOpening> {
  const params = await resolveParams(presetName)
  const words = open_lbfv_key_envelope(pk, params.degree, params.plaintextModulus, BigUint64Array.from(params.moduli))
  const rows = Array.from({ length: words.length / 32 - 1 }, (_, row) => words.slice(row * 32, (row + 1) * 32))
  return { publicKeyRows: rows, relinearizationKey: words.slice(-32) }
}

export async function computeCiphertextCommitment(ciphertext: Uint8Array, presetName: ThresholdBfvParamsPresetName): Promise<Uint8Array> {
  const params = await resolveParams(presetName)
  return compute_ct_commitment(ciphertext, params.degree, params.plaintextModulus, BigUint64Array.from(params.moduli))
}

export async function encryptNumber(data: bigint, pk: Uint8Array, presetName: ThresholdBfvParamsPresetName): Promise<Uint8Array> {
  const params = await resolveParams(presetName)
  return bfv_encrypt_number(data, pk, params.degree, params.plaintextModulus, BigUint64Array.from(params.moduli))
}

export async function encryptVector(
  data: BigUint64Array,
  pk: Uint8Array,
  presetName: ThresholdBfvParamsPresetName,
  options?: VectorEncryptOptions,
): Promise<Uint8Array> {
  if (resolveEncoding(options) === 'simd') {
    await initializeWasm()
    return bfv_encrypt_vector_simd(data, pk, presetName)
  }
  const params = await resolveParams(presetName)
  return bfv_encrypt_vector(data, pk, params.degree, params.plaintextModulus, BigUint64Array.from(params.moduli))
}

export async function encryptNumberAndGenInputs(
  data: bigint,
  pk: Uint8Array,
  presetName: ThresholdBfvParamsPresetName,
): Promise<EncryptedValueAndPublicInputs> {
  const params = await resolveParams(presetName)
  const [encryptedData, circuitInputs] = bfv_verifiable_encrypt_number(
    data,
    pk,
    params.degree,
    params.plaintextModulus,
    BigUint64Array.from(params.moduli),
  )
  return { encryptedData, circuitInputs: JSON.parse(circuitInputs) }
}

export async function encryptNumberAndGenProof(
  data: bigint,
  pk: Uint8Array,
  presetName: ThresholdBfvParamsPresetName,
): Promise<VerifiableEncryptionResult> {
  const { circuitInputs, encryptedData } = await encryptNumberAndGenInputs(data, pk, presetName)
  const proof = await generateProof(circuitInputs, presetName)
  return { encryptedData, proof }
}

export async function encryptVectorAndGenInputs(
  data: BigUint64Array,
  pk: Uint8Array,
  presetName: ThresholdBfvParamsPresetName,
  options?: VectorEncryptOptions,
): Promise<EncryptedValueAndPublicInputs> {
  if (resolveEncoding(options) === 'simd') {
    await initializeWasm()
    const [encryptedData, circuitInputs] = bfv_verifiable_encrypt_vector_simd(data, pk, presetName)
    return { encryptedData, circuitInputs: JSON.parse(circuitInputs) }
  }
  const params = await resolveParams(presetName)
  const [encryptedData, circuitInputs] = bfv_verifiable_encrypt_vector(
    data,
    pk,
    params.degree,
    params.plaintextModulus,
    BigUint64Array.from(params.moduli),
  )
  return { encryptedData, circuitInputs: JSON.parse(circuitInputs) }
}

export async function encryptVectorAndGenProof(
  data: BigUint64Array,
  pk: Uint8Array,
  presetName: ThresholdBfvParamsPresetName,
  options?: VectorEncryptOptions,
): Promise<VerifiableEncryptionResult> {
  const { circuitInputs, encryptedData } = await encryptVectorAndGenInputs(data, pk, presetName, options)
  const proof = await generateProof(circuitInputs, presetName)
  return { encryptedData, proof }
}
