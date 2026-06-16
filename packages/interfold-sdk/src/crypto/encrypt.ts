// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import initializeWasm from '@interfold/wasm/init'
import {
  bfv_encrypt_number,
  bfv_encrypt_vector,
  generate_public_key,
  bfv_verifiable_encrypt_number,
  bfv_verifiable_encrypt_vector,
  compute_pk_commitment,
  get_bfv_params,
} from '@interfold/wasm'
import { generateProof } from './user-data-encryption'
import type { BfvParams, EncryptedValueAndPublicInputs, ThresholdBfvParamsPresetName, VerifiableEncryptionResult } from './types'

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

export async function encryptNumber(data: bigint, pk: Uint8Array, presetName: ThresholdBfvParamsPresetName): Promise<Uint8Array> {
  const params = await resolveParams(presetName)
  return bfv_encrypt_number(data, pk, params.degree, params.plaintextModulus, BigUint64Array.from(params.moduli))
}

export async function encryptVector(data: BigUint64Array, pk: Uint8Array, presetName: ThresholdBfvParamsPresetName): Promise<Uint8Array> {
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
  const proof = await generateProof(circuitInputs)
  return { encryptedData, proof }
}

export async function encryptVectorAndGenInputs(
  data: BigUint64Array,
  pk: Uint8Array,
  presetName: ThresholdBfvParamsPresetName,
): Promise<EncryptedValueAndPublicInputs> {
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
): Promise<VerifiableEncryptionResult> {
  const { circuitInputs, encryptedData } = await encryptVectorAndGenInputs(data, pk, presetName)
  const proof = await generateProof(circuitInputs)
  return { encryptedData, proof }
}
