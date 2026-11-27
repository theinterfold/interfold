// SPDX-License-Identifier: LGPL-3.0-only

import { Barretenberg, UltraHonkBackend, UltraHonkVerifierBackend, type ProofData } from '@aztec-foundation/bb.js'
import { CompiledCircuit, Noir } from '@noir-lang/noir_js'
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest'
import { bytesToBigInt, bytesToHex, createPublicClient, http, toHex, zeroAddress } from 'viem'
import { hardhat } from 'viem/chains'
import { InterfoldSDK } from '../../src/interfold-sdk'
import { generateProof, getUserDataEncryptionVkChains, type CircuitInputs } from '../../src/crypto/user-data-encryption'
import { insecureLbfvProofBundle } from '../../src/crypto/presets/insecure-lbfv'
import type { ThresholdBfvParamsPresetName } from '../../src/crypto/types'
import trbfvCircuit from '../../../../circuits/bin/threshold/target/user_data_encryption.json'

const options = { verifierTarget: 'noir-recursive-no-zk' } as const

const sdkFor = (thresholdBfvParamsPresetName: ThresholdBfvParamsPresetName) =>
  new InterfoldSDK({
    publicClient: createPublicClient({ chain: hardhat, transport: http() }),
    contracts: { interfold: zeroAddress, ciphernodeRegistry: zeroAddress, feeToken: zeroAddress },
    thresholdBfvParamsPresetName,
  })

type ProvedInput = {
  proof: ProofData
  circuitInputs: Record<string, unknown>
  publicKeyCommitment: bigint
  ciphertextCommitment: bigint
}

// Reuse one proof for positive and negative checks. Do not regenerate it per assertion.
const proveOneInput = async (sdk: InterfoldSDK, presetName: ThresholdBfvParamsPresetName): Promise<ProvedInput> => {
  const publicKey = await sdk.generatePublicKey()
  const { encryptedData, circuitInputs } = await sdk.encryptVectorAndGenInputs(new BigUint64Array([1n, 2n]), publicKey)
  // Prove on WASM, the backend that browsers use: bb.js falls back to WASM in Node when
  // `BB_BINARY_PATH` names a missing binary. The verifier keeps the default backend.
  vi.stubEnv('BB_BINARY_PATH', '/nonexistent/bb')
  let proof: ProofData
  try {
    proof = await generateProof(circuitInputs, presetName)
  } finally {
    vi.unstubAllEnvs()
  }
  return {
    proof,
    circuitInputs: circuitInputs as unknown as Record<string, unknown>,
    publicKeyCommitment: bytesToBigInt(await sdk.computePublicKeyCommitment(publicKey)),
    ciphertextCommitment: bytesToBigInt(await sdk.computeCiphertextCommitment(encryptedData)),
  }
}

const rejectionChecks = (
  state: () => { proof: ProofData; verifier: UltraHonkVerifierBackend; verificationKey: Uint8Array },
  positions: number[],
) => {
  it.each(positions)('rejects an altered public input at position %i', async (index) => {
    const { proof, verifier, verificationKey } = state()
    const publicInputs = [...proof.publicInputs]
    publicInputs[index] = toHex(BigInt(publicInputs[index]) ^ 1n, { size: 32 })
    expect(await verifier.verifyProof({ ...proof, publicInputs, verificationKey }, options)).toBe(false)
  })

  it('rejects altered proof contents', async () => {
    const { proof, verifier, verificationKey } = state()
    const altered = proof.proof.slice()
    altered[altered.length - 1] ^= 1
    await expect(verifier.verifyProof({ ...proof, proof: altered, verificationKey }, options)).rejects.toThrow(
      'Deserialized point is not on the curve',
    )
  })
}

let api: Barretenberg | undefined
let verifier: UltraHonkVerifierBackend

beforeAll(async () => {
  api = await Barretenberg.new({ srsSize: 2 ** 21 })
  verifier = new UltraHonkVerifierBackend(api)
})

afterAll(async () => {
  await api?.destroy()
})

describe('real encryption proof under a trBFV key', () => {
  let proved: ProvedInput
  let verificationKey: Uint8Array
  let k1Commitment: bigint

  beforeAll(async () => {
    proved = await proveOneInput(sdkFor('INSECURE_THRESHOLD_64'), 'INSECURE_THRESHOLD_64')
    verificationKey = await new UltraHonkBackend(trbfvCircuit.bytecode, api!).getVerificationKey(options)
    // The circuit returns `k1_commitment` itself; that it is ct0's commitment of `k1` is checked by
    // the Noir test `both_legs_over_one_u_are_accepted`. Execute the circuit here, so the assertion
    // fails if the proof's public inputs are not the circuit's outputs. `CircuitInputs` carries Noir
    // structs that the `InputMap` index signature does not accept, so the witness map is cast in
    // the same way as the production prover.
    const { returnValue: outputs } = await new Noir(trbfvCircuit as CompiledCircuit).execute(proved.circuitInputs as any)
    k1Commitment = BigInt((outputs as string[])[2])
  })

  it('verifies against the compiled verification key and exact PK/ciphertext bindings', async () => {
    const { proof, publicKeyCommitment, ciphertextCommitment } = proved
    expect(proof.publicInputs).toHaveLength(3)
    expect(proof.publicInputs.map(BigInt)).toEqual([publicKeyCommitment, ciphertextCommitment, k1Commitment])
    expect(await verifier.verifyProof({ ...proof, verificationKey }, options)).toBe(true)
  })

  rejectionChecks(() => ({ proof: proved.proof, verifier, verificationKey }), [0, 1, 2])
})

// A real l-BFV proof needs a committee key envelope, which only a committee produces, so no test here
// proves the chunked tree end to end. These tests cover what the SDK adds around it: the path and
// preset checks that run before any proving, the VK chains a verifier must compare, and the keys the
// bundle ships.
describe('l-BFV proof path guards', () => {
  const chunkedInputs = (degree: number) => ({ u: { coefficients: new Array(degree).fill(0) }, r1is: [] }) as unknown as CircuitInputs
  const trbfvInputs = { u: { coefficients: new Array(64).fill(0) }, r: [] } as unknown as CircuitInputs

  it('rejects an l-BFV witness under a trBFV preset', async () => {
    await expect(generateProof(chunkedInputs(128), 'INSECURE_THRESHOLD_64')).rejects.toThrow('needs the trBFV witness')
  })

  it('rejects a trBFV witness under an l-BFV preset', async () => {
    await expect(generateProof(trbfvInputs, 'SECURE_THRESHOLD_16384')).rejects.toThrow('needs the l-BFV witness')
  })

  it('rejects a witness whose degree belongs to the other l-BFV preset', async () => {
    await expect(generateProof(chunkedInputs(16384), 'INSECURE_THRESHOLD_LBFV')).rejects.toThrow(
      'No user-data encryption circuit bundle supports polynomial degree 16384 for INSECURE_THRESHOLD_LBFV',
    )
  })

  it('computes one VK chain per leg and rejects a trBFV preset', async () => {
    const chains = await getUserDataEncryptionVkChains('INSECURE_THRESHOLD_LBFV')
    expect(chains.ct0).toMatch(/^0x[0-9a-f]{64}$/)
    expect(chains.ct1).toMatch(/^0x[0-9a-f]{64}$/)
    expect(chains.ct0).not.toBe(chains.ct1)
    expect(await getUserDataEncryptionVkChains('INSECURE_THRESHOLD_LBFV')).toEqual(chains)
    await expect(getUserDataEncryptionVkChains('INSECURE_THRESHOLD_64')).rejects.toThrow('has no chunked user-data encryption proof tree')
  })
})

describe('l-BFV proof tree verification keys', () => {
  // The prover takes these keys instead of rebuilding each circuit. A stale key would only make the
  // proof fail, but this names the circuit that went stale.
  it.each(Object.keys(insecureLbfvProofBundle.vks) as (keyof typeof insecureLbfvProofBundle.vks)[])(
    'ships the key that bb.js derives for %s',
    async (name) => {
      const derived = await new UltraHonkBackend(insecureLbfvProofBundle[name].bytecode, api!).getVerificationKey(options)
      const shipped = insecureLbfvProofBundle.vks[name].vkAsFields.map((field) => field.slice(2)).join('')
      expect(shipped).toBe(bytesToHex(derived).slice(2))
    },
  )
})
