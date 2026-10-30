// SPDX-License-Identifier: LGPL-3.0-only

// Opt-in benchmark of one client-side user-data encryption proof. It skips unless UDE_BENCH_PRESET
// names a preset. Use scripts/benchmark-user-data-encryption.sh, which builds that preset's circuits,
// runs this test on native bb and on WASM, and restores the previous build.
//
// It calls the SDK's provers directly, so it does not depend on the SDK's default preset or on the
// published package entry points. Proving uses the same circuits, prover code and bb.js as the SDK.
import { Barretenberg, UltraHonkBackend } from '@aztec-foundation/bb.js'
import { Noir } from '@noir-lang/noir_js'
import { describe, it } from 'vitest'
import { createPublicClient, http, zeroAddress } from 'viem'
import { hardhat } from 'viem/chains'
import { proveUserDataEncryptionTree } from '@interfold/user-data-encryption-prover'
import { InterfoldSDK } from '../../src/interfold-sdk'
import { insecureProofBundle } from '../../src/crypto/presets/insecure'
import { secure8192ProofBundle } from '../../src/crypto/presets/secure-8192'
import { secure16384ProofBundle } from '../../src/crypto/presets/secure-16384'
import type { UserDataEncryptionProofBundle } from '../../src/crypto/presets/types'
import type { ThresholdBfvParamsPresetName } from '../../src/crypto/types'
import { proofToFields } from '../../src/utils'

const preset = process.env.UDE_BENCH_PRESET as ThresholdBfvParamsPresetName | undefined
const runs = Number(process.env.UDE_BENCH_RUNS ?? 2)
const backend = process.env.BB_BINARY_PATH ?? 'default'

// The chunked proof tree for each polynomial degree, as the SDK selects it.
const CHUNKED_BUNDLES: Record<number, UserDataEncryptionProofBundle> = {
  128: insecureProofBundle,
  8192: secure8192ProofBundle,
  16384: secure16384ProofBundle,
}

const seconds = (start: number) => ((performance.now() - start) / 1000).toFixed(2)

/** Prove one encryption, returning the proving phases in seconds. */
const prove = async (circuitInputs: Record<string, unknown>): Promise<Record<string, string>> => {
  // The SDK's rule (`isChunkedInputs` in src/crypto/user-data-encryption.ts): only the l-BFV
  // witness has `r1is`. The trBFV witness is one proof that covers both ciphertext legs.
  if (!('r1is' in circuitInputs)) {
    const { proveUserDataEncryption } = await import('../../src/crypto/user-data-encryption-prover')
    const start = performance.now()
    await proveUserDataEncryption(circuitInputs as never)
    return { proof: seconds(start) }
  }
  const degree = (circuitInputs.u as { coefficients: unknown[] }).coefficients.length
  const { userDataEncryption, ...treeCircuits } = CHUNKED_BUNDLES[degree]
  const api = await Barretenberg.new({ srsSize: 2 ** 21 })
  try {
    let start = performance.now()
    const { ct0, ct1 } = await proveUserDataEncryptionTree(api, treeCircuits, circuitInputs as never)
    const tree = seconds(start)
    start = performance.now()
    const { witness } = await new Noir(userDataEncryption).execute({
      ct0_verification_key: ct0.vkAsFields,
      ct0_proof: proofToFields(ct0.proof),
      ct0_public_inputs: ct0.publicInputs,
      ct0_key_hash: ct0.vkHash,
      ct1_verification_key: ct1.vkAsFields,
      ct1_proof: proofToFields(ct1.proof),
      ct1_public_inputs: ct1.publicInputs,
      ct1_key_hash: ct1.vkHash,
    })
    await new UltraHonkBackend(userDataEncryption.bytecode, api).generateProof(witness, {
      verifierTarget: 'noir-recursive-no-zk',
    })
    return { tree, wrapper: seconds(start) }
  } finally {
    await api.destroy()
  }
}

describe.skipIf(!preset)('user-data encryption benchmark', () => {
  it(`times one encryption proof at ${preset}`, async () => {
    const sdk = new InterfoldSDK({
      publicClient: createPublicClient({ chain: hardhat, transport: http() }),
      contracts: { interfold: zeroAddress, ciphernodeRegistry: zeroAddress, feeToken: zeroAddress },
      thresholdBfvParamsPresetName: preset!,
    })
    const publicKey = await sdk.generatePublicKey()
    let start = performance.now()
    const { circuitInputs } = await sdk.encryptVectorAndGenInputs(new BigUint64Array([1n, 2n]), publicKey)
    console.log(`UDE_BENCH preset=${preset} backend=${backend} encrypt=${seconds(start)}s`)

    let peak = 0
    const sampler = setInterval(() => {
      peak = Math.max(peak, process.memoryUsage().rss)
    }, 100)
    try {
      for (let run = 0; run < runs; run++) {
        start = performance.now()
        const phases = await prove(circuitInputs as unknown as Record<string, unknown>)
        const detail = Object.entries(phases)
          .map(([name, value]) => `${name}=${value}s`)
          .join(' ')
        console.log(`UDE_BENCH preset=${preset} backend=${backend} run=${run} ${detail} total=${seconds(start)}s`)
      }
    } finally {
      clearInterval(sampler)
    }
    console.log(`UDE_BENCH preset=${preset} backend=${backend} peak_rss_mb=${Math.round(peak / 1048576)}`)
  }, 3_600_000)
})
