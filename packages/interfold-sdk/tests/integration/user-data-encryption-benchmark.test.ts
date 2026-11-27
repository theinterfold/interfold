// SPDX-License-Identifier: LGPL-3.0-only

// Opt-in benchmark of one client-side user-data encryption proof. It skips unless UDE_BENCH_PRESET
// names a preset. Use scripts/benchmark-user-data-encryption.sh, which builds that preset's circuits,
// runs this test on native bb and on WASM, and restores the previous build.
//
// It times the SDK's own `generateProof`, so it measures exactly what the SDK proves. The encryption
// uses a plain committee key, so the presets it can run are the ones whose plain key selects them:
// INSECURE_THRESHOLD_64, SECURE_THRESHOLD_8192 and SECURE_THRESHOLD_16384.
import { describe, it } from 'vitest'
import { createPublicClient, http, zeroAddress } from 'viem'
import { hardhat } from 'viem/chains'
import { InterfoldSDK } from '../../src/interfold-sdk'
import { generateProof } from '../../src/crypto/user-data-encryption'
import type { ThresholdBfvParamsPresetName } from '../../src/crypto/types'

const preset = process.env.UDE_BENCH_PRESET as ThresholdBfvParamsPresetName | undefined
const runs = Number(process.env.UDE_BENCH_RUNS ?? 2)
const backend = process.env.BB_BINARY_PATH ?? 'default'

const seconds = (start: number) => ((performance.now() - start) / 1000).toFixed(2)

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
        await generateProof(circuitInputs, preset)
        console.log(`UDE_BENCH preset=${preset} backend=${backend} run=${run} proof=${seconds(start)}s`)
      }
    } finally {
      clearInterval(sampler)
    }
    console.log(`UDE_BENCH preset=${preset} backend=${backend} peak_rss_mb=${Math.round(peak / 1048576)}`)
  }, 3_600_000)
})
