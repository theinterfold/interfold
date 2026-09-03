// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

// Browser wiring of the proving pipeline: loads the WASM encryptor, the
// three compiled circuits (served from /circuits, staged by
// scripts/stage-circuits.mjs) and one shared multithreaded Barretenberg
// api (2^18 CRS), then delegates to the SDK.

import type { CompiledCircuit } from '@noir-lang/noir_js'
import {
  CIRCUIT_NAMES,
  SRS_SIZE,
  proveSalarySubmission,
  type CircuitBundle,
  type Leg,
  type ProgressFn,
  type ProveResult,
  type ProverDeps,
} from '@interfold/ckks-salary-sdk'

let depsPromise: Promise<ProverDeps> | null = null

const loadCircuit = async (name: string): Promise<CompiledCircuit> => {
  const res = await fetch(`/circuits/${name}.json`)
  if (!res.ok) throw new Error(`circuit ${name} not staged: run pnpm stage:circuits`)
  return (await res.json()) as CompiledCircuit
}

export const loadProverDeps = (onProgress: ProgressFn = () => {}): Promise<ProverDeps> => {
  depsPromise ??= (async () => {
    onProgress('loading WASM encryptor')
    const [{ default: init }, wasm] = await Promise.all([
      import('@interfold/ckks-zk-inputs/init'),
      import('@interfold/ckks-zk-inputs'),
    ])
    await init()
    onProgress('loading circuits')
    const entries = await Promise.all(
      (Object.keys(CIRCUIT_NAMES) as Leg[]).map(async (leg) => [leg, await loadCircuit(CIRCUIT_NAMES[leg])] as const),
    )
    const circuits = Object.fromEntries(entries) as CircuitBundle
    onProgress('starting Barretenberg (multithreaded WASM)')
    const { Noir } = await import('@noir-lang/noir_js')
    const { Barretenberg, UltraHonkBackend } = await import('@aztec/bb.js')
    const api = await Barretenberg.new({ srsSize: SRS_SIZE })
    return {
      wasm: wasm as unknown as ProverDeps['wasm'],
      Noir: Noir as unknown as ProverDeps['Noir'],
      backendFor: async (circuit: CompiledCircuit) =>
        new UltraHonkBackend(circuit.bytecode, api) as unknown as Awaited<ReturnType<ProverDeps['backendFor']>>,
      circuits,
    }
  })()
  return depsPromise
}

export const proveInBrowser = async (
  publicKeyHex: string,
  salary: number,
  cap: number,
  onProgress: ProgressFn,
): Promise<ProveResult & { threads: boolean }> => {
  const deps = await loadProverDeps(onProgress)
  const pk = hexToBytes(publicKeyHex)
  const result = await proveSalarySubmission(deps, pk, salary, cap, onProgress)
  return { ...result, threads: globalThis.crossOriginIsolated === true }
}

const hexToBytes = (h: string): Uint8Array => {
  const s = h.startsWith('0x') ? h.slice(2) : h
  const out = new Uint8Array(s.length / 2)
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.slice(2 * i, 2 * i + 2), 16)
  return out
}
