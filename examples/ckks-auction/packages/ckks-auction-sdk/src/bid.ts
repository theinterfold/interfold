// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

// The bidder's local pipeline: ONE CKKS encryption (WASM, `@interfold/ckks-zk-inputs`) feeding
// three Honk proofs bound by commitments —
//
//   ct0 leg  user_data_encryption_ckks_ct0_ps2  → (pk0_c, ct0_c, m_commitment, u_commitment)
//   ct1 leg  user_data_encryption_ckks_ct1_ps2  → (pk1_c, ct1_c, u_commitment)
//   app leg  ckks_auction_validity_ps2          → [cap, address, merkle_root] ⇒ m_commitment
//
// The app leg takes the SAME message polynomial `m` the ct0 leg witnessed, recomputes
// `m_commitment`, and proves `bid ≤ balance` for the `(address, balance)` leaf under the round's
// root, plus that `m` is the slot-REPLICATED encoding of `bid / cap` (tail bound). The contract
// equates m across ct0/app and u across ct0/ct1 and requires `address == msg.sender`, so the bid
// must be sent from the bidder's own wallet (`publishBid`). The plaintext bid never leaves this
// process.

import { Barretenberg, BackendType, UltraHonkBackend } from '@aztec/bb.js'
import type { ProofData } from '@aztec/bb.js'
import { Noir } from '@noir-lang/noir_js'
import type { InputMap } from '@noir-lang/noir_js'
import { getAddress } from 'viem'
import type { Address, Hex } from 'viem'

import { requireCircuits } from './circuits'
import { rootFromProof } from './balanceTree'
import { AUCTION_PARAM_SET, BID_BOUND, MERKLE_MAX_DEPTH, NORMALIZATION_CAP } from './types'
import type { BalanceProof, BidSubmission, LegName, ProgressCallback, ProvenLeg, ProvingTimings } from './types'

type WasmModule = typeof import('@interfold/ckks-zk-inputs')

interface WitnessBundle {
  ciphertext_hex: string
  ct0_inputs: InputMap
  ct1_inputs: InputMap
  u_commitment_hex: string
  m_commitment_hex: string
}

// Cached Barretenberg API (CRISP getBBApi pattern): initialising WASM + the 2^20 SRS once per
// session, not per proof. The ps2 Greco legs have circuit_size ≈ 836k, so 2^20 is the smallest
// power that fits; a 2^21 CRS exceeds Chrome's IndexedDB per-value cap.
export const SRS_SIZE = 2 ** 20
let _api: Barretenberg | null = null
let _apiInit: Promise<Barretenberg> | null = null

export const getBBApi = async (): Promise<Barretenberg> => {
  if (_api) return _api
  if (!_apiInit) {
    _apiInit = (async () => {
      // Node: pin the WASM backend (the native socket backend hangs). Browser: auto (workers).
      const backend = typeof window === 'undefined' ? { backend: BackendType.Wasm } : {}
      const api = await Barretenberg.new({ srsSize: SRS_SIZE, ...backend })
      _api = api
      return api
    })()
  }
  return _apiInit
}

export const destroyBBApi = async (): Promise<void> => {
  if (_api) await _api.destroy()
  _api = null
  _apiInit = null
}

let _wasm: WasmModule | null = null
const loadWasm = async (): Promise<WasmModule> => {
  if (_wasm) return _wasm
  const init = (await import('@interfold/ckks-zk-inputs/init')).default
  await init()
  _wasm = await import('@interfold/ckks-zk-inputs')
  return _wasm
}

export const word = (value: bigint): Hex => `0x${value.toString(16).padStart(64, '0')}`
const bytesToHex = (bytes: Uint8Array): Hex => `0x${Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('')}`
const normalizeWords = (inputs: string[]): Hex[] => inputs.map((h) => word(BigInt(h)))

/** Local pre-check of exactly what the app leg and the contract will refuse, so a doomed bid fails in ms, not after 40 s of proving. */
export const checkBid = (bid: number, proof: BalanceProof, sender: Address): void => {
  if (!Number.isInteger(bid) || bid <= 0) throw new Error('bid must be a positive integer')
  if (bid > BID_BOUND) throw new Error(`bid ${bid} exceeds the ParamSet ${AUCTION_PARAM_SET} bound ${BID_BOUND}`)
  if (BigInt(bid) > BigInt(proof.balance)) throw new Error(`bid ${bid} exceeds your attested balance ${proof.balance}`)
  if (getAddress(proof.address) !== getAddress(sender)) throw new Error('balance proof is for a different address than the sender')
  if (proof.depth > MERKLE_MAX_DEPTH) throw new Error(`balance proof depth ${proof.depth} exceeds ${MERKLE_MAX_DEPTH}`)
  if (proof.indices.length !== proof.depth || proof.siblings.length !== proof.depth) throw new Error('balance proof path length mismatch')
  if (rootFromProof(proof).toLowerCase() !== proof.merkleRoot.toLowerCase()) throw new Error('balance proof does not open to its root')
}

/** noir_js InputMap for `ckks_auction_validity_ps2` (mirrors `AppInputs::to_toml`). */
export const buildAppInputs = (m: InputMap[string], bid: number, proof: BalanceProof): InputMap => {
  const indices = new Array<boolean>(MERKLE_MAX_DEPTH).fill(false)
  const siblings = new Array<string>(MERKLE_MAX_DEPTH).fill('0')
  for (let i = 0; i < proof.depth; i++) {
    indices[i] = proof.indices[i]
    siblings[i] = proof.siblings[i]
  }
  return {
    m,
    value_raw: String(bid),
    balance: proof.balance,
    depth: String(proof.depth),
    indices,
    siblings,
    cap: String(NORMALIZATION_CAP),
    address: BigInt(getAddress(proof.address)).toString(),
    merkle_root: BigInt(proof.merkleRoot).toString(),
  }
}

/**
 * Encrypt `bid` under the committee's CKKS public key and prove all three legs.
 *
 * Throws BEFORE any proving when the bid exceeds the attested balance (the same predicate the
 * circuit enforces — a forged witness cannot pass it either). `onProgress` receives each stage so
 * a UI can show per-leg timings.
 */
export const encryptAndProveBid = async (
  publicKey: Uint8Array,
  bid: number,
  balanceProof: BalanceProof,
  sender: Address,
  onProgress: ProgressCallback = () => {},
): Promise<BidSubmission> => {
  checkBid(bid, balanceProof, sender)
  const circuits = requireCircuits()
  const t0 = performance.now()
  const elapsed = () => performance.now() - t0
  const timings: ProvingTimings = {
    encryptMs: 0,
    executeMs: { ct0: 0, ct1: 0, app: 0 },
    proveMs: { ct0: 0, ct1: 0, app: 0 },
    backendInitMs: 0,
    totalMs: 0,
  }

  onProgress({ stage: 'encrypt' }, elapsed())
  const wasm = await loadWasm()
  let t = performance.now()
  const bundle = wasm.encryptAndWitness(AUCTION_PARAM_SET, publicKey, bid, NORMALIZATION_CAP, true, undefined) as WitnessBundle
  timings.encryptMs = performance.now() - t

  onProgress({ stage: 'backend' }, elapsed())
  t = performance.now()
  const api = await getBBApi()
  timings.backendInitMs = performance.now() - t

  const legs: { name: LegName; inputs: InputMap; expectPublic: number }[] = [
    { name: 'app', inputs: buildAppInputs(bundle.ct0_inputs.m, bid, balanceProof), expectPublic: 4 },
    { name: 'ct1', inputs: bundle.ct1_inputs, expectPublic: 3 },
    { name: 'ct0', inputs: bundle.ct0_inputs, expectPublic: 4 },
  ]
  const proven = {} as Record<LegName, ProvenLeg>
  for (const leg of legs) {
    const circuit = circuits[leg.name]
    onProgress({ stage: 'execute', leg: leg.name }, elapsed())
    t = performance.now()
    const { witness } = await new Noir(circuit).execute(leg.inputs)
    timings.executeMs[leg.name] = performance.now() - t

    onProgress({ stage: 'prove', leg: leg.name }, elapsed())
    t = performance.now()
    const backend = new UltraHonkBackend(circuit.bytecode, api)
    // 'evm' = keccak ZK transcript: the deployed verifiers are `bb write_vk -t evm` ZK verifiers.
    const proof: ProofData = await backend.generateProof(witness, { verifierTarget: 'evm' })
    timings.proveMs[leg.name] = performance.now() - t
    if (proof.publicInputs.length !== leg.expectPublic) {
      throw new Error(`${leg.name}: expected ${leg.expectPublic} public inputs, got ${proof.publicInputs.length}`)
    }
    proven[leg.name] = { proof: bytesToHex(proof.proof), publicInputs: normalizeWords(proof.publicInputs) }
  }

  // Cross-leg bindings the contract checks — assert them here so a mismatch is attributable.
  const uCommitment = word(BigInt(bundle.u_commitment_hex))
  const mCommitment = word(BigInt(bundle.m_commitment_hex))
  if (proven.ct0.publicInputs[3] !== uCommitment || proven.ct1.publicInputs[2] !== uCommitment) {
    throw new Error('u_commitment mismatch between the ct0 and ct1 legs')
  }
  if (proven.ct0.publicInputs[2] !== mCommitment || proven.app.publicInputs[3] !== mCommitment) {
    throw new Error('m_commitment mismatch between the ct0 and app legs')
  }

  timings.totalMs = elapsed()
  onProgress({ stage: 'done' }, timings.totalMs)
  return {
    ciphertext: `0x${bundle.ciphertext_hex}`,
    ct0: proven.ct0,
    ct1: proven.ct1,
    app: proven.app,
    mCommitment,
    uCommitment,
    timings,
  }
}
