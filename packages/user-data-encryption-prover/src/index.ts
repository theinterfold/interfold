// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { Barretenberg, UltraHonkBackend } from '@aztec/bb.js'
import { CompiledCircuit, Noir } from '@noir-lang/noir_js'

type Field = string
type RecursiveTarget = 'noir-recursive' | 'noir-recursive-no-zk'
type NoirInputMap = Parameters<Noir['execute']>[0]

export type NoirCoefficient = string | number
export type NoirPolynomial = { coefficients: NoirCoefficient[] }
export type NoirCrtPolynomial = NoirPolynomial[]

export type UserDataEncryptionInputs = {
  pk0is: NoirCrtPolynomial
  pk1is: NoirCrtPolynomial
  ct0is: NoirCrtPolynomial
  ct1is: NoirCrtPolynomial
  u: NoirPolynomial
  e0: NoirPolynomial
  e1: NoirPolynomial
  k1: NoirPolynomial
  /** Reduced ct0 quotients, `N` coefficients each (the identity is checked mod X^N + 1). */
  r1is: NoirCrtPolynomial
  /** Reduced ct1 quotients, `N` coefficients each. */
  p1is: NoirCrtPolynomial
  /** `commit(pk0is)`; round A passes it through instead of hashing the key. */
  pk0_commitment: Field
  /** `commit(pk1is)`; as `pk0_commitment`. */
  pk1_commitment: Field
  /** `commit(ct0is)`; the leaf hashes it into the challenge before the ciphertext circuit runs. */
  ct0_commitment: Field
  /** `commit(ct1is)`; as `ct0_commitment`. */
  ct1_commitment: Field
}

export type UserDataEncryptionCircuitName =
  | 'ct0ChunkMain'
  | 'ct0PkCtCommit'
  | 'ct0EvalChunkIdentity'
  | 'userDataEncryptionCt0'
  | 'ct1ChunkMain'
  | 'ct1PkCtCommit'
  | 'ct1EvalChunkIdentity'
  | 'userDataEncryptionCt1'

/** A circuit's recursive verification key, as bb.js `generateRecursiveProofArtifacts` returns it. */
export type RecursiveVk = {
  vkAsFields: Field[]
  vkHash: Field
}

export type UserDataEncryptionCircuitBundle = Record<UserDataEncryptionCircuitName, CompiledCircuit> & {
  /**
   * Keys written with the bytecode (`<circuit>.vk_recursive.json` from `build:circuits`). bb.js
   * rebuilds the whole circuit to return a key, so each shipped key saves one circuit build per
   * encryption. A circuit without a key falls back to that rebuild. bb 5.2.0 writes the same key
   * for `noir-recursive` and `noir-recursive-no-zk`, so one file serves both targets. A key that
   * does not match the bytecode cannot forge anything: the parent proof fails to verify.
   */
  vks?: Partial<Record<UserDataEncryptionCircuitName, RecursiveVk>>
}

export type RecursiveProof = RecursiveVk & {
  proof: Uint8Array
  publicInputs: Field[]
}

export type UserDataEncryptionProofTree = {
  ct0: RecursiveProof
  ct1: RecursiveProof
}

export type UserDataEncryptionTopLevelInputs = {
  ct0: NoirInputMap
  ct1: NoirInputMap
}

const proofToFields = (proof: Uint8Array): Field[] => {
  const fields: Field[] = []
  for (let offset = 0; offset < proof.length; offset += 32) {
    fields.push(`0x${Array.from(proof.slice(offset, offset + 32), (byte) => byte.toString(16).padStart(2, '0')).join('')}`)
  }
  return fields
}

const execute = async (circuit: CompiledCircuit, inputs: NoirInputMap): Promise<Uint8Array> => {
  const noir = new Noir(circuit)
  return (await noir.execute(inputs)).witness
}

const prove = async (
  api: Barretenberg,
  circuits: UserDataEncryptionCircuitBundle,
  name: UserDataEncryptionCircuitName,
  inputs: NoirInputMap,
  verifierTarget: RecursiveTarget,
): Promise<RecursiveProof> => {
  const circuit = circuits[name]
  const witness = await execute(circuit, inputs)
  const backend = new UltraHonkBackend(circuit.bytecode, api)
  const { proof, publicInputs } = await backend.generateProof(witness, { verifierTarget })
  const shipped = circuits.vks?.[name]
  if (shipped) return { proof, publicInputs, vkAsFields: shipped.vkAsFields, vkHash: shipped.vkHash }
  const artifacts = await backend.generateRecursiveProofArtifacts(proof, publicInputs.length, { verifierTarget })
  return { proof, publicInputs, vkAsFields: artifacts.vkAsFields, vkHash: artifacts.vkHash }
}

const assertShape = (inputs: UserDataEncryptionInputs): { n: number; l: number } => {
  const n = inputs.u.coefficients.length
  const l = inputs.pk0is.length
  if (n === 0) throw new Error('The user-data encryption degree must be positive.')
  if (l === 0) throw new Error('The user-data encryption input must contain at least one CRT limb.')

  const checkRows = (name: string, rows: NoirCrtPolynomial, width: number) => {
    if (rows.length !== l || rows.some((row) => row.coefficients.length !== width)) {
      throw new Error(`${name} must contain ${l} rows of ${width} coefficients.`)
    }
  }
  const checkPolynomial = (name: string, polynomial: NoirPolynomial, width: number) => {
    if (polynomial.coefficients.length !== width) throw new Error(`${name} must contain ${width} coefficients.`)
  }

  checkPolynomial('e0', inputs.e0, n)
  checkPolynomial('e1', inputs.e1, n)
  checkPolynomial('k1', inputs.k1, n)
  checkRows('pk0is', inputs.pk0is, n)
  checkRows('pk1is', inputs.pk1is, n)
  checkRows('ct0is', inputs.ct0is, n)
  checkRows('ct1is', inputs.ct1is, n)
  checkRows('r1is', inputs.r1is, n)
  checkRows('p1is', inputs.p1is, n)

  return { n, l }
}

const leafProof = (proof: RecursiveProof) => proofToFields(proof.proof)

// Each leg is four proofs. The leaf range-checks and commits the witness, derives the challenge
// from those commitments and the pk/ct commitments, and evaluates at it. The ciphertext circuit
// commits and evaluates `ct`. The identity circuit verifies the leaf, opens `pk` and `u` against
// its commitments and evaluates `pk * u mod X^N + 1`; the top-level circuit verifies the identity
// and ciphertext proofs and checks the batched identity.

const buildCt0TopLevelInputs = async (
  api: Barretenberg,
  circuits: UserDataEncryptionCircuitBundle,
  inputs: UserDataEncryptionInputs,
  l: number,
): Promise<NoirInputMap> => {
  // Leaf outputs: pk0/ct0 commitments, k1/u/e0/r1 roots, gammas[L], k1(gamma), e0(gamma), r1(gamma)[L].
  const leaf = await prove(
    api,
    circuits,
    'ct0ChunkMain',
    {
      u: inputs.u,
      e0: inputs.e0,
      k1: inputs.k1,
      r1is: inputs.r1is,
      pk0_commitment: inputs.pk0_commitment,
      ct0_commitment: inputs.ct0_commitment,
    },
    'noir-recursive',
  )
  const gamma = leaf.publicInputs[6]
  const ciphertext = await prove(api, circuits, 'ct0PkCtCommit', { ct0is: inputs.ct0is, gamma }, 'noir-recursive')
  const identity = await prove(
    api,
    circuits,
    'ct0EvalChunkIdentity',
    {
      leaf_vk: leaf.vkAsFields,
      leaf_key_hash: leaf.vkHash,
      leaf_proof: leafProof(leaf),
      leaf_public_inputs: leaf.publicInputs,
      pk0is: inputs.pk0is,
      u: inputs.u,
    },
    'noir-recursive',
  )
  if (identity.publicInputs.length !== 8 + l) throw new Error('ct0 identity proof has an unexpected public-input count.')

  return {
    identity_vk: identity.vkAsFields,
    identity_key_hash: identity.vkHash,
    identity_proof: leafProof(identity),
    identity_public_inputs: identity.publicInputs,
    ct_vk: ciphertext.vkAsFields,
    ct_key_hash: ciphertext.vkHash,
    ct_proof: leafProof(ciphertext),
    ct_public_inputs: ciphertext.publicInputs,
    k1: inputs.k1,
  }
}

const buildCt1TopLevelInputs = async (
  api: Barretenberg,
  circuits: UserDataEncryptionCircuitBundle,
  inputs: UserDataEncryptionInputs,
  l: number,
): Promise<NoirInputMap> => {
  // Leaf outputs: pk1/ct1 commitments, u/e1/p1 roots, gamma, batching[L], e1(gamma), p1(gamma)[L].
  const leaf = await prove(
    api,
    circuits,
    'ct1ChunkMain',
    {
      u: inputs.u,
      e1: inputs.e1,
      p1is: inputs.p1is,
      pk1_commitment: inputs.pk1_commitment,
      ct1_commitment: inputs.ct1_commitment,
    },
    'noir-recursive',
  )
  const gamma = leaf.publicInputs[5]
  const ciphertext = await prove(api, circuits, 'ct1PkCtCommit', { ct1is: inputs.ct1is, gamma }, 'noir-recursive')
  const identity = await prove(
    api,
    circuits,
    'ct1EvalChunkIdentity',
    {
      leaf_vk: leaf.vkAsFields,
      leaf_key_hash: leaf.vkHash,
      leaf_proof: leafProof(leaf),
      leaf_public_inputs: leaf.publicInputs,
      pk1is: inputs.pk1is,
      u: inputs.u,
    },
    'noir-recursive',
  )
  if (identity.publicInputs.length !== 8 + l) throw new Error('ct1 identity proof has an unexpected public-input count.')

  return {
    identity_vk: identity.vkAsFields,
    identity_key_hash: identity.vkHash,
    identity_proof: leafProof(identity),
    identity_public_inputs: identity.publicInputs,
    ct_vk: ciphertext.vkAsFields,
    ct_key_hash: ciphertext.vkHash,
    ct_proof: leafProof(ciphertext),
    ct_public_inputs: ciphertext.publicInputs,
  }
}

/** Build the recursive child proofs and return the two top-level circuit inputs. */
export const buildUserDataEncryptionTopLevelInputs = async (
  api: Barretenberg,
  circuits: UserDataEncryptionCircuitBundle,
  inputs: UserDataEncryptionInputs,
): Promise<UserDataEncryptionTopLevelInputs> => {
  const { l } = assertShape(inputs)
  const ct0 = await buildCt0TopLevelInputs(api, circuits, inputs, l)
  const ct1 = await buildCt1TopLevelInputs(api, circuits, inputs, l)
  return { ct0, ct1 }
}

/** Build both recursive user-data encryption legs from the original polynomial witness. */
export const proveUserDataEncryptionTree = async (
  api: Barretenberg,
  circuits: UserDataEncryptionCircuitBundle,
  inputs: UserDataEncryptionInputs,
): Promise<UserDataEncryptionProofTree> => {
  const topLevelInputs = await buildUserDataEncryptionTopLevelInputs(api, circuits, inputs)
  const ct0 = await prove(api, circuits, 'userDataEncryptionCt0', topLevelInputs.ct0, 'noir-recursive')
  const ct1 = await prove(api, circuits, 'userDataEncryptionCt1', topLevelInputs.ct1, 'noir-recursive-no-zk')
  return { ct0, ct1 }
}
