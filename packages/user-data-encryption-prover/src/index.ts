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
}

export type UserDataEncryptionCircuitBundle = {
  ct0ChunkMain: CompiledCircuit
  ct0PkCtCommit: CompiledCircuit
  ct0ChunkGamma: CompiledCircuit
  ct0EvalChunkMain: CompiledCircuit
  ct0EvalPkCt: CompiledCircuit
  ct0EvalChunkIdentity: CompiledCircuit
  userDataEncryptionCt0: CompiledCircuit
  ct1ChunkMain: CompiledCircuit
  ct1PkCtCommit: CompiledCircuit
  ct1ChunkGamma: CompiledCircuit
  ct1EvalChunkMain: CompiledCircuit
  ct1EvalPkCt: CompiledCircuit
  ct1EvalChunkIdentity: CompiledCircuit
  userDataEncryptionCt1: CompiledCircuit
}

export type RecursiveProof = {
  proof: Uint8Array
  publicInputs: Field[]
  vkAsFields: Field[]
  vkHash: Field
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
  circuit: CompiledCircuit,
  inputs: NoirInputMap,
  verifierTarget: RecursiveTarget,
): Promise<RecursiveProof> => {
  const witness = await execute(circuit, inputs)
  const backend = new UltraHonkBackend(circuit.bytecode, api)
  const { proof, publicInputs } = await backend.generateProof(witness, { verifierTarget })
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

// Each leg runs two rounds with one ZK leaf per round. Round A: the leaf range-checks and commits
// the witness, `*_pk_ct_commit` commits the ciphertext, and `*_chunk_gamma` verifies both and
// derives the challenge. Round B: the leaf re-derives the commitments and evaluates at gamma,
// `*_eval_pk_ct` evaluates the ciphertext and the reduced `pk * u` product, and
// `*_eval_chunk_identity` verifies both and checks the identity.

const buildCt0TopLevelInputs = async (
  api: Barretenberg,
  circuits: UserDataEncryptionCircuitBundle,
  inputs: UserDataEncryptionInputs,
  l: number,
): Promise<NoirInputMap> => {
  const witness = { u: inputs.u, e0: inputs.e0, k1: inputs.k1, r1is: inputs.r1is }

  // Leaf outputs: u, e0, k1, r1 commitments.
  const roundALeaf = await prove(api, circuits.ct0ChunkMain, witness, 'noir-recursive')
  const roundAPkCt = await prove(
    api,
    circuits.ct0PkCtCommit,
    { pk0_commitment: inputs.pk0_commitment, ct0is: inputs.ct0is },
    'noir-recursive',
  )
  // Round outputs: leaf and pk/ct key hashes, pk0 and ct0 commitments, k1/u/e0/r1 roots, gammas[L].
  const roundA = await prove(
    api,
    circuits.ct0ChunkGamma,
    {
      leaf_vk: roundALeaf.vkAsFields,
      leaf_key_hash: roundALeaf.vkHash,
      leaf_proof: leafProof(roundALeaf),
      u_commit: roundALeaf.publicInputs[0],
      e0_commit: roundALeaf.publicInputs[1],
      k1_commit: roundALeaf.publicInputs[2],
      r1_commit: roundALeaf.publicInputs[3],
      pk_ct_vk: roundAPkCt.vkAsFields,
      pk_ct_key_hash: roundAPkCt.vkHash,
      pk_ct_proof: leafProof(roundAPkCt),
      pk0_commitment: roundAPkCt.publicInputs[0],
      ct0_commitment: roundAPkCt.publicInputs[1],
    },
    'noir-recursive-no-zk',
  )

  const batching = roundA.publicInputs.slice(8, 8 + l)
  const gamma = batching[0]
  const roundBLeaf = await prove(api, circuits.ct0EvalChunkMain, { ...witness, gamma }, 'noir-recursive')
  const roundBPkCt = await prove(
    api,
    circuits.ct0EvalPkCt,
    { pk0is: inputs.pk0is, ct0is: inputs.ct0is, u: inputs.u, gamma },
    'noir-recursive',
  )
  const roundB = await prove(
    api,
    circuits.ct0EvalChunkIdentity,
    {
      leaf_vk: roundBLeaf.vkAsFields,
      leaf_key_hash: roundBLeaf.vkHash,
      leaf_proof: leafProof(roundBLeaf),
      leaf_public_inputs: roundBLeaf.publicInputs,
      pk_ct_vk: roundBPkCt.vkAsFields,
      pk_ct_key_hash: roundBPkCt.vkHash,
      pk_ct_proof: leafProof(roundBPkCt),
      pk_ct_public_inputs: roundBPkCt.publicInputs,
      ct0_batching_coeffs: batching,
    },
    'noir-recursive-no-zk',
  )

  return {
    a_vk: roundA.vkAsFields,
    a_key_hash: roundA.vkHash,
    a_proof: leafProof(roundA),
    a_public_inputs: roundA.publicInputs,
    b_vk: roundB.vkAsFields,
    b_key_hash: roundB.vkHash,
    b_proof: leafProof(roundB),
    b_public_inputs: roundB.publicInputs,
    k1: inputs.k1,
  }
}

const buildCt1TopLevelInputs = async (
  api: Barretenberg,
  circuits: UserDataEncryptionCircuitBundle,
  inputs: UserDataEncryptionInputs,
  l: number,
): Promise<NoirInputMap> => {
  const witness = { u: inputs.u, e1: inputs.e1, p1is: inputs.p1is }

  // Leaf outputs: u, e1, p1 commitments.
  const roundALeaf = await prove(api, circuits.ct1ChunkMain, witness, 'noir-recursive')
  const roundAPkCt = await prove(
    api,
    circuits.ct1PkCtCommit,
    { pk1_commitment: inputs.pk1_commitment, ct1is: inputs.ct1is },
    'noir-recursive',
  )
  // Round outputs: leaf and pk/ct key hashes, pk1 and ct1 commitments, u/e1/p1 roots, gamma,
  // batching[L].
  const roundA = await prove(
    api,
    circuits.ct1ChunkGamma,
    {
      leaf_vk: roundALeaf.vkAsFields,
      leaf_key_hash: roundALeaf.vkHash,
      leaf_proof: leafProof(roundALeaf),
      u_commit: roundALeaf.publicInputs[0],
      e1_commit: roundALeaf.publicInputs[1],
      p1_commit: roundALeaf.publicInputs[2],
      pk_ct_vk: roundAPkCt.vkAsFields,
      pk_ct_key_hash: roundAPkCt.vkHash,
      pk_ct_proof: leafProof(roundAPkCt),
      pk1_commitment: roundAPkCt.publicInputs[0],
      ct1_commitment: roundAPkCt.publicInputs[1],
    },
    'noir-recursive-no-zk',
  )

  const gamma = roundA.publicInputs[7]
  const roundBLeaf = await prove(api, circuits.ct1EvalChunkMain, { ...witness, gamma }, 'noir-recursive')
  const roundBPkCt = await prove(
    api,
    circuits.ct1EvalPkCt,
    { pk1is: inputs.pk1is, ct1is: inputs.ct1is, u: inputs.u, gamma },
    'noir-recursive',
  )
  const roundB = await prove(
    api,
    circuits.ct1EvalChunkIdentity,
    {
      leaf_vk: roundBLeaf.vkAsFields,
      leaf_key_hash: roundBLeaf.vkHash,
      leaf_proof: leafProof(roundBLeaf),
      leaf_public_inputs: roundBLeaf.publicInputs,
      pk_ct_vk: roundBPkCt.vkAsFields,
      pk_ct_key_hash: roundBPkCt.vkHash,
      pk_ct_proof: leafProof(roundBPkCt),
      pk_ct_public_inputs: roundBPkCt.publicInputs,
      ct1_batching_coeffs: roundA.publicInputs.slice(8, 8 + l),
    },
    'noir-recursive-no-zk',
  )

  return {
    a_vk: roundA.vkAsFields,
    a_key_hash: roundA.vkHash,
    a_proof: leafProof(roundA),
    a_public_inputs: roundA.publicInputs,
    b_vk: roundB.vkAsFields,
    b_key_hash: roundB.vkHash,
    b_proof: leafProof(roundB),
    b_public_inputs: roundB.publicInputs,
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
  const ct0 = await prove(api, circuits.userDataEncryptionCt0, topLevelInputs.ct0, 'noir-recursive')
  const ct1 = await prove(api, circuits.userDataEncryptionCt1, topLevelInputs.ct1, 'noir-recursive-no-zk')
  return { ct0, ct1 }
}
