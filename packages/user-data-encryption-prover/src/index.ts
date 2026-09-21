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
  e0is: NoirCrtPolynomial
  e0_quotients: NoirCrtPolynomial
  k1: NoirPolynomial
  r1is: NoirCrtPolynomial
  r2is: NoirCrtPolynomial
  p1is: NoirCrtPolynomial
  p2is: NoirCrtPolynomial
}

export type UserDataEncryptionCircuitBundle = {
  ct0ChunkMain: CompiledCircuit
  ct0ChunkMainRoot: CompiledCircuit
  ct0PkCtCommit: CompiledCircuit
  ct0ChunkGamma: CompiledCircuit
  ct0EvalChunkMain: CompiledCircuit
  ct0EvalChunkMainRoot: CompiledCircuit
  ct0EvalPkCt: CompiledCircuit
  ct0EvalChunkIdentity: CompiledCircuit
  userDataEncryptionCt0: CompiledCircuit
  ct1ChunkMain: CompiledCircuit
  ct1ChunkMainRoot: CompiledCircuit
  ct1PkCtCommit: CompiledCircuit
  ct1ChunkGamma: CompiledCircuit
  ct1EvalChunkMain: CompiledCircuit
  ct1EvalChunkMainRoot: CompiledCircuit
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

const assertShape = (inputs: UserDataEncryptionInputs): { n: number; l: number; chunkSize: number } => {
  const n = inputs.u.coefficients.length
  const l = inputs.pk0is.length
  if (n === 0 || n % 2 !== 0) throw new Error(`The user-data encryption degree must be positive and even; got ${n}.`)
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
  checkRows('e0is', inputs.e0is, n)
  checkRows('e0_quotients', inputs.e0_quotients, n)
  checkRows('r1is', inputs.r1is, 2 * n - 1)
  checkRows('r2is', inputs.r2is, n - 1)
  checkRows('p1is', inputs.p1is, 2 * n - 1)
  checkRows('p2is', inputs.p2is, n - 1)

  return { n, l, chunkSize: n / 2 }
}

const padLeadingZero = (polynomial: NoirPolynomial): NoirPolynomial => ({ coefficients: ['0', ...polynomial.coefficients] })
const chunk = (polynomial: NoirPolynomial, chunkIndex: number, chunkSize: number): NoirPolynomial => ({
  coefficients: polynomial.coefficients.slice(chunkIndex * chunkSize, (chunkIndex + 1) * chunkSize),
})
const chunkRows = (rows: NoirCrtPolynomial, chunkIndex: number, chunkSize: number): NoirCrtPolynomial =>
  rows.map((row) => chunk(row, chunkIndex, chunkSize))

const sameVerificationKey = (left: RecursiveProof, right: RecursiveProof, circuitName: string) => {
  if (left.vkHash !== right.vkHash) throw new Error(`${circuitName} instances produced different verification keys.`)
}

const leafProof = (proof: RecursiveProof) => proofToFields(proof.proof)

const buildCt0TopLevelInputs = async (
  api: Barretenberg,
  circuits: UserDataEncryptionCircuitBundle,
  inputs: UserDataEncryptionInputs,
  l: number,
  chunkSize: number,
): Promise<NoirInputMap> => {
  const r1is = inputs.r1is.map(padLeadingZero)
  const r2is = inputs.r2is.map(padLeadingZero)

  const roundALeaves: RecursiveProof[] = []
  for (let chunkIndex = 0; chunkIndex < 2; chunkIndex++) {
    roundALeaves.push(
      await prove(
        api,
        circuits.ct0ChunkMain,
        {
          chunk_idx: chunkIndex,
          u_chunk: chunk(inputs.u, chunkIndex, chunkSize),
          e0_chunk: chunk(inputs.e0, chunkIndex, chunkSize),
          k1_chunk: chunk(inputs.k1, chunkIndex, chunkSize),
          r2is_chunk: chunkRows(r2is, chunkIndex, chunkSize),
          r1is_chunk: chunkRows(r1is, chunkIndex, 2 * chunkSize),
        },
        'noir-recursive',
      ),
    )
  }
  sameVerificationKey(roundALeaves[0], roundALeaves[1], 'ct0_chunk_main')

  const roundARoot = await prove(
    api,
    circuits.ct0ChunkMainRoot,
    {
      leaf_vk: roundALeaves[0].vkAsFields,
      leaf_key_hash: roundALeaves[0].vkHash,
      leaf0_proof: leafProof(roundALeaves[0]),
      leaf0_u: roundALeaves[0].publicInputs[1],
      leaf0_e0: roundALeaves[0].publicInputs[2],
      leaf0_k1: roundALeaves[0].publicInputs[3],
      leaf0_r2: roundALeaves[0].publicInputs[4],
      leaf0_r1: roundALeaves[0].publicInputs[5],
      leaf1_proof: leafProof(roundALeaves[1]),
      leaf1_u: roundALeaves[1].publicInputs[1],
      leaf1_e0: roundALeaves[1].publicInputs[2],
      leaf1_k1: roundALeaves[1].publicInputs[3],
      leaf1_r2: roundALeaves[1].publicInputs[4],
      leaf1_r1: roundALeaves[1].publicInputs[5],
    },
    'noir-recursive-no-zk',
  )

  const roundAPkCt = await prove(api, circuits.ct0PkCtCommit, { pk0is: inputs.pk0is, ct0is: inputs.ct0is }, 'noir-recursive')
  const roundA = await prove(
    api,
    circuits.ct0ChunkGamma,
    {
      roots_vk: roundARoot.vkAsFields,
      roots_key_hash: roundARoot.vkHash,
      roots_proof: leafProof(roundARoot),
      leaf_key_hash: roundARoot.publicInputs[0],
      u_root: roundARoot.publicInputs[1],
      e0_root: roundARoot.publicInputs[2],
      k1_root: roundARoot.publicInputs[3],
      r2_root: roundARoot.publicInputs[4],
      r1_root: roundARoot.publicInputs[5],
      pk_ct_vk: roundAPkCt.vkAsFields,
      pk_ct_key_hash: roundAPkCt.vkHash,
      pk_ct_proof: leafProof(roundAPkCt),
      pk0_commitment: roundAPkCt.publicInputs[0],
      ct0_commitment: roundAPkCt.publicInputs[1],
    },
    'noir-recursive-no-zk',
  )

  const gamma = roundA.publicInputs[10]
  const roundBLeaves: RecursiveProof[] = []
  for (let chunkIndex = 0; chunkIndex < 2; chunkIndex++) {
    roundBLeaves.push(
      await prove(
        api,
        circuits.ct0EvalChunkMain,
        {
          chunk_idx: chunkIndex,
          u_chunk: chunk(inputs.u, chunkIndex, chunkSize),
          e0_chunk: chunk(inputs.e0, chunkIndex, chunkSize),
          k1_chunk: chunk(inputs.k1, chunkIndex, chunkSize),
          e0is_chunk: chunkRows(inputs.e0is, chunkIndex, chunkSize),
          e0_quotients_chunk: chunkRows(inputs.e0_quotients, chunkIndex, chunkSize),
          r2is_chunk: chunkRows(r2is, chunkIndex, chunkSize),
          r1is_chunk: chunkRows(r1is, chunkIndex, 2 * chunkSize),
          gamma,
        },
        'noir-recursive',
      ),
    )
  }
  sameVerificationKey(roundBLeaves[0], roundBLeaves[1], 'ct0_eval_chunk_main')

  const ct0EvalRootInputs = (leaf: RecursiveProof, prefix: 'leaf0' | 'leaf1') => {
    const values: NoirInputMap = {
      [`${prefix}_proof`]: leafProof(leaf),
      [`${prefix}_gamma`]: leaf.publicInputs[1],
      [`${prefix}_u`]: leaf.publicInputs[2],
      [`${prefix}_e0`]: leaf.publicInputs[3],
      [`${prefix}_k1`]: leaf.publicInputs[4],
      [`${prefix}_r2`]: leaf.publicInputs[5],
      [`${prefix}_r1`]: leaf.publicInputs[6],
      [`${prefix}_u_partial`]: leaf.publicInputs[7],
      [`${prefix}_k1_partial`]: leaf.publicInputs[8],
      [`${prefix}_e0is_partial`]: leaf.publicInputs.slice(9, 9 + l),
      [`${prefix}_r2i_partial`]: leaf.publicInputs.slice(9 + l, 9 + 2 * l),
      [`${prefix}_r1i_partial`]: leaf.publicInputs.slice(9 + 2 * l, 9 + 3 * l),
    }
    return values
  }
  const roundBRoot = await prove(
    api,
    circuits.ct0EvalChunkMainRoot,
    {
      leaf_vk: roundBLeaves[0].vkAsFields,
      leaf_key_hash: roundBLeaves[0].vkHash,
      ...ct0EvalRootInputs(roundBLeaves[0], 'leaf0'),
      ...ct0EvalRootInputs(roundBLeaves[1], 'leaf1'),
    },
    'noir-recursive-no-zk',
  )
  const roundBPkCt = await prove(api, circuits.ct0EvalPkCt, { pk0is: inputs.pk0is, ct0is: inputs.ct0is, gamma }, 'noir-recursive')
  const roundB = await prove(
    api,
    circuits.ct0EvalChunkIdentity,
    {
      roots_vk: roundBRoot.vkAsFields,
      roots_key_hash: roundBRoot.vkHash,
      roots_proof: leafProof(roundBRoot),
      roots_public_inputs: roundBRoot.publicInputs,
      pk_ct_vk: roundBPkCt.vkAsFields,
      pk_ct_key_hash: roundBPkCt.vkHash,
      pk_ct_proof: leafProof(roundBPkCt),
      pk_ct_public_inputs: roundBPkCt.publicInputs,
      ct0_batching_coeffs: roundA.publicInputs.slice(10, 10 + l),
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
  chunkSize: number,
): Promise<NoirInputMap> => {
  const p1is = inputs.p1is.map(padLeadingZero)
  const p2is = inputs.p2is.map(padLeadingZero)

  const roundALeaves: RecursiveProof[] = []
  for (let chunkIndex = 0; chunkIndex < 2; chunkIndex++) {
    roundALeaves.push(
      await prove(
        api,
        circuits.ct1ChunkMain,
        {
          chunk_idx: chunkIndex,
          u_chunk: chunk(inputs.u, chunkIndex, chunkSize),
          e1_chunk: chunk(inputs.e1, chunkIndex, chunkSize),
          p2is_chunk: chunkRows(p2is, chunkIndex, chunkSize),
          p1is_chunk: chunkRows(p1is, chunkIndex, 2 * chunkSize),
        },
        'noir-recursive',
      ),
    )
  }
  sameVerificationKey(roundALeaves[0], roundALeaves[1], 'ct1_chunk_main')

  const roundARoot = await prove(
    api,
    circuits.ct1ChunkMainRoot,
    {
      leaf_vk: roundALeaves[0].vkAsFields,
      leaf_key_hash: roundALeaves[0].vkHash,
      leaf0_proof: leafProof(roundALeaves[0]),
      leaf0_u: roundALeaves[0].publicInputs[1],
      leaf0_e1: roundALeaves[0].publicInputs[2],
      leaf0_p2: roundALeaves[0].publicInputs[3],
      leaf0_p1: roundALeaves[0].publicInputs[4],
      leaf1_proof: leafProof(roundALeaves[1]),
      leaf1_u: roundALeaves[1].publicInputs[1],
      leaf1_e1: roundALeaves[1].publicInputs[2],
      leaf1_p2: roundALeaves[1].publicInputs[3],
      leaf1_p1: roundALeaves[1].publicInputs[4],
    },
    'noir-recursive-no-zk',
  )
  const roundAPkCt = await prove(api, circuits.ct1PkCtCommit, { pk1is: inputs.pk1is, ct1is: inputs.ct1is }, 'noir-recursive')
  const roundA = await prove(
    api,
    circuits.ct1ChunkGamma,
    {
      roots_vk: roundARoot.vkAsFields,
      roots_key_hash: roundARoot.vkHash,
      roots_proof: leafProof(roundARoot),
      leaf_key_hash: roundARoot.publicInputs[0],
      u_root: roundARoot.publicInputs[1],
      e1_root: roundARoot.publicInputs[2],
      p2_root: roundARoot.publicInputs[3],
      p1_root: roundARoot.publicInputs[4],
      pk_ct_vk: roundAPkCt.vkAsFields,
      pk_ct_key_hash: roundAPkCt.vkHash,
      pk_ct_proof: leafProof(roundAPkCt),
      pk1_commitment: roundAPkCt.publicInputs[0],
      ct1_commitment: roundAPkCt.publicInputs[1],
    },
    'noir-recursive-no-zk',
  )

  const gamma = roundA.publicInputs[9]
  const roundBLeaves: RecursiveProof[] = []
  for (let chunkIndex = 0; chunkIndex < 2; chunkIndex++) {
    roundBLeaves.push(
      await prove(
        api,
        circuits.ct1EvalChunkMain,
        {
          chunk_idx: chunkIndex,
          u_chunk: chunk(inputs.u, chunkIndex, chunkSize),
          e1_chunk: chunk(inputs.e1, chunkIndex, chunkSize),
          p2is_chunk: chunkRows(p2is, chunkIndex, chunkSize),
          p1is_chunk: chunkRows(p1is, chunkIndex, 2 * chunkSize),
          gamma,
        },
        'noir-recursive',
      ),
    )
  }
  sameVerificationKey(roundBLeaves[0], roundBLeaves[1], 'ct1_eval_chunk_main')

  const ct1EvalRootInputs = (leaf: RecursiveProof, prefix: 'leaf0' | 'leaf1') => {
    const values: NoirInputMap = {
      [`${prefix}_proof`]: leafProof(leaf),
      [`${prefix}_gamma`]: leaf.publicInputs[1],
      [`${prefix}_u`]: leaf.publicInputs[2],
      [`${prefix}_e1`]: leaf.publicInputs[3],
      [`${prefix}_p2`]: leaf.publicInputs[4],
      [`${prefix}_p1`]: leaf.publicInputs[5],
      [`${prefix}_u_partial`]: leaf.publicInputs[6],
      [`${prefix}_e1_partial`]: leaf.publicInputs[7],
      [`${prefix}_p2i_partial`]: leaf.publicInputs.slice(8, 8 + l),
      [`${prefix}_p1i_partial`]: leaf.publicInputs.slice(8 + l, 8 + 2 * l),
    }
    return values
  }
  const roundBRoot = await prove(
    api,
    circuits.ct1EvalChunkMainRoot,
    {
      leaf_vk: roundBLeaves[0].vkAsFields,
      leaf_key_hash: roundBLeaves[0].vkHash,
      ...ct1EvalRootInputs(roundBLeaves[0], 'leaf0'),
      ...ct1EvalRootInputs(roundBLeaves[1], 'leaf1'),
    },
    'noir-recursive-no-zk',
  )
  const roundBPkCt = await prove(api, circuits.ct1EvalPkCt, { pk1is: inputs.pk1is, ct1is: inputs.ct1is, gamma }, 'noir-recursive')
  const roundB = await prove(
    api,
    circuits.ct1EvalChunkIdentity,
    {
      roots_vk: roundBRoot.vkAsFields,
      roots_key_hash: roundBRoot.vkHash,
      roots_proof: leafProof(roundBRoot),
      roots_public_inputs: roundBRoot.publicInputs,
      pk_ct_vk: roundBPkCt.vkAsFields,
      pk_ct_key_hash: roundBPkCt.vkHash,
      pk_ct_proof: leafProof(roundBPkCt),
      pk_ct_public_inputs: roundBPkCt.publicInputs,
      ct1_batching_coeffs: roundA.publicInputs.slice(10, 10 + l),
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
  const { l, chunkSize } = assertShape(inputs)
  const ct0 = await buildCt0TopLevelInputs(api, circuits, inputs, l, chunkSize)
  const ct1 = await buildCt1TopLevelInputs(api, circuits, inputs, l, chunkSize)
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
