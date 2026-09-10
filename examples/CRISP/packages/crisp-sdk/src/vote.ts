// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { type Vote, type CensusVariant, type PrepareBallotInputs, type PreparedBallot, ProofData } from './types'
import { getMaxVoteValue, proofToFields } from './utils'
import { attachSignatureImpl, prepareCircuitInputsImpl } from './circuitInputs'
import { MASK_SIGNATURE } from './constants'
export { encodeVote, encryptVote, decodeTally, decryptVote, generateBFVKeys } from './encoding'
export { splitDigest } from './circuitInputs'
import { Noir, type CompiledCircuit } from '@noir-lang/noir_js'
import { Barretenberg, BackendType, UltraHonkBackend } from '@aztec/bb.js'
// Only the aggregation circuits are imported here. Their ABI is proof and verification-key shaped
// rather than polynomial shaped, so one artifact serves every preset and inlining them costs ~0.3MB.
// The BFV-shaped circuits arrive through `setCircuits()` — see ./circuits.
import foldCircuit from '../../../circuits/bin/fold/target/crisp_fold.json'
import foldOnchainCircuit from '../../../circuits/bin/fold_onchain/target/crisp_onchain_fold.json'
import userDataEncryptionCircuit from '../../../../../circuits/bin/threshold/target/user_data_encryption.json'
import { requireCircuits } from './circuits'
import { bytesToHex, encodeAbiParameters, parseAbiParameters, numberToHex, getAddress, keccak256 } from 'viem/utils'
import { Hex } from 'viem'

// Cached Barretenberg API instance — avoids re-initialising WASM + SRS on every proof.
let _bbApi: Barretenberg | null = null
let _bbApiInitPromise: Promise<Barretenberg> | null = null

const getBBApi = async (): Promise<Barretenberg> => {
  if (_bbApi) return _bbApi
  if (_bbApiInitPromise) return _bbApiInitPromise

  _bbApiInitPromise = (async () => {
    try {
      // Outside the browser, bb.js prefers its native Unix-socket backend, allows the bb
      // process only 5s to create the socket, and drops the timeout into an unhandled
      // rejection — callers then wait forever instead of failing. Pin Node to WASM. The
      // browser is unaffected: it already selects the (multi-threaded) worker backend.
      const backend = typeof window === 'undefined' ? { backend: BackendType.Wasm } : {}
      const api = await Barretenberg.new({ srsSize: 2 ** 21, ...backend })
      _bbApi = api
      return api
    } finally {
      _bbApiInitPromise = null
    }
  })()

  return _bbApiInitPromise
}

// Destroy the cached Barretenberg API and free its resources.
export const destroyBBApi = (): void => {
  _bbApiInitPromise = null
  if (_bbApi) {
    _bbApi.destroy()
    _bbApi = null
  }
}

/**
 * Encrypt a ballot and build every circuit input that does not depend on the signature.
 * Runs in a worker when available to avoid blocking the main thread.
 */
export const prepareCircuitInputs = async (inputs: PrepareBallotInputs): Promise<PreparedBallot> => {
  const preset = requireCircuits().preset

  if (typeof Worker !== 'undefined') {
    try {
      const worker = new Worker(new URL('./workers/generateCircuitInputs.worker.js', import.meta.url), { type: 'module' })
      return new Promise((resolve, reject) => {
        worker.onmessage = (e: MessageEvent<{ type: 'result'; prepared: PreparedBallot } | { type: 'error'; error: string }>) => {
          worker.terminate()
          if (e.data.type === 'result') {
            resolve(e.data.prepared)
          } else {
            reject(new Error(e.data.error))
          }
        }
        worker.onerror = (err) => {
          worker.terminate()
          reject(err)
        }
        worker.postMessage({ inputs, preset })
      })
    } catch {
      // Worker creation failed (e.g. bundler path resolution); fall back to main thread
    }
  }

  return prepareCircuitInputsImpl(inputs)
}

/**
 * Execute a circuit.
 * @param circuit - The circuit to execute.
 * @param inputs - The inputs to the circuit.
 * @returns The execute circuit result.
 */
export const executeCircuit = async (circuit: CompiledCircuit, inputs: any): Promise<{ witness: Uint8Array; returnValue: any }> => {
  const noir = new Noir(circuit as CompiledCircuit)

  return noir.execute(inputs)
}

/**
 * Generate a proof for the CRISP circuit given the circuit inputs.
 * @param circuitInputs - Inputs used in both the CRISP and GRECO circuits.
 * @returns The proof.
 */
export const generateProof = async (circuitInputs: any, censusMode: CensusVariant = 'merkle') => {
  const api = await getBBApi()

  const circuits = requireCircuits()
  const ballotCircuit = censusMode === 'onchain' ? circuits.crispOnchain : circuits.crisp
  const foldCircuitForMode = censusMode === 'onchain' ? foldOnchainCircuit : foldCircuit

  const { witness: userDataEncryptionCt0Witness } = await executeCircuit(circuits.userDataEncryptionCt0 as CompiledCircuit, {
    pk0is: circuitInputs.pk0is,
    ct0is: circuitInputs.ct0is,
    u: circuitInputs.u,
    e0: circuitInputs.e0,
    e0is: circuitInputs.e0is,
    e0_quotients: circuitInputs.e0_quotients,
    k1: circuitInputs.k1,
    r1is: circuitInputs.r1is,
    r2is: circuitInputs.r2is,
  })
  const { witness: userDataEncryptionCt1Witness } = await executeCircuit(circuits.userDataEncryptionCt1 as CompiledCircuit, {
    pk1is: circuitInputs.pk1is,
    ct1is: circuitInputs.ct1is,
    u: circuitInputs.u,
    e1: circuitInputs.e1,
    p1is: circuitInputs.p1is,
    p2is: circuitInputs.p2is,
  })
  // The two stacks share every input except how eligibility reaches the circuit: a census round
  // proves a Merkle path, an on-chain round takes the voting power the contract read.
  const eligibilityInputs =
    censusMode === 'onchain'
      ? { voting_power: circuitInputs.voting_power }
      : {
          merkle_root: circuitInputs.merkle_root,
          balance: circuitInputs.balance,
          merkle_proof_length: circuitInputs.merkle_proof_length,
          merkle_proof_indices: circuitInputs.merkle_proof_indices,
          merkle_proof_siblings: circuitInputs.merkle_proof_siblings,
        }

  const { witness: crispWitness, returnValue: crispReturnValue } = await executeCircuit(ballotCircuit as CompiledCircuit, {
    prev_ct0is: circuitInputs.prev_ct0is,
    prev_ct1is: circuitInputs.prev_ct1is,
    prev_ct_commitment: circuitInputs.prev_ct_commitment,
    sum_ct0is: circuitInputs.sum_ct0is,
    sum_ct1is: circuitInputs.sum_ct1is,
    sum_r0is: circuitInputs.sum_r0is,
    sum_r1is: circuitInputs.sum_r1is,
    ct0is: circuitInputs.ct0is,
    ct1is: circuitInputs.ct1is,
    k1: circuitInputs.k1,
    public_key_x: circuitInputs.public_key_x,
    public_key_y: circuitInputs.public_key_y,
    signature: circuitInputs.signature,
    digest_hi: circuitInputs.digest_hi,
    digest_lo: circuitInputs.digest_lo,
    slot_address: circuitInputs.slot_address,
    ...eligibilityInputs,
    is_first_vote: circuitInputs.is_first_vote,
    is_mask_vote: circuitInputs.is_mask_vote,
    num_options: circuitInputs.num_options,
  })

  const userDataEncryptionCt0Backend = new UltraHonkBackend((circuits.userDataEncryptionCt0 as CompiledCircuit).bytecode, api)
  const userDataEncryptionCt1Backend = new UltraHonkBackend((circuits.userDataEncryptionCt1 as CompiledCircuit).bytecode, api)
  const userDataEncryptionBackend = new UltraHonkBackend((userDataEncryptionCircuit as CompiledCircuit).bytecode, api)
  const crispBackend = new UltraHonkBackend((ballotCircuit as CompiledCircuit).bytecode, api)
  const foldBackend = new UltraHonkBackend((foldCircuitForMode as CompiledCircuit).bytecode, api)

  const { proof: userDataEncryptionCt0Proof, publicInputs: userDataEncryptionCt0PublicInputs } =
    await userDataEncryptionCt0Backend.generateProof(userDataEncryptionCt0Witness, {
      verifierTarget: 'noir-recursive-no-zk',
    })
  const { proof: userDataEncryptionCt1Proof, publicInputs: userDataEncryptionCt1PublicInputs } =
    await userDataEncryptionCt1Backend.generateProof(userDataEncryptionCt1Witness, {
      verifierTarget: 'noir-recursive-no-zk',
    })
  const { proof: crispProof, publicInputs: crispPublicInputs } = await crispBackend.generateProof(crispWitness, {
    verifierTarget: 'noir-recursive-no-zk',
  })

  const userDataEncryptionCt0Artifacts = await userDataEncryptionCt0Backend.generateRecursiveProofArtifacts(
    userDataEncryptionCt0Proof,
    userDataEncryptionCt0PublicInputs.length,
    {
      verifierTarget: 'noir-recursive-no-zk',
    },
  )
  const userDataEncryptionCt1Artifacts = await userDataEncryptionCt1Backend.generateRecursiveProofArtifacts(
    userDataEncryptionCt1Proof,
    userDataEncryptionCt1PublicInputs.length,
    {
      verifierTarget: 'noir-recursive-no-zk',
    },
  )
  const crispArtifacts = await crispBackend.generateRecursiveProofArtifacts(crispProof, crispPublicInputs.length, {
    verifierTarget: 'noir-recursive-no-zk',
  })

  const { witness: userDataEncryptionWitness } = await executeCircuit(userDataEncryptionCircuit as CompiledCircuit, {
    ct0_verification_key: userDataEncryptionCt0Artifacts.vkAsFields,
    ct0_proof: proofToFields(userDataEncryptionCt0Proof),
    ct0_public_inputs: userDataEncryptionCt0PublicInputs,
    ct0_key_hash: userDataEncryptionCt0Artifacts.vkHash,
    ct1_verification_key: userDataEncryptionCt1Artifacts.vkAsFields,
    ct1_proof: proofToFields(userDataEncryptionCt1Proof),
    ct1_public_inputs: userDataEncryptionCt1PublicInputs,
    ct1_key_hash: userDataEncryptionCt1Artifacts.vkHash,
  })

  const { proof: userDataEncryptionProof, publicInputs: userDataEncryptionPublicInputs } = await userDataEncryptionBackend.generateProof(
    userDataEncryptionWitness,
    {
      verifierTarget: 'noir-recursive-no-zk',
    },
  )
  const userDataEncryptionArtifacts = await userDataEncryptionBackend.generateRecursiveProofArtifacts(
    userDataEncryptionProof,
    userDataEncryptionPublicInputs.length,
    {
      verifierTarget: 'noir-recursive-no-zk',
    },
  )

  const { witness: foldWitness } = await executeCircuit(foldCircuitForMode as CompiledCircuit, {
    user_data_encryption_verification_key: userDataEncryptionArtifacts.vkAsFields,
    user_data_encryption_proof: proofToFields(userDataEncryptionProof),
    user_data_encryption_public_inputs: userDataEncryptionPublicInputs,
    user_data_encryption_key_hash: userDataEncryptionArtifacts.vkHash,
    crisp_verification_key: crispArtifacts.vkAsFields,
    crisp_proof: proofToFields(crispProof),
    crisp_key_hash: crispArtifacts.vkHash,
    prev_ct_commitment: circuitInputs.prev_ct_commitment,
    digest_hi: circuitInputs.digest_hi,
    digest_lo: circuitInputs.digest_lo,
    slot_address: circuitInputs.slot_address,
    // Position 4 of the public inputs, and the only slot the two stacks disagree on.
    ...(censusMode === 'onchain' ? { voting_power: circuitInputs.voting_power } : { merkle_root: circuitInputs.merkle_root }),
    is_first_vote: circuitInputs.is_first_vote,
    num_options: circuitInputs.num_options,
    final_ct_commitment: crispReturnValue[0].toString(),
    ct_commitment: crispReturnValue[1].toString(),
    k1_commitment: crispReturnValue[2].toString(),
  })

  const proof = await foldBackend.generateProof(foldWitness, { verifierTarget: 'evm' })

  return proof
}

/**
 * Validate a vote.
 * @param vote - The vote to validate.
 * @param balance - The balance of the voter.
 */
export const validateVote = (vote: Vote, balance: bigint): void => {
  const numChoices = vote.length
  const maxValue = getMaxVoteValue(numChoices)

  for (let i = 0; i < vote.length; i++) {
    if (vote[i] < 0) {
      throw new Error(`Invalid vote: choice ${i} is negative`)
    }
    if (vote[i] > maxValue) {
      throw new Error(`Invalid vote: choice ${i} exceeds maximum encodable value`)
    }
  }

  if (numChoices === 2) {
    // Binary: mutually exclusive
    const nonZeroCount = vote.filter((v) => v > 0).length
    if (nonZeroCount > 1) {
      throw new Error('Invalid vote: for 2 options, only one choice can be non-zero')
    }
    const votedAmount = vote.find((v) => v > 0) ?? 0
    if (votedAmount > balance) {
      throw new Error('Invalid vote: vote exceeds balance')
    }
  } else {
    // 3+ options: split allowed, total capped
    const total = vote.reduce((sum, v) => sum + v, 0)
    if (total > balance) {
      throw new Error(`Invalid vote: total votes (${total}) exceed balance (${balance})`)
    }
  }
}

/**
 * Phase one: encrypt a ballot, before the voter signs anything.
 *
 * A ballot must be encrypted before it can be signed, because the digest binds the ciphertext.
 * Take `ctCommitment` from the result, read the digest from `CRISPProgram.ballotDigest`, have the
 * voter sign it, then call {@link finishBallotProof}.
 *
 * @param inputs - The ballot to encrypt.
 * @returns The prepared ballot.
 */
export const prepareBallot = async (inputs: PrepareBallotInputs): Promise<PreparedBallot> => {
  if (!inputs.isMaskVote) {
    validateVote(inputs.vote, inputs.censusMode === 'onchain' ? inputs.votingPower : inputs.balance)
  }

  // Through the worker wrapper, not the impl: BFV encryption is the heaviest step in the flow and
  // running it on the main thread freezes the browser for its duration. The wrapper falls back to
  // the main thread by itself where `Worker` is unavailable.
  return prepareCircuitInputs(inputs)
}

/**
 * Phase two: prove a prepared ballot, given the signature over its digest.
 *
 * Get the digest from `CRISPProgram.ballotDigest(e3Id, slot, prepared.ctCommitment)` and have the
 * voter sign it. Reading it from the contract rather than rebuilding the EIP-712 struct here means
 * there is only one implementation of the domain to keep correct.
 *
 * @param prepared The output of `prepareBallot`.
 * @param digest The ballot digest.
 * @param signature The voter signature over that digest.
 * @returns The proof.
 */
export const finishBallotProof = async (prepared: PreparedBallot, digest: `0x${string}`, signature: `0x${string}`): Promise<ProofData> => {
  const circuitInputs = await attachSignatureImpl(prepared, digest, signature)

  return {
    ...(await generateProof(circuitInputs, prepared.censusMode)),
    encryptedVote: prepared.encryptedVote,
    parentIndexPlusOne: prepared.parentIndexPlusOne,
  }
}

/**
 * Phase two for a mask.
 *
 * A mask carries the same digest as a real vote, because `CRISPProgram.publishInput` computes it
 * for every input regardless of branch. Only the signature is a placeholder, and the circuit does
 * not check it on the mask branch. Passing a real digest here is what keeps a mask and a vote
 * indistinguishable in the published public inputs.
 *
 * @param prepared The output of `prepareBallot` with `isMaskVote: true`.
 * @param digest The ballot digest, from the same contract call a real vote would use.
 * @returns The proof.
 */
export const finishMaskProof = async (prepared: PreparedBallot, digest: `0x${string}`): Promise<ProofData> => {
  return finishBallotProof(prepared, digest, MASK_SIGNATURE)
}

/**
 * Locally verify a Noir proof.
 * @param proof - The proof to verify.
 * @returns True if the proof is valid, false otherwise.
 */
export const verifyProof = async (proof: ProofData, censusMode: CensusVariant = 'merkle'): Promise<boolean> => {
  const api = await getBBApi()
  const circuit = censusMode === 'onchain' ? foldOnchainCircuit : foldCircuit
  const foldBackend = new UltraHonkBackend(circuit.bytecode, api)

  return foldBackend.verifyProof(proof, { verifierTarget: 'evm' })
}

/**
 * Encode the proof data into a format that can be used by the CRISP program in Solidity
 * to validate the proof.
 * @param proof The proof data.
 * @returns The encoded proof data as a hex string.
 */
export const encodeSolidityProof = ({ publicInputs, proof, encryptedVote, parentIndexPlusOne }: ProofData): Hex => {
  // Indices follow the fold circuit public inputs:
  //   0 prev_ct_commitment, 1 digest_hi, 2 digest_lo, 3 slot_address,
  //   4 merkle_root | voting_power, 5 is_first_vote, 6 num_options,
  //   7 final_ct_commitment, 8 committee public key
  const slotAddress = getAddress(numberToHex(BigInt(publicInputs[3]), { size: 20 }))
  const encryptedVoteCommitment = publicInputs[7] as `0x${string}`
  const encryptedVoteBytes = bytesToHex(encryptedVote)
  const encryptedVoteHash = keccak256(encryptedVoteBytes)

  // The last field contains the ciphertext only while the availability service stages the job.
  // The service removes it from the proof-commitment transaction, publishes it to Avail, and
  // later supplies the VectorX proof to `finalizeInput`.
  return encodeAbiParameters(parseAbiParameters('bytes, address, bytes32, bytes32, uint40, bytes'), [
    bytesToHex(proof),
    slotAddress,
    encryptedVoteCommitment,
    encryptedVoteHash,
    parentIndexPlusOne,
    encryptedVoteBytes,
  ])
}
