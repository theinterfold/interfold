// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { bytesToHex, encodeAbiParameters, getAddress, keccak256, recoverAddress, zeroAddress } from 'viem'
import type { AbiParameter } from 'viem'
import { getZkInputsGenerator, encodeVote } from './encoding'
import { extractSignatureComponents, generateMerkleProof, getZeroVote, numberArrayToBigInt64Array } from './utils'
import { MASK_SIGNATURE, MAX_SAFE_OWNERS, MAX_SAFE_SIGNERS } from './constants'
import type { PreparedBallot, PrepareBallotInputs, SlotOwners } from './types'

/**
 * Split a 32-byte digest into the two 16-byte halves the circuit takes as public inputs.
 *
 * A Keccak digest is 256 bits and a field element holds fewer than 254, so it cannot cross the
 * circuit boundary in one piece. `crisp_lib::ecdsa::digest_from_halves` rebuilds the 32 bytes and
 * range-checks each half, and `CRISPProgram.publishInput` splits the same way.
 *
 * @param digest The 32-byte ballot digest.
 * @returns The high and low halves as hex field elements.
 */
export const splitDigest = (digest: `0x${string}`): { digestHi: `0x${string}`; digestLo: `0x${string}` } => {
  if (digest.length !== 66) {
    throw new Error(`Invalid digest: expected 32 bytes, got ${(digest.length - 2) / 2}`)
  }

  return {
    digestHi: `0x${digest.slice(2, 34)}`,
    digestLo: `0x${digest.slice(34, 66)}`,
  }
}

/**
 * Phase one of building a ballot: encrypt the vote and build every circuit input that does not
 * depend on the signature.
 *
 * Kept separate from the signature because the digest a voter signs binds the ciphertext, so the
 * ciphertext has to exist first. The returned `ctCommitment` is what `CRISPProgram.ballotDigest`
 * takes as its `ciphertextCommitment` argument.
 *
 * One path for all three operations. A first vote, a re-vote, and a mask reach the same generator
 * with the same arguments, differ only in `isMaskVote` — which stays private to the proof — and
 * produce the same shape of submission. Branching here would make the three tellable apart by
 * anything watching the client, which is what masks exist to prevent.
 *
 * Kept in a separate module so it can run in a worker.
 *
 * @param inputs The ballot to prepare.
 * @returns The partial circuit inputs, the ciphertext, and its commitment.
 */
export const prepareCircuitInputsImpl = async (inputs: PrepareBallotInputs): Promise<PreparedBallot> => {
  const zkInputsGenerator = getZkInputsGenerator()

  const numOptions = inputs.isMaskVote ? inputs.numOptions : inputs.vote.length
  const vote = inputs.isMaskVote ? getZeroVote(numOptions) : inputs.vote
  const encodedVote = encodeVote(vote)

  // Only a mask adds to what the slot already holds. A vote replaces it, so a voter cannot have
  // their old ballot counted alongside the new one. The circuit derives the same choice from
  // `is_mask_vote` and rejects any witness built the other way.
  const keepPrevious = inputs.isMaskVote && !!inputs.previousCiphertext

  const { inputs: circuitInputs, encryptedVote } = await zkInputsGenerator.generateInputs(
    inputs.previousCiphertext,
    inputs.publicKey,
    numberArrayToBigInt64Array(encodedVote),
    keepPrevious,
  )

  circuitInputs.slot_address = inputs.slotAddress.toLowerCase()
  circuitInputs.is_first_vote = !inputs.previousCiphertext
  circuitInputs.is_mask_vote = inputs.isMaskVote
  circuitInputs.num_options = numOptions.toString()

  if (inputs.censusMode === 'onchain') {
    circuitInputs.voting_power = inputs.votingPower.toString()
  } else {
    // Derived here rather than by the caller. The old API recovered the slot address from the
    // signature to build this, which is no longer possible: the signature now comes after the
    // ciphertext, and the caller states the slot address instead.
    const merkleProof = generateMerkleProof(inputs.balance, inputs.slotAddress, inputs.merkleLeaves)

    circuitInputs.balance = inputs.balance.toString()
    circuitInputs.merkle_root = merkleProof.proof.root.toString()
    circuitInputs.merkle_proof_length = merkleProof.length.toString()
    circuitInputs.merkle_proof_indices = merkleProof.indices.map((i) => i === 1)
    circuitInputs.merkle_proof_siblings = merkleProof.proof.siblings.map((s) => s.toString())
  }

  // The commitment to `encryptedVote`, which is the ciphertext this ballot publishes: the ballot
  // itself for a vote or a re-vote, the slot plus the zero ballot for a mask over an occupied slot.
  // The circuit returns the same value as `final_ct_commitment`, `CRISPProgram` stores it, and
  // `CRISPProgram.ballotDigest` is built over it — so it is what a voter has to sign, and it has to
  // be known before proving because the digest is itself a circuit input.
  //
  // Exported by the wasm alongside the witness. Recomputing it here would have to match
  // `compute_ciphertext_commitment` exactly, so it is carried across instead.
  const ctCommitment = `0x${BigInt(circuitInputs.sum_ct_commitment).toString(16).padStart(64, '0')}` as `0x${string}`

  // Zero when there is nothing to extend, which is what the contract reads as `is_first_vote`.
  //
  // Checked at runtime as well as in the type, because a caller reaching this through plain
  // JavaScript or a widened object gets no type error. Defaulting a missing index to zero would
  // name the slot's first entry as the parent, and the proof would be built against one commitment
  // while the contract supplied another — visible only as a rejected proof.
  if (inputs.previousCiphertext !== undefined) {
    const index = inputs.previousIndex
    // Non-negative and safe, not merely an integer. `-1` would come back out as zero, which the
    // contract reads as "extends nothing" — a re-vote silently published as a first vote against a
    // slot that already holds one. Anything at or above `MAX_SAFE_INTEGER` cannot represent
    // `index + 1` exactly, so the parent it names is not the parent it meant.
    if (!Number.isSafeInteger(index) || (index as number) < 0 || (index as number) + 1 > Number.MAX_SAFE_INTEGER) {
      throw new Error(
        `previousCiphertext needs a non-negative safe integer previousIndex; got ${String(index)}. Pass the slot head as a pair.`,
      )
    }
  }

  const parentIndexPlusOne = inputs.previousCiphertext !== undefined ? (inputs.previousIndex as number) + 1 : 0

  return { circuitInputs, encryptedVote, ctCommitment, parentIndexPlusOne, censusMode: inputs.censusMode }
}

/**
 * Phase two: attach the signed digest to a prepared ballot.
 *
 * The digest is a public input in both branches, because `CRISPProgram.publishInput` computes it
 * for every input. A mask carries the same digest as a real vote and only skips the signature
 * check inside the circuit, which is what keeps the two indistinguishable on chain. In an ONCHAIN
 * round, the wallet is the single owner of its slot; see {@link attachOwnerSignaturesImpl}.
 *
 * @param prepared The output of `prepareCircuitInputsImpl`.
 * @param digest The digest from `CRISPProgram.ballotDigest`.
 * @param signature The signature over that digest. A mask passes the placeholder signature.
 * @returns The complete circuit inputs.
 */
export const attachSignatureImpl = async (prepared: PreparedBallot, digest: `0x${string}`, signature: `0x${string}`): Promise<any> => {
  if (prepared.censusMode === 'onchain') {
    return attachOwnerSignaturesImpl(prepared, digest, { owners: [prepared.circuitInputs.slot_address], threshold: 1 }, [signature])
  }

  const { digestHi, digestLo } = splitDigest(digest)
  const components = await extractSignatureComponents(signature, digest)

  const circuitInputs = prepared.circuitInputs
  circuitInputs.digest_hi = digestHi
  circuitInputs.digest_lo = digestLo
  circuitInputs.public_key_x = Array.from(components.publicKeyX).map((b) => b.toString())
  circuitInputs.public_key_y = Array.from(components.publicKeyY).map((b) => b.toString())
  circuitInputs.signature = Array.from(components.signature).map((b) => b.toString())

  return circuitInputs
}

/**
 * Name the slot head that a prepared vote extends.
 *
 * A vote replaces the slot, so its ciphertext, commitment and digest do not depend on the head. Its
 * owners can sign before the head is read, and the prover names the head right before proving, as
 * for any other input. A mask adds to the head, so it is prepared against the head instead.
 *
 * @param prepared A vote from `prepareBallot`.
 * @param parent The head's tree index and its {@link ciphertextCommitment}. Omit it for an empty slot.
 * @returns A copy of `prepared` that names `parent`.
 */
export const withBallotParent = (prepared: PreparedBallot, parent?: { index: number; commitment: `0x${string}` }): PreparedBallot => {
  if (prepared.circuitInputs.is_mask_vote) throw new Error('A mask adds to the slot head, so prepare it against the head.')
  if (parent && (!Number.isSafeInteger(parent.index) || parent.index < 0 || parent.index + 1 > Number.MAX_SAFE_INTEGER)) {
    throw new Error(`The parent needs a non-negative safe integer index; got ${String(parent.index)}`)
  }

  return {
    ...prepared,
    circuitInputs: {
      ...prepared.circuitInputs,
      prev_ct_commitment: parent ? BigInt(parent.commitment).toString() : '0',
      is_first_vote: !parent,
    },
    parentIndexPlusOne: parent ? parent.index + 1 : 0,
  }
}

/**
 * The commitment that `CRISPProgram` records for a ciphertext. For the slot head that the server
 * returns, this equals `CRISPProgram.inputCommitmentOf`: the server returns only a head whose bytes
 * reproduce its commitment.
 */
export const ciphertextCommitment = (ciphertext: Uint8Array): `0x${string}` =>
  bytesToHex(getZkInputsGenerator().computeCtCommitment(ciphertext))

/**
 * `keccak256(abi.encode(address[MAX_SAFE_OWNERS] owners, uint256 threshold))`, with the owners
 * padded with the zero address: what `CRISPProgram.ballotAuthorization` returns and `crisp_onchain`
 * checks.
 */
export const ownersCommitment = ({ owners, threshold }: SlotOwners): `0x${string}` => {
  if (owners.length > MAX_SAFE_OWNERS) throw new Error(`A slot can have at most ${MAX_SAFE_OWNERS} owners; got ${owners.length}`)
  // Plain `AbiParameter`s, because the array length comes from a constant.
  const params: AbiParameter[] = [{ type: `address[${MAX_SAFE_OWNERS}]` }, { type: 'uint256' }]
  return keccak256(
    encodeAbiParameters(params, [[...owners, ...Array(MAX_SAFE_OWNERS - owners.length).fill(zeroAddress)], BigInt(threshold)]),
  )
}

const toByteStrings = (bytes: Uint8Array) => Array.from(bytes, (b) => b.toString())

/**
 * Attach the digest and the `crisp_onchain` owner inputs. The proof always has `MAX_SAFE_SIGNERS`
 * signature slots, and the circuit checks the first `threshold`. The others repeat the first
 * signature, because every slot needs a valid public key.
 */
const attachOwnerInputs = async (
  prepared: PreparedBallot,
  digest: `0x${string}`,
  owners: readonly string[],
  threshold: number,
  commitment: `0x${string}`,
  signers: { signature: `0x${string}`; index: number }[],
): Promise<any> => {
  const slots = await Promise.all(
    Array.from({ length: MAX_SAFE_SIGNERS }, async (_, i) => {
      const { signature, index } = signers[i] ?? signers[0]
      return { ...(await extractSignatureComponents(signature, digest)), index }
    }),
  )
  const { digestHi, digestLo } = splitDigest(digest)
  const { digestHi: commitmentHi, digestLo: commitmentLo } = splitDigest(commitment)
  return Object.assign(prepared.circuitInputs, {
    digest_hi: digestHi,
    digest_lo: digestLo,
    owners: [...owners, ...Array(MAX_SAFE_OWNERS - owners.length).fill(zeroAddress)].map((owner) => BigInt(owner).toString()),
    threshold: threshold.toString(),
    public_keys_x: slots.map((slot) => toByteStrings(slot.publicKeyX)),
    public_keys_y: slots.map((slot) => toByteStrings(slot.publicKeyY)),
    signatures: slots.map((slot) => toByteStrings(slot.signature)),
    owner_indices: slots.map((slot) => slot.index.toString()),
    owners_commitment_hi: commitmentHi,
    owners_commitment_lo: commitmentLo,
  })
}

/**
 * Phase two for an ONCHAIN slot: attach its owners' signatures over the digest. The circuit takes
 * the first `threshold` distinct signers in ascending address order, as a Safe does.
 *
 * @param prepared The output of `prepareCircuitInputsImpl`, for an ONCHAIN round.
 * @param digest The `digest` from `CRISPProgram.ballotAuthorization`.
 * @param slotOwners The owners and threshold of the slot.
 * @param signatures Owner signatures over `digest`, in any order.
 * @returns The complete circuit inputs.
 */
export const attachOwnerSignaturesImpl = async (
  prepared: PreparedBallot,
  digest: `0x${string}`,
  { owners, threshold }: SlotOwners,
  signatures: readonly `0x${string}`[],
): Promise<any> => {
  if (prepared.censusMode !== 'onchain') throw new Error('Owner signatures authorise ONCHAIN ballots only.')
  if (!(threshold >= 1 && threshold <= MAX_SAFE_SIGNERS)) throw new Error(`Threshold ${threshold} is not from 1 to ${MAX_SAFE_SIGNERS}`)

  const checksummed = owners.map((owner) => getAddress(owner))
  const signers = new Map<`0x${string}`, `0x${string}`>()
  for (const signature of signatures) {
    const signer = await recoverAddress({ hash: digest, signature })
    if (!checksummed.includes(signer)) throw new Error(`${signer} signed, but it is not an owner of the slot`)
    signers.set(signer, signature)
  }
  if (signers.size < threshold) throw new Error(`The slot needs ${threshold} owner signatures; got ${signers.size} distinct signers`)

  const active = [...signers]
    .sort(([a], [b]) => (BigInt(a) < BigInt(b) ? -1 : 1))
    .slice(0, threshold)
    .map(([signer, signature]) => ({ signature, index: checksummed.indexOf(signer) }))
  return attachOwnerInputs(prepared, digest, owners, threshold, ownersCommitment({ owners, threshold }), active)
}

/**
 * Phase two for a mask: the same public inputs as a vote for the slot, which the contract computes
 * for every input, with placeholder signatures that the circuit does not check for a mask.
 *
 * @param prepared The output of `prepareCircuitInputsImpl`.
 * @param digest The `digest` from `CRISPProgram.ballotAuthorization`.
 * @param commitment The `ownersCommitment` from `CRISPProgram.ballotAuthorization`. Required in an
 * ONCHAIN round.
 * @returns The complete circuit inputs.
 */
export const attachMaskImpl = async (prepared: PreparedBallot, digest: `0x${string}`, commitment?: `0x${string}`): Promise<any> => {
  if (prepared.censusMode !== 'onchain') return attachSignatureImpl(prepared, digest, MASK_SIGNATURE)
  if (!commitment) throw new Error('An ONCHAIN mask needs the ownersCommitment from CRISPProgram.ballotAuthorization.')

  const placeholder = { signature: MASK_SIGNATURE, index: 0 } as const
  return attachOwnerInputs(prepared, digest, [], 1, commitment, [placeholder])
}
