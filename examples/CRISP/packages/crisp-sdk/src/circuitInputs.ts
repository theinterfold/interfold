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
 * Name the slot entry that a prepared vote extends, after the vote was prepared.
 *
 * A vote replaces the slot: the circuit adds the ballot to the zero ciphertext, so the published
 * ciphertext, its commitment and the digest the owners sign do not depend on the slot head. Only
 * three inputs do: the parent index, `is_first_vote`, and `prev_ct_commitment`, which the circuit
 * checks only for a mask. This lets the owners of a Safe sign a ballot over hours, with no request
 * to the CRISP server, and the coordinator reads the head only right before proving. The server
 * then sees the same head request, proof and submission sequence as for any other input, and a
 * mask that lands during the signing cannot leave the vote naming a stale parent.
 *
 * A mask adds to the head ciphertext itself, so it must be prepared against the head.
 *
 * @param prepared A vote from `prepareBallot`.
 * @param parent The head entry: its tree index and the commitment `CRISPProgram.inputCommitmentOf`
 * returns for it. Omit it for an empty slot.
 * @returns A copy of the prepared ballot that names `parent`.
 */
export const withBallotParent = (prepared: PreparedBallot, parent?: { index: number; commitment: `0x${string}` }): PreparedBallot => {
  if (prepared.circuitInputs.is_mask_vote) {
    throw new Error('A mask adds to the slot head, so prepare it against the head instead of naming the parent later.')
  }
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
 * The commitment `CRISPProgram` records for a ciphertext, computed from its bytes.
 *
 * Use it on the slot head that `state/previous-ciphertext` returns, to name that entry with
 * {@link withBallotParent}. The server selects only entries whose bytes reproduce their stored
 * commitment, so this equals `CRISPProgram.inputCommitmentOf` for the head, and computing it here
 * avoids a contract read that no other input makes.
 *
 * @param ciphertext The serialized ciphertext.
 * @returns The commitment.
 */
export const ciphertextCommitment = (ciphertext: Uint8Array): `0x${string}` =>
  bytesToHex(getZkInputsGenerator().computeCtCommitment(ciphertext))

/** One ECDSA signature as the circuit takes it: the public key and `r || s`, as byte strings. */
type SignatureSlot = { x: string[]; y: string[]; rs: string[]; signer: `0x${string}` }

const toByteStrings = (bytes: Uint8Array) => Array.from(bytes).map((b) => b.toString())

const signatureSlot = async (signature: `0x${string}`, digest: `0x${string}`): Promise<SignatureSlot> => {
  const components = await extractSignatureComponents(signature, digest)
  return {
    x: toByteStrings(components.publicKeyX),
    y: toByteStrings(components.publicKeyY),
    rs: toByteStrings(components.signature),
    signer: await recoverAddress({ hash: digest, signature }),
  }
}

/**
 * The owner commitment of an ONCHAIN slot:
 * `keccak256(abi.encode(address[MAX_SAFE_OWNERS] owners, uint256 threshold))`, with the owner list
 * padded with the zero address. `CRISPProgram.ballotAuthorization` returns the same value, and the
 * `crisp_onchain` circuit recomputes it.
 *
 * @param slotOwners The owner list, in the order the Safe reports it, and the threshold.
 * @returns The commitment.
 */
export const ownersCommitment = ({ owners, threshold }: SlotOwners): `0x${string}` => {
  if (owners.length > MAX_SAFE_OWNERS) {
    throw new Error(`A slot can have at most ${MAX_SAFE_OWNERS} owners; got ${owners.length}`)
  }
  const padded = [...owners.map((owner) => getAddress(owner)), ...Array(MAX_SAFE_OWNERS - owners.length).fill(zeroAddress)]
  // Declared as plain `AbiParameter`s: the fixed-size type is built from the constant, and viem
  // checks the array length at run time instead.
  const params: AbiParameter[] = [{ type: `address[${MAX_SAFE_OWNERS}]` }, { type: 'uint256' }]
  return keccak256(encodeAbiParameters(params, [padded, BigInt(threshold)]))
}

/** A wallet slot is its own single owner, with a threshold of one. */
const walletOwners = (prepared: PreparedBallot): SlotOwners => ({ owners: [getAddress(prepared.circuitInputs.slot_address)], threshold: 1 })

/**
 * Write the owner inputs of the `crisp_onchain` circuit.
 *
 * The proof always has `MAX_SAFE_SIGNERS` signature slots. Slots after the first `threshold` are
 * not checked, but each still needs a valid public key, so they repeat the first slot.
 */
const setOwnerInputs = (
  circuitInputs: any,
  owners: readonly `0x${string}`[],
  threshold: number,
  commitment: `0x${string}`,
  active: { slot: SignatureSlot; index: number }[],
) => {
  const slots = Array.from({ length: MAX_SAFE_SIGNERS }, (_, i) => active[i] ?? active[0])
  const { digestHi, digestLo } = splitDigest(commitment)

  circuitInputs.owners = [...owners, ...Array(MAX_SAFE_OWNERS - owners.length).fill(zeroAddress)].map((owner) => BigInt(owner).toString())
  circuitInputs.threshold = threshold.toString()
  circuitInputs.public_keys_x = slots.map(({ slot }) => slot.x)
  circuitInputs.public_keys_y = slots.map(({ slot }) => slot.y)
  circuitInputs.signatures = slots.map(({ slot }) => slot.rs)
  circuitInputs.owner_indices = slots.map(({ index }) => index.toString())
  circuitInputs.owners_commitment_hi = digestHi
  circuitInputs.owners_commitment_lo = digestLo
}

/**
 * Phase two for an ONCHAIN slot: attach the owners' signatures over the digest.
 *
 * The signers must be owners, and there must be at least `threshold` distinct ones. The circuit
 * takes the first `threshold` in ascending address order, which is the order a Safe requires.
 *
 * @param prepared The output of `prepareCircuitInputsImpl`, for an ONCHAIN round.
 * @param digest The `digest` from `CRISPProgram.ballotAuthorization`.
 * @param slotOwners The owners and threshold of the slot.
 * @param signatures 65-byte ECDSA signatures over `digest`, in any order.
 * @returns The complete circuit inputs.
 */
export const attachOwnerSignaturesImpl = async (
  prepared: PreparedBallot,
  digest: `0x${string}`,
  slotOwners: SlotOwners,
  signatures: readonly `0x${string}`[],
): Promise<any> => {
  if (prepared.censusMode !== 'onchain') {
    throw new Error('Owner signatures authorise ONCHAIN ballots only; a census ballot takes one signature.')
  }
  const owners = slotOwners.owners.map((owner) => getAddress(owner))
  const { threshold } = slotOwners
  if (!Number.isInteger(threshold) || threshold < 1 || threshold > MAX_SAFE_SIGNERS || threshold > owners.length) {
    throw new Error(`The threshold must be from 1 to ${Math.min(MAX_SAFE_SIGNERS, owners.length)}; got ${threshold}`)
  }

  const bySigner = new Map<string, SignatureSlot>()
  for (const signature of signatures) {
    const slot = await signatureSlot(signature, digest)
    if (!owners.includes(slot.signer)) throw new Error(`${slot.signer} signed, but it is not an owner of the slot`)
    bySigner.set(slot.signer, slot)
  }
  if (bySigner.size < threshold) {
    throw new Error(`The slot needs ${threshold} owner signatures; got ${bySigner.size} distinct signers`)
  }
  const active = [...bySigner.values()]
    .sort((a, b) => (BigInt(a.signer) < BigInt(b.signer) ? -1 : 1))
    .slice(0, threshold)
    .map((slot) => ({ slot, index: owners.indexOf(slot.signer) }))

  const { digestHi, digestLo } = splitDigest(digest)
  const circuitInputs = prepared.circuitInputs
  circuitInputs.digest_hi = digestHi
  circuitInputs.digest_lo = digestLo
  setOwnerInputs(circuitInputs, owners, threshold, ownersCommitment({ owners, threshold }), active)

  return circuitInputs
}

/**
 * Phase two for a wallet: attach its signature over the digest.
 *
 * In a census round the circuit checks this one signature against the slot key. In an ONCHAIN
 * round the slot is its own single owner, so this is `attachOwnerSignaturesImpl` with that owner.
 *
 * @param prepared The output of `prepareCircuitInputsImpl`.
 * @param digest The digest from `CRISPProgram.ballotDigest`.
 * @param signature The signature over that digest.
 * @returns The complete circuit inputs.
 */
export const attachSignatureImpl = async (prepared: PreparedBallot, digest: `0x${string}`, signature: `0x${string}`): Promise<any> => {
  if (prepared.censusMode === 'onchain') return attachOwnerSignaturesImpl(prepared, digest, walletOwners(prepared), [signature])

  const { digestHi, digestLo } = splitDigest(digest)
  const components = await extractSignatureComponents(signature, digest)

  const circuitInputs = prepared.circuitInputs
  circuitInputs.digest_hi = digestHi
  circuitInputs.digest_lo = digestLo
  circuitInputs.public_key_x = toByteStrings(components.publicKeyX)
  circuitInputs.public_key_y = toByteStrings(components.publicKeyY)
  circuitInputs.signature = toByteStrings(components.signature)

  return circuitInputs
}

/**
 * Phase two for a mask: attach the digest and the owner commitment, with no real signature.
 *
 * The digest and the commitment are public inputs, because `CRISPProgram.publishInput` computes
 * them for every input. A mask carries the same values as a real vote for the slot and only skips
 * the signature check inside the circuit, which keeps the two indistinguishable on chain. The
 * signature slots hold a placeholder, and the owner list is not needed.
 *
 * @param prepared The output of `prepareCircuitInputsImpl`.
 * @param digest The `digest` from `CRISPProgram.ballotAuthorization`.
 * @param commitment The `ownersCommitment` from `CRISPProgram.ballotAuthorization`. Required for an
 * ONCHAIN slot that is a Safe; for any other ONCHAIN slot, the SDK derives it from the slot.
 * @returns The complete circuit inputs.
 */
export const attachMaskImpl = async (prepared: PreparedBallot, digest: `0x${string}`, commitment?: `0x${string}`): Promise<any> => {
  if (prepared.censusMode !== 'onchain') return attachSignatureImpl(prepared, digest, MASK_SIGNATURE)

  const { digestHi, digestLo } = splitDigest(digest)
  const circuitInputs = prepared.circuitInputs
  circuitInputs.digest_hi = digestHi
  circuitInputs.digest_lo = digestLo
  const placeholder = { slot: await signatureSlot(MASK_SIGNATURE, digest), index: 0 }
  setOwnerInputs(circuitInputs, [], 1, commitment ?? ownersCommitment(walletOwners(prepared)), [placeholder])

  return circuitInputs
}
