// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
import { describe, it, expect, beforeAll, beforeEach, afterEach, afterAll, vi } from 'vitest'
import { Vote } from '../src/types'
import { MAX_MSG_NON_ZERO_COEFFS, MAX_VOTE_OPTIONS, SIGNATURE_MESSAGE_HASH, SIGNATURE_MESSAGE } from '../src/constants'
import { decodeTally, verifyProof, encodeVote, generateBFVKeys, encryptVote, decryptVote, destroyBBApi } from '../src/vote'
import { publicKeyToAddress, sign, signMessage } from 'viem/accounts'
import { Hex, concat, keccak256, numberToHex, recoverPublicKey } from 'viem'
import { CRISP_SERVER_URL, ECDSA_PRIVATE_KEY, SLOT_ADDRESS } from './constants'
import { CrispSDK } from '../src/sdk'
import { setCircuits } from '../src/circuits'
import { loadCircuits } from '../src/presets/insecure-512'
import { generateTestLeaves } from './helpers'

// Proving needs a preset installed; the BFV-shaped circuits are no longer part of the main entry.
beforeAll(async () => {
  setCircuits(await loadCircuits())
})

describe('Vote', () => {
  let vote: Vote
  let signature: Hex
  let balance: bigint
  let address: string
  let leaves: bigint[]
  let publicKey: Uint8Array
  let secretKey: Uint8Array
  let previousCiphertext: Uint8Array
  let e3Id: bigint
  let sdk: CrispSDK

  // The server answers with the end of the slot's chain of usable entries and its tree index; the
  // SDK names that index as the parent of the input it is about to build.
  const mockGetPreviousCiphertextResponse = () =>
    ({
      ok: true,
      status: 200,
      json: async () => ({ ciphertext: previousCiphertext, index: 0 }),
    }) as Response

  const mockPreviousCiphertextNotFoundResponse = () => ({ ok: false, status: 404 }) as Response

  beforeEach(() => {
    vi.clearAllMocks()
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  afterAll(() => {
    destroyBBApi()
  })

  beforeAll(async () => {
    vote = [10, 0, 0]
    signature = await signMessage({ message: SIGNATURE_MESSAGE, privateKey: ECDSA_PRIVATE_KEY })
    balance = 10n
    address = publicKeyToAddress(await recoverPublicKey({ hash: SIGNATURE_MESSAGE_HASH, signature }))
    leaves = generateTestLeaves([
      { address, balance },
      { address: SLOT_ADDRESS, balance },
    ])
    const keys = generateBFVKeys()
    publicKey = keys.publicKey
    secretKey = keys.secretKey
    // A non-zero ballot in the slot, so a re-vote that added to it instead of replacing it would
    // decrypt to something other than the new ballot.
    previousCiphertext = encryptVote([5, 0, 0], publicKey)
    e3Id = (1n << 200n) + 7n
    sdk = new CrispSDK(CRISP_SERVER_URL)
  })

  describe('decodeTally', () => {
    it('Should decode an encoded tally into its decimal representation', () => {
      const expected: Vote = [10000000, 30000000]
      const encoded = encodeVote(expected)
      const decoded = decodeTally(encoded, 2)

      expect(decoded[0]).toBe(BigInt(expected[0]))
      expect(decoded[1]).toBe(BigInt(expected[1]))
    })

    it('Should decode totals above Number.MAX_SAFE_INTEGER without losing precision', () => {
      // After aggregation a coefficient is a ballot count, not a bit. This models 2**30
      // ballots landing on the top coefficient of option 0 and one on its bottom coefficient,
      // giving a total that a double cannot represent exactly.
      const coefficients = new Array(MAX_MSG_NON_ZERO_COEFFS).fill(0)
      coefficients[0] = 2 ** 30
      coefficients[MAX_MSG_NON_ZERO_COEFFS / 2 - 1] = 1

      const decoded = decodeTally(coefficients, 2)

      expect(decoded[0]).toBe((1n << 54n) + 1n)
      expect(decoded[0] > BigInt(Number.MAX_SAFE_INTEGER)).toBe(true)
    })

    it('Should reject a tally shorter than the payload region', () => {
      const tooShort = new Array(MAX_MSG_NON_ZERO_COEFFS - 1).fill(0)

      expect(() => decodeTally(tooShort, 2)).toThrow('is less than MAX_MSG_NON_ZERO_COEFFS')
    })

    it('Should reject fewer than two choices', () => {
      const coefficients = new Array(MAX_MSG_NON_ZERO_COEFFS).fill(0)

      // `CRISPProgram.validate` reverts below 2, so a one-option tally cannot exist on-chain.
      expect(() => decodeTally(coefficients, 1)).toThrow('must be an integer of at least 2')
      expect(() => decodeTally(coefficients, 0)).toThrow('must be an integer of at least 2')
      expect(() => decodeTally(coefficients, -1)).toThrow('must be an integer of at least 2')
      // The lower boundary itself stays decodable.
      expect(decodeTally(coefficients, 2)).toHaveLength(2)
    })

    it('Should reject a non-integer number of choices', () => {
      const coefficients = new Array(MAX_MSG_NON_ZERO_COEFFS).fill(0)

      // A fraction silently decoded `ceil(numChoices)` segments; NaN passed both bound
      // checks and returned an empty tally.
      expect(() => decodeTally(coefficients, 2.5)).toThrow('must be an integer of at least 2')
      expect(() => decodeTally(coefficients, Number.NaN)).toThrow('must be an integer of at least 2')
      expect(() => decodeTally(coefficients, Number.POSITIVE_INFINITY)).toThrow('must be an integer of at least 2')
    })

    it('Should reject more choices than the circuit allows', () => {
      const coefficients = new Array(MAX_MSG_NON_ZERO_COEFFS).fill(0)

      expect(() => decodeTally(coefficients, MAX_VOTE_OPTIONS + 1)).toThrow('exceeds MAX_VOTE_OPTIONS')
      // The boundary itself stays decodable.
      expect(decodeTally(coefficients, MAX_VOTE_OPTIONS)).toHaveLength(MAX_VOTE_OPTIONS)
    })
  })

  describe('encodeVote', () => {
    it('Should fail when the number of choices is less than 2', () => {
      expect(() => encodeVote([10])).toThrow('Vote must have at least two choices')
      expect(() => encodeVote([])).toThrow('Vote must have at least two choices')
    })

    it('Should fail when the number of choices exceeds the circuit maximum', () => {
      expect(() => encodeVote(new Array(MAX_VOTE_OPTIONS + 1).fill(0))).toThrow('exceeds MAX_VOTE_OPTIONS')
      // The boundary itself still encodes and round-trips.
      const encoded = encodeVote(new Array(MAX_VOTE_OPTIONS).fill(1))
      expect(decodeTally(encoded, MAX_VOTE_OPTIONS)).toEqual(new Array(MAX_VOTE_OPTIONS).fill(1n))
    })

    it('Should encode votes correctly with 2 choices', () => {
      const encoded = encodeVote([10, 2])
      const decoded = decodeTally(encoded, 2)

      expect(decoded[0]).toBe(10n)
      expect(decoded[1]).toBe(2n)
    })

    it('Should encode zero votes correctly', () => {
      const encoded = encodeVote([0, 5])
      const decoded = decodeTally(encoded, 2)

      expect(decoded[0]).toBe(0n)
      expect(decoded[1]).toBe(5n)
    })

    it('Should only contain binary digits (0 or 1)', () => {
      const encoded = encodeVote([255, 128])

      expect(Array.from(encoded).every((b) => b === 0 || b === 1)).toBe(true)
    })

    it('Should encode votes correctly with 3 choices', () => {
      const encoded = encodeVote([10, 2, 3])
      const decoded = decodeTally(encoded, 3)

      expect(decoded[0]).toBe(10n)
      expect(decoded[1]).toBe(2n)
      expect(decoded[2]).toBe(3n)
    })

    it('Should encode votes correctly with 5 choices', () => {
      const encoded = encodeVote([100, 50, 25, 10, 5])
      const decoded = decodeTally(encoded, 5)

      expect(decoded[0]).toBe(100n)
      expect(decoded[1]).toBe(50n)
      expect(decoded[2]).toBe(25n)
      expect(decoded[3]).toBe(10n)
      expect(decoded[4]).toBe(5n)
    })

    it('Should zero-pad unused slots in the first MAX_MSG_NON_ZERO_COEFFS coeffs for 3 choices', () => {
      const encoded = encodeVote([1, 1, 1])
      const decoded = decodeTally(encoded, 3)

      expect(decoded[0]).toBe(1n)
      expect(decoded[1]).toBe(1n)
      expect(decoded[2]).toBe(1n)

      const segmentSize = Math.floor(MAX_MSG_NON_ZERO_COEFFS / 3)
      expect(encoded.slice(segmentSize * 3, MAX_MSG_NON_ZERO_COEFFS).every((b) => b === 0)).toBe(true)
    })
  })

  describe('generateVoteProof', () => {
    it('Should generate a valid vote proof', { timeout: 300000 }, async () => {
      vi.spyOn(global, 'fetch').mockResolvedValueOnce(mockPreviousCiphertextNotFoundResponse())

      const prepared = await sdk.prepareBallot({
        censusMode: 'merkle',
        vote,
        publicKey,
        merkleLeaves: leaves,
        balance,
        // The signer's own address. A real vote proves `slot_address == address(pubkey)`, so the
        // slot has to be the one the ballot signature recovers to. The previous API took the slot
        // address as an argument and then silently overrode it with the recovered address, which
        // hid a caller passing a slot it could not sign for.
        slotAddress: address,
        isMaskVote: false,
        numOptions: vote.length,
        e3Id,
      })

      // In production this comes from `CRISPProgram.ballotDigest(e3Id, slot, ctCommitment)`. The
      // SDK does not check where it came from — binding it to the ballot is the contract's job,
      // and the circuit only proves the signature covers whatever digest was published.
      //
      // Signed raw rather than with `signMessage`: the contract builds an EIP-712 digest, which a
      // wallet signs directly through `signTypedData`, with no EIP-191 prefix.
      const digest = keccak256(concat([prepared.ctCommitment, numberToHex(e3Id, { size: 32 })]))
      const ballotSignature = await sign({ hash: digest, privateKey: ECDSA_PRIVATE_KEY, to: 'hex' })

      const proof = await sdk.finishBallot(prepared, digest, ballotSignature)

      // The wasm computes `ctCommitment` over the ciphertext-addition limbs; the circuit returns
      // `final_ct_commitment` over the user_data_encryption limbs. `CRISPProgram.publishInput`
      // builds the ballot digest from the latter, so a caller signing over the former would
      // produce a proof the contract rejects. They must be the same value.
      expect(BigInt(proof.publicInputs[7])).toBe(BigInt(prepared.ctCommitment))

      expect(proof).toBeDefined()
      expect(proof.proof).toBeDefined()
      expect(proof.publicInputs).toBeDefined()
      expect(proof.encryptedVote).toBeDefined()

      const decryptedVote = decryptVote(proof.encryptedVote, secretKey, vote.length)

      expect(decryptedVote).toEqual(vote.map(BigInt))

      const isValid = await verifyProof(proof)

      expect(isValid).toBe(true)
    })
  })

  describe('prepareBallot', () => {
    // A re-vote must replace the ballot in the slot rather than add to it, or a voter would have
    // both ballots counted. The zk-inputs crate checks the witness for each branch, and the
    // contract suite proves and publishes a real re-vote. This checks the SDK's part: turning the
    // server's slot head into a re-vote over that parent.
    it('Should build a re-vote over the slot head that replaces the ballot', async () => {
      vi.spyOn(global, 'fetch').mockResolvedValueOnce(mockGetPreviousCiphertextResponse())

      const updated: Vote = [0, 4, 0]
      const prepared = await sdk.prepareBallot({
        censusMode: 'merkle',
        vote: updated,
        publicKey,
        merkleLeaves: leaves,
        balance,
        slotAddress: address,
        isMaskVote: false,
        numOptions: updated.length,
        e3Id,
      })

      // The server named index 0 as the slot head, so the re-vote extends it.
      expect(prepared.parentIndexPlusOne).toBe(1)
      expect(prepared.circuitInputs.is_first_vote).toBe(false)
      expect(BigInt(prepared.circuitInputs.prev_ct_commitment)).not.toBe(0n)

      // Replaced, not added: the published ciphertext decrypts to the new ballot alone.
      expect(decryptVote(prepared.encryptedVote, secretKey, updated.length)).toEqual(updated.map(BigInt))
    })
  })

  describe('generateMaskVoteProof', () => {
    // A mask must not be able to carry a payload. The zero check used to read only coefficients
    // that the SDK layout never writes to, so any plaintext passed it — and anyone can write a mask
    // to any eligible slot without a signature, which made it a way to corrupt a slot the submitter
    // cannot vote in.
    //
    // The slot is empty on purpose. Over an occupied slot the mask branch also adds the slot's
    // ciphertext, which a ballot's witness does not, so the circuit would reject even a zero payload
    // there, and the zero check would go untested.
    it('Should refuse a mask that carries a ballot', { timeout: 300000 }, async () => {
      vi.spyOn(global, 'fetch').mockResolvedValueOnce(mockPreviousCiphertextNotFoundResponse())

      // Encrypted as a real ballot, then submitted on the mask branch, which a third party can
      // reach. The plaintext is whatever the attacker chose.
      const prepared = await sdk.prepareBallot({
        censusMode: 'merkle',
        vote: [7, 0],
        balance,
        slotAddress: SLOT_ADDRESS,
        publicKey,
        merkleLeaves: leaves,
        isMaskVote: false,
        numOptions: 2,
        e3Id: 0n,
      })

      prepared.circuitInputs.is_mask_vote = true

      const digest = keccak256(concat([prepared.ctCommitment, numberToHex(0, { size: 32 })]))

      await expect(sdk.finishBallot(prepared, digest)).rejects.toThrow()
    })
  })
})
