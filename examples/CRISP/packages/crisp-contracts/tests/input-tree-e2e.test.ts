// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import {
  hashLeaf,
  generateBFVKeys,
  SIGNATURE_MESSAGE,
  prepareBallot,
  finishBallotProof,
  finishMaskProof,
  getAddressFromSignature,
  encodeSolidityProof,
  generateMerkleTree,
  SIGNATURE_MESSAGE_HASH,
  destroyBBApi,
} from '@crisp-e3/sdk'
import type { ProofData } from '@crisp-e3/sdk'
import { setCircuits } from '@crisp-e3/sdk'
import { loadCircuits } from '@crisp-e3/sdk/insecure-512'

// The BFV-shaped circuits ship as a separate entry point per preset, so proving needs one
// installed. These tests run against the insecure-512 parameters the contracts are deployed with.
before(async () => {
  setCircuits(await loadCircuits())
})
import { expect } from 'chai'
import { mkdirSync, writeFileSync } from 'fs'
import { dirname } from 'path'
import { fileURLToPath } from 'url'
import { deployCRISPProgram, deployHonkVerifier, deployMockInterfold, ethers, publishAvailableInput } from './utils'
import type { CRISPProgram, HonkVerifier, MockInterfold } from '../types'

const keys = generateBFVKeys()
const publicKey = keys.publicKey

/// Where the Rust side reads the same tree from.
/// Regenerate with `UPDATE_INPUT_TREE_FIXTURE=1 pnpm test`, then re-run
/// `cargo test -p e3-user-program`.
const FIXTURE = fileURLToPath(new URL('fixtures/input-tree.json', import.meta.url))
const APPEND_FIXTURE = fileURLToPath(new URL('fixtures/input-tree-append.json', import.meta.url))
const REVOTE_FIXTURE = fileURLToPath(new URL('fixtures/input-tree-revote.json', import.meta.url))

/// End-to-end over the seam that no single-language test can cover.
///
/// The contract builds each input tree leaf from the published ciphertext bytes and the proven
/// commitment. The Secure Process rebuilds the same tree in Rust and the E3 program compares the
/// two roots, so a one-byte divergence between the implementations makes every round fail with no
/// other symptom.
///
/// This test drives the real path — real BFV ciphertexts, real Noir proofs, real `publishInput` —
/// and records the resulting tree so `program/tests/onchain_root_agreement.rs` can assert that Rust
/// reproduces the exact on-chain root.
describe('CRISPProgram input tree (e2e)', function () {
  // 600s was a per-test budget, not a per-file one, and the tests are unevenly weighted: the
  // heaviest here generates three ballots where the lightest generates one. A CI runner proves
  // roughly 4x slower than a dev machine, which put the three-ballot test over the line while
  // every lighter test stayed comfortably inside it.
  //
  // A timeout here is also not contained. `destroyBBApi()` runs in `after()`, so one Barretenberg
  // instance is shared by the whole file, and mocha abandons a timed-out test without stopping the
  // proof it left in flight. The next test then fails inside witness generation with "Cannot
  // satisfy constraint" rather than a timeout of its own — the fold circuit asserts the inner
  // proofs verify, so a proof that came back from a contended instance fails there rather than
  // where it was produced. Treat a constraint error immediately after a timeout as fallout from
  // that timeout, not as a circuit bug. The per-leg `timeout-minutes` in CI is the real backstop
  // for a genuine hang, so this only needs to clear honest work.
  this.timeout(1_200_000)

  let honkVerifier: HonkVerifier
  let mockInterfold: MockInterfold
  let crispProgram: CRISPProgram
  let address: string
  let leaves: bigint[]
  let e3Id: bigint

  const balance = 100n

  /// A ballot bound to this round, with its own ciphertext and commitment.
  async function buildBallot(vote: number[]): Promise<ProofData & { ctCommitment: `0x${string}` }> {
    const [signer] = await ethers.getSigners()
    const prepared = await prepareBallot({
      censusMode: 'merkle',
      vote,
      publicKey,
      merkleLeaves: leaves,
      balance,
      slotAddress: address,
      isMaskVote: false,
      numOptions: 2,
    })

    const digest = (await crispProgram.ballotDigest(e3Id, address, prepared.ctCommitment)) as `0x${string}`
    const domain = {
      name: 'CRISP',
      version: '1',
      chainId: (await ethers.provider.getNetwork()).chainId,
      verifyingContract: await crispProgram.getAddress(),
    }
    const types = {
      Ballot: [
        { name: 'e3Id', type: 'uint256' },
        { name: 'slot', type: 'address' },
        { name: 'ciphertextCommitment', type: 'bytes32' },
      ],
    }
    const message = { e3Id, slot: address, ciphertextCommitment: prepared.ctCommitment }
    const ballotSignature = (await signer.signTypedData(domain, types, message)) as `0x${string}`

    const proof = await finishBallotProof(prepared, digest, ballotSignature)
    return { ...proof, ctCommitment: prepared.ctCommitment }
  }

  /// A mask over an existing ciphertext: a zero vote that anyone may append to an occupied slot.
  /// No signature is checked on this path, which is what makes the poisoning case reachable.
  async function buildMaskOver(
    previousCiphertext: Uint8Array,
    previousIndex: number,
  ): Promise<ProofData & { ctCommitment: `0x${string}` }> {
    const prepared = await prepareBallot({
      censusMode: 'merkle',
      vote: [0, 0],
      publicKey,
      merkleLeaves: leaves,
      balance,
      slotAddress: address,
      isMaskVote: true,
      numOptions: 2,
      previousCiphertext,
      previousIndex,
    })
    // One commitment for every branch: `ctCommitment` is the commitment of the ciphertext this
    // input publishes, which for a mask over an occupied slot is the sum. The contract stores that
    // and builds the digest over it.
    const digest = (await crispProgram.ballotDigest(e3Id, address, prepared.ctCommitment)) as `0x${string}`
    const proof = await finishMaskProof(prepared, digest)
    return { ...proof, ctCommitment: prepared.ctCommitment }
  }

  /// A real re-vote: `isMaskVote: false` over a slot that already holds a ballot.
  ///
  /// The digest is built over `prepared.ctCommitment` exactly as a first vote and a mask are. A
  /// re-vote replaces rather than adds, so that commitment is the new ballot's own — but the caller
  /// does not have to know which, and nothing about the request says so.
  async function buildReVote(
    vote: number[],
    previousCiphertext: Uint8Array,
    previousIndex: number,
  ): Promise<ProofData & { ctCommitment: `0x${string}` }> {
    const [signer] = await ethers.getSigners()
    const prepared = await prepareBallot({
      censusMode: 'merkle',
      vote,
      publicKey,
      merkleLeaves: leaves,
      balance,
      slotAddress: address,
      isMaskVote: false,
      numOptions: 2,
      previousCiphertext,
      previousIndex,
    })

    const digest = (await crispProgram.ballotDigest(e3Id, address, prepared.ctCommitment)) as `0x${string}`
    const domain = {
      name: 'CRISP',
      version: '1',
      chainId: (await ethers.provider.getNetwork()).chainId,
      verifyingContract: await crispProgram.getAddress(),
    }
    const types = {
      Ballot: [
        { name: 'e3Id', type: 'uint256' },
        { name: 'slot', type: 'address' },
        { name: 'ciphertextCommitment', type: 'bytes32' },
      ],
    }
    const message = { e3Id, slot: address, ciphertextCommitment: prepared.ctCommitment }
    const ballotSignature = (await signer.signTypedData(domain, types, message)) as `0x${string}`

    const proof = await finishBallotProof(prepared, digest, ballotSignature)
    return { ...proof, ctCommitment: prepared.ctCommitment }
  }

  before(async function () {
    mockInterfold = await deployMockInterfold()
    honkVerifier = await deployHonkVerifier()
    crispProgram = await deployCRISPProgram({ mockInterfold, honkVerifier })

    const [signer] = await ethers.getSigners()
    const signature = (await signer.signMessage(SIGNATURE_MESSAGE)) as `0x${string}`
    address = await getAddressFromSignature(signature, SIGNATURE_MESSAGE_HASH)
    leaves = [...[10n, 20n, 30n], hashLeaf(address, balance)]

    e3Id = await mockInterfold.nextE3Id()
    await mockInterfold.request(await crispProgram.getAddress())
  })

  after(() => {
    destroyBBApi()
  })

  it('reproduces the on-chain root in Rust, over real ciphertexts', async function () {
    const ballot = await buildBallot([10, 0])

    await mockInterfold.setCommitteePublicKey(ballot.publicInputs[8])
    await crispProgram.setMerkleRoot(e3Id, generateMerkleTree(leaves).root)

    await publishAvailableInput(crispProgram, e3Id, encodeSolidityProof(ballot))

    const [, , , , inputRoot] = await crispProgram.getRoundData(e3Id)
    expect(inputRoot, 'the round must have an input root after publishing').to.not.equal(0n)

    const record = {
      note: 'Generated by tests/input-tree-e2e.test.ts. Asserted by program/tests/onchain_root_agreement.rs.',
      inputRoot: `0x${BigInt(inputRoot).toString(16).padStart(64, '0')}`,
      // publicInputs[7] is the commitment `publishInput` actually stores; recorded alongside the
      // prepared one so a divergence between them is visible rather than silent.
      contractLeaf: (
        await crispProgram.inputLeaf(
          ethers.keccak256(`0x${Buffer.from(ballot.encryptedVote).toString('hex')}`),
          ballot.publicInputs[7],
          address,
          ballot.parentIndexPlusOne,
        )
      ).toString(),
      inputs: [
        {
          encryptedVote: `0x${Buffer.from(ballot.encryptedVote).toString('hex')}`,
          commitment: ballot.publicInputs[7],
          slot: address,
          parentIndexPlusOne: ballot.parentIndexPlusOne,
          preparedCommitment: ballot.ctCommitment,
        },
      ],
    }

    if (process.env.UPDATE_INPUT_TREE_FIXTURE === '1') {
      mkdirSync(dirname(FIXTURE), { recursive: true })
      writeFileSync(FIXTURE, `${JSON.stringify(record, null, 2)}\n`)
      console.log(`[fixture] wrote ${FIXTURE}`)
    }

    // The leaf the contract stored must be the one it computes from the published pair. This is
    // the value the Rust side has to match; the fixture carries it across the language boundary.
    const expectedLeaf = await crispProgram.inputLeaf(
      ethers.keccak256(record.inputs[0].encryptedVote),
      record.inputs[0].commitment,
      record.inputs[0].slot,
      record.inputs[0].parentIndexPlusOne,
    )
    expect(expectedLeaf).to.not.equal(0n)

    // Append-only: one publish, one leaf. `_processVote` never updates in place, so an entry
    // already in the tree cannot be replaced by a later writer.
    const [, , , , , numberOfVotes] = await crispProgram.getRoundData(e3Id)
    expect(numberOfVotes).to.equal(1n)
  })

  /// The premise of the whole fix: the contract cannot tell that the bytes are wrong.
  ///
  /// The proof constrains the commitment, so a submitter can publish any bytes beside it and
  /// `publishInput` still succeeds. Nothing on chain can reject this, which is why the check has
  /// to happen in the Secure Process.
  it('accepts an input whose bytes are not the ciphertext that was proven', async function () {
    // Its own round: a second input from the same slot would be a re-vote, and the ballot here is
    // built as a first vote.
    const forgedE3Id = await mockInterfold.nextE3Id()
    await mockInterfold.request(await crispProgram.getAddress())
    const previous = e3Id
    e3Id = forgedE3Id

    try {
      const ballot = await buildBallot([5, 0])
      await mockInterfold.setCommitteePublicKey(ballot.publicInputs[8])
      await crispProgram.setMerkleRoot(forgedE3Id, generateMerkleTree(leaves).root)

      const [, , , , rootBefore] = await crispProgram.getRoundData(forgedE3Id)

      // A genuine proof, published beside bytes that are not its ciphertext. Nothing on chain can
      // reject this, which is exactly why the Secure Process has to check it.
      const forged = { ...ballot, encryptedVote: new Uint8Array([0xde, 0xad, 0xbe, 0xef]) }
      await publishAvailableInput(crispProgram, forgedE3Id, encodeSolidityProof(forged))

      const [, , , , rootAfter] = await crispProgram.getRoundData(forgedE3Id)
      expect(rootAfter, 'the forged input entered the tree').to.not.equal(rootBefore)

      // The leaf reflects the forged bytes, so the Secure Process still reproduces the root while
      // being able to see that this input does not match its commitment.
      const forgedLeaf = await crispProgram.inputLeaf(
        ethers.keccak256('0xdeadbeef'),
        ballot.publicInputs[7],
        address,
        ballot.parentIndexPlusOne,
      )
      const honestLeaf = await crispProgram.inputLeaf(
        ethers.keccak256(`0x${Buffer.from(ballot.encryptedVote).toString('hex')}`),
        ballot.publicInputs[7],
        address,
        ballot.parentIndexPlusOne,
      )
      expect(forgedLeaf).to.not.equal(honestLeaf)
    } finally {
      e3Id = previous
    }
  })

  /// Append-only, on chain, with real masks over the ballot already in the slot.
  ///
  /// This is the poisoning case end to end: a genuine mask proof, published beside bytes that are
  /// not the summed ciphertext it proved. The contract cannot reject it — nothing on chain can tell
  /// that the bytes are wrong. What has to hold is that the slot stays writable: because the
  /// poisoned entry is never selected, it is never a valid parent either, so the next honest mask
  /// names the same parent it did and takes the slot.
  ///
  /// That is what stops the poisoning being a coercion receipt. A slot nobody can mask is one where
  /// every later input is provably its owner voting again, which is exactly the receipt masks exist
  /// to destroy.
  it('lets an honest mask follow a poisoned one, over the same parent', async function () {
    const appendE3Id = await mockInterfold.nextE3Id()
    await mockInterfold.request(await crispProgram.getAddress())
    const previous = e3Id
    e3Id = appendE3Id

    try {
      const ballot = await buildBallot([6, 0])
      await mockInterfold.setCommitteePublicKey(ballot.publicInputs[8])
      await crispProgram.setMerkleRoot(appendE3Id, generateMerkleTree(leaves).root)
      await publishAvailableInput(crispProgram, appendE3Id, encodeSolidityProof(ballot))

      const [, , , , rootAfterFirst, votesAfterFirst] = await crispProgram.getRoundData(appendE3Id)
      expect(votesAfterFirst).to.equal(1n)
      expect(await crispProgram.getSlotIndex(appendE3Id, address)).to.equal(0n)

      // A third party masks over the slot. No signature is checked on this path.
      const mask = await buildMaskOver(ballot.encryptedVote, 0)
      const poisoned = { ...mask, encryptedVote: new Uint8Array([0xde, 0xad, 0xbe, 0xef]) }
      await publishAvailableInput(crispProgram, appendE3Id, encodeSolidityProof(poisoned))

      const [, , , , rootAfterSecond, votesAfterSecond] = await crispProgram.getRoundData(appendE3Id)

      // Append-only: the poisoned entry is a new leaf, and the honest one is untouched at index 0.
      expect(votesAfterSecond, 'the second entry is a new leaf').to.equal(2n)
      expect(rootAfterSecond).to.not.equal(rootAfterFirst)

      // The recovery. The poisoned entry cannot be a parent, so an honest mask names index 0 — the
      // same parent the poisoned one named — and the contract accepts it.
      const recovery = await buildMaskOver(ballot.encryptedVote, 0)
      await publishAvailableInput(crispProgram, appendE3Id, encodeSolidityProof(recovery))

      const [, , , , rootAfterThird, votesAfterThird] = await crispProgram.getRoundData(appendE3Id)
      expect(votesAfterThird, 'the recovery is a third leaf').to.equal(3n)

      // Naming the poisoned entry is refused on chain as well, but only because its commitment is
      // recorded: the contract still cannot tell the bytes were wrong.
      expect(await crispProgram.inputCommitmentOf(appendE3Id, address, 1)).to.equal(mask.publicInputs[7])

      if (process.env.UPDATE_INPUT_TREE_FIXTURE === '1') {
        const record = {
          note: 'Generated by tests/input-tree-e2e.test.ts. Asserted by program/tests/onchain_root_agreement.rs.',
          inputRoot: `0x${BigInt(rootAfterThird).toString(16).padStart(64, '0')}`,
          honestIndex: 2,
          inputs: [
            {
              encryptedVote: `0x${Buffer.from(ballot.encryptedVote).toString('hex')}`,
              commitment: ballot.publicInputs[7],
              slot: address,
              parentIndexPlusOne: ballot.parentIndexPlusOne,
            },
            {
              encryptedVote: '0xdeadbeef',
              commitment: mask.publicInputs[7],
              slot: address,
              parentIndexPlusOne: mask.parentIndexPlusOne,
            },
            {
              encryptedVote: `0x${Buffer.from(recovery.encryptedVote).toString('hex')}`,
              commitment: recovery.publicInputs[7],
              slot: address,
              parentIndexPlusOne: recovery.parentIndexPlusOne,
            },
          ],
        }
        mkdirSync(dirname(APPEND_FIXTURE), { recursive: true })
        writeFileSync(APPEND_FIXTURE, `${JSON.stringify(record, null, 2)}\n`)
      }
    } finally {
      e3Id = previous
    }
  })

  /// A voter must be able to change their mind, and the new ballot must be the one tallied.
  ///
  /// Writes a fixture so `rust_tallies_the_re_vote` can assert which entry the Secure Process
  /// selects. The published bytes and the stored commitment have to describe the same ciphertext,
  /// or the re-vote is excluded and the voter is silently stuck with their first choice.
  it('publishes a real re-vote to a slot that already holds a ballot', async function () {
    const revoteE3Id = await mockInterfold.nextE3Id()
    await mockInterfold.request(await crispProgram.getAddress())
    const previous = e3Id
    e3Id = revoteE3Id

    try {
      const first = await buildBallot([4, 0])
      await mockInterfold.setCommitteePublicKey(first.publicInputs[8])
      await crispProgram.setMerkleRoot(revoteE3Id, generateMerkleTree(leaves).root)
      await publishAvailableInput(crispProgram, revoteE3Id, encodeSolidityProof(first))

      const second = await buildReVote([0, 9], first.encryptedVote, 0)
      await publishAvailableInput(crispProgram, revoteE3Id, encodeSolidityProof(second))

      const [, , , , root, votes] = await crispProgram.getRoundData(revoteE3Id)
      expect(votes, 'the re-vote is appended').to.equal(2n)

      if (process.env.UPDATE_INPUT_TREE_FIXTURE === '1') {
        const record = {
          note: 'Generated by tests/input-tree-e2e.test.ts. Asserted by program/tests/onchain_root_agreement.rs.',
          inputRoot: `0x${BigInt(root).toString(16).padStart(64, '0')}`,
          reVoteIndex: 1,
          inputs: [first, second].map((b) => ({
            encryptedVote: `0x${Buffer.from(b.encryptedVote).toString('hex')}`,
            commitment: b.publicInputs[7],
            slot: address,
            parentIndexPlusOne: b.parentIndexPlusOne,
          })),
        }
        mkdirSync(dirname(REVOTE_FIXTURE), { recursive: true })
        writeFileSync(REVOTE_FIXTURE, `${JSON.stringify(record, null, 2)}\n`)
      }
    } finally {
      e3Id = previous
    }
  })
})
