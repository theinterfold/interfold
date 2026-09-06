// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

/**
 * CkksMatchingE3Program: FIVE-leg gate (Greco ct0 + ct1 for the VECTOR
 * ciphertext, Greco ct0 + ct1 for the MASK ciphertext, and the matching
 * validity leg proving the vector message is the `forward` (A) / `reversed`
 * (B) coefficient encoding of 16 entries with |v| <= 1 and the mask message
 * the `mask` layout of 128 integers in [0, 1024)) on ParamSet 5 (N=512, 3
 * limbs, delta=2^40), driven by REAL fixtures for BOTH parties: A = hardhat
 * account #0 (slot 0, role 0), B = account #1 (slot 1, role 1).
 *
 * Fixture recipe: `scripts/ckks-matching-fixtures.sh` (witness → nargo →
 * bb write_vk/prove -t evm → fixture JSON), then
 * `scripts/generate-verifiers.ts --write --no-compile --circuits ckks_matching_validity_ps5,user_data_encryption_ckks_ct0_ps5,user_data_encryption_ckks_ct1_ps5`.
 */
import { expect } from "chai";
import { readFileSync } from "fs";
import { network } from "hardhat";
import { dirname, join } from "path";
import { fileURLToPath } from "url";

import type { LegFixture } from "./helpers/ckksApp";
import {
  HONK_VERIFY_GAS_LIMIT,
  deployVerifier,
  tamperProof,
  word,
} from "./helpers/ckksApp";

const fixtureDir = join(
  dirname(fileURLToPath(import.meta.url)),
  "fixtures",
  "ckks_matching_ps5",
);

interface PairFixture {
  ct0: LegFixture;
  ct1: LegFixture;
}

interface PartyFixture {
  ciphertextVec: string;
  ciphertextMask: string;
  vector: PairFixture;
  mask: PairFixture;
  app: LegFixture;
  role: number;
  index: number;
  values: number[];
  valuesF64: number[];
  maskValues: number[];
  mCommitmentVec: string;
  mCommitmentMask: string;
  extra: {
    address: string;
    addressWord: string;
    roleWord: string;
    indexWord: string;
  };
}

interface MatchingFixture {
  a: PartyFixture;
  b: PartyFixture;
  expectedScore: number;
}

interface OutOfRangeFixture {
  role: number;
  index: number;
  values: number[];
  appPublicInputs: string[];
  nargoExecute: { exitCode: number; failedAssertion: string };
}

type Ethers = Awaited<ReturnType<typeof network.connect>>["ethers"];

interface Overrides {
  ct0ProofV: string;
  ct1ProofV: string;
  ct0ProofM: string;
  ct1ProofM: string;
  appProof: string;
  appPublicInputs: string[];
  ct0PublicInputsM: string[];
}

/** ABI-encodes the five-leg envelope `CkksMatchingE3Program.publishInput` takes. */
function encodeFiveLegInput(
  ethers: Ethers,
  f: PartyFixture,
  o?: Partial<Overrides>,
): string {
  // Matches `MatchingSubmission { GrecoPair vector; GrecoPair mask;
  // bytes appProof; bytes32[] appPub; }` — nested dynamic tuples, NOT a
  // flat field list.
  const grecoPair = "(bytes,bytes,bytes32[],bytes,bytes32[])";
  return ethers.AbiCoder.defaultAbiCoder().encode(
    [`tuple(${grecoPair},${grecoPair},bytes,bytes32[])`],
    [
      [
        [
          f.ciphertextVec,
          o?.ct0ProofV ?? f.vector.ct0.proof,
          f.vector.ct0.publicInputs,
          o?.ct1ProofV ?? f.vector.ct1.proof,
          f.vector.ct1.publicInputs,
        ],
        [
          f.ciphertextMask,
          o?.ct0ProofM ?? f.mask.ct0.proof,
          o?.ct0PublicInputsM ?? f.mask.ct0.publicInputs,
          o?.ct1ProofM ?? f.mask.ct1.proof,
          f.mask.ct1.publicInputs,
        ],
        o?.appProof ?? f.app.proof,
        o?.appPublicInputs ?? f.app.publicInputs,
      ],
    ],
  );
}

describe("CkksMatchingE3Program (two Greco pairs + matching validity, ParamSet 5)", function () {
  let fixture: MatchingFixture;
  let outOfRange: OutOfRangeFixture;

  before(function () {
    fixture = JSON.parse(
      readFileSync(join(fixtureDir, "verified_input.json"), "utf-8"),
    ) as MatchingFixture;
    outOfRange = JSON.parse(
      readFileSync(join(fixtureDir, "out_of_range_entry.json"), "utf-8"),
    ) as OutOfRangeFixture;
  });

  async function deployAll() {
    const { ethers, networkHelpers } = await network.connect();
    await networkHelpers.setBlockGasLimit(HONK_VERIFY_GAS_LIMIT);
    const ct0 = await deployVerifier(
      ethers,
      "UserDataEncryptionCkksCt0Ps5Verifier.sol",
      "UserDataEncryptionCkksCt0Ps5Verifier",
    );
    const ct1 = await deployVerifier(
      ethers,
      "UserDataEncryptionCkksCt1Ps5Verifier.sol",
      "UserDataEncryptionCkksCt1Ps5Verifier",
    );
    const app = await deployVerifier(
      ethers,
      "CkksMatchingValidityPs5Verifier.sol",
      "CkksMatchingValidityPs5Verifier",
    );
    const { CkksMatchingE3Program__factory } = await import("../types");
    const [alice, bob, carol] = await ethers.getSigners();
    const program = await new CkksMatchingE3Program__factory(alice).deploy(
      await ct0.getAddress(),
      await ct1.getAddress(),
      await app.getAddress(),
    );
    return { ethers, program, alice, bob, carol };
  }

  /** Registers round 7 with Alice = A (slot 0) and Bob = B (slot 1). */
  async function registerDefault(
    program: Awaited<ReturnType<typeof deployAll>>["program"],
    a: string,
    b: string,
    parties?: string[],
  ) {
    await program.registerRound(7n, parties ?? [a, b]);
  }

  it("fixture legs are bound for both parties: u commitments, m commitments, role + index words", function () {
    for (const p of [fixture.a, fixture.b]) {
      for (const pair of [p.vector, p.mask]) {
        expect(pair.ct0.publicInputs).to.have.length(4);
        expect(pair.ct1.publicInputs).to.have.length(3);
        expect(pair.ct0.publicInputs[3]).to.equal(pair.ct1.publicInputs[2]);
      }
      expect(p.app.publicInputs).to.have.length(5);
      expect(p.vector.ct0.publicInputs[2]).to.equal(p.app.publicInputs[3]);
      expect(p.mask.ct0.publicInputs[2]).to.equal(p.app.publicInputs[4]);
      expect(p.app.publicInputs[3]).to.equal(p.mCommitmentVec);
      expect(p.app.publicInputs[4]).to.equal(p.mCommitmentMask);
      expect(p.mCommitmentVec).to.not.equal(p.mCommitmentMask);
      expect(p.vector.ct0.publicInputs[3]).to.not.equal(p.mask.ct0.publicInputs[3]);
      expect(p.app.publicInputs[0]).to.equal(word(BigInt(p.role)));
      expect(p.app.publicInputs[1]).to.equal(p.extra.addressWord);
      expect(p.app.publicInputs[2]).to.equal(word(BigInt(p.index)));
      expect(p.role).to.equal(p.index);
      // The vector and the mask are private: no entry appears as a word.
      // (0 is skipped: it is indistinguishable from the public role/index 0.)
      for (const v of p.values) {
        if (v > 0) expect(p.app.publicInputs).to.not.include(word(BigInt(v)));
      }
      expect(p.values).to.have.length(16);
      expect(p.maskValues).to.have.length(128);
      for (const m of p.maskValues) expect(m).to.be.lessThan(1024);
    }
    expect(fixture.a.role).to.equal(0);
    expect(fixture.b.role).to.equal(1);
    expect(fixture.a.mCommitmentVec).to.not.equal(fixture.b.mCommitmentVec);
    const dot = fixture.a.valuesF64.reduce((s, x, j) => s + x * fixture.b.valuesF64[j], 0);
    expect(Math.abs(dot - fixture.expectedScore)).to.be.lessThan(1e-9);
  });

  it("accepts both parties' genuine submissions from their registered senders", async function () {
    const { ethers, program, alice, bob } = await deployAll();
    expect((await alice.getAddress()).toLowerCase()).to.equal(fixture.a.extra.address);
    expect((await bob.getAddress()).toLowerCase()).to.equal(fixture.b.extra.address);
    await registerDefault(program, await alice.getAddress(), await bob.getAddress());

    for (const [signer, f, slot] of [
      [alice, fixture.a, 0n],
      [bob, fixture.b, 1n],
    ] as const) {
      const data = encodeFiveLegInput(ethers, f);
      const tx = await program.connect(signer).publishInput(7n, data, {
        gasLimit: HONK_VERIFY_GAS_LIMIT,
      });
      const receipt = await tx.wait();
      const parsed = receipt!.logs
        .map((l: { topics: readonly string[]; data: string }) =>
          program.interface.parseLog(l),
        )
        .find((e: { name: string } | null) => e?.name === "SubmissionPublished");
      expect(parsed, "SubmissionPublished must fire").to.not.be.undefined;
      expect(parsed!.args.party).to.equal(await signer.getAddress());
      expect(parsed!.args.index).to.equal(slot);
      expect(parsed!.args.mCommitmentVec).to.equal(f.mCommitmentVec);
      expect(parsed!.args.mCommitmentMask).to.equal(f.mCommitmentMask);
      expect(parsed!.args.vectorCiphertextHash).to.equal(ethers.keccak256(f.ciphertextVec));
      expect(parsed!.args.maskCiphertextHash).to.equal(ethers.keccak256(f.ciphertextMask));
    }
    expect(await program.submissionCount(7n)).to.equal(2n);
    const stored = await program.submissionAt(7n, 1n);
    expect(stored.party).to.equal(await bob.getAddress());
    expect(stored.index).to.equal(1n);
    expect(stored.uCommitmentVec).to.equal(fixture.b.vector.ct0.publicInputs[3]);
    expect(await program.hasSubmitted(7n, await alice.getAddress())).to.equal(true);
    expect(await program.hasSubmitted(7n, await bob.getAddress())).to.equal(true);
  });

  it("rejects a submission before the round is registered", async function () {
    const { ethers, program } = await deployAll();
    await expect(
      program.publishInput(7n, encodeFiveLegInput(ethers, fixture.a), {
        gasLimit: HONK_VERIFY_GAS_LIMIT,
      }),
    ).to.be.revertedWithCustomError(program, "RoundNotRegistered");
  });

  it("rejects the wrong role: A's forward proof relayed at B's slot and vice versa", async function () {
    const { ethers, program, alice, bob } = await deployAll();
    // Swap the slots: Bob = A (slot 0), Alice = B (slot 1).
    await registerDefault(program, await alice.getAddress(), await bob.getAddress(), [
      await bob.getAddress(),
      await alice.getAddress(),
    ]);
    // Alice's proof carries index 0 / role 0 but she is registered at slot 1.
    await expect(
      program.publishInput(7n, encodeFiveLegInput(ethers, fixture.a), {
        gasLimit: HONK_VERIFY_GAS_LIMIT,
      }),
    ).to.be.revertedWithCustomError(program, "WrongIndex");
    // Forging the index word alone trips the role/index binding.
    let appPublicInputs = [...fixture.a.app.publicInputs];
    appPublicInputs[2] = word(1n);
    await expect(
      program.publishInput(7n, encodeFiveLegInput(ethers, fixture.a, { appPublicInputs }), {
        gasLimit: HONK_VERIFY_GAS_LIMIT,
      }),
    ).to.be.revertedWithCustomError(program, "WrongRole");
    // Forging both role and index words breaks the app proof (the role
    // selects which layout the circuit checked).
    appPublicInputs = [...fixture.a.app.publicInputs];
    appPublicInputs[0] = word(1n);
    appPublicInputs[2] = word(1n);
    await expect(
      program.publishInput(7n, encodeFiveLegInput(ethers, fixture.a, { appPublicInputs }), {
        gasLimit: HONK_VERIFY_GAS_LIMIT,
      }),
    ).to.be.revertedWithCustomError(program, "AppProofInvalid");
    // Bob (registered at slot 0 here) sending his role-1 proof: WrongIndex.
    await expect(
      program.connect(bob).publishInput(7n, encodeFiveLegInput(ethers, fixture.b), {
        gasLimit: HONK_VERIFY_GAS_LIMIT,
      }),
    ).to.be.revertedWithCustomError(program, "WrongIndex");
  });

  it("rejects a submission relayed by a different sender (wrong-sender)", async function () {
    const { ethers, program, alice, bob, carol } = await deployAll();
    await registerDefault(program, await alice.getAddress(), await bob.getAddress());
    // Bob relays Alice's envelope: the proven address is Alice's.
    await expect(
      program.connect(bob).publishInput(7n, encodeFiveLegInput(ethers, fixture.a), {
        gasLimit: HONK_VERIFY_GAS_LIMIT,
      }),
    ).to.be.revertedWithCustomError(program, "WrongSender");
    // Bob relabels Alice's proof with his own address + slot: the address
    // is a public input of the circuit, so the proof no longer verifies.
    const appPublicInputs = [...fixture.a.app.publicInputs];
    appPublicInputs[0] = word(1n);
    appPublicInputs[1] = word(BigInt(await bob.getAddress()));
    appPublicInputs[2] = word(1n);
    await expect(
      program
        .connect(bob)
        .publishInput(7n, encodeFiveLegInput(ethers, fixture.a, { appPublicInputs }), {
          gasLimit: HONK_VERIFY_GAS_LIMIT,
        }),
    ).to.be.revertedWithCustomError(program, "AppProofInvalid");
    // An unregistered third party with a self-addressed word: NotRegistered.
    const relabeled = [...fixture.a.app.publicInputs];
    relabeled[1] = word(BigInt(await carol.getAddress()));
    await expect(
      program
        .connect(carol)
        .publishInput(7n, encodeFiveLegInput(ethers, fixture.a, { appPublicInputs: relabeled }), {
          gasLimit: HONK_VERIFY_GAS_LIMIT,
        }),
    ).to.be.revertedWithCustomError(program, "NotRegistered");
  });

  it("rejects each tampered leg (both parties)", async function () {
    const { ethers, program, alice, bob } = await deployAll();
    await registerDefault(program, await alice.getAddress(), await bob.getAddress());
    for (const [signer, f] of [
      [alice, fixture.a],
      [bob, fixture.b],
    ] as const) {
      for (const [key, error, proof] of [
        ["ct0ProofV", "Ct0ProofInvalid", f.vector.ct0.proof],
        ["ct1ProofV", "Ct1ProofInvalid", f.vector.ct1.proof],
        ["ct0ProofM", "Ct0ProofInvalid", f.mask.ct0.proof],
        ["ct1ProofM", "Ct1ProofInvalid", f.mask.ct1.proof],
        ["appProof", "AppProofInvalid", f.app.proof],
      ] as const) {
        const data = encodeFiveLegInput(ethers, f, { [key]: tamperProof(proof) });
        await expect(
          program.connect(signer).publishInput(7n, data, { gasLimit: HONK_VERIFY_GAS_LIMIT }),
          `${f.role}:${key}`,
        ).to.be.revertedWithCustomError(program, error);
      }
    }
  });

  it("rejects a cross-leg m_commitment mismatch and a swapped Greco pair", async function () {
    const { ethers, program, alice, bob } = await deployAll();
    await registerDefault(program, await alice.getAddress(), await bob.getAddress());
    const appPublicInputs = [...fixture.a.app.publicInputs];
    appPublicInputs[3] = fixture.a.vector.ct0.publicInputs[1];
    await expect(
      program.publishInput(7n, encodeFiveLegInput(ethers, fixture.a, { appPublicInputs }), {
        gasLimit: HONK_VERIFY_GAS_LIMIT,
      }),
    ).to.be.revertedWithCustomError(program, "MCommitmentMismatch");
    await expect(
      program.publishInput(
        7n,
        encodeFiveLegInput(ethers, fixture.a, {
          ct0PublicInputsM: fixture.a.vector.ct0.publicInputs,
        }),
        { gasLimit: HONK_VERIFY_GAS_LIMIT },
      ),
    ).to.be.revertedWithCustomError(program, "UCommitmentMismatch");
  });

  it("rejects a duplicate submission (same sender)", async function () {
    const { ethers, program, alice, bob } = await deployAll();
    await registerDefault(program, await alice.getAddress(), await bob.getAddress());
    const data = encodeFiveLegInput(ethers, fixture.a);
    await program.publishInput(7n, data, { gasLimit: HONK_VERIFY_GAS_LIMIT });
    await expect(
      program.publishInput(7n, data, { gasLimit: HONK_VERIFY_GAS_LIMIT }),
    ).to.be.revertedWithCustomError(program, "AlreadySubmitted");
  });

  it("an entry above 1 has no proof: the circuit rejects it at proving time", async function () {
    expect(outOfRange.values[0]).to.equal(98304); // 1.5 * 2^16
    expect(outOfRange.nargoExecute.exitCode).to.equal(1);
    expect(outOfRange.nargoExecute.failedAssertion).to.contain("assert_entry_range");
    // The over-one witness commits to a DIFFERENT vector message, so its
    // public words cannot ride on the genuine proof: the gate first sees the
    // m_commitment mismatch against the genuine ct0 leg…
    const { ethers, program, alice, bob } = await deployAll();
    await registerDefault(program, await alice.getAddress(), await bob.getAddress());
    expect(outOfRange.appPublicInputs[3]).to.not.equal(fixture.a.app.publicInputs[3]);
    const mismatched = [...outOfRange.appPublicInputs];
    mismatched[4] = fixture.a.app.publicInputs[4];
    await expect(
      program.publishInput(
        7n,
        encodeFiveLegInput(ethers, fixture.a, { appPublicInputs: mismatched }),
        { gasLimit: HONK_VERIFY_GAS_LIMIT },
      ),
    ).to.be.revertedWithCustomError(program, "MCommitmentMismatch");
    // …and with the genuine ct0 words swapped in for the over-one vector's,
    // the genuine app proof does not verify those words either.
    const forged = [...fixture.a.app.publicInputs];
    forged[3] = outOfRange.appPublicInputs[3];
    await expect(
      program.publishInput(
        7n,
        encodeFiveLegInput(ethers, fixture.a, { appPublicInputs: forged }),
        { gasLimit: HONK_VERIFY_GAS_LIMIT },
      ),
    ).to.be.revertedWithCustomError(program, "MCommitmentMismatch");
  });

  it("only the owner registers a round, once, with exactly two distinct parties", async function () {
    const { program, alice, bob, carol } = await deployAll();
    const a = await alice.getAddress();
    const b = await bob.getAddress();
    const c = await carol.getAddress();
    await expect(program.connect(bob).registerRound(7n, [a, b])).to.be.revertedWithCustomError(
      program,
      "NotOwner",
    );
    await expect(program.registerRound(7n, [a])).to.be.revertedWithCustomError(
      program,
      "WrongPartyCount",
    );
    await expect(program.registerRound(7n, [a, b, c])).to.be.revertedWithCustomError(
      program,
      "WrongPartyCount",
    );
    await expect(program.registerRound(7n, [a, a])).to.be.revertedWithCustomError(
      program,
      "DuplicateParty",
    );
    await program.registerRound(7n, [a, b]);
    await expect(program.registerRound(7n, [a, b])).to.be.revertedWithCustomError(
      program,
      "RoundAlreadyRegistered",
    );
    expect(await program.parties(7n)).to.deep.equal([a, b]);
    expect(await program.partySlot(7n, a)).to.equal(1n);
    expect(await program.partySlot(7n, b)).to.equal(2n);
    expect(await program.partySlot(7n, c)).to.equal(0n);
  });

  it("verifyOutput accepts exactly 64 int128 words", async function () {
    const { program } = await deployAll();
    expect(await program.OUTPUT_BYTES()).to.equal(1024n);
    expect(await program.verifyOutput(`0x${"00".repeat(1024)}`)).to.equal(true);
    expect(await program.verifyOutput(`0x${"00".repeat(1023)}`)).to.equal(false);
    expect(await program.verifyOutput(`0x${"00".repeat(16)}`)).to.equal(false);
  });
});
