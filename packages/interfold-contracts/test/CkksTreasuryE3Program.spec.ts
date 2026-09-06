// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

/**
 * CkksTreasuryE3Program: SEVEN-leg gate (Greco ct0 + ct1 for each of the
 * FORWARD, REVERSED and MASK ciphertexts, and the treasury validity leg
 * proving the three messages are `forward(x)`, `reversed(w o x)` and
 * `mask(m)` in the ParamSet-5 coefficient layout with `x_a in [0, 1]`, the
 * round's PUBLIC weights `w` and `m_j in [0, 1024)`) on ParamSet 5 (N=512,
 * 3 limbs, delta=2^40), driven by a REAL fixture (exposures
 * [0.30, 0.10, 0.45, 0.15], weights [0.5, -0.25, 1.0, 0.125] (x 2^16),
 * slot 0, Alice = hardhat account #0).
 *
 * Fixture recipe: `scripts/ckks-treasury-fixtures.sh` (witness → nargo →
 * bb write_vk/prove -t evm → fixture JSON), then
 * `scripts/generate-verifiers.ts --write --no-compile --circuits ckks_treasury_validity_ps5`.
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
  "ckks_treasury_ps5",
);

interface PairFixture {
  ct0: LegFixture;
  ct1: LegFixture;
}

interface TreasuryFixture {
  ciphertextFwd: string;
  ciphertextRev: string;
  ciphertextMask: string;
  forward: PairFixture;
  reversed: PairFixture;
  mask: PairFixture;
  app: LegFixture;
  index: number;
  exposures: number[];
  exposuresF64: number[];
  weights: number[];
  weightsF64: number[];
  weightWords: string[];
  maskValues: number[];
  singleDaoRisk: number;
  mCommitmentFwd: string;
  mCommitmentRev: string;
  mCommitmentMask: string;
  wordIndex: { weights: number; address: number; index: number; mFwd: number; mRev: number; mMask: number };
  extra: { address: string; addressWord: string; indexWord: string };
}

interface OutOfRangeFixture {
  exposures: number[];
  appPublicInputs: string[];
  nargoExecute: { exitCode: number; failedAssertion: string };
}

type Ethers = Awaited<ReturnType<typeof network.connect>>["ethers"];

interface Overrides {
  ct0ProofF: string;
  ct1ProofF: string;
  ct0ProofR: string;
  ct1ProofR: string;
  ct0ProofM: string;
  ct1ProofM: string;
  appProof: string;
  appPublicInputs: string[];
  ct0PublicInputsF: string[];
  ct0PublicInputsR: string[];
}

const GRECO_PAIR = "(bytes,bytes,bytes32[],bytes,bytes32[])";

/** ABI-encodes the seven-leg envelope `CkksTreasuryE3Program.publishInput` takes. */
function encodeSevenLegInput(
  ethers: Ethers,
  f: TreasuryFixture,
  o?: Partial<Overrides>,
): string {
  // Matches `TreasurySubmission { GrecoPair forward; GrecoPair reversed;
  // GrecoPair mask; bytes appProof; bytes32[] appPub; }` — each tuple is
  // encoded head/tail with its own offsets (NOT a flat field list).
  return ethers.AbiCoder.defaultAbiCoder().encode(
    [`tuple(${GRECO_PAIR},${GRECO_PAIR},${GRECO_PAIR},bytes,bytes32[])`],
    [
      [
        [
          f.ciphertextFwd,
          o?.ct0ProofF ?? f.forward.ct0.proof,
          o?.ct0PublicInputsF ?? f.forward.ct0.publicInputs,
          o?.ct1ProofF ?? f.forward.ct1.proof,
          f.forward.ct1.publicInputs,
        ],
        [
          f.ciphertextRev,
          o?.ct0ProofR ?? f.reversed.ct0.proof,
          o?.ct0PublicInputsR ?? f.reversed.ct0.publicInputs,
          o?.ct1ProofR ?? f.reversed.ct1.proof,
          f.reversed.ct1.publicInputs,
        ],
        [
          f.ciphertextMask,
          o?.ct0ProofM ?? f.mask.ct0.proof,
          f.mask.ct0.publicInputs,
          o?.ct1ProofM ?? f.mask.ct1.proof,
          f.mask.ct1.publicInputs,
        ],
        o?.appProof ?? f.app.proof,
        o?.appPublicInputs ?? f.app.publicInputs,
      ],
    ],
  );
}

/** The FLAT field list — what a naive encoder would produce; the contract must reject it. */
function encodeFlatInput(ethers: Ethers, f: TreasuryFixture): string {
  const leg = ["bytes", "bytes", "bytes32[]", "bytes", "bytes32[]"];
  return ethers.AbiCoder.defaultAbiCoder().encode(
    [...leg, ...leg, ...leg, "bytes", "bytes32[]"],
    [
      f.ciphertextFwd, f.forward.ct0.proof, f.forward.ct0.publicInputs, f.forward.ct1.proof, f.forward.ct1.publicInputs,
      f.ciphertextRev, f.reversed.ct0.proof, f.reversed.ct0.publicInputs, f.reversed.ct1.proof, f.reversed.ct1.publicInputs,
      f.ciphertextMask, f.mask.ct0.proof, f.mask.ct0.publicInputs, f.mask.ct1.proof, f.mask.ct1.publicInputs,
      f.app.proof, f.app.publicInputs,
    ],
  );
}

/** Big-endian `int128` words at 4 decimals (`e3_trckks::program::encode_fixed_point_output`). */
function encodeOutput(values: number[]): string {
  const words = new Array<number>(64).fill(0).map((_, i) => values[i] ?? 0);
  let hex = "0x";
  for (const v of words) {
    let scaled = BigInt(Math.round(v * 10_000));
    if (scaled < 0n) scaled += 1n << 128n;
    hex += scaled.toString(16).padStart(32, "0");
  }
  return hex;
}

describe("CkksTreasuryE3Program (three Greco pairs + treasury validity, ParamSet 5)", function () {
  let fixture: TreasuryFixture;
  let outOfRange: OutOfRangeFixture;

  before(function () {
    fixture = JSON.parse(
      readFileSync(join(fixtureDir, "verified_input.json"), "utf-8"),
    ) as TreasuryFixture;
    outOfRange = JSON.parse(
      readFileSync(join(fixtureDir, "out_of_range_exposure.json"), "utf-8"),
    ) as OutOfRangeFixture;
  });

  const weights = () => fixture.weightWords as [string, string, string, string];

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
      "CkksTreasuryValidityPs5Verifier.sol",
      "CkksTreasuryValidityPs5Verifier",
    );
    const { CkksTreasuryE3Program__factory } = await import("../types");
    const [deployer, bob] = await ethers.getSigners();
    const program = await new CkksTreasuryE3Program__factory(deployer).deploy(
      await ct0.getAddress(),
      await ct1.getAddress(),
      await app.getAddress(),
    );
    return { ethers, program, alice: deployer, bob };
  }

  /** Registers round 7 with Alice at slot 0 and Bob at slot 1. */
  async function registerDefault(
    program: Awaited<ReturnType<typeof deployAll>>["program"],
    alice: string,
    bob: string,
    opts?: { weights?: [string, string, string, string]; daos?: string[] },
  ) {
    await program.registerRound(7n, opts?.weights ?? weights(), opts?.daos ?? [alice, bob]);
  }

  it("fixture legs are bound: three u commitments, three m commitments, weight + index words", function () {
    const W = fixture.wordIndex;
    for (const pair of [fixture.forward, fixture.reversed, fixture.mask]) {
      expect(pair.ct0.publicInputs).to.have.length(4);
      expect(pair.ct1.publicInputs).to.have.length(3);
      expect(pair.ct0.publicInputs[3]).to.equal(pair.ct1.publicInputs[2]);
    }
    expect(fixture.app.publicInputs).to.have.length(9);
    expect(fixture.forward.ct0.publicInputs[2]).to.equal(fixture.app.publicInputs[W.mFwd]);
    expect(fixture.reversed.ct0.publicInputs[2]).to.equal(fixture.app.publicInputs[W.mRev]);
    expect(fixture.mask.ct0.publicInputs[2]).to.equal(fixture.app.publicInputs[W.mMask]);
    expect(fixture.app.publicInputs[W.mFwd]).to.equal(fixture.mCommitmentFwd);
    expect(fixture.app.publicInputs[W.mRev]).to.equal(fixture.mCommitmentRev);
    expect(fixture.app.publicInputs[W.mMask]).to.equal(fixture.mCommitmentMask);
    expect(new Set([fixture.mCommitmentFwd, fixture.mCommitmentRev, fixture.mCommitmentMask]).size).to.equal(3);
    expect(
      new Set([
        fixture.forward.ct0.publicInputs[3],
        fixture.reversed.ct0.publicInputs[3],
        fixture.mask.ct0.publicInputs[3],
      ]).size,
    ).to.equal(3);
    expect(fixture.app.publicInputs.slice(0, 4)).to.deep.equal(fixture.weightWords);
    expect(fixture.app.publicInputs[W.address]).to.equal(fixture.extra.addressWord);
    expect(fixture.app.publicInputs[W.index]).to.equal(word(BigInt(fixture.index)));
    // w = [0.5, -0.25, 1.0, 0.125] x 2^16; the negative word is p - 16384.
    expect(fixture.weights).to.deep.equal([32768, -16384, 65536, 8192]);
    expect(fixture.weightWords[0]).to.equal(word(32768n));
    expect(fixture.weightWords[1]).to.equal(
      word(21888242871839275222246405745257275088548364400416034343698204186575808495617n - 16384n),
    );
    // Exposures and the mask are private: never public inputs.
    for (const x of fixture.exposures) expect(fixture.app.publicInputs).to.not.include(word(BigInt(x)));
    expect(fixture.maskValues).to.have.length(128);
    expect(fixture.maskValues.every((m) => m >= 0 && m < 1024)).to.equal(true);
    // Single-DAO oracle: sum_a w_a x_a^2 for [0.30,0.10,0.45,0.15].
    const x = fixture.exposuresF64;
    const w = fixture.weightsF64;
    const want = x.reduce((acc, v, a) => acc + w[a] * v * v, 0);
    expect(Math.abs(fixture.singleDaoRisk - want)).to.be.lessThan(1e-9);
  });

  it("accepts a genuine submission from the registered sender at its slot (prints 7-leg gas)", async function () {
    const { ethers, program, alice, bob } = await deployAll();
    expect((await alice.getAddress()).toLowerCase()).to.equal(String(fixture.extra.address));
    await registerDefault(program, await alice.getAddress(), await bob.getAddress());
    const data = encodeSevenLegInput(ethers, fixture);
    const tx = await program.publishInput(7n, data, { gasLimit: HONK_VERIFY_GAS_LIMIT });
    const receipt = await tx.wait();
    console.log(
      `      7-leg publishInput gas: ${receipt!.gasUsed.toString()} (calldata ${(data.length - 2) / 2} bytes)`,
    );
    const parsed = receipt!.logs
      .map((l: { topics: readonly string[]; data: string }) => program.interface.parseLog(l))
      .find((e: { name: string } | null) => e?.name === "SubmissionPublished");
    expect(parsed, "SubmissionPublished must fire").to.not.be.undefined;
    expect(parsed!.args.dao).to.equal(await alice.getAddress());
    expect(parsed!.args.index).to.equal(0n);
    expect(parsed!.args.mCommitmentFwd).to.equal(fixture.mCommitmentFwd);
    expect(parsed!.args.mCommitmentRev).to.equal(fixture.mCommitmentRev);
    expect(parsed!.args.mCommitmentMask).to.equal(fixture.mCommitmentMask);
    expect(parsed!.args.forwardCiphertextHash).to.equal(ethers.keccak256(fixture.ciphertextFwd));
    expect(parsed!.args.reversedCiphertextHash).to.equal(ethers.keccak256(fixture.ciphertextRev));
    expect(parsed!.args.maskCiphertextHash).to.equal(ethers.keccak256(fixture.ciphertextMask));
    expect(await program.submissionCount(7n)).to.equal(1n);
    const stored = await program.submissionAt(7n, 0n);
    expect(stored.dao).to.equal(await alice.getAddress());
    expect(stored.index).to.equal(0n);
    expect(stored.uCommitmentFwd).to.equal(fixture.forward.ct0.publicInputs[3]);
    expect(stored.uCommitmentRev).to.equal(fixture.reversed.ct0.publicInputs[3]);
    expect(stored.uCommitmentMask).to.equal(fixture.mask.ct0.publicInputs[3]);
    expect(await program.hasSubmitted(7n, await alice.getAddress())).to.equal(true);
  });

  it("rejects a flat (non-nested) envelope", async function () {
    const { ethers, program, alice, bob } = await deployAll();
    await registerDefault(program, await alice.getAddress(), await bob.getAddress());
    await expect(
      program.publishInput(7n, encodeFlatInput(ethers, fixture), { gasLimit: HONK_VERIFY_GAS_LIMIT }),
    ).to.be.revert(ethers);
  });

  it("rejects a submission before the round is registered", async function () {
    const { ethers, program } = await deployAll();
    await expect(
      program.publishInput(7n, encodeSevenLegInput(ethers, fixture), { gasLimit: HONK_VERIFY_GAS_LIMIT }),
    ).to.be.revertedWithCustomError(program, "RoundNotRegistered");
  });

  it("rejects wrong weights (registered weights differ; forged weight word breaks the proof)", async function () {
    const { ethers, program, alice, bob } = await deployAll();
    const w = [...weights()] as [string, string, string, string];
    w[1] = word(BigInt(w[1]) + 1n);
    await registerDefault(program, await alice.getAddress(), await bob.getAddress(), { weights: w });
    await expect(
      program.publishInput(7n, encodeSevenLegInput(ethers, fixture), { gasLimit: HONK_VERIFY_GAS_LIMIT }),
    ).to.be.revertedWithCustomError(program, "WrongWeights");
    // Forging the weight word in the proof's public inputs breaks the proof.
    const appPublicInputs = [...fixture.app.publicInputs];
    appPublicInputs[1] = w[1];
    await expect(
      program.publishInput(7n, encodeSevenLegInput(ethers, fixture, { appPublicInputs }), {
        gasLimit: HONK_VERIFY_GAS_LIMIT,
      }),
    ).to.be.revertedWithCustomError(program, "AppProofInvalid");
  });

  it("rejects a submission relayed by a different sender (wrong-sender)", async function () {
    const { ethers, program, alice, bob } = await deployAll();
    await registerDefault(program, await alice.getAddress(), await bob.getAddress());
    const data = encodeSevenLegInput(ethers, fixture);
    await expect(
      program.connect(bob).publishInput(7n, data, { gasLimit: HONK_VERIFY_GAS_LIMIT }),
    ).to.be.revertedWithCustomError(program, "WrongSender");
    // Bob cannot relabel Alice's proof: the address is a public input.
    const appPublicInputs = [...fixture.app.publicInputs];
    appPublicInputs[fixture.wordIndex.address] = word(BigInt(await bob.getAddress()));
    appPublicInputs[fixture.wordIndex.index] = word(1n);
    await expect(
      program.connect(bob).publishInput(7n, encodeSevenLegInput(ethers, fixture, { appPublicInputs }), {
        gasLimit: HONK_VERIFY_GAS_LIMIT,
      }),
    ).to.be.revertedWithCustomError(program, "AppProofInvalid");
  });

  it("rejects a wrong slot index and an unregistered sender", async function () {
    const { ethers, program, alice, bob } = await deployAll();
    await registerDefault(program, await alice.getAddress(), await bob.getAddress(), {
      daos: [await bob.getAddress(), await alice.getAddress()],
    });
    await expect(
      program.publishInput(7n, encodeSevenLegInput(ethers, fixture), { gasLimit: HONK_VERIFY_GAS_LIMIT }),
    ).to.be.revertedWithCustomError(program, "WrongIndex");
    const { ethers: e2, program: p2, alice: a2, bob: b2 } = await deployAll();
    await registerDefault(p2, await a2.getAddress(), await b2.getAddress(), { daos: [await b2.getAddress()] });
    await expect(
      p2.publishInput(7n, encodeSevenLegInput(e2, fixture), { gasLimit: HONK_VERIFY_GAS_LIMIT }),
    ).to.be.revertedWithCustomError(p2, "NotRegistered");
  });

  it("rejects each tampered leg", async function () {
    const { ethers, program, alice, bob } = await deployAll();
    await registerDefault(program, await alice.getAddress(), await bob.getAddress());
    for (const [key, error, proof] of [
      ["ct0ProofF", "Ct0ProofInvalid", fixture.forward.ct0.proof],
      ["ct1ProofF", "Ct1ProofInvalid", fixture.forward.ct1.proof],
      ["ct0ProofR", "Ct0ProofInvalid", fixture.reversed.ct0.proof],
      ["ct1ProofR", "Ct1ProofInvalid", fixture.reversed.ct1.proof],
      ["ct0ProofM", "Ct0ProofInvalid", fixture.mask.ct0.proof],
      ["ct1ProofM", "Ct1ProofInvalid", fixture.mask.ct1.proof],
      ["appProof", "AppProofInvalid", fixture.app.proof],
    ] as const) {
      const data = encodeSevenLegInput(ethers, fixture, { [key]: tamperProof(proof) });
      await expect(
        program.publishInput(7n, data, { gasLimit: HONK_VERIFY_GAS_LIMIT }),
        key,
      ).to.be.revertedWithCustomError(program, error);
    }
  });

  it("rejects a cross-leg m_commitment mismatch and a shared u across ciphertexts", async function () {
    const { ethers, program, alice, bob } = await deployAll();
    await registerDefault(program, await alice.getAddress(), await bob.getAddress());
    const appPublicInputs = [...fixture.app.publicInputs];
    appPublicInputs[fixture.wordIndex.mRev] = fixture.reversed.ct0.publicInputs[1];
    await expect(
      program.publishInput(7n, encodeSevenLegInput(ethers, fixture, { appPublicInputs }), {
        gasLimit: HONK_VERIFY_GAS_LIMIT,
      }),
    ).to.be.revertedWithCustomError(program, "MCommitmentMismatch");
    // The reversed pair's ct0 public inputs swapped for the forward pair's.
    await expect(
      program.publishInput(
        7n,
        encodeSevenLegInput(ethers, fixture, { ct0PublicInputsR: fixture.forward.ct0.publicInputs }),
        { gasLimit: HONK_VERIFY_GAS_LIMIT },
      ),
    ).to.be.revertedWithCustomError(program, "UCommitmentMismatch");
  });

  it("rejects a duplicate submission (same sender)", async function () {
    const { ethers, program, alice, bob } = await deployAll();
    await registerDefault(program, await alice.getAddress(), await bob.getAddress());
    const data = encodeSevenLegInput(ethers, fixture);
    await program.publishInput(7n, data, { gasLimit: HONK_VERIFY_GAS_LIMIT });
    await expect(
      program.publishInput(7n, data, { gasLimit: HONK_VERIFY_GAS_LIMIT }),
    ).to.be.revertedWithCustomError(program, "AlreadySubmitted");
  });

  it("an out-of-range exposure has no proof: the circuit rejects it at proving time", async function () {
    expect(outOfRange.exposures[2]).to.equal(65537);
    expect(outOfRange.nargoExecute.exitCode).to.equal(1);
    expect(outOfRange.nargoExecute.failedAssertion).to.contain("assert_exposure_range");
    // Exposures are PRIVATE: the words the DAO would have published differ from the genuine
    // ones ONLY in the forward / reversed m_commitments (the messages differ, not the weights,
    // address or index). The gate cannot see the exposure — only the missing proof.
    const W = fixture.wordIndex;
    for (const i of [0, 1, 2, 3, W.address, W.index, W.mMask]) {
      expect(outOfRange.appPublicInputs[i]).to.equal(fixture.app.publicInputs[i]);
    }
    expect(outOfRange.appPublicInputs[W.mFwd]).to.not.equal(fixture.app.publicInputs[W.mFwd]);
    expect(outOfRange.appPublicInputs[W.mRev]).to.not.equal(fixture.app.publicInputs[W.mRev]);
    const { ethers, program, alice, bob } = await deployAll();
    await registerDefault(program, await alice.getAddress(), await bob.getAddress());
    // The out-of-range words with the genuine legs: the cross-leg binding refuses them before
    // any Honk verify.
    await expect(
      program.publishInput(7n, encodeSevenLegInput(ethers, fixture, { appPublicInputs: outOfRange.appPublicInputs }), {
        gasLimit: HONK_VERIFY_GAS_LIMIT,
      }),
    ).to.be.revertedWithCustomError(program, "MCommitmentMismatch");
    // A CONSISTENT forgery (the ct0 legs relabelled with the out-of-range m_commitments too)
    // passes the bindings and dies at the first proof: there is no Greco proof for those
    // messages either, so the gate never reaches the treasury leg.
    const ct0PublicInputsF = [...fixture.forward.ct0.publicInputs];
    ct0PublicInputsF[2] = outOfRange.appPublicInputs[W.mFwd];
    const ct0PublicInputsR = [...fixture.reversed.ct0.publicInputs];
    ct0PublicInputsR[2] = outOfRange.appPublicInputs[W.mRev];
    await expect(
      program.publishInput(
        7n,
        encodeSevenLegInput(ethers, fixture, { appPublicInputs: outOfRange.appPublicInputs, ct0PublicInputsF, ct0PublicInputsR }),
        { gasLimit: HONK_VERIFY_GAS_LIMIT },
      ),
    ).to.be.revertedWithCustomError(program, "Ct0ProofInvalid");
  });

  it("only the owner registers a round, once, with a non-empty unique DAO list", async function () {
    const { program, alice, bob } = await deployAll();
    const a = await alice.getAddress();
    const b = await bob.getAddress();
    await expect(program.connect(bob).registerRound(7n, weights(), [a, b])).to.be.revertedWithCustomError(program, "NotOwner");
    await expect(program.registerRound(7n, weights(), [])).to.be.revertedWithCustomError(program, "NoDaos");
    await expect(program.registerRound(7n, weights(), [a, a])).to.be.revertedWithCustomError(program, "DuplicateDao");
    await program.registerRound(7n, weights(), [a, b]);
    await expect(program.registerRound(7n, weights(), [a, b])).to.be.revertedWithCustomError(program, "RoundAlreadyRegistered");
    expect(await program.daos(7n)).to.deep.equal([a, b]);
    expect(await program.daoSlot(7n, b)).to.equal(2n);
    expect(await program.weights(7n)).to.deep.equal(weights());
  });

  it("decodes the 64-word int128 output and reads the risk as -coefficient_0", async function () {
    const { program } = await deployAll();
    const out = encodeOutput([-0.2478, 12.5, -3.25]);
    expect((out.length - 2) / 2).to.equal(64 * 16);
    const words = await program.decodeOutput(out);
    expect(words[0]).to.equal(-2478n);
    expect(words[1]).to.equal(125000n);
    expect(words[2]).to.equal(-32500n);
    expect(words[63]).to.equal(0n);
    expect(await program.riskFromOutput(out)).to.equal(2478n);
    await expect(program.decodeOutput("0x1234")).to.be.revertedWithCustomError(program, "InvalidOutputLength");
    // `verify` is the ciphertext-publish hook (mock ciphertext verifier on the dev stack).
    expect(await program.verify(7n, word(0n), word(0n), "0x12345678")).to.equal(true);
  });
});
