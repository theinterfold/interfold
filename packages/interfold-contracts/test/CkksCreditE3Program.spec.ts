// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

/**
 * CkksCreditE3Program v2: FIVE-leg gate (Greco ct0 + ct1 for the LOGIT
 * ciphertext, Greco ct0 + ct1 for the MASK ciphertext, and the credit
 * validity leg proving both messages are slot-`index` encodings — the
 * registered model's logit over a Merkle-attested feature vector, and an
 * output mask in [0, 1024)) on ParamSet 4 (N=512, 5 limbs, delta=2^40),
 * driven by a REAL fixture (features [520,130,350,999,0,1,777,42] over cap
 * 1000, model [1.7,-2.3,0.9,0.4,-1.1,2.6,-0.5,1.2] + -0.8 (x 2^16), mask
 * 529664 / 2^10 = 517.25, slot 0, Alice = hardhat account #0 under a
 * two-leaf issuer tree {Alice, Bob}).
 *
 * Fixture recipe: `scripts/ckks-credit-fixtures.sh` (witness → nargo →
 * bb write_vk/prove -t evm → fixture JSON), then
 * `scripts/generate-verifiers.ts --write --no-compile --circuits <the three ps4 packages>`.
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
  "ckks_credit_ps4",
);

interface PairFixture {
  ct0: LegFixture;
  ct1: LegFixture;
}

interface CreditFixture {
  ciphertextZ: string;
  ciphertextM: string;
  logit: PairFixture;
  mask: PairFixture;
  app: LegFixture;
  cap: number;
  index: number;
  maskValue: number;
  logitValue: number;
  model: { weights: number[]; bias: number };
  modelWords: string[];
  mCommitmentZ: string;
  mCommitmentM: string;
  extra: {
    address: string;
    addressWord: string;
    merkleRoot: string;
    indexWord: string;
    features: string;
    bobFeatures: string;
  };
}

interface OutOfRangeFixture {
  cap: number;
  features: number[];
  appPublicInputs: string[];
  nargoExecute: { exitCode: number; failedAssertion: string };
}

type Ethers = Awaited<ReturnType<typeof network.connect>>["ethers"];

interface Overrides {
  ct0ProofZ: string;
  ct1ProofZ: string;
  ct0ProofM: string;
  ct1ProofM: string;
  appProof: string;
  appPublicInputs: string[];
  ct0PublicInputsM: string[];
}

/** ABI-encodes the five-leg envelope `CkksCreditE3Program.publishInput` takes. */
function encodeFiveLegInput(
  ethers: Ethers,
  f: CreditFixture,
  o?: Partial<Overrides>,
): string {
  // Matches `CreditApplication { GrecoPair logit; GrecoPair mask;
  // bytes appProof; bytes32[] appPub; }` with
  // `GrecoPair { bytes ciphertext; bytes ct0Proof; bytes32[] ct0Pub;
  //              bytes ct1Proof; bytes32[] ct1Pub; }`.
  // Nested dynamic structs are NOT the flat field list: each tuple is
  // encoded head/tail with its own offsets, so the tuple types must be
  // spelled out here exactly as the contract decodes them.
  const grecoPair = "(bytes,bytes,bytes32[],bytes,bytes32[])";
  return ethers.AbiCoder.defaultAbiCoder().encode(
    [`tuple(${grecoPair},${grecoPair},bytes,bytes32[])`],
    [
      [
        [
          f.ciphertextZ,
          o?.ct0ProofZ ?? f.logit.ct0.proof,
          f.logit.ct0.publicInputs,
          o?.ct1ProofZ ?? f.logit.ct1.proof,
          f.logit.ct1.publicInputs,
        ],
        [
          f.ciphertextM,
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

describe("CkksCreditE3Program v2 (two Greco pairs + credit validity, ParamSet 4)", function () {
  let fixture: CreditFixture;
  let outOfRange: OutOfRangeFixture;

  before(function () {
    fixture = JSON.parse(
      readFileSync(join(fixtureDir, "verified_input.json"), "utf-8"),
    ) as CreditFixture;
    outOfRange = JSON.parse(
      readFileSync(join(fixtureDir, "out_of_range_feature.json"), "utf-8"),
    ) as OutOfRangeFixture;
  });

  const root = () => String(fixture.extra.merkleRoot);
  const model = (cap: bigint = BigInt(fixture.cap)) => ({
    cap,
    weights: fixture.modelWords.slice(0, 8),
    bias: fixture.modelWords[8],
  });

  async function deployAll() {
    const { ethers, networkHelpers } = await network.connect();
    await networkHelpers.setBlockGasLimit(HONK_VERIFY_GAS_LIMIT);
    const ct0 = await deployVerifier(
      ethers,
      "UserDataEncryptionCkksCt0Ps4Verifier.sol",
      "UserDataEncryptionCkksCt0Ps4Verifier",
    );
    const ct1 = await deployVerifier(
      ethers,
      "UserDataEncryptionCkksCt1Ps4Verifier.sol",
      "UserDataEncryptionCkksCt1Ps4Verifier",
    );
    const app = await deployVerifier(
      ethers,
      "CkksCreditValidityPs4Verifier.sol",
      "CkksCreditValidityPs4Verifier",
    );
    const { CkksCreditE3Program__factory } = await import("../types");
    const [deployer, bob] = await ethers.getSigners();
    const program = await new CkksCreditE3Program__factory(deployer).deploy(
      await ct0.getAddress(),
      await ct1.getAddress(),
      await app.getAddress(),
    );
    return { ethers, program, alice: deployer, bob };
  }

  /** Registers round 7 with Alice at slot 0 and Bob at slot 1 (the fixture tree order). */
  async function registerDefault(
    program: Awaited<ReturnType<typeof deployAll>>["program"],
    alice: string,
    bob: string,
    opts?: { root?: string; cap?: bigint; applicants?: string[] },
  ) {
    await program.registerRound(
      7n,
      opts?.root ?? root(),
      model(opts?.cap),
      opts?.applicants ?? [alice, bob],
    );
  }

  it("fixture legs are bound: two u commitments, two m commitments, model + index words", function () {
    for (const pair of [fixture.logit, fixture.mask]) {
      expect(pair.ct0.publicInputs).to.have.length(4);
      expect(pair.ct1.publicInputs).to.have.length(3);
      expect(pair.ct0.publicInputs[3]).to.equal(pair.ct1.publicInputs[2]);
    }
    expect(fixture.app.publicInputs).to.have.length(15);
    expect(fixture.logit.ct0.publicInputs[2]).to.equal(fixture.app.publicInputs[13]);
    expect(fixture.mask.ct0.publicInputs[2]).to.equal(fixture.app.publicInputs[14]);
    expect(fixture.app.publicInputs[13]).to.equal(fixture.mCommitmentZ);
    expect(fixture.app.publicInputs[14]).to.equal(fixture.mCommitmentM);
    expect(fixture.mCommitmentZ).to.not.equal(fixture.mCommitmentM);
    expect(fixture.logit.ct0.publicInputs[3]).to.not.equal(fixture.mask.ct0.publicInputs[3]);
    expect(fixture.app.publicInputs[0]).to.equal(word(BigInt(fixture.cap)));
    expect(fixture.app.publicInputs[1]).to.equal(fixture.extra.addressWord);
    expect(fixture.app.publicInputs[2]).to.equal(root());
    expect(fixture.app.publicInputs[3]).to.equal(word(BigInt(fixture.index)));
    expect(fixture.app.publicInputs.slice(4, 13)).to.deep.equal(fixture.modelWords);
    // The mask is applicant-chosen and NEVER a public input; the logit neither.
    expect(fixture.app.publicInputs).to.not.include(word(BigInt(fixture.maskValue)));
    expect(fixture.maskValue).to.equal(529664);
    // `closeTo` is overridden by hardhat's chai matchers to expect BigInt, so
    // compare the float logit numerically instead.
    expect(Math.abs(fixture.logitValue - 0.164)).to.be.lessThan(1e-3);
  });

  it("accepts a genuine application from the registered sender at its slot", async function () {
    const { ethers, program, alice, bob } = await deployAll();
    expect((await alice.getAddress()).toLowerCase()).to.equal(
      String(fixture.extra.address),
    );
    await registerDefault(program, await alice.getAddress(), await bob.getAddress());
    const data = encodeFiveLegInput(ethers, fixture);
    const tx = await program.publishInput(7n, data, {
      gasLimit: HONK_VERIFY_GAS_LIMIT,
    });
    const receipt = await tx.wait();
    const parsed = receipt!.logs
      .map((l: { topics: readonly string[]; data: string }) =>
        program.interface.parseLog(l),
      )
      .find((e: { name: string } | null) => e?.name === "ApplicationPublished");
    expect(parsed, "ApplicationPublished must fire").to.not.be.undefined;
    expect(parsed!.args.applicant).to.equal(await alice.getAddress());
    expect(parsed!.args.index).to.equal(0n);
    expect(parsed!.args.mCommitmentZ).to.equal(fixture.mCommitmentZ);
    expect(parsed!.args.mCommitmentM).to.equal(fixture.mCommitmentM);
    expect(parsed!.args.logitCiphertextHash).to.equal(
      ethers.keccak256(fixture.ciphertextZ),
    );
    expect(parsed!.args.maskCiphertextHash).to.equal(
      ethers.keccak256(fixture.ciphertextM),
    );
    expect(await program.applicationCount(7n)).to.equal(1n);
    const stored = await program.applicationAt(7n, 0n);
    expect(stored.applicant).to.equal(await alice.getAddress());
    expect(stored.index).to.equal(0n);
    expect(stored.uCommitmentZ).to.equal(fixture.logit.ct0.publicInputs[3]);
    expect(stored.uCommitmentM).to.equal(fixture.mask.ct0.publicInputs[3]);
    expect(await program.hasApplied(7n, await alice.getAddress())).to.equal(true);
  });

  it("rejects an application before the round is registered", async function () {
    const { ethers, program } = await deployAll();
    const data = encodeFiveLegInput(ethers, fixture);
    await expect(
      program.publishInput(7n, data, { gasLimit: HONK_VERIFY_GAS_LIMIT }),
    ).to.be.revertedWithCustomError(program, "RoundNotRegistered");
  });

  it("rejects an application proven against a different root (wrong-root)", async function () {
    const { ethers, program, alice, bob } = await deployAll();
    await registerDefault(program, await alice.getAddress(), await bob.getAddress(), {
      root: word(12345n),
    });
    const data = encodeFiveLegInput(ethers, fixture);
    await expect(
      program.publishInput(7n, data, { gasLimit: HONK_VERIFY_GAS_LIMIT }),
    ).to.be.revertedWithCustomError(program, "WrongRoot");
    // Forging the root word in the public inputs breaks the app proof.
    const appPublicInputs = [...fixture.app.publicInputs];
    appPublicInputs[2] = word(12345n);
    const forged = encodeFiveLegInput(ethers, fixture, { appPublicInputs });
    await expect(
      program.publishInput(7n, forged, { gasLimit: HONK_VERIFY_GAS_LIMIT }),
    ).to.be.revertedWithCustomError(program, "AppProofInvalid");
  });

  it("rejects an application relayed by a different sender (wrong-sender)", async function () {
    const { ethers, program, alice, bob } = await deployAll();
    await registerDefault(program, await alice.getAddress(), await bob.getAddress());
    const data = encodeFiveLegInput(ethers, fixture);
    await expect(
      program.connect(bob).publishInput(7n, data, { gasLimit: HONK_VERIFY_GAS_LIMIT }),
    ).to.be.revertedWithCustomError(program, "WrongSender");
    // Bob cannot relabel Alice's proof with his own address either: the
    // address is a public input of the credit circuit.
    const appPublicInputs = [...fixture.app.publicInputs];
    appPublicInputs[1] = word(BigInt(await bob.getAddress()));
    appPublicInputs[3] = word(1n);
    const relabeled = encodeFiveLegInput(ethers, fixture, { appPublicInputs });
    await expect(
      program
        .connect(bob)
        .publishInput(7n, relabeled, { gasLimit: HONK_VERIFY_GAS_LIMIT }),
    ).to.be.revertedWithCustomError(program, "AppProofInvalid");
  });

  it("rejects a wrong slot index (registered position) and an unregistered sender", async function () {
    const { ethers, program, alice, bob } = await deployAll();
    // Alice registered at slot 1 (Bob first): her proof carries index 0.
    await registerDefault(program, await alice.getAddress(), await bob.getAddress(), {
      applicants: [await bob.getAddress(), await alice.getAddress()],
    });
    const data = encodeFiveLegInput(ethers, fixture);
    await expect(
      program.publishInput(7n, data, { gasLimit: HONK_VERIFY_GAS_LIMIT }),
    ).to.be.revertedWithCustomError(program, "WrongIndex");
    // Forging the index word breaks the app proof (the slot is what the
    // encoding is checked at).
    const appPublicInputs = [...fixture.app.publicInputs];
    appPublicInputs[3] = word(1n);
    const forged = encodeFiveLegInput(ethers, fixture, { appPublicInputs });
    await expect(
      program.publishInput(7n, forged, { gasLimit: HONK_VERIFY_GAS_LIMIT }),
    ).to.be.revertedWithCustomError(program, "AppProofInvalid");
    // Not registered at all.
    const { ethers: e2, program: p2, alice: a2, bob: b2 } = await deployAll();
    await registerDefault(p2, await a2.getAddress(), await b2.getAddress(), {
      applicants: [await b2.getAddress()],
    });
    await expect(
      p2.publishInput(7n, encodeFiveLegInput(e2, fixture), {
        gasLimit: HONK_VERIFY_GAS_LIMIT,
      }),
    ).to.be.revertedWithCustomError(p2, "NotRegistered");
  });

  it("rejects a wrong model (registered weights / bias / cap differ)", async function () {
    const { ethers, program, alice, bob } = await deployAll();
    const m = model();
    const weights = [...m.weights];
    weights[1] = word(BigInt(weights[1]) + 1n);
    await program.registerRound(7n, root(), { ...m, weights }, [
      await alice.getAddress(),
      await bob.getAddress(),
    ]);
    const data = encodeFiveLegInput(ethers, fixture);
    await expect(
      program.publishInput(7n, data, { gasLimit: HONK_VERIFY_GAS_LIMIT }),
    ).to.be.revertedWithCustomError(program, "WrongModel");
    // Wrong cap.
    const { ethers: e2, program: p2, alice: a2, bob: b2 } = await deployAll();
    await registerDefault(p2, await a2.getAddress(), await b2.getAddress(), { cap: 500n });
    await expect(
      p2.publishInput(7n, encodeFiveLegInput(e2, fixture), {
        gasLimit: HONK_VERIFY_GAS_LIMIT,
      }),
    ).to.be.revertedWithCustomError(p2, "WrongCap");
    // Forging the model word in the proof's public inputs breaks the proof.
    const { ethers: e3, program: p3, alice: a3, bob: b3 } = await deployAll();
    await p3.registerRound(7n, root(), { ...m, weights }, [
      await a3.getAddress(),
      await b3.getAddress(),
    ]);
    const appPublicInputs = [...fixture.app.publicInputs];
    appPublicInputs[5] = weights[1];
    await expect(
      p3.publishInput(7n, encodeFiveLegInput(e3, fixture, { appPublicInputs }), {
        gasLimit: HONK_VERIFY_GAS_LIMIT,
      }),
    ).to.be.revertedWithCustomError(p3, "AppProofInvalid");
  });

  it("rejects each tampered leg", async function () {
    const { ethers, program, alice, bob } = await deployAll();
    await registerDefault(program, await alice.getAddress(), await bob.getAddress());
    for (const [key, error, proof] of [
      ["ct0ProofZ", "Ct0ProofInvalid", fixture.logit.ct0.proof],
      ["ct1ProofZ", "Ct1ProofInvalid", fixture.logit.ct1.proof],
      ["ct0ProofM", "Ct0ProofInvalid", fixture.mask.ct0.proof],
      ["ct1ProofM", "Ct1ProofInvalid", fixture.mask.ct1.proof],
      ["appProof", "AppProofInvalid", fixture.app.proof],
    ] as const) {
      const data = encodeFiveLegInput(ethers, fixture, {
        [key]: tamperProof(proof),
      });
      await expect(
        program.publishInput(7n, data, { gasLimit: HONK_VERIFY_GAS_LIMIT }),
        key,
      ).to.be.revertedWithCustomError(program, error);
    }
  });

  it("rejects a cross-leg m_commitment mismatch on either ciphertext", async function () {
    const { ethers, program, alice, bob } = await deployAll();
    await registerDefault(program, await alice.getAddress(), await bob.getAddress());
    // Validity leg's m_commitment_z replaced by another word.
    const appPublicInputs = [...fixture.app.publicInputs];
    appPublicInputs[13] = fixture.logit.ct0.publicInputs[1];
    await expect(
      program.publishInput(7n, encodeFiveLegInput(ethers, fixture, { appPublicInputs }), {
        gasLimit: HONK_VERIFY_GAS_LIMIT,
      }),
    ).to.be.revertedWithCustomError(program, "MCommitmentMismatch");
    // The mask pair's ct0 leg swapped for the logit pair's (same u across
    // the two ciphertexts = the mask ct0 m_commitment no longer matches).
    await expect(
      program.publishInput(
        7n,
        encodeFiveLegInput(ethers, fixture, {
          ct0PublicInputsM: fixture.logit.ct0.publicInputs,
        }),
        { gasLimit: HONK_VERIFY_GAS_LIMIT },
      ),
    ).to.be.revertedWithCustomError(program, "UCommitmentMismatch");
  });

  it("rejects a duplicate application (same sender / same u commitments)", async function () {
    const { ethers, program, alice, bob } = await deployAll();
    await registerDefault(program, await alice.getAddress(), await bob.getAddress());
    const data = encodeFiveLegInput(ethers, fixture);
    await program.publishInput(7n, data, { gasLimit: HONK_VERIFY_GAS_LIMIT });
    await expect(
      program.publishInput(7n, data, { gasLimit: HONK_VERIFY_GAS_LIMIT }),
    ).to.be.revertedWithCustomError(program, "AlreadyApplied");
  });

  it("an out-of-range feature has no proof: the circuit rejects it at proving time", async function () {
    // The proving-failure fixture: x_3 = cap + 1 attested by an issuer
    // leaf. `nargo execute` fails in the circuit's range check, so the
    // applicant has no app proof. Relaying the genuine proof under that
    // application's public inputs (its root) cannot pass the verifier.
    expect(outOfRange.features[3]).to.equal(outOfRange.cap + 1);
    expect(outOfRange.nargoExecute.exitCode).to.equal(1);
    expect(outOfRange.nargoExecute.failedAssertion).to.contain("assert_cap_range");
    const { ethers, program, alice, bob } = await deployAll();
    await registerDefault(program, await alice.getAddress(), await bob.getAddress(), {
      root: outOfRange.appPublicInputs[2],
    });
    const appPublicInputs = [...outOfRange.appPublicInputs];
    // Keep the genuine legs' m_commitments so the ONLY thing failing is
    // the app proof itself.
    appPublicInputs[13] = fixture.app.publicInputs[13];
    appPublicInputs[14] = fixture.app.publicInputs[14];
    const data = encodeFiveLegInput(ethers, fixture, { appPublicInputs });
    await expect(
      program.publishInput(7n, data, { gasLimit: HONK_VERIFY_GAS_LIMIT }),
    ).to.be.revertedWithCustomError(program, "AppProofInvalid");
  });

  it("only the owner registers a round, once, with a valid root/cap/list", async function () {
    const { program, alice, bob } = await deployAll();
    const a = await alice.getAddress();
    const b = await bob.getAddress();
    await expect(
      program.connect(bob).registerRound(7n, root(), model(), [a, b]),
    ).to.be.revertedWithCustomError(program, "NotOwner");
    await expect(
      program.registerRound(7n, word(0n), model(), [a, b]),
    ).to.be.revertedWithCustomError(program, "InvalidRoot");
    await expect(
      program.registerRound(7n, root(), model(0n), [a, b]),
    ).to.be.revertedWithCustomError(program, "InvalidCap");
    await expect(
      program.registerRound(7n, root(), model(), []),
    ).to.be.revertedWithCustomError(program, "NoApplicants");
    await expect(
      program.registerRound(7n, root(), model(), [a, a]),
    ).to.be.revertedWithCustomError(program, "DuplicateApplicant");
    await program.registerRound(7n, root(), model(), [a, b]);
    await expect(
      program.registerRound(7n, root(), model(), [a, b]),
    ).to.be.revertedWithCustomError(program, "RoundAlreadyRegistered");
    expect(await program.applicants(7n)).to.deep.equal([a, b]);
    expect(await program.applicantSlot(7n, b)).to.equal(2n);
    const stored = await program.model(7n);
    expect(stored.cap).to.equal(BigInt(fixture.cap));
    expect(stored.bias).to.equal(fixture.modelWords[8]);
  });
});
