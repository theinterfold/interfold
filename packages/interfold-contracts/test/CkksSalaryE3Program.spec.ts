// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

/**
 * CkksSalaryE3Program: three-leg gate (Greco ct0 + ct1 + salary validity)
 * on ParamSet 3, driven by a REAL fixture (salary 52000 over cap 100000,
 * slot-replicated).
 */
import { expect } from "chai";
import { readFileSync } from "fs";
import { network } from "hardhat";
import { dirname, join } from "path";
import { fileURLToPath } from "url";

import type { AppFixture } from "./helpers/ckksApp";
import {
  HONK_VERIFY_GAS_LIMIT,
  deployVerifier,
  encodeThreeLegInput,
  tamperProof,
  word,
} from "./helpers/ckksApp";

const fixturePath = join(
  dirname(fileURLToPath(import.meta.url)),
  "fixtures",
  "ckks_salary_ps3",
  "verified_input.json",
);

describe("CkksSalaryE3Program (Greco + salary-range validity, ParamSet 3)", function () {
  let fixture: AppFixture;

  before(function () {
    fixture = JSON.parse(readFileSync(fixturePath, "utf-8")) as AppFixture;
  });

  async function deployAll(cap: bigint = BigInt(fixture.cap)) {
    const { ethers, networkHelpers } = await network.connect();
    await networkHelpers.setBlockGasLimit(HONK_VERIFY_GAS_LIMIT);
    const ct0 = await deployVerifier(
      ethers,
      "UserDataEncryptionCkksCt0Ps3Verifier.sol",
      "UserDataEncryptionCkksCt0Ps3Verifier",
    );
    const ct1 = await deployVerifier(
      ethers,
      "UserDataEncryptionCkksCt1Ps3Verifier.sol",
      "UserDataEncryptionCkksCt1Ps3Verifier",
    );
    const app = await deployVerifier(
      ethers,
      "CkksSalaryValidityPs3Verifier.sol",
      "CkksSalaryValidityPs3Verifier",
    );
    const program = await (
      await ethers.getContractFactory("CkksSalaryE3Program")
    ).deploy(
      await ct0.getAddress(),
      await ct1.getAddress(),
      await app.getAddress(),
      cap,
    );
    return { ethers, program };
  }

  it("fixture legs are bound (u across ct0/ct1, m across ct0/app)", function () {
    expect(fixture.ct0.publicInputs[3]).to.equal(fixture.ct1.publicInputs[2]);
    expect(fixture.ct0.publicInputs[2]).to.equal(fixture.app.publicInputs[1]);
    expect(fixture.app.publicInputs[1]).to.equal(fixture.mCommitment);
    expect(fixture.app.publicInputs[0]).to.equal(word(BigInt(fixture.cap)));
  });

  it("accepts a genuine submission and records it", async function () {
    const { ethers, program } = await deployAll();
    const [signer] = await ethers.getSigners();
    const data = encodeThreeLegInput(ethers, fixture);
    const tx = await program.publishInput(1n, data, {
      gasLimit: HONK_VERIFY_GAS_LIMIT,
    });
    const receipt = await tx.wait();
    const parsed = receipt!.logs
      .map((l: { topics: readonly string[]; data: string }) =>
        program.interface.parseLog(l),
      )
      .find(
        (e: { name: string } | null) => e?.name === "VerifiedInputPublished",
      );
    expect(parsed, "VerifiedInputPublished must fire").to.not.be.undefined;
    expect(parsed!.args.mCommitment).to.equal(fixture.mCommitment);
    expect(parsed!.args.uCommitment).to.equal(fixture.ct0.publicInputs[3]);
    expect(parsed!.args.ciphertextHash).to.equal(
      ethers.keccak256(fixture.ciphertext),
    );
    expect(await program.submissionCount(1n)).to.equal(1n);
    const stored = await program.submissionAt(1n, 0n);
    expect(stored.publisher).to.equal(await signer.getAddress());
    expect(stored.mCommitment).to.equal(fixture.mCommitment);
  });

  it("rejects a tampered ct0 proof", async function () {
    const { ethers, program } = await deployAll();
    const data = encodeThreeLegInput(ethers, fixture, {
      ct0Proof: tamperProof(fixture.ct0.proof),
    });
    await expect(
      program.publishInput(1n, data, { gasLimit: HONK_VERIFY_GAS_LIMIT }),
    ).to.be.revertedWithCustomError(program, "Ct0ProofInvalid");
  });

  it("rejects a tampered ct1 proof", async function () {
    const { ethers, program } = await deployAll();
    const data = encodeThreeLegInput(ethers, fixture, {
      ct1Proof: tamperProof(fixture.ct1.proof),
    });
    await expect(
      program.publishInput(1n, data, { gasLimit: HONK_VERIFY_GAS_LIMIT }),
    ).to.be.revertedWithCustomError(program, "Ct1ProofInvalid");
  });

  it("rejects a tampered app proof", async function () {
    const { ethers, program } = await deployAll();
    const data = encodeThreeLegInput(ethers, fixture, {
      appProof: tamperProof(fixture.app.proof),
    });
    await expect(
      program.publishInput(1n, data, { gasLimit: HONK_VERIFY_GAS_LIMIT }),
    ).to.be.revertedWithCustomError(program, "AppProofInvalid");
  });

  it("rejects an app leg whose m_commitment differs from the ct0 leg", async function () {
    const { ethers, program } = await deployAll();
    const appPublicInputs = [...fixture.app.publicInputs];
    appPublicInputs[1] = fixture.ct0.publicInputs[1]; // some other word
    const data = encodeThreeLegInput(ethers, fixture, { appPublicInputs });
    await expect(
      program.publishInput(1n, data, { gasLimit: HONK_VERIFY_GAS_LIMIT }),
    ).to.be.revertedWithCustomError(program, "MCommitmentMismatch");
  });

  it("rejects a submission against a different cap (over-cap posture)", async function () {
    // A salary proven against cap 100000 cannot be replayed as a fraction
    // of a smaller cap: the program pins the cap it was deployed with.
    const { ethers, program } = await deployAll(50_000n);
    const data = encodeThreeLegInput(ethers, fixture);
    await expect(
      program.publishInput(1n, data, { gasLimit: HONK_VERIFY_GAS_LIMIT }),
    ).to.be.revertedWithCustomError(program, "WrongCap");
    // And forging the cap word makes the app proof fail (cap is a public
    // input of the app circuit).
    const appPublicInputs = [...fixture.app.publicInputs];
    appPublicInputs[0] = word(50_000n);
    const forged = encodeThreeLegInput(ethers, fixture, { appPublicInputs });
    await expect(
      program.publishInput(1n, forged, { gasLimit: HONK_VERIFY_GAS_LIMIT }),
    ).to.be.revertedWithCustomError(program, "AppProofInvalid");
  });

  it("rejects a duplicate submission (same u commitment)", async function () {
    const { ethers, program } = await deployAll();
    const data = encodeThreeLegInput(ethers, fixture);
    await program.publishInput(1n, data, { gasLimit: HONK_VERIFY_GAS_LIMIT });
    await expect(
      program.publishInput(1n, data, { gasLimit: HONK_VERIFY_GAS_LIMIT }),
    ).to.be.revertedWithCustomError(program, "DuplicateSubmission");
  });

  it("rejects wrong public-input counts", async function () {
    const { ethers, program } = await deployAll();
    const data = encodeThreeLegInput(ethers, fixture, {
      appPublicInputs: [fixture.app.publicInputs[1]],
    });
    await expect(
      program.publishInput(1n, data, { gasLimit: HONK_VERIFY_GAS_LIMIT }),
    ).to.be.revertedWithCustomError(program, "WrongPublicInputCount");
  });
});
