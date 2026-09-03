// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

/**
 * CkksAuctionE3Program: three-leg gate (Greco ct0 + ct1 + auction
 * validity with Merkle-attested balance) on ParamSet 2, driven by a REAL
 * fixture (bid 700, cap 1, Alice = hardhat account #0 with balance 800
 * under a two-leaf tree {Alice: 800, Bob: 300}).
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
  "ckks_auction_ps2",
  "verified_input.json",
);

describe("CkksAuctionE3Program (Greco + Merkle-balance bid validity, ParamSet 2)", function () {
  let fixture: AppFixture;

  before(function () {
    fixture = JSON.parse(readFileSync(fixturePath, "utf-8")) as AppFixture;
  });

  async function deployAll(cap: bigint = BigInt(fixture.cap)) {
    const { ethers, networkHelpers } = await network.connect();
    await networkHelpers.setBlockGasLimit(HONK_VERIFY_GAS_LIMIT);
    const ct0 = await deployVerifier(
      ethers,
      "UserDataEncryptionCkksCt0Ps2Verifier.sol",
      "UserDataEncryptionCkksCt0Ps2Verifier",
    );
    const ct1 = await deployVerifier(
      ethers,
      "UserDataEncryptionCkksCt1Ps2Verifier.sol",
      "UserDataEncryptionCkksCt1Ps2Verifier",
    );
    const app = await deployVerifier(
      ethers,
      "CkksAuctionValidityPs2Verifier.sol",
      "CkksAuctionValidityPs2Verifier",
    );
    const { CkksAuctionE3Program__factory } = await import("../types");
    const [deployer] = await ethers.getSigners();
    const program = await new CkksAuctionE3Program__factory(deployer).deploy(
      await ct0.getAddress(),
      await ct1.getAddress(),
      await app.getAddress(),
      cap,
    );
    return { ethers, program };
  }

  const root = () => String(fixture.extra.merkleRoot);

  it("fixture legs are bound and carry Alice + the root", function () {
    expect(fixture.ct0.publicInputs[3]).to.equal(fixture.ct1.publicInputs[2]);
    expect(fixture.ct0.publicInputs[2]).to.equal(fixture.app.publicInputs[3]);
    expect(fixture.app.publicInputs[0]).to.equal(word(BigInt(fixture.cap)));
    expect(fixture.app.publicInputs[1]).to.equal(fixture.extra.addressWord);
    expect(fixture.app.publicInputs[2]).to.equal(root());
  });

  it("accepts a genuine bid from the attested sender under the set root", async function () {
    const { ethers, program } = await deployAll();
    const [alice] = await ethers.getSigners();
    expect((await alice.getAddress()).toLowerCase()).to.equal(
      String(fixture.extra.address),
    );
    await program.setBalanceRoot(7n, root());
    const data = encodeThreeLegInput(ethers, fixture);
    const tx = await program.publishInput(7n, data, {
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
    expect(parsed!.args.publisher).to.equal(await alice.getAddress());
    expect(parsed!.args.mCommitment).to.equal(fixture.mCommitment);
    expect(await program.submissionCount(7n)).to.equal(1n);
  });

  it("rejects a bid before the balance root is set", async function () {
    const { ethers, program } = await deployAll();
    const data = encodeThreeLegInput(ethers, fixture);
    await expect(
      program.publishInput(7n, data, { gasLimit: HONK_VERIFY_GAS_LIMIT }),
    ).to.be.revertedWithCustomError(program, "RootNotSet");
  });

  it("rejects a bid proven against a different root", async function () {
    const { ethers, program } = await deployAll();
    await program.setBalanceRoot(7n, word(12345n));
    const data = encodeThreeLegInput(ethers, fixture);
    await expect(
      program.publishInput(7n, data, { gasLimit: HONK_VERIFY_GAS_LIMIT }),
    ).to.be.revertedWithCustomError(program, "WrongRoot");
    // Forging the root word in the public inputs breaks the app proof.
    const appPublicInputs = [...fixture.app.publicInputs];
    appPublicInputs[2] = word(12345n);
    const forged = encodeThreeLegInput(ethers, fixture, { appPublicInputs });
    await expect(
      program.publishInput(7n, forged, { gasLimit: HONK_VERIFY_GAS_LIMIT }),
    ).to.be.revertedWithCustomError(program, "AppProofInvalid");
  });

  it("rejects a bid relayed by a different sender (wrong-sender)", async function () {
    const { ethers, program } = await deployAll();
    const [, bob] = await ethers.getSigners();
    await program.setBalanceRoot(7n, root());
    const data = encodeThreeLegInput(ethers, fixture);
    await expect(
      program
        .connect(bob)
        .publishInput(7n, data, { gasLimit: HONK_VERIFY_GAS_LIMIT }),
    ).to.be.revertedWithCustomError(program, "WrongSender");
    // Bob cannot simply relabel Alice's proof with his own address either:
    // the address is a public input of the app circuit.
    const appPublicInputs = [...fixture.app.publicInputs];
    appPublicInputs[1] = word(BigInt(await bob.getAddress()));
    const relabeled = encodeThreeLegInput(ethers, fixture, { appPublicInputs });
    await expect(
      program
        .connect(bob)
        .publishInput(7n, relabeled, { gasLimit: HONK_VERIFY_GAS_LIMIT }),
    ).to.be.revertedWithCustomError(program, "AppProofInvalid");
  });

  it("rejects each tampered leg", async function () {
    const { ethers, program } = await deployAll();
    await program.setBalanceRoot(7n, root());
    for (const [key, error] of [
      ["ct0Proof", "Ct0ProofInvalid"],
      ["ct1Proof", "Ct1ProofInvalid"],
      ["appProof", "AppProofInvalid"],
    ] as const) {
      const leg =
        key === "ct0Proof" ? "ct0" : key === "ct1Proof" ? "ct1" : "app";
      const data = encodeThreeLegInput(ethers, fixture, {
        [key]: tamperProof(fixture[leg].proof),
      });
      await expect(
        program.publishInput(7n, data, { gasLimit: HONK_VERIFY_GAS_LIMIT }),
        error,
      ).to.be.revertedWithCustomError(program, error);
    }
  });

  it("rejects an app leg whose m_commitment differs from the ct0 leg", async function () {
    const { ethers, program } = await deployAll();
    await program.setBalanceRoot(7n, root());
    const appPublicInputs = [...fixture.app.publicInputs];
    appPublicInputs[3] = fixture.ct0.publicInputs[1];
    const data = encodeThreeLegInput(ethers, fixture, { appPublicInputs });
    await expect(
      program.publishInput(7n, data, { gasLimit: HONK_VERIFY_GAS_LIMIT }),
    ).to.be.revertedWithCustomError(program, "MCommitmentMismatch");
  });

  it("rejects a wrong cap", async function () {
    const { ethers, program } = await deployAll(1000n);
    await program.setBalanceRoot(7n, root());
    const data = encodeThreeLegInput(ethers, fixture);
    await expect(
      program.publishInput(7n, data, { gasLimit: HONK_VERIFY_GAS_LIMIT }),
    ).to.be.revertedWithCustomError(program, "WrongCap");
  });

  it("rejects a duplicate bid (same u commitment)", async function () {
    const { ethers, program } = await deployAll();
    await program.setBalanceRoot(7n, root());
    const data = encodeThreeLegInput(ethers, fixture);
    await program.publishInput(7n, data, { gasLimit: HONK_VERIFY_GAS_LIMIT });
    await expect(
      program.publishInput(7n, data, { gasLimit: HONK_VERIFY_GAS_LIMIT }),
    ).to.be.revertedWithCustomError(program, "DuplicateSubmission");
  });

  it("only the owner sets a root, once", async function () {
    const { ethers, program } = await deployAll();
    const [, bob] = await ethers.getSigners();
    await expect(
      program.connect(bob).setBalanceRoot(7n, root()),
    ).to.be.revertedWithCustomError(program, "NotOwner");
    await program.setBalanceRoot(7n, root());
    await expect(
      program.setBalanceRoot(7n, root()),
    ).to.be.revertedWithCustomError(program, "RootAlreadySet");
  });
});
