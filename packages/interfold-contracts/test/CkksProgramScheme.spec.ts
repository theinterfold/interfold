// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
import { expect } from "chai";

import {
  deployInterfoldSystem,
  ethers,
  makeRequest,
  networkHelpers,
} from "./fixtures";

const { loadFixture } = networkHelpers;

/**
 * Program-address => protocol mapping: the E3 program IS the scheme
 * selector. Requesting through a CKKS program binds
 * keccak256("fhe.rs:CKKS") — a requester only chooses committee size and
 * paramSet; the scheme follows from the program address, and the node's
 * EVM reader dispatches on the id carried in the E3 struct.
 */
describe("CKKS program => protocol mapping", function () {
  const CKKS_SCHEME_ID = ethers.keccak256(ethers.toUtf8Bytes("fhe.rs:CKKS"));
  const BFV_SCHEME_ID = ethers.keccak256(ethers.toUtf8Bytes("fhe.rs:BFV"));

  async function setup() {
    const sys = await deployInterfoldSystem();
    const { interfold, owner } = sys;

    // Deploy + register the CKKS program (the program ADDRESS keys the
    // scheme — "0x12 => ckks, 0x13 => bfv" in spirit).
    const ckksProgram = await ethers.deployContract("MockCkksE3Program");
    await ckksProgram.waitForDeployment();
    await interfold.connect(owner).registerE3Program(ckksProgram);

    // CKKS verifiers for the scheme id (mock level, mirroring how BFV's
    // were staged; a DecryptionAggregator-keyed verifier follows the
    // recursive-aggregation work).
    const ckksDecryptionVerifier = await ethers.deployContract(
      "MockDecryptionVerifier",
    );
    await ckksDecryptionVerifier.waitForDeployment();
    await interfold
      .connect(owner)
      .setDecryptionVerifier(CKKS_SCHEME_ID, ckksDecryptionVerifier);
    await interfold
      .connect(owner)
      .setPkVerifier(CKKS_SCHEME_ID, await sys.mocks.pkVerifier.getAddress());
    await interfold
      .connect(owner)
      .setCiphertextVerifier(
        CKKS_SCHEME_ID,
        await sys.mocks.ciphertextVerifier.getAddress(),
      );

    return { ...sys, ckksProgram, ckksDecryptionVerifier };
  }

  it("requesting through the CKKS program binds the CKKS scheme id", async function () {
    const sys = await loadFixture(setup);
    const { interfold, usdcToken, request, ckksProgram } = sys;

    // Same request params as BFV — only the program address changes.
    const tx = await makeRequest(interfold, usdcToken, {
      ...request,
      e3Program: await ckksProgram.getAddress(),
    });
    await tx.wait();

    const e3Id = (await interfold.nexte3Id()) - 1n;
    const e3 = await interfold.getE3(e3Id);
    expect(e3.encryptionSchemeId).to.equal(CKKS_SCHEME_ID);
    expect(e3.e3Program).to.equal(await ckksProgram.getAddress());
    expect(e3.decryptionVerifier).to.equal(
      await sys.ckksDecryptionVerifier.getAddress(),
    );

    // And the BFV program still binds BFV — the two coexist.
    const tx2 = await makeRequest(interfold, usdcToken, request);
    await tx2.wait();
    const bfvE3 = await interfold.getE3((await interfold.nexte3Id()) - 1n);
    expect(bfvE3.encryptionSchemeId).to.equal(BFV_SCHEME_ID);
    expect(bfvE3.decryptionVerifier).to.not.equal(
      await sys.ckksDecryptionVerifier.getAddress(),
    );
  });

  it("CKKS request reverts when no verifier is registered for the scheme", async function () {
    const sys = await deployInterfoldSystem();
    const { interfold, owner, usdcToken, request } = sys;

    const ckksProgram = await ethers.deployContract("MockCkksE3Program");
    await ckksProgram.waitForDeployment();
    await interfold.connect(owner).registerE3Program(ckksProgram);
    // Deliberately NO setDecryptionVerifier(CKKS_SCHEME_ID, ...).
    // The config gate now admits CKKS, so the request must fail at the
    // NEXT gate: the ciphertext-verifier registry lookup inside
    // `bindCryptoConfig` (InvalidEncryptionScheme) — an admitted scheme
    // with no verifiers still cannot be requested.
    await expect(
      makeRequest(interfold, usdcToken, {
        ...request,
        e3Program: await ckksProgram.getAddress(),
      }),
    ).to.be.revertedWithCustomError(interfold, "InvalidEncryptionScheme");
  });
});
