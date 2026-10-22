// SPDX-License-Identifier: LGPL-3.0-only
import { expect } from "chai";
import { readFileSync } from "node:fs";

import { CIRCUIT_DIMENSIONS, COMMITTEES } from "../bfv.js";
import { ethers } from "./fixtures/connection";

const fixture = JSON.parse(
  readFileSync(
    new URL(
      "../../../crates/fhe-params/tests/fixtures/bfv_protocol.json",
      import.meta.url,
    ),
    "utf8",
  ),
);

describe("BFV protocol bindings", function () {
  it("preserves the independently frozen protocol identities in Solidity", async function () {
    const harness = await (
      await ethers.getContractFactory("BfvProtocolHarness")
    ).deploy();
    for (const vector of fixture.vectors.filter(
      (vector: { preset: string | null }) => vector.preset !== null,
    )) {
      expect(await harness.identity(vector.paramSet)).to.deep.equal([
        fixture.encryptionSchemeId,
        ethers.id(vector.circuitVersion),
        vector.parameterHash,
        vector.cryptoConfigId,
      ]);
    }
    await expect(harness.identity(1)).to.be.revertedWithCustomError(
      harness,
      "UnsupportedCryptoConfig",
    );
    await expect(harness.identity(255)).to.be.revertedWithCustomError(
      harness,
      "UnsupportedCryptoConfig",
    );
  });

  it("shares committee ordering and circuit dimensions without changing policy errors", async function () {
    const harness = await (
      await ethers.getContractFactory("BfvProtocolHarness")
    ).deploy();
    for (const committee of Object.values(COMMITTEES)) {
      expect(await harness.committee(committee.committeeSize)).to.deep.equal([
        BigInt(committee.t),
        BigInt(committee.h),
        BigInt(committee.n),
      ]);
    }
    await expect(harness.committee(255)).to.be.revertedWithCustomError(
      harness,
      "UnsupportedCryptoConfig",
    );
    expect(await harness.dimensions()).to.deep.equal([
      BigInt(CIRCUIT_DIMENSIONS.messageCoeffsCount),
      BigInt(CIRCUIT_DIMENSIONS.messageCoeffByteLen),
      BigInt(CIRCUIT_DIMENSIONS.fieldByteLen),
      BigInt(CIRCUIT_DIMENSIONS.plaintextByteLen),
    ]);
  });
});
