// SPDX-License-Identifier: LGPL-3.0-only
import { expect } from "chai";
import { readFileSync } from "node:fs";

import {
  CIRCUIT_DIMENSIONS,
  COMMITTEES,
  decryptionAggregatorLayout,
} from "../bfv.js";
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
  it("shares the frozen decryption layout across Solidity and TypeScript", async function () {
    const harness = await (
      await ethers.getContractFactory("BfvProtocolHarness")
    ).deploy();
    for (const [threshold, expected] of [
      [1, [8, 10, 12, 14, 64]],
      [4, [8, 13, 18, 23, 73]],
      [9, [8, 18, 28, 38, 88]],
      [2, [8, 11, 14, 17, 67]],
    ] as const) {
      expect(await harness.layout(threshold)).to.deep.equal(
        expected.map(BigInt),
      );
      const layout = decryptionAggregatorLayout(threshold);
      expect([
        layout.partyIdOffset,
        layout.skOffset,
        layout.esmOffset,
        layout.messageOffset,
        layout.publicInputsLength,
      ]).to.deep.equal(expected);
    }
  });

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
