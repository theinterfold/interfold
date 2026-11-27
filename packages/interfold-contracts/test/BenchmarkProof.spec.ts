// SPDX-License-Identifier: LGPL-3.0-only
import { expect } from "chai";
import { AbiCoder } from "ethers";

import { decodeBenchmarkProof } from "../scripts/benchmarkProof";

describe("Saved benchmark proof calldata", function () {
  const fields = [`0x00${"ab".repeat(31)}`, `0x${"cd".repeat(31)}ef`];
  const inputs = fields.map((field) => field.slice(2)).join("");

  it("preserves every byte with or without prefixes", function () {
    const abi = AbiCoder.defaultAbiCoder();
    const types = ["bytes", "bytes32[]"];
    const expected = abi.encode(types, ["0x00ab", fields]);
    for (const proofHex of ["0x00ab", "00AB"]) {
      for (const inputHex of [`0x${inputs}`, inputs.toUpperCase()]) {
        const decoded = decodeBenchmarkProof(proofHex, inputHex);
        expect(abi.encode(types, [decoded.proof, decoded.fields])).to.equal(
          expected,
        );
      }
    }
  });

  it("rejects empty, partial and malformed fields before encoding", function () {
    for (const invalid of [
      "",
      "0x",
      inputs.slice(1),
      `${inputs}00`,
      `zz${inputs.slice(2)}`,
    ])
      expect(() => decodeBenchmarkProof("ab", invalid)).to.throw();
    for (const invalid of ["", "0x", "a", "0xgg"])
      expect(() => decodeBenchmarkProof(invalid, inputs)).to.throw();
  });
});
