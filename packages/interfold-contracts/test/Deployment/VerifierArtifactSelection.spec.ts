// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
import { expect } from "chai";

import { selectCanonicalVerifierFqn } from "../../scripts/deployAndSave/verifiers";

describe("verifier artifact selection", function () {
  const contractName = "DkgAggregatorVerifier";
  const source = `contracts/verifiers/bfv/honk/${contractName}.sol:${contractName}`;

  it("selects the canonical verifier when preset artifacts have the same name", function () {
    expect(
      selectCanonicalVerifierFqn(
        [
          `project/${source}`,
          `project/contracts/verifiers/bfv/honk/insecure/micro/${contractName}.sol:${contractName}`,
          `project/contracts/verifiers/bfv/honk/secure-8192/small/${contractName}.sol:${contractName}`,
        ],
        contractName,
      ),
    ).to.equal(source);
  });

  it("normalizes the canonical verifier from the package artifact namespace", function () {
    expect(
      selectCanonicalVerifierFqn(
        [
          `npm/@interfold/contracts@1.2.3/${source}`,
          `npm/@interfold/contracts@1.2.3/contracts/verifiers/bfv/honk/secure-8192/minimum/${contractName}.sol:${contractName}`,
        ],
        contractName,
      ),
    ).to.equal(`@interfold/contracts/${source}`);
  });

  it("rejects an artifact set without the canonical verifier", function () {
    expect(() =>
      selectCanonicalVerifierFqn(
        [
          `project/contracts/verifiers/bfv/honk/insecure/micro/${contractName}.sol:${contractName}`,
        ],
        contractName,
      ),
    ).to.throw(
      `Expected one canonical artifact for ${contractName} in contracts/verifiers/bfv/honk, found 0.`,
    );
  });
});
