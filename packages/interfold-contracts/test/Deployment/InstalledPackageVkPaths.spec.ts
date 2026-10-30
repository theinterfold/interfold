// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
import { expect } from "chai";
import fs from "fs";
import { mock } from "node:test";
import path from "path";

import {
  SECURE_16384_MICRO_BFV_CONFIG,
  SECURE_16384_MINIMUM_BFV_CONFIG,
  SECURE_16384_SMALL_BFV_CONFIG,
  bfvConfigsForChain,
  bfvHonkSource,
  bfvPkV2PublicInputLayout,
  getBfvDecryptionSubCircuitVkHashPaths,
  getBfvPkSubCircuitVkHashPaths,
  getBfvPkVkBindingHashPaths,
  getBfvV2SubCircuitVkHashPaths,
  getBfvV2VkBindingHashPaths,
} from "../../scripts/utils";

describe("installed-package BFV VK paths", function () {
  const previous = process.env.INTERFOLD_CIRCUITS_DIR;
  const release = path.resolve("release-circuits");

  beforeEach(function () {
    // Model an installed package: no ancestor has the monorepo package marker.
    mock.method(fs, "existsSync", () => false);
    process.env.INTERFOLD_CIRCUITS_DIR = release;
  });

  afterEach(function () {
    mock.restoreAll();
    if (previous === undefined) delete process.env.INTERFOLD_CIRCUITS_DIR;
    else process.env.INTERFOLD_CIRCUITS_DIR = previous;
  });

  it("uses the active insecure pair without requiring a checkout", function () {
    expect(getBfvPkSubCircuitVkHashPaths().nodesFold).to.equal(
      path.join(
        release,
        "insecure-64/minimum/default/recursive_aggregation/nodes_fold/nodes_fold.vk_tree_hash",
      ),
    );
  });

  it("resolves every independent l-BFV manifest under the selected release pair", function () {
    const config = SECURE_16384_MINIMUM_BFV_CONFIG;
    const prefix = path.join(release, "secure-16384/minimum") + path.sep;
    const legacy = getBfvPkVkBindingHashPaths(config);
    const v2 = getBfvV2VkBindingHashPaths(config);
    expect(legacy).to.have.length(15);
    expect(v2).to.have.length(11);
    for (const file of [
      ...legacy,
      ...v2,
      ...Object.values(getBfvV2SubCircuitVkHashPaths(config)),
    ]) {
      expect(file.startsWith(prefix)).to.equal(true);
    }
    expect(getBfvDecryptionSubCircuitVkHashPaths(config).c7).to.equal(
      path.join(
        prefix,
        "default/threshold/decrypted_shares_aggregation_wide/decrypted_shares_aggregation_wide.vk_hash",
      ),
    );
  });

  it("fails closed when no release circuit directory is configured", function () {
    delete process.env.INTERFOLD_CIRCUITS_DIR;
    expect(() =>
      getBfvV2VkBindingHashPaths(SECURE_16384_MINIMUM_BFV_CONFIG),
    ).to.throw("set INTERFOLD_CIRCUITS_DIR");
  });

  for (const [config, committee, committeeSize, n, t, h, length] of [
    [SECURE_16384_MICRO_BFV_CONFIG, "micro", 1, 9, 4, 5, 72],
    [SECURE_16384_SMALL_BFV_CONFIG, "small", 2, 19, 9, 14, 99],
  ] as const) {
    it(`resolves secure ${committee} with ZK C2 finalizers and a ${length}-field V2 layout`, function () {
      expect(bfvHonkSource(config, "DkgAggregatorV2Verifier")).to.equal(
        `contracts/verifiers/bfv/honk/secure-16384/${committee}/DkgAggregatorV2Verifier.sol`,
      );
      expect(config).to.include({
        paramSet: 3,
        committeeSize,
        n,
        t,
        h,
      });
      const prefix = path.join(release, `secure-16384/${committee}`) + path.sep;
      const legacy = getBfvPkVkBindingHashPaths(config);
      for (const file of [...legacy, ...getBfvV2VkBindingHashPaths(config)]) {
        expect(file.startsWith(prefix)).to.equal(true);
      }
      for (const index of [5, 6]) {
        expect(legacy[index]).to.include(
          `${path.sep}recursive${path.sep}recursive_aggregation${path.sep}`,
        );
      }
      expect(bfvPkV2PublicInputLayout(config.h, 6).length).to.equal(length);
      expect(bfvConfigsForChain(31337)).to.include(config);
      expect(bfvConfigsForChain(11155111)).to.include(config);
      expect(
        bfvConfigsForChain(1).every((route) => route.paramSet === 2),
      ).to.equal(true);
    });
  }
});

describe("local l-BFV VK variants", function () {
  it("selects ZK leaf keys and non-ZK fold keys in the local artifact layout", function () {
    const legacy = getBfvPkVkBindingHashPaths();
    for (const [index, file] of legacy.entries()) {
      expect(file).to.match(
        [1, 5, 6, 8, 9, 11, 12].includes(index)
          ? /\.vk_noir_hash$/
          : /\.vk_recursive_hash$/,
      );
    }
    const v2 = getBfvV2VkBindingHashPaths();
    for (const [index, file] of v2.entries()) {
      expect(file).to.match(
        [5, 6, 9, 10].includes(index)
          ? /\.vk_noir_hash$/
          : /\.vk_recursive_hash$/,
      );
    }
  });
});
