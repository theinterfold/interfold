// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
import { expect } from "chai";
import { network } from "hardhat";

const { ethers } = await network.connect();

/**
 * CkksFixedPointLib: decodes the canonical CKKS fixed-point output bytes.
 *
 * The fixture below is pinned on the Rust side by
 * `e3_trckks::program_tests::solidity_fixture_vector` — the two tests
 * encode/decode the SAME bytes. If one changes, change both.
 */
describe("CkksFixedPointLib", function () {
  // encode_fixed_point_output(&[640.0, -0.05, 123456.78], 2)
  const FIXTURE =
    "0x" +
    "0000000000000000000000000000fa00" + //  64000  (640.00)
    "fffffffffffffffffffffffffffffffb" + //     -5  (-0.05)
    "00000000000000000000000000bc614e"; // 12345678 (123456.78)

  async function deployHarness() {
    const factory = await ethers.getContractFactory("CkksFixedPointHarness");
    return factory.deploy();
  }

  it("decodes the cross-language fixture exactly", async function () {
    const harness = await deployHarness();
    expect(await harness.count(FIXTURE)).to.equal(3n);
    expect(await harness.valueAt(FIXTURE, 0)).to.equal(64000n);
    expect(await harness.valueAt(FIXTURE, 1)).to.equal(-5n);
    expect(await harness.valueAt(FIXTURE, 2)).to.equal(12345678n);

    const all = await harness.decodeAll(FIXTURE);
    expect([...all]).to.deep.equal([64000n, -5n, 12345678n]);
  });

  it("rejects ragged payloads", async function () {
    const harness = await deployHarness();
    const ragged = "0x" + "00".repeat(15);
    await expect(harness.count(ragged)).to.be.revertedWithCustomError(
      harness,
      "RaggedFixedPointPayload",
    );
  });

  it("handles the extremes of int128", async function () {
    const harness = await deployHarness();
    const max = (1n << 127n) - 1n;
    const min = -(1n << 127n);
    const maxHex = max.toString(16).padStart(32, "0");
    const minHex = (min & ((1n << 128n) - 1n)).toString(16).padStart(32, "0");
    const payload = "0x" + maxHex + minHex;
    expect(await harness.valueAt(payload, 0)).to.equal(max);
    expect(await harness.valueAt(payload, 1)).to.equal(min);
  });
});
