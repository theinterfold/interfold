// SPDX-License-Identifier: LGPL-3.0-only
import { expect } from "chai";

import { assertCommitteeOwnerCapacity } from "../../tasks/committeeCapacity";
import {
  deployInterfoldSystem,
  ethers,
  networkHelpers,
  setupOperatorForSortition,
} from "../fixtures";

const { loadFixture, time } = networkHelpers;

async function setup() {
  const sys = await deployInterfoldSystem({
    setupOperators: 0,
    committeeThresholds: [
      [0, [2, 3]],
      [2, [14, 19]],
    ],
  });
  const signers = await ethers.getSigners();
  const operators = signers.slice(5, 9);
  for (const [i, node] of operators.entries()) {
    await setupOperatorForSortition(
      node,
      signers[i < 3 ? 0 : 1],
      sys.bondingRegistry,
      sys.ciphernodeBondToken,
      sys.usdcToken,
      sys.ticketToken,
      sys.ciphernodeRegistry,
      sys.nodeReleaseRegistry,
    );
  }
  await time.increase(2);
  return { ...sys, operators, signers };
}

describe("Committee owner-capacity preflight", function () {
  it("rejects many operators under too few owners before payment", async function () {
    const sys = await loadFixture(setup);
    const before = await sys.interfold.nexte3Id();
    await expect(
      assertCommitteeOwnerCapacity(sys.interfold, 0, 0),
    ).to.be.rejectedWith(
      "Committee needs 3 distinct eligible bond owners; found 2",
    );
    expect(await sys.interfold.nexte3Id()).to.equal(before);
  });

  it("uses historical owners at the same boundary as the ticket balances", async function () {
    const sys = await loadFixture(setup);
    const node = sys.operators[0].address;
    await sys.bondingRegistry
      .connect(sys.signers[0])
      .proposeBondOwner(node, sys.signers[2].address);
    await sys.bondingRegistry.connect(sys.signers[2]).acceptBondOwner(node);
    // The newest transfer is not part of head.timestamp - 1 yet.
    await expect(
      assertCommitteeOwnerCapacity(sys.interfold, 0, 0),
    ).to.be.rejectedWith("found 2");
    await time.increase(2);
    const result = await assertCommitteeOwnerCapacity(sys.interfold, 0, 0);
    expect(result.requiredOwners).to.equal(3);
    expect(result.eligibleOwners).to.equal(3);
    await expect(
      assertCommitteeOwnerCapacity(sys.interfold, 2, 0),
    ).to.be.rejectedWith("Committee needs 19");
  });

  it("does not count inactive nodes or accept an invalid history range", async function () {
    const sys = await loadFixture(setup);
    await sys.bondingRegistry
      .connect(sys.signers[0])
      .proposeBondOwner(sys.operators[0].address, sys.signers[2].address);
    await sys.bondingRegistry
      .connect(sys.signers[2])
      .acceptBondOwner(sys.operators[0].address);
    await time.increase(2);
    await assertCommitteeOwnerCapacity(sys.interfold, 0, 0);
    await sys.bondingRegistry
      .connect(sys.signers[1])
      .deregisterOperatorFor(sys.operators[3].address);
    await expect(
      assertCommitteeOwnerCapacity(sys.interfold, 0, 0),
    ).to.be.rejectedWith("found 2");
    await expect(
      assertCommitteeOwnerCapacity(sys.interfold, 0, -1),
    ).to.be.rejectedWith("Invalid registry history start block");
  });
});
