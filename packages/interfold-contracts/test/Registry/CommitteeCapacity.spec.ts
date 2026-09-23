// SPDX-License-Identifier: LGPL-3.0-only
import { expect } from "chai";

import { assertCommitteeOwnerCapacity } from "../../tasks/committeeCapacity";
import {
  deployInterfoldSystem,
  ethers,
  networkHelpers,
  setupOperatorForSortition,
} from "../fixtures";

const { loadFixture, time, setStorageAt } = networkHelpers;
const coder = ethers.AbiCoder.defaultAbiCoder();

function slot(keyType: string, key: string | bigint, base: bigint): bigint {
  return BigInt(
    ethers.keccak256(coder.encode([keyType, "uint256"], [key, base])),
  );
}

const ownerHistorySlot =
  BigInt(
    ethers.keccak256(
      coder.encode(
        ["uint256"],
        [BigInt(ethers.id("interfold.storage.BondOwnerHistory")) - 1n],
      ),
    ),
  ) & ~255n;

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
  it("rejects direct requests without charging fees or spending a VRF request", async function () {
    const sys = await loadFixture(setup);
    const now = await time.latest();
    const params = {
      ...sys.request,
      inputWindow: [now + 100, now + 10_000] as [number, number],
    };
    await sys.usdcToken.approve(
      await sys.interfold.getAddress(),
      ethers.MaxUint256,
    );
    const e3Id = await sys.interfold.nexte3Id();
    const payer = await sys.owner.getAddress();
    const treasury = await sys.treasury.getAddress();
    const token = await sys.usdcToken.getAddress();
    const balance = await sys.usdcToken.balanceOf(payer);
    const credited = await sys.interfold.pendingTreasuryClaim(treasury, token);
    const vrf = sys.mocks.randomnessProvider!;
    const nextDraw = await vrf.nextRequestId();
    expect(await sys.bondingRegistry.numActiveOperators()).to.equal(4);
    await expect(sys.interfold.request(params))
      .to.be.revertedWithCustomError(
        sys.ciphernodeRegistry,
        "InsufficientBondOwners",
      )
      .withArgs(3, 2);
    expect(await sys.usdcToken.balanceOf(payer)).to.equal(balance);
    expect(await sys.interfold.pendingTreasuryClaim(treasury, token)).to.equal(
      credited,
    );
    expect(await sys.interfold.nexte3Id()).to.equal(e3Id);
    expect(await sys.interfold.e3Payments(e3Id)).to.equal(0);
    expect(await sys.interfold.activeE3Count()).to.equal(0);
    expect(await sys.ciphernodeRegistry.unreleasedCommitteeCount()).to.equal(0);
    expect(await sys.bondingRegistry.unresolvedCommitteeCount()).to.equal(0);
    expect(await vrf.nextRequestId()).to.equal(nextDraw);

    // The same request succeeds once three distinct owners can supply a seat.
    await sys.bondingRegistry
      .connect(sys.signers[0])
      .proposeBondOwner(sys.operators[0].address, sys.signers[2].address);
    await sys.bondingRegistry
      .connect(sys.signers[2])
      .acceptBondOwner(sys.operators[0].address);
    await time.increase(2);
    await expect(sys.interfold.request(params)).to.emit(
      sys.interfold,
      "E3Requested",
    );
    expect(await vrf.nextRequestId()).to.equal(nextDraw + 1n);
  });

  it("counts active owners once across transfers, withdrawals, and refreshes", async function () {
    const sys = await loadFixture(setup);
    const bonding = sys.bondingRegistry;
    const capacity = async () =>
      bonding.committeeOwnerCapacity(await time.latest());
    expect(await capacity()).to.equal(2);
    await bonding.refreshOperatorStatuses(
      sys.operators.map((node) => node.address),
    );
    await bonding.refreshOperatorStatus(sys.operators[0].address);
    expect(await capacity()).to.equal(2);
    await bonding
      .connect(sys.signers[0])
      .proposeBondOwner(sys.operators[0].address, sys.signers[2].address);
    expect(await capacity()).to.equal(2);
    const beforeTransfer = await time.latest();
    await bonding
      .connect(sys.signers[2])
      .acceptBondOwner(sys.operators[0].address);
    expect(await capacity()).to.equal(3);
    expect(await bonding.committeeOwnerCapacity(beforeTransfer)).to.equal(2);
    await bonding
      .connect(sys.signers[2])
      .proposeBondOwner(sys.operators[0].address, sys.signers[1].address);
    await bonding
      .connect(sys.signers[1])
      .acceptBondOwner(sys.operators[0].address);
    expect(await capacity()).to.equal(2);

    const amount = await sys.ticketToken.balanceOf(sys.operators[0].address);
    await bonding
      .connect(sys.signers[1])
      .removeTicketBalanceFor(sys.operators[0].address, amount);
    expect(await capacity()).to.equal(2); // This owner still has another active operator.
    await bonding
      .connect(sys.signers[1])
      .removeTicketBalanceFor(sys.operators[3].address, amount);
    expect(await capacity()).to.equal(1);
    await time.increase((await bonding.exitDelay()) + 1n);
    await bonding.claimExitsFor(sys.operators[3].address, ethers.MaxUint256, 0);
    await sys.usdcToken
      .connect(sys.signers[1])
      .approve(await sys.ticketToken.getAddress(), amount);
    await bonding
      .connect(sys.signers[1])
      .addTicketBalanceFor(sys.operators[3].address, amount);
    expect(await capacity()).to.equal(2);
    await bonding
      .connect(sys.signers[1])
      .deregisterOperatorFor(sys.operators[3].address);
    expect(await capacity()).to.equal(1);
  });

  it("invalidates owner capacity with eligibility policy and excludes same-time refreshes", async function () {
    const sys = await loadFixture(setup);
    const bonding = sys.bondingRegistry;
    const before = await time.latest();
    expect(await bonding.committeeOwnerCapacity(before)).to.equal(2);
    await bonding.setMinTicketBalance((await bonding.minTicketBalance()) + 1n);
    expect(await bonding.committeeOwnerCapacity(before)).to.equal(0);
    expect(await bonding.committeeOwnerCapacity(await time.latest())).to.equal(
      0,
    );
    await bonding.refreshOperatorStatus(sys.operators[0].address);
    const refreshedAt = await time.latest();
    expect(await bonding.committeeOwnerCapacity(refreshedAt - 1)).to.equal(0);
    expect(await bonding.committeeOwnerCapacity(refreshedAt)).to.equal(1);
    await bonding.refreshOperatorStatuses(
      sys.operators.map((node) => node.address),
    );
    expect(await bonding.committeeOwnerCapacity(await time.latest())).to.equal(
      2,
    );
    // A stale generation's owner transfer must not enter or remove a counted owner.
    await bonding.setMinTicketBalance((await bonding.minTicketBalance()) + 1n);
    await bonding
      .connect(sys.signers[0])
      .proposeBondOwner(sys.operators[0].address, sys.signers[2].address);
    await bonding
      .connect(sys.signers[2])
      .acceptBondOwner(sys.operators[0].address);
    expect(await bonding.committeeOwnerCapacity(await time.latest())).to.equal(
      0,
    );
    await bonding.refreshOperatorStatuses(
      sys.operators.map((node) => node.address),
    );
    expect(await bonding.committeeOwnerCapacity(await time.latest())).to.equal(
      3,
    );
  });

  it("enrolls legacy active operators only through permissionless status refresh", async function () {
    const sys = await loadFixture(setup);
    const bonding = sys.bondingRegistry;
    const address = await bonding.getAddress();
    const version = (await bonding.eligibilityConfigurationVersion()) + 1n;
    // Reproduce the empty appended capacity fields of an upgraded proxy.
    for (const owner of sys.signers.slice(0, 2)) {
      await setStorageAt(
        address,
        slot(
          "address",
          owner.address,
          slot("uint256", version, ownerHistorySlot + 1n),
        ),
        0n,
      );
    }
    for (const operator of sys.operators) {
      const counted = slot("address", operator.address, ownerHistorySlot + 2n);
      await setStorageAt(address, counted, 0n);
      await setStorageAt(address, counted + 1n, 0n);
    }
    await setStorageAt(address, ownerHistorySlot + 3n, 0n);
    await setStorageAt(address, ownerHistorySlot + 4n, 0n);
    expect(await bonding.numActiveOperators()).to.equal(4);
    expect(await bonding.committeeOwnerCapacity(await time.latest())).to.equal(
      0,
    );
    await bonding
      .connect(sys.signers[0])
      .proposeBondOwner(sys.operators[0].address, sys.signers[2].address);
    await bonding
      .connect(sys.signers[2])
      .acceptBondOwner(sys.operators[0].address);
    expect(await bonding.committeeOwnerCapacity(await time.latest())).to.equal(
      0,
    );
    await bonding
      .connect(sys.signers[19])
      .refreshOperatorStatus(sys.operators[1].address);
    expect(await bonding.committeeOwnerCapacity(await time.latest())).to.equal(
      1,
    );
    await bonding
      .connect(sys.signers[19])
      .refreshOperatorStatuses(sys.operators.map((node) => node.address));
    expect(await bonding.committeeOwnerCapacity(await time.latest())).to.equal(
      3,
    );
    await bonding.refreshOperatorStatuses(
      sys.operators.map((node) => node.address),
    );
    expect(await bonding.committeeOwnerCapacity(await time.latest())).to.equal(
      3,
    );
    await time.increase(2);
    await sys.usdcToken.approve(
      await sys.interfold.getAddress(),
      ethers.MaxUint256,
    );
    const now = await time.latest();
    await expect(
      sys.interfold.request({
        ...sys.request,
        inputWindow: [now + 100, now + 10_000],
      }),
    ).to.emit(sys.interfold, "E3Requested");
  });

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
