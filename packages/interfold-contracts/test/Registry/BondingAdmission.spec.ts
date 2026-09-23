// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
import { expect } from "chai";

import {
  deployInterfoldSystem,
  ethers,
  networkHelpers,
  setupOperatorForSortition,
} from "../fixtures";

const { loadFixture, time, setStorageAt } = networkHelpers;
const DELAY = 3 * 24 * 60 * 60;

async function setup() {
  const ctx = await deployInterfoldSystem({ submissionWindow: 600 });
  const signers = await ethers.getSigners();
  const extra = signers[10];
  const newOwner = signers[11];
  await time.increase(DELAY);
  return { ...ctx, extra, newOwner };
}
type Context = Awaited<ReturnType<typeof setup>>;

async function add(ctx: Context) {
  await setupOperatorForSortition(
    ctx.extra,
    ctx.extra,
    ctx.bondingRegistry,
    ctx.ciphernodeBondToken,
    ctx.usdcToken,
    ctx.ticketToken,
    ctx.ciphernodeRegistry,
    ctx.nodeReleaseRegistry,
  );
  await time.increase(1);
  return time.latest();
}

async function refresh(ctx: Context) {
  const operators = [...ctx.operators];
  if (await ctx.bondingRegistry.isRegistered(ctx.extra.address))
    operators.push(ctx.extra);
  await ctx.bondingRegistry.refreshOperatorStatuses(
    await Promise.all(operators.map((n) => n.getAddress())),
  );
  await time.increase(1);
}

async function request(ctx: Context) {
  const now = await time.latest();
  const id = await ctx.interfold.nexte3Id();
  const params = {
    ...ctx.request,
    inputWindow: [now + 100, now + 10_000] as [number, number],
  };
  await ctx.usdcToken.approve(
    await ctx.interfold.getAddress(),
    await ctx.interfold.getE3Quote(params),
  );
  await ctx.interfold.request(params);
  return id;
}

async function eligible(
  ctx: Context,
  node: { getAddress(): Promise<string> } = ctx.extra,
  at?: number,
) {
  return (
    await ctx.bondingRegistry.eligibilityAt(
      await node.getAddress(),
      at ?? (await time.latest()),
    )
  )[0];
}

async function transfer(ctx: Context) {
  await ctx.bondingRegistry
    .connect(ctx.extra)
    .proposeBondOwner(ctx.extra.address, ctx.newOwner.address);
  await ctx.bondingRegistry
    .connect(ctx.newOwner)
    .acceptBondOwner(ctx.extra.address);
  return time.latest();
}

describe("Governance-controlled committee admission", function () {
  it("defaults to disabled, restricts policy changes to governance, and emits complete policy", async function () {
    const ctx = await loadFixture(setup);
    const b = ctx.bondingRegistry;
    expect(
      (await b.admissionPolicyAt(await time.latest())).cooldownEnabled,
    ).to.equal(false);
    await expect(
      b.connect(ctx.extra).setAdmissionPolicy(true, DELAY, false),
    ).to.be.revertedWithCustomError(b, "OwnableUnauthorizedAccount");
    await expect(b.setAdmissionPolicy(true, DELAY, false)).to.emit(
      b,
      "AdmissionPolicyUpdated",
    );
    const policy = await b.admissionPolicyAt(await time.latest());
    expect(policy.cooldownDuration).to.equal(DELAY);
    expect(policy.cooldownEnabled).to.equal(true);
    await expect(b.setAdmissionPolicy(true, DELAY, false)).not.to.emit(
      b,
      "AdmissionPolicyUpdated",
    );
  });

  it("requires the complete delay and refreshes conservative owner capacity at maturity", async function () {
    const ctx = await loadFixture(setup);
    await ctx.bondingRegistry.setAdmissionPolicy(true, DELAY, false);
    await add(ctx);
    await refresh(ctx);
    const logs = await ctx.bondingRegistry.queryFilter(
      ctx.bondingRegistry.filters.AdmissionStarted(ctx.extra.address),
    );
    const since = Number(logs.at(-1)!.args.timepoint);
    expect(await ctx.bondingRegistry.isActive(ctx.extra.address)).to.equal(
      true,
    );
    expect(await eligible(ctx)).to.equal(false);
    expect(
      await ctx.bondingRegistry.committeeOwnerCapacity(await time.latest()),
    ).to.equal(3);
    await time.increaseTo(since + DELAY - 1);
    expect(await eligible(ctx)).to.equal(false);
    await time.increaseTo(since + DELAY);
    expect(await eligible(ctx)).to.equal(true);
    expect(
      await ctx.bondingRegistry.committeeOwnerCapacity(await time.latest()),
    ).to.equal(3);
    await refresh(ctx);
    expect(
      await ctx.bondingRegistry.committeeOwnerCapacity(await time.latest()),
    ).to.equal(4);
  });

  it("records starts while disabled, and re-enabling uses the recorded age", async function () {
    const ctx = await loadFixture(setup);
    await add(ctx);
    expect(await eligible(ctx)).to.equal(true);
    await ctx.bondingRegistry.setAdmissionPolicy(true, DELAY, false);
    expect(await eligible(ctx)).to.equal(false);
    await ctx.bondingRegistry.setAdmissionPolicy(false, DELAY, false);
    expect(await eligible(ctx)).to.equal(true);
    await ctx.bondingRegistry.setAdmissionPolicy(true, DELAY, false);
    expect(await eligible(ctx)).to.equal(false);
  });

  it("keeps waiting nodes out during a pause, including after expiry and disabling the delay", async function () {
    const ctx = await loadFixture(setup);
    await ctx.bondingRegistry.setAdmissionPolicy(true, DELAY, false);
    await add(ctx);
    await ctx.bondingRegistry.setAdmissionPolicy(true, DELAY, true);
    expect(await eligible(ctx, ctx.operators[0])).to.equal(true);
    await time.increase(DELAY + 1);
    expect(await eligible(ctx)).to.equal(false);
    await ctx.bondingRegistry.setAdmissionPolicy(false, 0, true);
    expect(await eligible(ctx)).to.equal(false);
    await ctx.bondingRegistry.setAdmissionPolicy(true, DELAY, false);
    expect(await eligible(ctx)).to.equal(true);
  });

  it("blocks new registrations during a pause even with the cooldown disabled", async function () {
    const ctx = await loadFixture(setup);
    await ctx.bondingRegistry.setAdmissionPolicy(false, 0, true);
    await add(ctx);
    expect(await eligible(ctx)).to.equal(false);
    await ctx.bondingRegistry.setAdmissionPolicy(false, 0, false);
    expect(await eligible(ctx)).to.equal(true);
  });

  it("requires eligibility before the pause, not only an old registration", async function () {
    const ctx = await loadFixture(setup);
    await add(ctx);
    await time.increase(DELAY);
    const amount = await ctx.bondingRegistry.getTicketBalance(
      ctx.extra.address,
    );
    await ctx.bondingRegistry
      .connect(ctx.extra)
      .removeTicketBalanceFor(ctx.extra.address, amount);
    await time.increase(1);
    await ctx.bondingRegistry.setAdmissionPolicy(true, DELAY, true);
    await ctx.usdcToken
      .connect(ctx.extra)
      .approve(await ctx.ticketToken.getAddress(), amount);
    await ctx.bondingRegistry
      .connect(ctx.extra)
      .addTicketBalanceFor(ctx.extra.address, amount);
    expect(await ctx.bondingRegistry.isActive(ctx.extra.address)).to.equal(
      true,
    );
    expect(await eligible(ctx)).to.equal(false);
  });

  it("restarts the delay on accepted ownership changes, not on proposals or self-transfers", async function () {
    const ctx = await loadFixture(setup);
    await add(ctx);
    await time.increase(DELAY);
    await ctx.bondingRegistry.setAdmissionPolicy(true, DELAY, false);
    await refresh(ctx);
    await ctx.bondingRegistry
      .connect(ctx.extra)
      .proposeBondOwner(ctx.extra.address, ctx.extra.address);
    await ctx.bondingRegistry
      .connect(ctx.extra)
      .acceptBondOwner(ctx.extra.address);
    expect(await eligible(ctx)).to.equal(true);
    const before = await time.latest();
    const changed = await transfer(ctx);
    expect(await eligible(ctx, ctx.extra, before)).to.equal(true);
    expect(await eligible(ctx)).to.equal(false);
    expect(await ctx.bondingRegistry.isActive(ctx.extra.address)).to.equal(
      true,
    );
    expect(await ctx.bondingRegistry.committeeOwnerCapacity(changed)).to.equal(
      3,
    );
    await time.increaseTo(changed + DELAY);
    expect(await eligible(ctx)).to.equal(true);
  });

  it("does not let a transfer during a pause enter after its delay expires", async function () {
    const ctx = await loadFixture(setup);
    await add(ctx);
    await ctx.bondingRegistry.setAdmissionPolicy(false, 0, true);
    await transfer(ctx);
    await time.increase(DELAY);
    expect(await eligible(ctx)).to.equal(false);
    await ctx.bondingRegistry.setAdmissionPolicy(false, 0, false);
    expect(await eligible(ctx)).to.equal(true);
  });

  it("starts a new delay after re-registration and preserves the exit lock", async function () {
    const ctx = await loadFixture(setup);
    await add(ctx);
    await time.increase(DELAY);
    await ctx.bondingRegistry
      .connect(ctx.extra)
      .deregisterOperatorFor(ctx.extra.address);
    await ctx.bondingRegistry.setAdmissionPolicy(false, 0, false);
    expect(await eligible(ctx)).to.equal(false);
    await expect(
      ctx.bondingRegistry
        .connect(ctx.extra)
        .registerOperatorFor(ctx.extra.address),
    ).to.be.revertedWithCustomError(ctx.bondingRegistry, "ExitInProgress");
    await time.increase(await ctx.bondingRegistry.exitDelay());
    await ctx.bondingRegistry.setAdmissionPolicy(true, DELAY, false);
    const bond = ethers.parseEther("1000");
    await ctx.ciphernodeBondToken
      .connect(ctx.extra)
      .approve(await ctx.bondingRegistry.getAddress(), bond);
    await ctx.bondingRegistry
      .connect(ctx.extra)
      .bondCiphernodeFor(ctx.extra.address, bond);
    await ctx.bondingRegistry
      .connect(ctx.extra)
      .registerOperatorFor(ctx.extra.address);
    const registered = await time.latest();
    const tickets = ethers.parseUnits("100", 6);
    await ctx.usdcToken
      .connect(ctx.extra)
      .approve(await ctx.ticketToken.getAddress(), tickets);
    await ctx.bondingRegistry
      .connect(ctx.extra)
      .addTicketBalanceFor(ctx.extra.address, tickets);
    expect(await ctx.bondingRegistry.isActive(ctx.extra.address)).to.equal(
      true,
    );
    expect(await eligible(ctx)).to.equal(false);
    await time.increaseTo(registered + DELAY);
    expect(await eligible(ctx)).to.equal(true);
  });

  it("uses the pre-pause timestamp at the exact maturity boundary", async function () {
    const ctx = await loadFixture(setup);
    await ctx.bondingRegistry.setAdmissionPolicy(true, DELAY, false);
    await add(ctx);
    const logs = await ctx.bondingRegistry.queryFilter(
      ctx.bondingRegistry.filters.AdmissionStarted(ctx.extra.address),
    );
    const since = Number(logs.at(-1)!.args.timepoint);
    await time.setNextBlockTimestamp(since + DELAY);
    await ctx.bondingRegistry.setAdmissionPolicy(true, DELAY, true);
    expect(await eligible(ctx)).to.equal(false);
    await ctx.bondingRegistry.setAdmissionPolicy(true, DELAY, false);
    expect(await eligible(ctx)).to.equal(true);
    await ctx.bondingRegistry.setAdmissionPolicy(true, DELAY, true);
    expect(await eligible(ctx)).to.equal(true);
  });

  it("does not admit waiting nodes through disable-and-pause changes in one block", async function () {
    const ctx = await loadFixture(setup);
    await ctx.bondingRegistry.setAdmissionPolicy(true, DELAY, false);
    await add(ctx);
    await ethers.provider.send("evm_setAutomine", [false]);
    try {
      const disable = await ctx.bondingRegistry.setAdmissionPolicy(
        false,
        0,
        false,
      );
      const pause = await ctx.bondingRegistry.setAdmissionPolicy(
        false,
        0,
        true,
      );
      await networkHelpers.mine();
      const disabledAt = await disable.wait();
      const pausedAt = await pause.wait();
      expect(disabledAt!.blockNumber).to.equal(pausedAt!.blockNumber);
      expect(await eligible(ctx)).to.equal(false);
    } finally {
      await ethers.provider.send("evm_setAutomine", [true]);
    }
  });

  it("preserves the frozen pool across an unpause and re-pause in one block", async function () {
    const ctx = await loadFixture(setup);
    await ctx.bondingRegistry.setAdmissionPolicy(true, DELAY, false);
    await add(ctx);
    await ctx.bondingRegistry.setAdmissionPolicy(true, DELAY, true);
    const frozen = await ctx.bondingRegistry.admissionPolicyAt(
      await time.latest(),
    );
    await time.increase(DELAY + 1);
    await ethers.provider.send("evm_setAutomine", [false]);
    try {
      const unpause = await ctx.bondingRegistry.setAdmissionPolicy(
        true,
        DELAY,
        false,
      );
      const pause = await ctx.bondingRegistry.setAdmissionPolicy(
        true,
        DELAY,
        true,
      );
      await networkHelpers.mine();
      expect((await unpause.wait())!.blockNumber).to.equal(
        (await pause.wait())!.blockNumber,
      );
      expect(await eligible(ctx)).to.equal(false);
      expect(await eligible(ctx, ctx.operators[0])).to.equal(true);
      expect(
        (await ctx.bondingRegistry.admissionPolicyAt(await time.latest()))
          .pauseTimepoint,
      ).to.equal(frozen.pauseTimepoint);
    } finally {
      await ethers.provider.send("evm_setAutomine", [true]);
    }
  });

  it("applies changed durations to future requests without resetting position age", async function () {
    const ctx = await loadFixture(setup);
    await add(ctx);
    const logs = await ctx.bondingRegistry.queryFilter(
      ctx.bondingRegistry.filters.AdmissionStarted(ctx.extra.address),
    );
    const since = Number(logs.at(-1)!.args.timepoint);
    await time.increaseTo(since + DELAY);
    await ctx.bondingRegistry.setAdmissionPolicy(true, DELAY, false);
    const before = await time.latest();
    expect(await eligible(ctx)).to.equal(true);
    await ctx.bondingRegistry.setAdmissionPolicy(true, DELAY * 2, false);
    expect(await eligible(ctx)).to.equal(false);
    expect(await eligible(ctx, ctx.extra, before)).to.equal(true);
    await ctx.bondingRegistry.setAdmissionPolicy(true, DELAY, false);
    expect(await eligible(ctx)).to.equal(true);
    const starts = await ctx.bondingRegistry.queryFilter(
      ctx.bondingRegistry.filters.AdmissionStarted(ctx.extra.address),
    );
    expect(starts).to.have.length(logs.length);
  });

  it("keeps requested E3s unchanged by later policy and owner changes", async function () {
    const ctx = await loadFixture(setup);
    await add(ctx);
    const id = await request(ctx);
    await ctx.bondingRegistry.setAdmissionPolicy(true, DELAY, true);
    await transfer(ctx);
    expect(await eligible(ctx)).to.equal(false);
    await expect(
      ctx.ciphernodeRegistry.connect(ctx.extra).submitTicket(id, 1),
    ).to.emit(ctx.ciphernodeRegistry, "TicketSubmitted");
    for (const node of ctx.operators)
      await ctx.ciphernodeRegistry.connect(node).submitTicket(id, 1);
    await time.increaseTo(
      (await ctx.ciphernodeRegistry.getCommitteeDeadline(id)) + 1n,
    );
    await expect(ctx.ciphernodeRegistry.finalizeCommittee(id)).to.emit(
      ctx.ciphernodeRegistry,
      "SortitionCommitteeFinalized",
    );
  });

  it("excludes waiting operators from new tickets and cannot bypass the seat cap", async function () {
    const ctx = await loadFixture(setup);
    await ctx.bondingRegistry.setAdmissionPolicy(true, DELAY, false);
    await add(ctx);
    await refresh(ctx);
    const id = await request(ctx);
    await expect(
      ctx.ciphernodeRegistry.connect(ctx.extra).submitTicket(id, 1),
    ).to.be.revertedWithCustomError(ctx.ciphernodeRegistry, "NodeNotEligible");
    // Disabling after the request cannot change its snapshot.
    await ctx.bondingRegistry.setAdmissionPolicy(false, 0, false);
    await expect(
      ctx.ciphernodeRegistry.connect(ctx.extra).submitTicket(id, 1),
    ).to.be.revertedWithCustomError(ctx.ciphernodeRegistry, "NodeNotEligible");
    await ctx.bondingRegistry
      .connect(ctx.extra)
      .proposeBondOwner(ctx.extra.address, await ctx.operators[0].getAddress());
    await ctx.bondingRegistry
      .connect(ctx.operators[0])
      .acceptBondOwner(ctx.extra.address);
    await refresh(ctx);
    expect(
      await ctx.bondingRegistry.committeeOwnerCapacity(await time.latest()),
    ).to.equal(3);
  });

  it("rejects requests until the new policy's distinct-owner capacity is refreshed", async function () {
    const ctx = await loadFixture(setup);
    const past = await time.latest();
    await ctx.bondingRegistry.setAdmissionPolicy(true, DELAY, false);
    expect(await ctx.bondingRegistry.committeeOwnerCapacity(past)).to.equal(0);
    const next = await ctx.interfold.nexte3Id();
    await expect(request(ctx)).to.be.revertedWithCustomError(
      ctx.ciphernodeRegistry,
      "InsufficientBondOwners",
    );
    expect(await ctx.interfold.nexte3Id()).to.equal(next);
    await refresh(ctx);
    await request(ctx);
  });

  it("grandfathers only unchanged pre-upgrade positions, not later ownership changes", async function () {
    const ctx = await loadFixture(setup);
    await add(ctx);
    const coder = ethers.AbiCoder.defaultAbiCoder();
    const base =
      BigInt(
        ethers.keccak256(
          coder.encode(
            ["uint256"],
            [BigInt(ethers.id("interfold.storage.BondingAdmission")) - 1n],
          ),
        ),
      ) & ~255n;
    const starts = ethers.keccak256(
      coder.encode(["address", "uint256"], [ctx.extra.address, base + 2n]),
    );
    // Model an existing position with no admission checkpoints at upgrade.
    await setStorageAt(
      await ctx.bondingRegistry.getAddress(),
      starts,
      ethers.ZeroHash,
    );
    await ctx.bondingRegistry.setAdmissionPolicy(true, DELAY, false);
    expect(await eligible(ctx)).to.equal(true);
    await transfer(ctx);
    expect(await eligible(ctx)).to.equal(false);
  });
});
