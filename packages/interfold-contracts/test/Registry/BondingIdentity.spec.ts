// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
import { expect } from "chai";
import type { Signer } from "ethers";

import { deployInterfoldSystem, ethers, networkHelpers } from "../fixtures";

const { loadFixture, time } = networkHelpers;

async function setup() {
  const ctx = await deployInterfoldSystem({ submissionWindow: 600 });
  const verifier = await ethers.deployContract("MockIdentityVerifier");
  const identityRegistry = await ethers.deployContract(
    "OwnerIdentityRegistry",
    [await ctx.owner.getAddress(), await verifier.getAddress()],
  );
  const signers = await ethers.getSigners();
  return { ...ctx, verifier, identityRegistry, newOwner: signers[11] };
}
type Context = Awaited<ReturnType<typeof setup>>;

async function verify(
  ctx: Context,
  owner = ctx.operators[0],
  expiresAt?: number,
) {
  const address = await owner.getAddress();
  const id = ethers.id(address);
  const expiry = expiresAt ?? (await time.latest()) + 10_000;
  await ctx.verifier.setResult(address, id, expiry);
  await ctx.identityRegistry.connect(owner).register("0x");
  return { id, expiresAt: expiry };
}

async function eligible(ctx: Context, operator: Signer, at?: number) {
  return (
    await ctx.bondingRegistry.eligibilityAt(
      await operator.getAddress(),
      at ?? (await time.latest()),
    )
  )[0];
}

async function refresh(ctx: Context) {
  await ctx.bondingRegistry.refreshOperatorStatuses(
    await Promise.all(ctx.operators.map((operator) => operator.getAddress())),
  );
  await time.increase(1);
}

async function capacity(ctx: Context, at?: number) {
  return ctx.bondingRegistry.committeeOwnerCapacity(
    at ?? (await time.latest()),
  );
}

describe("Bond-owner identity admission", function () {
  it("defaults to off and leaves unverified operators eligible when disabled", async function () {
    const ctx = await loadFixture(setup);
    const b = ctx.bondingRegistry;
    const before = await time.latest();
    expect((await b.identityPolicyAt(before)).required).to.equal(false);
    expect(await eligible(ctx, ctx.operators[0])).to.equal(true);
    await expect(
      b
        .connect(ctx.newOwner)
        .setIdentityPolicy(await ctx.identityRegistry.getAddress(), true),
    ).to.be.revertedWithCustomError(b, "OwnableUnauthorizedAccount");
    const registry = await ctx.identityRegistry.getAddress();
    const updatedAt = (await time.latest()) + 10;
    await time.setNextBlockTimestamp(updatedAt);
    await expect(b.setIdentityPolicy(registry, false))
      .to.emit(b, "IdentityPolicyUpdated")
      .withArgs(updatedAt, registry, false);
    expect((await b.identityPolicyAt(await time.latest())).registry).to.equal(
      registry,
    );
    expect((await b.identityPolicyAt(before)).registry).to.equal(
      ethers.ZeroAddress,
    );
    expect(await eligible(ctx, ctx.operators[0])).to.equal(true);
  });

  it("uses the policy and owner credential at the snapshot, including registration after it", async function () {
    const ctx = await loadFixture(setup);
    const beforePolicy = await time.latest();
    await verify(ctx);
    await ctx.bondingRegistry.setIdentityPolicy(
      await ctx.identityRegistry.getAddress(),
      true,
    );
    const snapshot = await time.latest();
    expect(await eligible(ctx, ctx.operators[0], snapshot)).to.equal(true);
    expect(await eligible(ctx, ctx.operators[1], snapshot)).to.equal(false);
    expect(
      await ctx.bondingRegistry.isActive(await ctx.operators[1].getAddress()),
    ).to.equal(true);
    expect(await eligible(ctx, ctx.operators[1], beforePolicy)).to.equal(true);
    await verify(ctx, ctx.operators[1]);
    expect(await eligible(ctx, ctx.operators[1])).to.equal(true);
    expect(await eligible(ctx, ctx.operators[1], snapshot)).to.equal(false);
  });

  it("fails capacity closed after expiry and rebuilds distinct owners through refreshes", async function () {
    const ctx = await loadFixture(setup);
    const b = ctx.bondingRegistry;
    const sharedOwner = await ctx.operators[0].getAddress();
    const transferred = await ctx.operators[1].getAddress();
    await b
      .connect(ctx.operators[1])
      .proposeBondOwner(transferred, sharedOwner);
    await b.connect(ctx.operators[0]).acceptBondOwner(transferred);
    const { expiresAt } = await verify(
      ctx,
      ctx.operators[0],
      (await time.latest()) + 100,
    );
    await verify(ctx, ctx.operators[2]);
    await b.setIdentityPolicy(await ctx.identityRegistry.getAddress(), true);
    await refresh(ctx);
    const snapshot = await time.latest();
    expect(await capacity(ctx)).to.equal(2);
    await time.increaseTo(expiresAt);
    expect(await eligible(ctx, ctx.operators[0])).to.equal(true);
    expect(await capacity(ctx)).to.equal(2);
    await time.increase(1);
    const expiredAt = await time.latest();
    expect(await eligible(ctx, ctx.operators[0])).to.equal(false);
    expect(await eligible(ctx, ctx.operators[0], snapshot)).to.equal(true);
    expect(await capacity(ctx)).to.equal(0);
    expect(await capacity(ctx, snapshot)).to.equal(2);
    const remaining = await ctx.operators[2].getAddress();
    await b.connect(ctx.newOwner).refreshOperatorStatus(remaining);
    expect(await capacity(ctx)).to.equal(1);
    await b.connect(ctx.newOwner).refreshOperatorStatus(remaining);
    expect(await capacity(ctx)).to.equal(1);
    await refresh(ctx);
    expect(await capacity(ctx)).to.equal(1);
    expect(await capacity(ctx, snapshot)).to.equal(2);
    expect(await capacity(ctx, expiredAt)).to.equal(0);
  });

  it("fails capacity closed after revocation and rebuilds only verified owners", async function () {
    const ctx = await loadFixture(setup);
    const { id } = await verify(ctx);
    await verify(ctx, ctx.operators[1]);
    await verify(ctx, ctx.operators[2]);
    await ctx.bondingRegistry.setIdentityPolicy(
      await ctx.identityRegistry.getAddress(),
      true,
    );
    await refresh(ctx);
    const snapshot = await time.latest();
    expect(await capacity(ctx)).to.equal(3);
    await ctx.identityRegistry.revoke(id);
    const revokedAt = await time.latest();
    expect(await eligible(ctx, ctx.operators[0])).to.equal(false);
    expect(await eligible(ctx, ctx.operators[0], snapshot)).to.equal(true);
    expect(await capacity(ctx)).to.equal(0);
    expect(await capacity(ctx, snapshot)).to.equal(3);
    await ctx.bondingRegistry
      .connect(ctx.newOwner)
      .refreshOperatorStatus(await ctx.operators[1].getAddress());
    expect(await capacity(ctx)).to.equal(1);
    await refresh(ctx);
    expect(await capacity(ctx)).to.equal(2);
    expect(await capacity(ctx, snapshot)).to.equal(3);
    expect(await capacity(ctx, revokedAt)).to.equal(0);
  });

  it("records a verified transfer's earlier expiry before another status refresh", async function () {
    const ctx = await loadFixture(setup);
    const b = ctx.bondingRegistry;
    for (const operator of ctx.operators) await verify(ctx, operator);
    const { expiresAt } = await verify(
      ctx,
      ctx.newOwner,
      (await time.latest()) + 100,
    );
    await b.setIdentityPolicy(await ctx.identityRegistry.getAddress(), true);
    await refresh(ctx);
    const operator = ctx.operators[0];
    const address = await operator.getAddress();
    await b.connect(operator).proposeBondOwner(address, ctx.newOwner.address);
    await b.connect(ctx.newOwner).acceptBondOwner(address);
    const snapshot = await time.latest();
    expect(await capacity(ctx)).to.equal(3);
    await time.increaseTo(expiresAt + 1);
    const expiredAt = await time.latest();
    expect(await capacity(ctx)).to.equal(0);
    expect(await capacity(ctx, snapshot)).to.equal(3);
    await refresh(ctx);
    expect(await capacity(ctx)).to.equal(2);
    expect(await capacity(ctx, expiredAt)).to.equal(0);
  });

  it("uses historical ownership and drops capacity when a verified owner transfers to an unverified owner", async function () {
    const ctx = await loadFixture(setup);
    const b = ctx.bondingRegistry;
    const operator = ctx.operators[0];
    const address = await operator.getAddress();
    await verify(ctx);
    await b.setIdentityPolicy(await ctx.identityRegistry.getAddress(), true);
    await refresh(ctx);
    const before = await time.latest();
    expect(await capacity(ctx)).to.equal(1);
    await b.connect(operator).proposeBondOwner(address, ctx.newOwner.address);
    await b.connect(ctx.newOwner).acceptBondOwner(address);
    const changed = await time.latest();
    expect(await b.bondOwnerAt(address, changed)).to.equal(
      ctx.newOwner.address,
    );
    expect(await eligible(ctx, operator, before)).to.equal(true);
    expect(await eligible(ctx, operator, changed)).to.equal(false);
    expect(await capacity(ctx)).to.equal(0);
    await verify(ctx, ctx.newOwner);
    expect(await eligible(ctx, operator)).to.equal(true);
    expect(await eligible(ctx, operator, changed)).to.equal(false);
    await refresh(ctx);
    expect(await capacity(ctx)).to.equal(1);
  });

  it("resets capacity across policy changes and repopulates it with the same identity rule", async function () {
    const ctx = await loadFixture(setup);
    const b = ctx.bondingRegistry;
    const registry = await ctx.identityRegistry.getAddress();
    await refresh(ctx);
    expect(await capacity(ctx)).to.equal(3);
    await verify(ctx);
    const before = await time.latest();
    await b.setIdentityPolicy(registry, true);
    const enabled = await time.latest();
    expect(await capacity(ctx)).to.equal(0);
    expect(await capacity(ctx, before)).to.equal(0);
    await refresh(ctx);
    expect(await capacity(ctx)).to.equal(1);
    await b.setIdentityPolicy(registry, false);
    expect(await capacity(ctx)).to.equal(0);
    expect(await eligible(ctx, ctx.operators[1], enabled)).to.equal(false);
    expect(await eligible(ctx, ctx.operators[1])).to.equal(true);
    await refresh(ctx);
    expect(await capacity(ctx)).to.equal(3);
    await expect(b.setIdentityPolicy(registry, false)).not.to.emit(
      b,
      "IdentityPolicyUpdated",
    );
    expect(await capacity(ctx)).to.equal(3);
  });

  it("refuses a required policy without a callable identity registry", async function () {
    const ctx = await loadFixture(setup);
    const b = ctx.bondingRegistry;
    for (const registry of [ethers.ZeroAddress, ctx.newOwner.address]) {
      await expect(b.setIdentityPolicy(registry, true))
        .to.be.revertedWithCustomError(b, "InvalidIdentityRegistry")
        .withArgs(registry);
    }
    await expect(
      b.setIdentityPolicy(await ctx.verifier.getAddress(), true),
    ).to.be.revert(ethers);
    expect((await b.identityPolicyAt(await time.latest())).required).to.equal(
      false,
    );
    await b.setIdentityPolicy(ethers.ZeroAddress, false);
  });

  it("still applies the cooldown to a verified owner", async function () {
    const ctx = await loadFixture(setup);
    await verify(ctx);
    await ctx.bondingRegistry.setIdentityPolicy(
      await ctx.identityRegistry.getAddress(),
      true,
    );
    expect(await eligible(ctx, ctx.operators[0])).to.equal(true);
    await ctx.bondingRegistry.setAdmissionPolicy(true, 10_000, false);
    expect(await eligible(ctx, ctx.operators[0])).to.equal(false);
  });
});
