// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
import { expect } from "chai";

import type { OwnerIdentityRegistry } from "../../types";
import { ethers, networkHelpers } from "../fixtures";

const { loadFixture, time } = networkHelpers;
const ID = ethers.id("person-one");
const NEW_ID = ethers.id("renewed-document");

async function setup() {
  const [governance, alice, bob] = await ethers.getSigners();
  const verifier = await ethers.deployContract("MockIdentityVerifier");
  const registry = (await ethers.deployContract("OwnerIdentityRegistry", [
    governance.address,
    await verifier.getAddress(),
  ])) as unknown as OwnerIdentityRegistry;
  const expiresAt = (await time.latest()) + 100;
  await verifier.setResult(alice.address, ID, expiresAt);
  return { governance, alice, bob, verifier, registry, expiresAt };
}

describe("OwnerIdentityRegistry", function () {
  it("registers the caller and checkpoints the inclusive credential expiry", async function () {
    const { alice, registry, expiresAt } = await loadFixture(setup);
    const before = await time.latest();
    await expect(registry.connect(alice).register("0x1234"))
      .to.emit(registry, "IdentityRegistered")
      .withArgs(alice.address, ID, expiresAt);
    const registeredAt = await time.latest();
    expect(await registry.identityOf(alice.address)).to.deep.equal([
      ID,
      BigInt(expiresAt),
    ]);
    expect(await registry.ownerOfIdentity(ID)).to.equal(alice.address);
    expect(await registry.isVerifiedAt(alice.address, before)).to.equal(false);
    expect(await registry.isVerifiedAt(alice.address, registeredAt)).to.equal(
      true,
    );
    await expect(registry.connect(alice).register("0x1234")).not.to.emit(
      registry,
      "IdentityRegistered",
    );
    await time.increaseTo(expiresAt);
    expect(await registry.isVerifiedAt(alice.address, expiresAt)).to.equal(
      true,
    );
    await time.increase(1);
    expect(
      await registry.isVerifiedAt(alice.address, await time.latest()),
    ).to.equal(false);
    expect(await registry.isVerifiedAt(alice.address, registeredAt)).to.equal(
      true,
    );
  });

  it("rejects a shorter replacement and renews without filling an expired historical interval", async function () {
    const { alice, verifier, registry, expiresAt } = await loadFixture(setup);
    await registry.connect(alice).register("0x");
    const first = await time.latest();
    await verifier.setResult(alice.address, NEW_ID, expiresAt - 1);
    await expect(registry.connect(alice).register("0x"))
      .to.be.revertedWithCustomError(registry, "IdentityExpiryReduced")
      .withArgs(expiresAt, expiresAt - 1);
    expect(await registry.ownerOfIdentity(NEW_ID)).to.equal(ethers.ZeroAddress);
    await time.increaseTo(expiresAt + 1);
    await verifier.setResult(alice.address, ID, expiresAt + 1000);
    await registry.connect(alice).register("0x");
    expect(await registry.identityOf(alice.address)).to.deep.equal([
      ID,
      BigInt(expiresAt + 1000),
    ]);
    expect(await registry.isVerifiedAt(alice.address, first)).to.equal(true);
    expect(await registry.isVerifiedAt(alice.address, expiresAt + 1)).to.equal(
      false,
    );
    expect(
      await registry.isVerifiedAt(alice.address, await time.latest()),
    ).to.equal(true);
  });

  it("keeps identifiers reserved through replacement, expiry, and revocation", async function () {
    const { alice, bob, verifier, registry, expiresAt } =
      await loadFixture(setup);
    await registry.connect(alice).register("0x");
    await verifier.setResult(alice.address, NEW_ID, expiresAt + 1000);
    await registry.connect(alice).register("0x");
    expect(await registry.ownerOfIdentity(ID)).to.equal(alice.address);
    expect(await registry.ownerOfIdentity(NEW_ID)).to.equal(alice.address);
    for (const id of [ID, NEW_ID]) {
      await verifier.setResult(bob.address, id, expiresAt + 1000);
      await expect(registry.connect(bob).register("0x"))
        .to.be.revertedWithCustomError(registry, "IdentityInUse")
        .withArgs(id, alice.address);
    }
    await registry.revoke(ID);
    expect(await registry.identityOf(alice.address)).to.deep.equal([
      NEW_ID,
      BigInt(expiresAt + 1000),
    ]);
    expect(
      await registry.isVerifiedAt(alice.address, await time.latest()),
    ).to.equal(true);
    await time.increaseTo(expiresAt + 1001);
    await verifier.setResult(bob.address, NEW_ID, expiresAt + 2000);
    await expect(registry.connect(bob).register("0x"))
      .to.be.revertedWithCustomError(registry, "IdentityInUse")
      .withArgs(NEW_ID, alice.address);
  });

  it("revokes from the current timestamp and keeps the identifier reserved", async function () {
    const { alice, bob, verifier, registry, expiresAt } =
      await loadFixture(setup);
    await registry.connect(alice).register("0x");
    const snapshot = await time.latest();
    expect(await registry.revocationCountAt(snapshot)).to.equal(0);
    await expect(registry.revoke(ID))
      .to.emit(registry, "IdentityRevoked")
      .withArgs(alice.address, ID);
    const revokedAt = await time.latest();
    expect(await registry.revocationCountAt(revokedAt)).to.equal(1);
    expect(await registry.revocationCountAt(snapshot)).to.equal(0);
    expect(await registry.identityOf(alice.address)).to.deep.equal([
      ethers.ZeroHash,
      0n,
    ]);
    expect(await registry.ownerOfIdentity(ID)).to.equal(alice.address);
    expect(await registry.isVerifiedAt(alice.address, snapshot)).to.equal(true);
    expect(
      await registry.isVerifiedAt(alice.address, await time.latest()),
    ).to.equal(false);
    await verifier.setResult(bob.address, ID, expiresAt);
    for (const caller of [alice, bob]) {
      await expect(registry.connect(caller).register("0x"))
        .to.be.revertedWithCustomError(registry, "IdentityIsRevoked")
        .withArgs(ID);
    }
    await verifier.setResult(alice.address, NEW_ID, expiresAt - 1);
    await registry.connect(alice).register("0x");
    expect(await registry.ownerOfIdentity(ID)).to.equal(alice.address);
    expect(
      await registry.isVerifiedAt(alice.address, await time.latest()),
    ).to.equal(true);
    await registry.revoke(NEW_ID);
    expect(await registry.revocationCountAt(await time.latest())).to.equal(2);
    expect(await registry.revocationCountAt(revokedAt)).to.equal(1);
    expect(await registry.revocationCountAt(snapshot)).to.equal(0);
  });

  it("rejects expired evidence without reserving its identifier", async function () {
    const { alice, registry, expiresAt } = await loadFixture(setup);
    await time.increaseTo(expiresAt + 1);
    await expect(registry.connect(alice).register("0x"))
      .to.be.revertedWithCustomError(registry, "IdentityExpired")
      .withArgs(ID, expiresAt);
    expect(await registry.ownerOfIdentity(ID)).to.equal(ethers.ZeroAddress);
  });

  it("restricts verifier changes and revocation to governance and preserves existing credentials when verification is disabled", async function () {
    const { alice, registry } = await loadFixture(setup);
    await registry.connect(alice).register("0x");
    await expect(
      registry.connect(alice).setVerifier(ethers.ZeroAddress),
    ).to.be.revertedWithCustomError(registry, "OwnableUnauthorizedAccount");
    await expect(
      registry.connect(alice).revoke(ID),
    ).to.be.revertedWithCustomError(registry, "OwnableUnauthorizedAccount");
    await expect(registry.revoke(NEW_ID))
      .to.be.revertedWithCustomError(registry, "UnknownIdentity")
      .withArgs(NEW_ID);
    await expect(registry.setVerifier(ethers.ZeroAddress))
      .to.emit(registry, "VerifierUpdated")
      .withArgs(ethers.ZeroAddress);
    expect(await registry.verifier()).to.equal(ethers.ZeroAddress);
    expect(
      await registry.isVerifiedAt(alice.address, await time.latest()),
    ).to.equal(true);
    await expect(
      registry.connect(alice).register("0x"),
    ).to.be.revertedWithCustomError(registry, "VerifierNotSet");
  });

  it("accepts an unset initial verifier and uses two-step governance transfer", async function () {
    const { governance, alice } = await loadFixture(setup);
    const registry = (await ethers.deployContract("OwnerIdentityRegistry", [
      governance.address,
      ethers.ZeroAddress,
    ])) as unknown as OwnerIdentityRegistry;
    await expect(
      registry.connect(alice).register("0x"),
    ).to.be.revertedWithCustomError(registry, "VerifierNotSet");
    await registry.transferOwnership(alice.address);
    expect(await registry.owner()).to.equal(governance.address);
    await registry.connect(alice).acceptOwnership();
    expect(await registry.owner()).to.equal(alice.address);
  });
});
