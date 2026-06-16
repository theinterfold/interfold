// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
import { expect } from "chai";
import { network } from "hardhat";

import {
  InterfoldTicketToken__factory as InterfoldTicketTokenFactory,
  MockFeeOnTransferToken__factory as MockFeeOnTransferTokenFactory,
  MockUSDC__factory as MockUSDCFactory,
} from "../../types";

const { ethers, networkHelpers } = await network.connect();
const { loadFixture, time } = networkHelpers;

const AddressOne = "0x0000000000000000000000000000000000000001";
const AddressTwo = "0x0000000000000000000000000000000000000002";
const REGISTRY_CHANGE_DELAY = 24 * 60 * 60;

describe("InterfoldTicketToken", function () {
  async function deploy() {
    const [deployer, initialOwner, registry, otherRegistry, alice, bob] =
      await ethers.getSigners();

    const underlying = await new MockUSDCFactory(deployer).deploy(1_000_000);
    const token = await new InterfoldTicketTokenFactory(deployer).deploy(
      await underlying.getAddress(),
      await registry.getAddress(),
      await initialOwner.getAddress(),
    );

    return {
      deployer,
      initialOwner,
      registry,
      otherRegistry,
      alice,
      bob,
      underlying,
      token,
    };
  }

  // ── H-02 ──────────────────────────────────────────────────────────────────
  describe("H-02 — registry initialization", function () {
    it("constructor sets registry directly without requiring deployer==owner", async function () {
      const { token, registry, initialOwner } = await loadFixture(deploy);
      expect(await token.registry()).to.equal(await registry.getAddress());
      expect(await token.owner()).to.equal(await initialOwner.getAddress());
    });

    it("constructor emits RegistryChanged(0, registry_)", async function () {
      const [deployer, initialOwner, registry] = await ethers.getSigners();
      const underlying = await new MockUSDCFactory(deployer).deploy(1_000);
      const factory = new InterfoldTicketTokenFactory(deployer);
      const token = await factory.deploy(
        await underlying.getAddress(),
        await registry.getAddress(),
        await initialOwner.getAddress(),
      );
      await expect(token.deploymentTransaction())
        .to.emit(token, "RegistryChanged")
        .withArgs(ethers.ZeroAddress, await registry.getAddress());
    });

    it("constructor reverts when registry is zero", async function () {
      const [deployer, initialOwner] = await ethers.getSigners();
      const underlying = await new MockUSDCFactory(deployer).deploy(1_000);
      const factory = new InterfoldTicketTokenFactory(deployer);
      await expect(
        factory.deploy(
          await underlying.getAddress(),
          ethers.ZeroAddress,
          await initialOwner.getAddress(),
        ),
      ).to.be.revertedWithCustomError(factory, "ZeroAddress");
    });
  });

  // ── H-03 ──────────────────────────────────────────────────────────────────
  describe("H-03 — fee-on-transfer safe deposit", function () {
    it("depositFor mints actual amount received, not requested amount", async function () {
      const [deployer, initialOwner, registry, alice] =
        await ethers.getSigners();
      const fot = await new MockFeeOnTransferTokenFactory(deployer).deploy(100); // 1% fee
      const token = await new InterfoldTicketTokenFactory(deployer).deploy(
        await fot.getAddress(),
        await registry.getAddress(),
        await initialOwner.getAddress(),
      );

      const amount = ethers.parseUnits("1000", 18);
      await fot.mint(await registry.getAddress(), amount);
      await fot.connect(registry).approve(await token.getAddress(), amount);

      await token
        .connect(registry)
        .depositFor(await alice.getAddress(), amount);

      const expectedNet = (amount * 9900n) / 10_000n; // 1% fee burned to 0xdead
      expect(await token.balanceOf(await alice.getAddress())).to.equal(
        expectedNet,
      );
      expect(await token.totalSupply()).to.equal(expectedNet);
    });

    it("depositFrom mints actual amount received from third party", async function () {
      const [deployer, initialOwner, registry, alice, bob] =
        await ethers.getSigners();
      const fot = await new MockFeeOnTransferTokenFactory(deployer).deploy(250); // 2.5% fee
      const token = await new InterfoldTicketTokenFactory(deployer).deploy(
        await fot.getAddress(),
        await registry.getAddress(),
        await initialOwner.getAddress(),
      );

      const amount = ethers.parseUnits("400", 18);
      await fot.mint(await alice.getAddress(), amount);
      await fot.connect(alice).approve(await token.getAddress(), amount);

      await token
        .connect(registry)
        .depositFrom(await alice.getAddress(), await bob.getAddress(), amount);

      const expectedNet = (amount * 9750n) / 10_000n;
      expect(await token.balanceOf(await bob.getAddress())).to.equal(
        expectedNet,
      );
    });
  });

  // ── H-16 / H-20 / M-22 ────────────────────────────────────────────────────
  describe("H-16/H-20/M-22 — registry swap lock and timelock", function () {
    it("instant setRegistry works before lock", async function () {
      const { token, initialOwner, otherRegistry } = await loadFixture(deploy);
      await expect(
        token
          .connect(initialOwner)
          .setRegistry(await otherRegistry.getAddress()),
      )
        .to.emit(token, "RegistryChanged")
        .withArgs(
          // old registry (set in fixture)
          (await ethers.getSigners())[2].address,
          await otherRegistry.getAddress(),
        );
      expect(await token.registry()).to.equal(await otherRegistry.getAddress());
    });

    it("setRegistry reverts once locked", async function () {
      const { token, initialOwner, otherRegistry } = await loadFixture(deploy);
      await token.connect(initialOwner).lockRegistry();
      await expect(
        token
          .connect(initialOwner)
          .setRegistry(await otherRegistry.getAddress()),
      ).to.be.revertedWithCustomError(token, "RegistryAlreadyLocked");
    });

    it("lockRegistry is one-way", async function () {
      const { token, initialOwner } = await loadFixture(deploy);
      await expect(token.connect(initialOwner).lockRegistry()).to.emit(
        token,
        "RegistryLocked",
      );
      await expect(
        token.connect(initialOwner).lockRegistry(),
      ).to.be.revertedWithCustomError(token, "RegistryLockAlreadySet");
    });

    it("requestRegistryChange requires the registry to be locked", async function () {
      const { token, initialOwner, otherRegistry } = await loadFixture(deploy);
      await expect(
        token
          .connect(initialOwner)
          .requestRegistryChange(await otherRegistry.getAddress()),
      ).to.be.revertedWithCustomError(token, "RegistryNotLocked");
    });

    it("activateRegistryChange enforces REGISTRY_CHANGE_DELAY", async function () {
      const { token, initialOwner, otherRegistry } = await loadFixture(deploy);
      await token.connect(initialOwner).lockRegistry();
      await token
        .connect(initialOwner)
        .requestRegistryChange(await otherRegistry.getAddress());

      await expect(
        token.connect(initialOwner).activateRegistryChange(),
      ).to.be.revertedWithCustomError(token, "RegistryChangeNotReady");

      await time.increase(REGISTRY_CHANGE_DELAY);

      await expect(
        token.connect(initialOwner).activateRegistryChange(),
      ).to.emit(token, "RegistryChanged");
      expect(await token.registry()).to.equal(await otherRegistry.getAddress());
      expect(await token.pendingRegistry()).to.equal(ethers.ZeroAddress);
    });

    it("cancelRegistryChange clears the pending swap", async function () {
      const { token, initialOwner, otherRegistry } = await loadFixture(deploy);
      await token.connect(initialOwner).lockRegistry();
      await token
        .connect(initialOwner)
        .requestRegistryChange(await otherRegistry.getAddress());
      await expect(token.connect(initialOwner).cancelRegistryChange())
        .to.emit(token, "RegistryChangeCancelled")
        .withArgs(await otherRegistry.getAddress());
      expect(await token.pendingRegistry()).to.equal(ethers.ZeroAddress);
    });
  });

  // ── M-11 ──────────────────────────────────────────────────────────────────
  describe("M-11 — permit disabled", function () {
    it("permit always reverts", async function () {
      const { token, alice } = await loadFixture(deploy);
      await expect(
        token.permit(
          await alice.getAddress(),
          AddressOne,
          1n,
          ethers.MaxUint256,
          27,
          ethers.ZeroHash,
          ethers.ZeroHash,
        ),
      ).to.be.revertedWithCustomError(token, "PermitDisabled");
    });
  });

  // ── M-12 ──────────────────────────────────────────────────────────────────
  describe("M-12 — rescueERC20", function () {
    it("rescues unrelated ERC20s", async function () {
      const { token, initialOwner, alice } = await loadFixture(deploy);
      const stray = await new MockUSDCFactory(initialOwner).deploy(1_000);
      const amount = ethers.parseUnits("100", 6);
      await stray.mint(await token.getAddress(), amount);
      await expect(
        token
          .connect(initialOwner)
          .rescueERC20(
            await stray.getAddress(),
            await alice.getAddress(),
            amount,
          ),
      )
        .to.emit(token, "ERC20Rescued")
        .withArgs(await stray.getAddress(), await alice.getAddress(), amount);
      expect(await stray.balanceOf(await alice.getAddress())).to.equal(amount);
    });

    it("refuses to rescue the underlying asset", async function () {
      const { token, initialOwner, underlying, alice } =
        await loadFixture(deploy);
      await expect(
        token
          .connect(initialOwner)
          .rescueERC20(
            await underlying.getAddress(),
            await alice.getAddress(),
            1n,
          ),
      ).to.be.revertedWithCustomError(token, "CannotRescueUnderlying");
    });
  });

  // ── M-25 ──────────────────────────────────────────────────────────────────
  describe("M-25 — delegation locked to self", function () {
    it("delegate(self) is allowed (no-op for already-self-delegated)", async function () {
      const { token, alice } = await loadFixture(deploy);
      await token.connect(alice).delegate(await alice.getAddress());
      expect(await token.delegates(await alice.getAddress())).to.equal(
        await alice.getAddress(),
      );
    });

    it("delegate(other) reverts with DelegationLocked", async function () {
      const { token, alice, bob } = await loadFixture(deploy);
      await expect(
        token.connect(alice).delegate(await bob.getAddress()),
      ).to.be.revertedWithCustomError(token, "DelegationLocked");
    });

    it("delegateBySig reverts", async function () {
      const { token } = await loadFixture(deploy);
      await expect(
        token.delegateBySig(
          AddressOne,
          0n,
          ethers.MaxUint256,
          27,
          ethers.ZeroHash,
          ethers.ZeroHash,
        ),
      ).to.be.revertedWithCustomError(token, "DelegationLocked");
    });
  });

  // ── M-29 ──────────────────────────────────────────────────────────────────
  describe("M-29 — EIP-6372 timestamp clock", function () {
    it("clock() returns block.timestamp", async function () {
      const { token } = await loadFixture(deploy);
      const ts = await time.latest();
      expect(await token.clock()).to.equal(ts);
    });

    it("CLOCK_MODE() returns mode=timestamp", async function () {
      const { token } = await loadFixture(deploy);
      expect(await token.CLOCK_MODE()).to.equal("mode=timestamp");
    });
  });

  // Silence unused-binding lint for AddressTwo
  void AddressTwo;
});
