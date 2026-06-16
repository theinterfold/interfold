// SPDX-License-Identifier: LGPL-3.0-only
//
// Governance — access control, bounds, events, Ownable2Step.
// Covers Ownable2Step + renounceOwnership disabling on the four
// upgradeable contracts and the two ERC20 tokens, public bounds on
// Interfold / CiphernodeRegistry / BondingRegistry / E3RefundManager /
// SlashingManager, the BondingRegistry distributor cap, the PkVerifierSet / SlashingManager setter events, the
// SortitionCommitteeFinalized event rename, and ParamSetUpdated on
// `setParamSet` overwrites.
import { expect } from "chai";

import { deployInterfoldSystem, ethers } from "../fixtures";

async function deployAll() {
  const sys = await deployInterfoldSystem({
    setupOperators: 0,
    wireSlashingManager: false,
  });
  // The fixture wires `interfold` as a reward distributor; the distributor
  // cap test assumes a clean slate. Revoke it here so the cap counts
  // start at zero.
  await sys.bondingRegistry.revokeRewardDistributor(
    await sys.interfold.getAddress(),
  );
  return {
    ...sys,
    other: sys.notTheOwner,
    ownerAddress: await sys.owner.getAddress(),
  };
}

describe("Governance — access control, bounds & events", function () {
  describe("Ownable2Step + renounceOwnership disabled", function () {
    it("Interfold: transferOwnership is two-step", async function () {
      const { interfold, other, ownerAddress } = await deployAll();
      const otherAddress = await other.getAddress();
      await interfold.transferOwnership(otherAddress);
      expect(await interfold.owner()).to.equal(ownerAddress);
      expect(await interfold.pendingOwner()).to.equal(otherAddress);
      await interfold.connect(other).acceptOwnership();
      expect(await interfold.owner()).to.equal(otherAddress);
    });

    it("CiphernodeRegistry: transferOwnership is two-step", async function () {
      const { ciphernodeRegistry, other, ownerAddress } = await deployAll();
      const otherAddress = await other.getAddress();
      await ciphernodeRegistry.transferOwnership(otherAddress);
      expect(await ciphernodeRegistry.owner()).to.equal(ownerAddress);
      expect(await ciphernodeRegistry.pendingOwner()).to.equal(otherAddress);
      await ciphernodeRegistry.connect(other).acceptOwnership();
      expect(await ciphernodeRegistry.owner()).to.equal(otherAddress);
    });

    it("BondingRegistry: transferOwnership is two-step", async function () {
      const { bondingRegistry, other, ownerAddress } = await deployAll();
      const otherAddress = await other.getAddress();
      await bondingRegistry.transferOwnership(otherAddress);
      expect(await bondingRegistry.owner()).to.equal(ownerAddress);
      expect(await bondingRegistry.pendingOwner()).to.equal(otherAddress);
      await bondingRegistry.connect(other).acceptOwnership();
      expect(await bondingRegistry.owner()).to.equal(otherAddress);
    });

    it("E3RefundManager: transferOwnership is two-step", async function () {
      const { e3RefundManager, other, ownerAddress } = await deployAll();
      const otherAddress = await other.getAddress();
      await e3RefundManager.transferOwnership(otherAddress);
      expect(await e3RefundManager.owner()).to.equal(ownerAddress);
      expect(await e3RefundManager.pendingOwner()).to.equal(otherAddress);
      await e3RefundManager.connect(other).acceptOwnership();
      expect(await e3RefundManager.owner()).to.equal(otherAddress);
    });

    it("InterfoldToken: renounceOwnership reverts", async function () {
      const { licenseToken } = await deployAll();
      await expect(
        licenseToken.renounceOwnership(),
      ).to.be.revertedWithCustomError(
        licenseToken,
        "RenounceOwnershipDisabled",
      );
    });

    it("InterfoldTicketToken: renounceOwnership reverts", async function () {
      const { ticketToken } = await deployAll();
      await expect(
        ticketToken.renounceOwnership(),
      ).to.be.revertedWithCustomError(ticketToken, "RenounceOwnershipDisabled");
    });

    it("Interfold: renounceOwnership reverts", async function () {
      const { interfold } = await deployAll();
      await expect(interfold.renounceOwnership()).to.be.revertedWithCustomError(
        interfold,
        "RenounceOwnershipDisabled",
      );
    });

    it("CiphernodeRegistry: renounceOwnership reverts", async function () {
      const { ciphernodeRegistry } = await deployAll();
      await expect(
        ciphernodeRegistry.renounceOwnership(),
      ).to.be.revertedWithCustomError(
        ciphernodeRegistry,
        "RenounceOwnershipDisabled",
      );
    });

    it("BondingRegistry: renounceOwnership reverts", async function () {
      const { bondingRegistry } = await deployAll();
      await expect(
        bondingRegistry.renounceOwnership(),
      ).to.be.revertedWithCustomError(
        bondingRegistry,
        "RenounceOwnershipDisabled",
      );
    });

    it("E3RefundManager: renounceOwnership reverts", async function () {
      const { e3RefundManager } = await deployAll();
      await expect(
        e3RefundManager.renounceOwnership(),
      ).to.be.revertedWithCustomError(
        e3RefundManager,
        "RenounceOwnershipDisabled",
      );
    });
  });

  describe("Interfold bounds exposed", function () {
    it("setMaxDuration reverts above MAX_DURATION_CAP", async function () {
      const { interfold } = await deployAll();
      const cap = await interfold.MAX_DURATION_CAP();
      await expect(
        interfold.setMaxDuration(cap + 1n),
      ).to.be.revertedWithCustomError(interfold, "InvalidDuration");
    });

    it("exposes MAX_TIMEOUT_WINDOW / MAX_COMMITTEE_SIZE / MAX_*_BPS", async function () {
      const { interfold } = await deployAll();
      expect(await interfold.MAX_DURATION_CAP()).to.equal(
        365n * 24n * 60n * 60n,
      );
      expect(await interfold.MAX_TIMEOUT_WINDOW()).to.equal(
        30n * 24n * 60n * 60n,
      );
      expect(await interfold.MAX_COMMITTEE_SIZE()).to.equal(256n);
      expect(await interfold.MAX_MARGIN_BPS()).to.equal(5_000n);
      expect(await interfold.MAX_PROTOCOL_SHARE_BPS()).to.equal(5_000n);
    });
  });

  describe("registry & bonding bounds", function () {
    it("setSortitionSubmissionWindow reverts when out of bounds", async function () {
      const { ciphernodeRegistry } = await deployAll();
      await expect(
        ciphernodeRegistry.setSortitionSubmissionWindow(0),
      ).to.be.revertedWithCustomError(
        ciphernodeRegistry,
        "SortitionSubmissionWindowOutOfBounds",
      );
      const max = await ciphernodeRegistry.MAX_SORTITION_SUBMISSION_WINDOW();
      await expect(
        ciphernodeRegistry.setSortitionSubmissionWindow(max + 1n),
      ).to.be.revertedWithCustomError(
        ciphernodeRegistry,
        "SortitionSubmissionWindowOutOfBounds",
      );
    });

    it("BondingRegistry.setExitDelay reverts when out of bounds", async function () {
      const { bondingRegistry } = await deployAll();
      const min = await bondingRegistry.MIN_EXIT_DELAY();
      await expect(
        bondingRegistry.setExitDelay(min - 1n),
      ).to.be.revertedWithCustomError(bondingRegistry, "ExitDelayOutOfBounds");
      const max = await bondingRegistry.MAX_EXIT_DELAY();
      await expect(
        bondingRegistry.setExitDelay(max + 1n),
      ).to.be.revertedWithCustomError(bondingRegistry, "ExitDelayOutOfBounds");
    });
  });

  describe("bps and appeal-window caps exposed", function () {
    it("E3RefundManager exposes MAX_PROTOCOL_BPS", async function () {
      const { e3RefundManager } = await deployAll();
      expect(await e3RefundManager.MAX_PROTOCOL_BPS()).to.equal(5_000n);
    });

    it("SlashingManager exposes MAX_APPEAL_WINDOW", async function () {
      const { slashingManager } = await deployAll();
      expect(await slashingManager.MAX_APPEAL_WINDOW()).to.equal(
        30n * 24n * 60n * 60n,
      );
    });
  });

  describe("BondingRegistry distributor cap", function () {
    it("reverts after MAX_AUTHORIZED_DISTRIBUTORS, succeeds after revoke", async function () {
      const { bondingRegistry } = await deployAll();
      const cap = await bondingRegistry.MAX_AUTHORIZED_DISTRIBUTORS();
      const distributors: string[] = [];
      for (let i = 0; i < Number(cap); i++) {
        const w = ethers.Wallet.createRandom();
        distributors.push(w.address);
        await bondingRegistry.setRewardDistributor(w.address);
      }
      const extra = ethers.Wallet.createRandom();
      await expect(
        bondingRegistry.setRewardDistributor(extra.address),
      ).to.be.revertedWithCustomError(
        bondingRegistry,
        "MaxAuthorizedDistributors",
      );
      await bondingRegistry.revokeRewardDistributor(distributors[0]!);
      await bondingRegistry.setRewardDistributor(extra.address);
    });
  });

  describe("PkVerifierSet event", function () {
    it("emits PkVerifierSet when setPkVerifier is called", async function () {
      const { interfold } = await deployAll();
      const schemeId =
        "0x2c2a814a0495f913a3a312fc4771e37552bc14f8a2d4075a08122d356f0849c6";
      const verifier = ethers.Wallet.createRandom().address;
      await expect(interfold.setPkVerifier(schemeId, verifier))
        .to.emit(interfold, "PkVerifierSet")
        .withArgs(schemeId, verifier);
    });
  });

  describe("SlashingManager setter events", function () {
    it("emits BondingRegistryUpdated", async function () {
      const { slashingManager } = await deployAll();
      const target = ethers.Wallet.createRandom().address;
      await expect(slashingManager.setBondingRegistry(target)).to.emit(
        slashingManager,
        "BondingRegistryUpdated",
      );
    });
  });

  describe("SortitionCommitteeFinalized event rename", function () {
    it("ABI exposes SortitionCommitteeFinalized but not CommitteeFinalized", async function () {
      const { ciphernodeRegistry } = await deployAll();
      expect(
        ciphernodeRegistry.interface.getEvent("SortitionCommitteeFinalized"),
      ).to.not.equal(null);
      expect(
        ciphernodeRegistry.interface.getEvent(
          "CommitteeFinalized" as unknown as "SortitionCommitteeFinalized",
        ),
      ).to.equal(null);
    });
  });

  describe("setParamSet overwrite emits ParamSetUpdated", function () {
    it("first call emits ParamSetRegistered; second emits ParamSetUpdated", async function () {
      const { interfold } = await deployAll();
      const abi = ethers.AbiCoder.defaultAbiCoder();
      const a = abi.encode(
        ["uint256", "uint256", "uint256[]"],
        [512, 10, [68719403009n, 68719230977n]],
      );
      const b = abi.encode(
        ["uint256", "uint256", "uint256[]"],
        [1024, 17, [68719403009n]],
      );
      await expect(interfold.setParamSet(7, a))
        .to.emit(interfold, "ParamSetRegistered")
        .withArgs(7, a);
      await expect(interfold.setParamSet(7, b))
        .to.emit(interfold, "ParamSetUpdated")
        .withArgs(7, a, b);
    });
  });
});
