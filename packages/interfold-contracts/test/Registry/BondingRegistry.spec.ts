// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
import { expect } from "chai";

import { MockFeeOnTransferToken__factory as MockFeeOnTransferTokenFactory } from "../../types";
import {
  ADDRESS_TWO as AddressTwo,
  MIN_TICKET_BALANCE,
  REQUIRED_CIPHERNODE_BOND,
  SEVEN_DAYS,
  TICKET_PRICE,
  deployInterfoldSystem,
  deploySlashingManager,
  ethers,
  networkHelpers,
  setBondingAssetConfig,
} from "../fixtures";

const { loadFixture, time } = networkHelpers;

const REASON_DEPOSIT = ethers.encodeBytes32String("DEPOSIT");
const REASON_WITHDRAW = ethers.encodeBytes32String("WITHDRAW");
const REASON_BOND = ethers.encodeBytes32String("BOND");
const REASON_UNBOND = ethers.encodeBytes32String("UNBOND");

describe("BondingRegistry", function () {
  const SEVEN_DAYS_IN_SECONDS = SEVEN_DAYS;
  let operator1Address: string;
  let operator2Address: string;
  let operator1OwnerAddress: string;
  let operator2OwnerAddress: string;

  async function setup() {
    const signers = await ethers.getSigners();
    const [
      owner,
      operatorKey1,
      operatorKey2,
      treasury,
      notTheOwner,
      operator1,
      operator2,
    ] = signers;
    const ownerAddress = await owner.getAddress();
    operator1Address = await operatorKey1.getAddress();
    operator2Address = await operatorKey2.getAddress();
    operator1OwnerAddress = await operator1.getAddress();
    operator2OwnerAddress = await operator2.getAddress();
    const treasuryAddress = await treasury.getAddress();

    const sys = await deployInterfoldSystem({
      useMockCiphernodeRegistry: true,
      setupOperators: 0,
      wireSlashingManager: false,
      slashedFundsTreasury: treasury,
      mintUsdcTo: [],
    });
    const {
      bondingRegistry,
      ticketToken,
      ciphernodeBondToken,
      usdcToken,
      slashingManager,
      mockCiphernodeRegistry,
      nodeReleaseRegistry,
    } = sys;
    // Spec consumes the (mock) registry typed as the real interface.
    const ciphernodeRegistry = mockCiphernodeRegistry!;

    // ── Mint Tokens (owner + spec-local bond owners) ────────────────────────
    const USDC_AMOUNT = ethers.parseUnits("100000", 6);
    const LICENSE_AMOUNT = ethers.parseEther("100000");

    for (const address of [
      ownerAddress,
      operator1OwnerAddress,
      operator2OwnerAddress,
    ]) {
      await usdcToken.mint(address, USDC_AMOUNT);
      await ciphernodeBondToken.mint(
        address,
        LICENSE_AMOUNT,
        ethers.encodeBytes32String("Test allocation"),
      );
    }
    await bondingRegistry
      .connect(operatorKey1)
      .setBondOwner(operator1OwnerAddress);
    await bondingRegistry
      .connect(operatorKey2)
      .setBondOwner(operator2OwnerAddress);
    await nodeReleaseRegistry
      .connect(operatorKey1)
      .acknowledgeNodeRelease(
        ethers.id("interfold.node.release:v1:test"),
        1,
        1,
      );
    await nodeReleaseRegistry
      .connect(operatorKey2)
      .acknowledgeNodeRelease(
        ethers.id("interfold.node.release:v1:test"),
        1,
        1,
      );

    return {
      bondingRegistry,
      ticketToken,
      ciphernodeBondToken,
      usdcToken,
      slashingManager,
      ciphernodeRegistry,
      owner,
      operatorKey1,
      operatorKey2,
      operator1,
      operator2,
      treasury,
      notTheOwner,
      ownerAddress,
      operator1Address,
      operator2Address,
      operator1OwnerAddress,
      operator2OwnerAddress,
      treasuryAddress,
    };
  }

  async function impersonateSlashingManager(
    slashingManager: Awaited<ReturnType<typeof setup>>["slashingManager"],
  ) {
    const managerAddress = await slashingManager.getAddress();
    await networkHelpers.setBalance(managerAddress, ethers.parseEther("1"));
    await networkHelpers.impersonateAccount(managerAddress);
    return ethers.getSigner(managerAddress);
  }
  describe("constructor / initialize()", function () {
    it("correctly sets initial parameters", async function () {
      const {
        bondingRegistry,
        ticketToken,
        ciphernodeBondToken,
        treasuryAddress,
      } = await loadFixture(setup);

      expect(await bondingRegistry.ticketToken()).to.equal(
        await ticketToken.getAddress(),
      );
      expect(await bondingRegistry.ciphernodeBondToken()).to.equal(
        await ciphernodeBondToken.getAddress(),
      );
      expect(await bondingRegistry.slashedFundsTreasury()).to.equal(
        treasuryAddress,
      );
      expect(await bondingRegistry.ticketPrice()).to.equal(TICKET_PRICE);
      expect(await bondingRegistry.requiredCiphernodeBond()).to.equal(
        REQUIRED_CIPHERNODE_BOND,
      );
      expect(await bondingRegistry.minTicketBalance()).to.equal(
        MIN_TICKET_BALANCE,
      );
      expect(await bondingRegistry.exitDelay()).to.equal(SEVEN_DAYS_IN_SECONDS);
      expect(await bondingRegistry.ciphernodeBondActiveBps()).to.equal(8000);
    });
  });

  describe("separate bond owner and operator key", function () {
    it("keeps the operator as protocol identity while the owner controls collateral", async function () {
      const {
        bondingRegistry,
        ticketToken,
        ciphernodeBondToken,
        usdcToken,
        operatorKey1,
        operator1,
        operator1Address,
        operator1OwnerAddress,
      } = await loadFixture(setup);
      const registryAddress = await bondingRegistry.getAddress();
      const ticketTokenAddress = await ticketToken.getAddress();
      const bondAmount = REQUIRED_CIPHERNODE_BOND;
      const ticketAmount = ethers.parseUnits("100", 6);

      expect(await bondingRegistry.bondOwnerOf(operator1Address)).to.equal(
        operator1OwnerAddress,
      );

      await ciphernodeBondToken
        .connect(operator1)
        .approve(registryAddress, bondAmount);
      await bondingRegistry
        .connect(operator1)
        .bondCiphernodeFor(operator1Address, bondAmount);
      expect(
        await bondingRegistry.getCiphernodeBond(operator1Address),
      ).to.equal(bondAmount);
      expect(await bondingRegistry.totalBonded(operator1OwnerAddress)).to.equal(
        bondAmount,
      );
      expect(await bondingRegistry.totalBonded(operator1Address)).to.equal(0);

      await bondingRegistry
        .connect(operator1)
        .registerOperatorFor(operator1Address);
      expect(await bondingRegistry.isRegistered(operator1Address)).to.be.true;

      await usdcToken
        .connect(operator1)
        .approve(ticketTokenAddress, ticketAmount);
      await bondingRegistry
        .connect(operator1)
        .addTicketBalanceFor(operator1Address, ticketAmount);
      expect(await ticketToken.balanceOf(operator1Address)).to.equal(
        ticketAmount,
      );
      expect(await ticketToken.balanceOf(operator1OwnerAddress)).to.equal(0);

      await expect(
        bondingRegistry
          .connect(operatorKey1)
          .unbondCiphernodeFor(operator1Address, 1),
      )
        .to.be.revertedWithCustomError(bondingRegistry, "NotBondOwner")
        .withArgs(operator1Address, operator1Address);

      await bondingRegistry
        .connect(operatorKey1)
        .deregisterOperatorFor(operator1Address);
      await time.increase(SEVEN_DAYS_IN_SECONDS + 1);

      const ownerUsdcBefore = await usdcToken.balanceOf(operator1OwnerAddress);
      const ownerFoldBefore = await ciphernodeBondToken.balanceOf(
        operator1OwnerAddress,
      );
      const operatorUsdcBefore = await usdcToken.balanceOf(operator1Address);
      const operatorFoldBefore =
        await ciphernodeBondToken.balanceOf(operator1Address);

      await expect(
        bondingRegistry
          .connect(operatorKey1)
          .claimExitsFor(operator1Address, ticketAmount, bondAmount),
      )
        .to.be.revertedWithCustomError(bondingRegistry, "NotBondOwner")
        .withArgs(operator1Address, operator1Address);
      await bondingRegistry
        .connect(operator1)
        .claimExitsFor(operator1Address, ticketAmount, bondAmount);

      expect(await usdcToken.balanceOf(operator1OwnerAddress)).to.equal(
        ownerUsdcBefore + ticketAmount,
      );
      expect(
        await ciphernodeBondToken.balanceOf(operator1OwnerAddress),
      ).to.equal(ownerFoldBefore + bondAmount);
      expect(await usdcToken.balanceOf(operator1Address)).to.equal(
        operatorUsdcBefore,
      );
      expect(await ciphernodeBondToken.balanceOf(operator1Address)).to.equal(
        operatorFoldBefore,
      );
      expect(await bondingRegistry.totalBonded(operator1OwnerAddress)).to.equal(
        0,
      );
    });

    it("allows self-ownership while blocking direct reassignment", async function () {
      const { bondingRegistry, ciphernodeBondToken } = await loadFixture(setup);
      const signers = await ethers.getSigners();
      const operator = signers[7];
      const bondOwner = signers[8];
      const operatorAddress = await operator.getAddress();
      const bondOwnerAddress = await bondOwner.getAddress();
      const registryAddress = await bondingRegistry.getAddress();
      const bondAmount = REQUIRED_CIPHERNODE_BOND;

      expect(await bondingRegistry.bondOwnerOf(operatorAddress)).to.equal(
        ethers.ZeroAddress,
      );
      await expect(
        bondingRegistry.connect(operator).setBondOwner(ethers.ZeroAddress),
      )
        .to.be.revertedWithCustomError(bondingRegistry, "ZeroAddress")
        .withArgs();
      await expect(
        bondingRegistry
          .connect(bondOwner)
          .bondCiphernodeFor(operatorAddress, REQUIRED_CIPHERNODE_BOND),
      )
        .to.be.revertedWithCustomError(bondingRegistry, "NotBondOwner")
        .withArgs(bondOwnerAddress, operatorAddress);
      await expect(
        bondingRegistry.connect(operator).setBondOwner(operatorAddress),
      )
        .to.emit(bondingRegistry, "BondOwnerSet")
        .withArgs(operatorAddress, operatorAddress);

      await ciphernodeBondToken.mint(
        operatorAddress,
        bondAmount,
        ethers.encodeBytes32String("Self-owned operator"),
      );
      await ciphernodeBondToken
        .connect(operator)
        .approve(registryAddress, bondAmount);
      await bondingRegistry
        .connect(operator)
        .bondCiphernodeFor(operatorAddress, bondAmount);

      expect(await bondingRegistry.getCiphernodeBond(operatorAddress)).to.equal(
        bondAmount,
      );
      expect(await bondingRegistry.totalBonded(operatorAddress)).to.equal(
        bondAmount,
      );
      await expect(
        bondingRegistry.connect(operator).setBondOwner(signers[9].address),
      )
        .to.be.revertedWithCustomError(bondingRegistry, "BondOwnerAlreadySet")
        .withArgs(operatorAddress, operatorAddress);
    });

    it("allows the operator to correct an owner before the position is funded", async function () {
      const { bondingRegistry } = await loadFixture(setup);
      const signers = await ethers.getSigners();
      const operator = signers[7];
      const typoOwner = signers[8];
      const correctedOwner = signers[9];
      const operatorAddress = await operator.getAddress();
      const correctedOwnerAddress = await correctedOwner.getAddress();

      await bondingRegistry
        .connect(operator)
        .setBondOwner(await typoOwner.getAddress());
      await expect(
        bondingRegistry.connect(operator).setBondOwner(correctedOwnerAddress),
      )
        .to.emit(bondingRegistry, "BondOwnerSet")
        .withArgs(operatorAddress, correctedOwnerAddress);

      expect(await bondingRegistry.bondOwnerOf(operatorAddress)).to.equal(
        correctedOwnerAddress,
      );
    });

    it("transfers ownership and migrates active plus pending FOLD accounting", async function () {
      const {
        bondingRegistry,
        ciphernodeBondToken,
        operator1,
        operator2,
        operator1Address,
        operator1OwnerAddress,
        operator2OwnerAddress,
        notTheOwner,
      } = await loadFixture(setup);
      const bondAmount = ethers.parseEther("1000");
      const pendingAmount = ethers.parseEther("300");

      await ciphernodeBondToken
        .connect(operator1)
        .approve(await bondingRegistry.getAddress(), bondAmount);
      await bondingRegistry
        .connect(operator1)
        .bondCiphernodeFor(operator1Address, bondAmount);
      await bondingRegistry
        .connect(operator1)
        .unbondCiphernodeFor(operator1Address, pendingAmount);

      await expect(
        bondingRegistry
          .connect(notTheOwner)
          .proposeBondOwner(operator1Address, operator2OwnerAddress),
      )
        .to.be.revertedWithCustomError(bondingRegistry, "NotBondOwner")
        .withArgs(await notTheOwner.getAddress(), operator1Address);

      await expect(
        bondingRegistry
          .connect(operator1)
          .proposeBondOwner(operator1Address, operator2OwnerAddress),
      )
        .to.emit(bondingRegistry, "BondOwnerTransferProposed")
        .withArgs(
          operator1Address,
          operator1OwnerAddress,
          operator2OwnerAddress,
        );
      expect(
        await bondingRegistry.pendingBondOwnerOf(operator1Address),
      ).to.equal(operator2OwnerAddress);

      await expect(
        bondingRegistry.connect(notTheOwner).acceptBondOwner(operator1Address),
      ).to.be.revertedWithCustomError(bondingRegistry, "Unauthorized");

      await expect(
        bondingRegistry.connect(operator2).acceptBondOwner(operator1Address),
      )
        .to.emit(bondingRegistry, "BondOwnerSet")
        .withArgs(operator1Address, operator2OwnerAddress);

      expect(await bondingRegistry.bondOwnerOf(operator1Address)).to.equal(
        operator2OwnerAddress,
      );
      expect(
        await bondingRegistry.pendingBondOwnerOf(operator1Address),
      ).to.equal(ethers.ZeroAddress);
      expect(await bondingRegistry.totalBonded(operator1OwnerAddress)).to.equal(
        0,
      );
      expect(await bondingRegistry.totalBonded(operator2OwnerAddress)).to.equal(
        bondAmount,
      );

      await time.increase(SEVEN_DAYS_IN_SECONDS + 1);
      const before = await ciphernodeBondToken.balanceOf(operator2OwnerAddress);
      await bondingRegistry
        .connect(operator2)
        .claimExitsFor(operator1Address, 0, pendingAmount);
      expect(
        await ciphernodeBondToken.balanceOf(operator2OwnerAddress),
      ).to.equal(before + pendingAmount);
      expect(await bondingRegistry.totalBonded(operator2OwnerAddress)).to.equal(
        bondAmount - pendingAmount,
      );
    });

    it("aggregates owned FOLD and reduces the owner's lock on slash", async function () {
      const {
        bondingRegistry,
        ciphernodeBondToken,
        owner,
        slashingManager,
        ownerAddress,
      } = await loadFixture(setup);
      const signers = await ethers.getSigners();
      const operator1 = signers[7];
      const operator2 = signers[8];
      const operator1Address = await operator1.getAddress();
      const operator2Address = await operator2.getAddress();
      const bondAmount = REQUIRED_CIPHERNODE_BOND;
      const slashAmount = bondAmount / 2n;

      await bondingRegistry.connect(operator1).setBondOwner(ownerAddress);
      await bondingRegistry.connect(operator2).setBondOwner(ownerAddress);
      await ciphernodeBondToken
        .connect(owner)
        .approve(await bondingRegistry.getAddress(), bondAmount * 2n);
      await bondingRegistry
        .connect(owner)
        .bondCiphernodeFor(operator1Address, bondAmount);
      await bondingRegistry
        .connect(owner)
        .bondCiphernodeFor(operator2Address, bondAmount);

      expect(await bondingRegistry.totalBonded(ownerAddress)).to.equal(
        bondAmount * 2n,
      );

      const slashSigner = await impersonateSlashingManager(slashingManager);
      await bondingRegistry
        .connect(slashSigner)
        .slashCiphernodeBond(
          operator1Address,
          slashAmount,
          ethers.encodeBytes32String("TEST_SLASH"),
        );
      await networkHelpers.stopImpersonatingAccount(
        await slashingManager.getAddress(),
      );

      expect(await bondingRegistry.totalBonded(ownerAddress)).to.equal(
        bondAmount * 2n - slashAmount,
      );
      expect(await bondingRegistry.totalBonded(operator1Address)).to.equal(0);
      expect(await bondingRegistry.totalBonded(operator2Address)).to.equal(0);
    });

    it("routes distributor rewards to the configured owner", async function () {
      const {
        bondingRegistry,
        usdcToken,
        owner,
        notTheOwner,
        operator1Address,
        operator1OwnerAddress,
      } = await loadFixture(setup);
      const ownerAddress = await owner.getAddress();
      const fallbackRecipient = await notTheOwner.getAddress();
      const ownerReward = ethers.parseUnits("10", 6);
      const fallbackReward = ethers.parseUnits("5", 6);

      await bondingRegistry.setRewardDistributor(ownerAddress);
      await usdcToken
        .connect(owner)
        .approve(
          await bondingRegistry.getAddress(),
          ownerReward + fallbackReward,
        );

      const bondOwnerBefore = await usdcToken.balanceOf(operator1OwnerAddress);
      const operatorBefore = await usdcToken.balanceOf(operator1Address);
      const fallbackBefore = await usdcToken.balanceOf(fallbackRecipient);
      await bondingRegistry.distributeRewards(
        await usdcToken.getAddress(),
        [operator1Address, fallbackRecipient],
        [ownerReward, fallbackReward],
      );

      expect(await usdcToken.balanceOf(operator1OwnerAddress)).to.equal(
        bondOwnerBefore + ownerReward,
      );
      expect(await usdcToken.balanceOf(operator1Address)).to.equal(
        operatorBefore,
      );
      expect(await usdcToken.balanceOf(fallbackRecipient)).to.equal(
        fallbackBefore + fallbackReward,
      );
    });
  });

  describe("bondCiphernodeFor()", function () {
    it("allows operators to bond FOLD", async function () {
      const { bondingRegistry, ciphernodeBondToken, operator1 } =
        await loadFixture(setup);

      const bondAmount = ethers.parseEther("1000");
      await ciphernodeBondToken
        .connect(operator1)
        .approve(await bondingRegistry.getAddress(), bondAmount);

      await expect(
        bondingRegistry
          .connect(operator1)
          .bondCiphernodeFor(operator1Address, bondAmount),
      )
        .to.emit(bondingRegistry, "CiphernodeBondUpdated")
        .withArgs(operator1Address, bondAmount, bondAmount, REASON_BOND);

      expect(
        await bondingRegistry.getCiphernodeBond(operator1Address),
      ).to.equal(bondAmount);
      expect(await bondingRegistry.totalBonded(operator1OwnerAddress)).to.equal(
        bondAmount,
      );
      expect(await bondingRegistry.totalCiphernodeBondLiability()).to.equal(
        bondAmount,
      );
    });

    it("reverts if amount is zero", async function () {
      const { bondingRegistry, operator1 } = await loadFixture(setup);

      await expect(
        bondingRegistry
          .connect(operator1)
          .bondCiphernodeFor(operator1Address, 0),
      ).to.be.revertedWithCustomError(bondingRegistry, "ZeroAmount");
    });

    it("enforces bond-owner authorization inside the accounting path", async function () {
      const { bondingRegistry, notTheOwner } = await loadFixture(setup);
      const caller = await notTheOwner.getAddress();

      await expect(
        bondingRegistry
          .connect(notTheOwner)
          .bondCiphernodeFor(operator1Address, REQUIRED_CIPHERNODE_BOND),
      )
        .to.be.revertedWithCustomError(bondingRegistry, "NotBondOwner")
        .withArgs(caller, operator1Address);

      await expect(
        bondingRegistry
          .connect(notTheOwner)
          .bondCiphernodeFor(ethers.ZeroAddress, REQUIRED_CIPHERNODE_BOND),
      ).to.be.revertedWithCustomError(bondingRegistry, "ZeroAddress");
    });

    it("reverts if exit is in progress", async function () {
      const { bondingRegistry, ciphernodeBondToken, operator1 } =
        await loadFixture(setup);

      const bondAmount = ethers.parseEther("1000");
      await ciphernodeBondToken
        .connect(operator1)
        .approve(await bondingRegistry.getAddress(), bondAmount);
      await bondingRegistry
        .connect(operator1)
        .bondCiphernodeFor(operator1Address, bondAmount);

      await bondingRegistry
        .connect(operator1)
        .registerOperatorFor(operator1Address);

      await bondingRegistry
        .connect(operator1)
        .deregisterOperatorFor(operator1Address);

      await ciphernodeBondToken
        .connect(operator1)
        .approve(await bondingRegistry.getAddress(), bondAmount);
      await expect(
        bondingRegistry
          .connect(operator1)
          .bondCiphernodeFor(operator1Address, bondAmount),
      ).to.be.revertedWithCustomError(bondingRegistry, "ExitInProgress");
    });

    it("accumulates multiple bond amounts", async function () {
      const { bondingRegistry, ciphernodeBondToken, operator1 } =
        await loadFixture(setup);

      const bondAmount1 = ethers.parseEther("500");
      const bondAmount2 = ethers.parseEther("300");

      await ciphernodeBondToken
        .connect(operator1)
        .approve(await bondingRegistry.getAddress(), bondAmount1);
      await bondingRegistry
        .connect(operator1)
        .bondCiphernodeFor(operator1Address, bondAmount1);

      await ciphernodeBondToken
        .connect(operator1)
        .approve(await bondingRegistry.getAddress(), bondAmount2);
      await bondingRegistry
        .connect(operator1)
        .bondCiphernodeFor(operator1Address, bondAmount2);

      expect(
        await bondingRegistry.getCiphernodeBond(operator1Address),
      ).to.equal(bondAmount1 + bondAmount2);
    });
  });

  describe("unbondCiphernodeFor()", function () {
    it("allows operators to unbond FOLD", async function () {
      const { bondingRegistry, ciphernodeBondToken, operator1 } =
        await loadFixture(setup);

      const bondAmount = ethers.parseEther("1000");
      const unbondAmount = ethers.parseEther("200");

      await ciphernodeBondToken
        .connect(operator1)
        .approve(await bondingRegistry.getAddress(), bondAmount);
      await bondingRegistry
        .connect(operator1)
        .bondCiphernodeFor(operator1Address, bondAmount);

      await expect(
        bondingRegistry
          .connect(operator1)
          .unbondCiphernodeFor(operator1Address, unbondAmount),
      )
        .to.emit(bondingRegistry, "CiphernodeBondUpdated")
        .withArgs(
          operator1Address,
          -unbondAmount,
          bondAmount - unbondAmount,
          REASON_UNBOND,
        );

      expect(
        await bondingRegistry.getCiphernodeBond(operator1Address),
      ).to.equal(bondAmount - unbondAmount);
    });

    it("reverts if amount is zero", async function () {
      const { bondingRegistry, operator1 } = await loadFixture(setup);

      await expect(
        bondingRegistry
          .connect(operator1)
          .unbondCiphernodeFor(operator1Address, 0),
      ).to.be.revertedWithCustomError(bondingRegistry, "ZeroAmount");
    });

    it("reverts if insufficient balance", async function () {
      const { bondingRegistry, operator1 } = await loadFixture(setup);

      await expect(
        bondingRegistry
          .connect(operator1)
          .unbondCiphernodeFor(operator1Address, ethers.parseEther("100")),
      ).to.be.revertedWithCustomError(bondingRegistry, "InsufficientBalance");
    });

    it("queues ciphernode bond tokens for exit", async function () {
      const { bondingRegistry, ciphernodeBondToken, operator1 } =
        await loadFixture(setup);

      const bondAmount = ethers.parseEther("1000");
      const unbondAmount = ethers.parseEther("200");

      await ciphernodeBondToken
        .connect(operator1)
        .approve(await bondingRegistry.getAddress(), bondAmount);
      await bondingRegistry
        .connect(operator1)
        .bondCiphernodeFor(operator1Address, bondAmount);

      await bondingRegistry
        .connect(operator1)
        .unbondCiphernodeFor(operator1Address, unbondAmount);

      const [, ciphernodeBondPending] =
        await bondingRegistry.pendingExits(operator1Address);
      expect(ciphernodeBondPending).to.equal(unbondAmount);
      expect(await bondingRegistry.totalBonded(operator1OwnerAddress)).to.equal(
        bondAmount,
      );
    });

    it("slashes active and pending ciphernode bond from totalBonded", async function () {
      const {
        bondingRegistry,
        ciphernodeBondToken,
        operator1,
        slashingManager,
      } = await loadFixture(setup);
      const operatorAddress = operator1Address;
      const slashReason = ethers.encodeBytes32String("TEST_SLASH");

      const bondAmount = ethers.parseEther("1000");
      const unbondAmount = ethers.parseEther("300");
      const slashAmount = ethers.parseEther("800");

      await ciphernodeBondToken
        .connect(operator1)
        .approve(await bondingRegistry.getAddress(), bondAmount);
      await bondingRegistry
        .connect(operator1)
        .bondCiphernodeFor(operator1Address, bondAmount);
      await bondingRegistry
        .connect(operator1)
        .unbondCiphernodeFor(operator1Address, unbondAmount);
      const slashSigner = await impersonateSlashingManager(slashingManager);

      await expect(
        bondingRegistry
          .connect(slashSigner)
          .slashCiphernodeBond(operatorAddress, slashAmount, slashReason),
      )
        .to.emit(bondingRegistry, "CiphernodeBondUpdated")
        .withArgs(operatorAddress, -slashAmount, 0, slashReason);
      await networkHelpers.stopImpersonatingAccount(
        await slashingManager.getAddress(),
      );

      const [, pendingCiphernodeBond] =
        await bondingRegistry.pendingExits(operatorAddress);
      expect(pendingCiphernodeBond).to.equal(bondAmount - slashAmount);
      expect(await bondingRegistry.totalBonded(operator1OwnerAddress)).to.equal(
        bondAmount - slashAmount,
      );
      expect(await bondingRegistry.slashedCiphernodeBond()).to.equal(
        slashAmount,
      );
      expect(await bondingRegistry.totalCiphernodeBondLiability()).to.equal(
        bondAmount,
      );
    });
  });

  describe("registerOperatorFor()", function () {
    it("allows properly bonded operators to register", async function () {
      const { bondingRegistry, ciphernodeBondToken, operator1 } =
        await loadFixture(setup);

      const bondAmount = REQUIRED_CIPHERNODE_BOND;
      await ciphernodeBondToken
        .connect(operator1)
        .approve(await bondingRegistry.getAddress(), bondAmount);
      await bondingRegistry
        .connect(operator1)
        .bondCiphernodeFor(operator1Address, bondAmount);

      await bondingRegistry
        .connect(operator1)
        .registerOperatorFor(operator1Address);

      expect(await bondingRegistry.isRegistered(operator1Address)).to.be.true;
      expect(await bondingRegistry.isActive(operator1Address)).to.be.false;
    });

    it("reverts if not properly bonded", async function () {
      const { bondingRegistry, operator1 } = await loadFixture(setup);

      await expect(
        bondingRegistry
          .connect(operator1)
          .registerOperatorFor(operator1Address),
      ).to.be.revertedWithCustomError(bondingRegistry, "NotCiphernodeBonded");
    });

    it("reverts on a bond that only meets the active-maintenance floor", async function () {
      const { bondingRegistry, ciphernodeBondToken, operator1 } =
        await loadFixture(setup);

      // isCiphernodeBonded() tests requiredCiphernodeBond * ciphernodeBondActiveBps (80% by
      // default). Registration requires the full bond, so a bond inside that
      // window reads as bonded but must still be rejected.
      const activeBps = await bondingRegistry.ciphernodeBondActiveBps();
      const flooredBond = (REQUIRED_CIPHERNODE_BOND * activeBps) / 10_000n;
      expect(flooredBond).to.be.lessThan(REQUIRED_CIPHERNODE_BOND);

      await ciphernodeBondToken
        .connect(operator1)
        .approve(await bondingRegistry.getAddress(), flooredBond);
      await bondingRegistry
        .connect(operator1)
        .bondCiphernodeFor(operator1Address, flooredBond);

      expect(
        await bondingRegistry.isCiphernodeBonded(operator1Address),
      ).to.equal(true);

      await expect(
        bondingRegistry
          .connect(operator1)
          .registerOperatorFor(operator1Address),
      ).to.be.revertedWithCustomError(bondingRegistry, "NotCiphernodeBonded");
    });

    it("reverts if already registered", async function () {
      const { bondingRegistry, ciphernodeBondToken, operator1 } =
        await loadFixture(setup);

      const bondAmount = REQUIRED_CIPHERNODE_BOND;
      await ciphernodeBondToken
        .connect(operator1)
        .approve(await bondingRegistry.getAddress(), bondAmount);
      await bondingRegistry
        .connect(operator1)
        .bondCiphernodeFor(operator1Address, bondAmount);
      await bondingRegistry
        .connect(operator1)
        .registerOperatorFor(operator1Address);

      await expect(
        bondingRegistry
          .connect(operator1)
          .registerOperatorFor(operator1Address),
      ).to.be.revertedWithCustomError(bondingRegistry, "AlreadyRegistered");
    });

    it("clears previous exit request when re-registering", async function () {
      const { bondingRegistry, ciphernodeBondToken, operator1 } =
        await loadFixture(setup);

      const bondAmount = REQUIRED_CIPHERNODE_BOND;
      await ciphernodeBondToken
        .connect(operator1)
        .approve(await bondingRegistry.getAddress(), bondAmount);
      await bondingRegistry
        .connect(operator1)
        .bondCiphernodeFor(operator1Address, bondAmount);
      await bondingRegistry
        .connect(operator1)
        .registerOperatorFor(operator1Address);

      await bondingRegistry
        .connect(operator1)
        .deregisterOperatorFor(operator1Address);

      await time.increase(SEVEN_DAYS_IN_SECONDS + 1);

      await ciphernodeBondToken
        .connect(operator1)
        .approve(await bondingRegistry.getAddress(), bondAmount);
      await bondingRegistry
        .connect(operator1)
        .bondCiphernodeFor(operator1Address, bondAmount);
      await bondingRegistry
        .connect(operator1)
        .registerOperatorFor(operator1Address);

      expect(await bondingRegistry.hasExitInProgress(operator1Address)).to.be
        .false;
    });
  });

  describe("deregisterOperatorFor()", function () {
    it("allows registered operators to deregister", async function () {
      const { bondingRegistry, ciphernodeBondToken, operator1 } =
        await loadFixture(setup);

      const bondAmount = REQUIRED_CIPHERNODE_BOND;
      await ciphernodeBondToken
        .connect(operator1)
        .approve(await bondingRegistry.getAddress(), bondAmount);
      await bondingRegistry
        .connect(operator1)
        .bondCiphernodeFor(operator1Address, bondAmount);
      await bondingRegistry
        .connect(operator1)
        .registerOperatorFor(operator1Address);

      const latestTime = await time.latest();
      await expect(
        bondingRegistry
          .connect(operator1)
          .deregisterOperatorFor(operator1Address),
      )
        .to.emit(bondingRegistry, "CiphernodeDeregistrationRequested")
        .withArgs(operator1Address, latestTime + SEVEN_DAYS_IN_SECONDS + 1);

      expect(await bondingRegistry.isRegistered(operator1Address)).to.be.false;
      expect(await bondingRegistry.hasExitInProgress(operator1Address)).to.be
        .true;
    });

    it("allows the operator key to trigger an emergency exit", async function () {
      const { bondingRegistry, ciphernodeBondToken, operatorKey1, operator1 } =
        await loadFixture(setup);

      await ciphernodeBondToken
        .connect(operator1)
        .approve(await bondingRegistry.getAddress(), REQUIRED_CIPHERNODE_BOND);
      await bondingRegistry
        .connect(operator1)
        .bondCiphernodeFor(operator1Address, REQUIRED_CIPHERNODE_BOND);
      await bondingRegistry
        .connect(operator1)
        .registerOperatorFor(operator1Address);

      await expect(
        bondingRegistry
          .connect(operatorKey1)
          .deregisterOperatorFor(operator1Address),
      ).to.emit(bondingRegistry, "CiphernodeDeregistrationRequested");
      expect(await bondingRegistry.isRegistered(operator1Address)).to.be.false;
    });

    it("rejects deregistration by unrelated callers", async function () {
      const { bondingRegistry, ciphernodeBondToken, operator1, notTheOwner } =
        await loadFixture(setup);

      await ciphernodeBondToken
        .connect(operator1)
        .approve(await bondingRegistry.getAddress(), REQUIRED_CIPHERNODE_BOND);
      await bondingRegistry
        .connect(operator1)
        .bondCiphernodeFor(operator1Address, REQUIRED_CIPHERNODE_BOND);
      await bondingRegistry
        .connect(operator1)
        .registerOperatorFor(operator1Address);

      await expect(
        bondingRegistry
          .connect(notTheOwner)
          .deregisterOperatorFor(operator1Address),
      )
        .to.be.revertedWithCustomError(bondingRegistry, "NotBondOwner")
        .withArgs(await notTheOwner.getAddress(), operator1Address);
    });

    it("reverts if not registered", async function () {
      const { bondingRegistry, operator1 } = await loadFixture(setup);

      await expect(
        bondingRegistry
          .connect(operator1)
          .deregisterOperatorFor(operator1Address),
      ).to.be.revertedWithCustomError(bondingRegistry, "NotRegistered");
    });

    it("queues assets for exit when deregistering", async function () {
      const {
        bondingRegistry,
        ciphernodeBondToken,
        usdcToken,
        ticketToken,
        operator1,
      } = await loadFixture(setup);

      const bondAmount = REQUIRED_CIPHERNODE_BOND;
      await ciphernodeBondToken
        .connect(operator1)
        .approve(await bondingRegistry.getAddress(), bondAmount);
      await bondingRegistry
        .connect(operator1)
        .bondCiphernodeFor(operator1Address, bondAmount);
      await bondingRegistry
        .connect(operator1)
        .registerOperatorFor(operator1Address);

      const ticketAmount = ethers.parseUnits("100", 6);
      await usdcToken
        .connect(operator1)
        .approve(await ticketToken.getAddress(), ticketAmount);
      await bondingRegistry
        .connect(operator1)
        .addTicketBalanceFor(operator1Address, ticketAmount);

      await bondingRegistry
        .connect(operator1)
        .deregisterOperatorFor(operator1Address);

      const [ticketPending, ciphernodeBondPending] =
        await bondingRegistry.pendingExits(operator1Address);
      expect(ticketPending).to.equal(ticketAmount);
      expect(ciphernodeBondPending).to.equal(bondAmount);
    });
  });

  describe("addTicketBalanceFor()", function () {
    it("allows registered operators to add ticket balance", async function () {
      const {
        bondingRegistry,
        ciphernodeBondToken,
        usdcToken,
        ticketToken,
        operator1,
      } = await loadFixture(setup);

      const bondAmount = REQUIRED_CIPHERNODE_BOND;
      await ciphernodeBondToken
        .connect(operator1)
        .approve(await bondingRegistry.getAddress(), bondAmount);
      await bondingRegistry
        .connect(operator1)
        .bondCiphernodeFor(operator1Address, bondAmount);
      await bondingRegistry
        .connect(operator1)
        .registerOperatorFor(operator1Address);

      const ticketAmount = ethers.parseUnits("100", 6);
      await usdcToken
        .connect(operator1)
        .approve(await ticketToken.getAddress(), ticketAmount);

      await expect(
        bondingRegistry
          .connect(operator1)
          .addTicketBalanceFor(operator1Address, ticketAmount),
      )
        .to.emit(bondingRegistry, "TicketBalanceUpdated")
        .withArgs(operator1Address, ticketAmount, ticketAmount, REASON_DEPOSIT);

      expect(await bondingRegistry.getTicketBalance(operator1Address)).to.equal(
        ticketAmount,
      );
    });

    it("activates operator when minimum balance is reached", async function () {
      const {
        bondingRegistry,
        ciphernodeBondToken,
        usdcToken,
        ticketToken,
        operator1,
      } = await loadFixture(setup);

      const bondAmount = REQUIRED_CIPHERNODE_BOND;
      await ciphernodeBondToken
        .connect(operator1)
        .approve(await bondingRegistry.getAddress(), bondAmount);
      await bondingRegistry
        .connect(operator1)
        .bondCiphernodeFor(operator1Address, bondAmount);
      await bondingRegistry
        .connect(operator1)
        .registerOperatorFor(operator1Address);

      const ticketAmount = ethers.parseUnits("50", 6);
      await usdcToken
        .connect(operator1)
        .approve(await ticketToken.getAddress(), ticketAmount);

      await expect(
        bondingRegistry
          .connect(operator1)
          .addTicketBalanceFor(operator1Address, ticketAmount),
      )
        .to.emit(bondingRegistry, "OperatorActivationChanged")
        .withArgs(operator1Address, true);

      expect(await bondingRegistry.isActive(operator1Address)).to.be.true;
    });

    it("reverts if not registered", async function () {
      const { bondingRegistry, operator1 } = await loadFixture(setup);

      await expect(
        bondingRegistry
          .connect(operator1)
          .addTicketBalanceFor(operator1Address, ethers.parseUnits("100", 6)),
      ).to.be.revertedWithCustomError(bondingRegistry, "NotRegistered");
    });

    it("reverts if amount is zero", async function () {
      const { bondingRegistry, ciphernodeBondToken, operator1 } =
        await loadFixture(setup);

      const bondAmount = REQUIRED_CIPHERNODE_BOND;
      await ciphernodeBondToken
        .connect(operator1)
        .approve(await bondingRegistry.getAddress(), bondAmount);
      await bondingRegistry
        .connect(operator1)
        .bondCiphernodeFor(operator1Address, bondAmount);
      await bondingRegistry
        .connect(operator1)
        .registerOperatorFor(operator1Address);

      await expect(
        bondingRegistry
          .connect(operator1)
          .addTicketBalanceFor(operator1Address, 0),
      ).to.be.revertedWithCustomError(bondingRegistry, "ZeroAmount");
    });
  });

  describe("removeTicketBalanceFor()", function () {
    it("allows operators to remove ticket balance", async function () {
      const {
        bondingRegistry,
        ciphernodeBondToken,
        usdcToken,
        ticketToken,
        operator1,
      } = await loadFixture(setup);

      const bondAmount = REQUIRED_CIPHERNODE_BOND;
      await ciphernodeBondToken
        .connect(operator1)
        .approve(await bondingRegistry.getAddress(), bondAmount);
      await bondingRegistry
        .connect(operator1)
        .bondCiphernodeFor(operator1Address, bondAmount);
      await bondingRegistry
        .connect(operator1)
        .registerOperatorFor(operator1Address);

      const ticketAmount = ethers.parseUnits("100", 6);
      await usdcToken
        .connect(operator1)
        .approve(await ticketToken.getAddress(), ticketAmount);
      await bondingRegistry
        .connect(operator1)
        .addTicketBalanceFor(operator1Address, ticketAmount);

      const removeAmount = ethers.parseUnits("30", 6);
      await expect(
        bondingRegistry
          .connect(operator1)
          .removeTicketBalanceFor(operator1Address, removeAmount),
      )
        .to.emit(bondingRegistry, "TicketBalanceUpdated")
        .withArgs(
          operator1Address,
          -removeAmount,
          ticketAmount - removeAmount,
          REASON_WITHDRAW,
        );

      expect(await bondingRegistry.getTicketBalance(operator1Address)).to.equal(
        ticketAmount - removeAmount,
      );
    });

    it("queues removed tickets for exit", async function () {
      const {
        bondingRegistry,
        ciphernodeBondToken,
        usdcToken,
        ticketToken,
        operator1,
      } = await loadFixture(setup);

      const bondAmount = REQUIRED_CIPHERNODE_BOND;
      await ciphernodeBondToken
        .connect(operator1)
        .approve(await bondingRegistry.getAddress(), bondAmount);
      await bondingRegistry
        .connect(operator1)
        .bondCiphernodeFor(operator1Address, bondAmount);
      await bondingRegistry
        .connect(operator1)
        .registerOperatorFor(operator1Address);

      const ticketAmount = ethers.parseUnits("100", 6);
      await usdcToken
        .connect(operator1)
        .approve(await ticketToken.getAddress(), ticketAmount);
      await bondingRegistry
        .connect(operator1)
        .addTicketBalanceFor(operator1Address, ticketAmount);

      const removeAmount = ethers.parseUnits("30", 6);
      await bondingRegistry
        .connect(operator1)
        .removeTicketBalanceFor(operator1Address, removeAmount);

      const [ticketPending] =
        await bondingRegistry.pendingExits(operator1Address);
      expect(ticketPending).to.equal(removeAmount);
    });

    it("deactivates operator if balance falls below minimum", async function () {
      const {
        bondingRegistry,
        ciphernodeBondToken,
        usdcToken,
        ticketToken,
        operator1,
      } = await loadFixture(setup);

      const bondAmount = REQUIRED_CIPHERNODE_BOND;
      await ciphernodeBondToken
        .connect(operator1)
        .approve(await bondingRegistry.getAddress(), bondAmount);
      await bondingRegistry
        .connect(operator1)
        .bondCiphernodeFor(operator1Address, bondAmount);
      await bondingRegistry
        .connect(operator1)
        .registerOperatorFor(operator1Address);

      const ticketAmount = ethers.parseUnits("60", 6);
      await usdcToken
        .connect(operator1)
        .approve(await ticketToken.getAddress(), ticketAmount);
      await bondingRegistry
        .connect(operator1)
        .addTicketBalanceFor(operator1Address, ticketAmount);

      const removeAmount = ethers.parseUnits("20", 6);
      await expect(
        bondingRegistry
          .connect(operator1)
          .removeTicketBalanceFor(operator1Address, removeAmount),
      )
        .to.emit(bondingRegistry, "OperatorActivationChanged")
        .withArgs(operator1Address, false);

      expect(await bondingRegistry.isActive(operator1Address)).to.be.false;
    });

    it("reverts if insufficient balance", async function () {
      const { bondingRegistry, ciphernodeBondToken, operator1 } =
        await loadFixture(setup);

      const bondAmount = REQUIRED_CIPHERNODE_BOND;
      await ciphernodeBondToken
        .connect(operator1)
        .approve(await bondingRegistry.getAddress(), bondAmount);
      await bondingRegistry
        .connect(operator1)
        .bondCiphernodeFor(operator1Address, bondAmount);
      await bondingRegistry
        .connect(operator1)
        .registerOperatorFor(operator1Address);

      await expect(
        bondingRegistry
          .connect(operator1)
          .removeTicketBalanceFor(
            operator1Address,
            ethers.parseUnits("100", 6),
          ),
      ).to.be.revertedWithCustomError(bondingRegistry, "InsufficientBalance");
    });
  });

  describe("slashTicketBalance()", function () {
    it("accounts for the ticket amount taken from the exit queue", async function () {
      const {
        bondingRegistry,
        ciphernodeBondToken,
        usdcToken,
        ticketToken,
        operator1,
        slashingManager,
      } = await loadFixture(setup);
      const bondAmount = REQUIRED_CIPHERNODE_BOND;
      const ticketAmount = ethers.parseUnits("100", 6);
      const slashReason = ethers.encodeBytes32String("TEST_SLASH");

      await ciphernodeBondToken
        .connect(operator1)
        .approve(await bondingRegistry.getAddress(), bondAmount);
      await bondingRegistry
        .connect(operator1)
        .bondCiphernodeFor(operator1Address, bondAmount);
      await bondingRegistry
        .connect(operator1)
        .registerOperatorFor(operator1Address);
      await usdcToken
        .connect(operator1)
        .approve(await ticketToken.getAddress(), ticketAmount);
      await bondingRegistry
        .connect(operator1)
        .addTicketBalanceFor(operator1Address, ticketAmount);
      await bondingRegistry
        .connect(operator1)
        .removeTicketBalanceFor(operator1Address, ticketAmount);
      const slashSigner = await impersonateSlashingManager(slashingManager);

      expect(
        await bondingRegistry
          .connect(slashSigner)
          .slashTicketBalance.staticCall(
            operator1Address,
            ticketAmount,
            slashReason,
          ),
      ).to.equal(ticketAmount);
      await bondingRegistry
        .connect(slashSigner)
        .slashTicketBalance(operator1Address, ticketAmount, slashReason);
      await networkHelpers.stopImpersonatingAccount(
        await slashingManager.getAddress(),
      );

      const [pendingTickets] =
        await bondingRegistry.pendingExits(operator1Address);
      expect(pendingTickets).to.equal(0);
      expect(await bondingRegistry.slashedTicketBalance()).to.equal(
        ticketAmount,
      );
    });
  });

  describe("claimExitsFor()", function () {
    it("allows claiming after exit delay", async function () {
      const {
        bondingRegistry,
        ciphernodeBondToken,
        usdcToken,
        ticketToken,
        operator1,
      } = await loadFixture(setup);

      const bondAmount = REQUIRED_CIPHERNODE_BOND;
      await ciphernodeBondToken
        .connect(operator1)
        .approve(await bondingRegistry.getAddress(), bondAmount);
      await bondingRegistry
        .connect(operator1)
        .bondCiphernodeFor(operator1Address, bondAmount);
      await bondingRegistry
        .connect(operator1)
        .registerOperatorFor(operator1Address);

      const ticketAmount = ethers.parseUnits("100", 6);
      await usdcToken
        .connect(operator1)
        .approve(await ticketToken.getAddress(), ticketAmount);
      await bondingRegistry
        .connect(operator1)
        .addTicketBalanceFor(operator1Address, ticketAmount);

      await bondingRegistry
        .connect(operator1)
        .deregisterOperatorFor(operator1Address);

      await time.increase(SEVEN_DAYS_IN_SECONDS + 1);

      const initialUSDCBalance = await usdcToken.balanceOf(
        operator1OwnerAddress,
      );
      const initialFOLDBalance = await ciphernodeBondToken.balanceOf(
        operator1OwnerAddress,
      );

      await bondingRegistry
        .connect(operator1)
        .claimExitsFor(operator1Address, ticketAmount, bondAmount);

      expect(await usdcToken.balanceOf(operator1OwnerAddress)).to.equal(
        initialUSDCBalance + ticketAmount,
      );
      expect(
        await ciphernodeBondToken.balanceOf(operator1OwnerAddress),
      ).to.equal(initialFOLDBalance + bondAmount);
    });

    it("lets anyone settle matured ticket exits to the bond owner", async function () {
      const {
        bondingRegistry,
        ticketToken,
        ciphernodeBondToken,
        usdcToken,
        operator1,
        notTheOwner,
      } = await loadFixture(setup);
      const ticketAmount = ethers.parseUnits("100", 6);

      await ciphernodeBondToken
        .connect(operator1)
        .approve(await bondingRegistry.getAddress(), REQUIRED_CIPHERNODE_BOND);
      await bondingRegistry
        .connect(operator1)
        .bondCiphernodeFor(operator1Address, REQUIRED_CIPHERNODE_BOND);
      await bondingRegistry
        .connect(operator1)
        .registerOperatorFor(operator1Address);
      await usdcToken
        .connect(operator1)
        .approve(await ticketToken.getAddress(), ticketAmount);
      await bondingRegistry
        .connect(operator1)
        .addTicketBalanceFor(operator1Address, ticketAmount);
      await bondingRegistry
        .connect(operator1)
        .removeTicketBalanceFor(operator1Address, ticketAmount);
      await time.increase(SEVEN_DAYS_IN_SECONDS + 1);

      const ownerBalanceBefore = await usdcToken.balanceOf(
        operator1OwnerAddress,
      );
      await bondingRegistry
        .connect(notTheOwner)
        .claimExitsFor(operator1Address, ticketAmount, 0);

      expect(await usdcToken.balanceOf(operator1OwnerAddress)).to.equal(
        ownerBalanceBefore + ticketAmount,
      );
      expect(await ticketToken.payableBalance()).to.equal(0);
    });

    it("keeps license-exit settlement restricted to the bond owner", async function () {
      const { bondingRegistry, ciphernodeBondToken, operator1, notTheOwner } =
        await loadFixture(setup);
      const bondAmount = REQUIRED_CIPHERNODE_BOND;

      await ciphernodeBondToken
        .connect(operator1)
        .approve(await bondingRegistry.getAddress(), bondAmount);
      await bondingRegistry
        .connect(operator1)
        .bondCiphernodeFor(operator1Address, bondAmount);
      await bondingRegistry
        .connect(operator1)
        .unbondCiphernodeFor(operator1Address, bondAmount);
      await time.increase(SEVEN_DAYS_IN_SECONDS + 1);

      await expect(
        bondingRegistry
          .connect(notTheOwner)
          .claimExitsFor(operator1Address, 0, bondAmount),
      ).to.be.revertedWithCustomError(bondingRegistry, "NotBondOwner");
    });

    it("reverts if exit not ready", async function () {
      const { bondingRegistry, ciphernodeBondToken, operator1 } =
        await loadFixture(setup);

      const bondAmount = REQUIRED_CIPHERNODE_BOND;
      await ciphernodeBondToken
        .connect(operator1)
        .approve(await bondingRegistry.getAddress(), bondAmount);
      await bondingRegistry
        .connect(operator1)
        .bondCiphernodeFor(operator1Address, bondAmount);
      await bondingRegistry
        .connect(operator1)
        .registerOperatorFor(operator1Address);

      await bondingRegistry
        .connect(operator1)
        .deregisterOperatorFor(operator1Address);

      await expect(
        bondingRegistry
          .connect(operator1)
          .claimExitsFor(operator1Address, 0, bondAmount),
      ).to.be.revertedWithCustomError(bondingRegistry, "ExitNotReady");
    });

    it("allows partial claims", async function () {
      const {
        bondingRegistry,
        ciphernodeBondToken,
        usdcToken,
        ticketToken,
        operator1,
      } = await loadFixture(setup);

      const bondAmount = REQUIRED_CIPHERNODE_BOND;
      await ciphernodeBondToken
        .connect(operator1)
        .approve(await bondingRegistry.getAddress(), bondAmount);
      await bondingRegistry
        .connect(operator1)
        .bondCiphernodeFor(operator1Address, bondAmount);
      await bondingRegistry
        .connect(operator1)
        .registerOperatorFor(operator1Address);

      const ticketAmount = ethers.parseUnits("100", 6);
      await usdcToken
        .connect(operator1)
        .approve(await ticketToken.getAddress(), ticketAmount);
      await bondingRegistry
        .connect(operator1)
        .addTicketBalanceFor(operator1Address, ticketAmount);

      await bondingRegistry
        .connect(operator1)
        .deregisterOperatorFor(operator1Address);

      await time.increase(SEVEN_DAYS_IN_SECONDS + 1);

      const partialTickets = ethers.parseUnits("50", 6);
      const partialCiphernodeBond = ethers.parseEther("500");

      const initialUSDCBalance = await usdcToken.balanceOf(
        operator1OwnerAddress,
      );
      const initialFOLDBalance = await ciphernodeBondToken.balanceOf(
        operator1OwnerAddress,
      );

      await bondingRegistry
        .connect(operator1)
        .claimExitsFor(operator1Address, partialTickets, partialCiphernodeBond);

      expect(await usdcToken.balanceOf(operator1OwnerAddress)).to.equal(
        initialUSDCBalance + partialTickets,
      );
      expect(
        await ciphernodeBondToken.balanceOf(operator1OwnerAddress),
      ).to.equal(initialFOLDBalance + partialCiphernodeBond);

      const [remainingTickets, remainingCiphernodeBond] =
        await bondingRegistry.pendingExits(operator1Address);
      expect(remainingTickets).to.equal(ticketAmount - partialTickets);
      expect(remainingCiphernodeBond).to.equal(
        bondAmount - partialCiphernodeBond,
      );
    });
  });

  describe("isCiphernodeBonded()", function () {
    it("returns false when operator has insufficient ciphernode bond", async function () {
      const { bondingRegistry, ciphernodeBondToken, operator1 } =
        await loadFixture(setup);

      const insufficientBond = (REQUIRED_CIPHERNODE_BOND * 7999n) / 10000n;
      await ciphernodeBondToken
        .connect(operator1)
        .approve(await bondingRegistry.getAddress(), insufficientBond);
      await bondingRegistry
        .connect(operator1)
        .bondCiphernodeFor(operator1Address, insufficientBond);

      expect(await bondingRegistry.isCiphernodeBonded(operator1Address)).to.be
        .false;
    });
  });

  describe("availableTickets()", function () {
    it("calculates available tickets correctly", async function () {
      const {
        bondingRegistry,
        ciphernodeBondToken,
        usdcToken,
        ticketToken,
        operator1,
      } = await loadFixture(setup);

      const bondAmount = REQUIRED_CIPHERNODE_BOND;
      await ciphernodeBondToken
        .connect(operator1)
        .approve(await bondingRegistry.getAddress(), bondAmount);
      await bondingRegistry
        .connect(operator1)
        .bondCiphernodeFor(operator1Address, bondAmount);
      await bondingRegistry
        .connect(operator1)
        .registerOperatorFor(operator1Address);

      const ticketAmount = ethers.parseUnits("100", 6);
      await usdcToken
        .connect(operator1)
        .approve(await ticketToken.getAddress(), ticketAmount);
      await bondingRegistry
        .connect(operator1)
        .addTicketBalanceFor(operator1Address, ticketAmount);

      expect(await bondingRegistry.availableTickets(operator1Address)).to.equal(
        10,
      );
    });

    it("returns 0 when operator has zero ticket balance", async function () {
      const { bondingRegistry } = await loadFixture(setup);

      expect(await bondingRegistry.availableTickets(operator1Address)).to.equal(
        0,
      );
    });
  });

  describe("Admin Functions", function () {
    describe("setSlashingManager()", function () {
      it("rejects managers without the required code and registry binding", async function () {
        const { bondingRegistry, notTheOwner, owner } =
          await loadFixture(setup);
        const eoa = await notTheOwner.getAddress();

        await expect(bondingRegistry.setSlashingManager(eoa))
          .to.be.revertedWithCustomError(
            bondingRegistry,
            "IncompatibleSlashingManager",
          )
          .withArgs(eoa);

        const candidate = await deploySlashingManager(
          0,
          await owner.getAddress(),
        );
        const candidateAddress = await candidate.getAddress();
        await expect(bondingRegistry.setSlashingManager(candidateAddress))
          .to.be.revertedWithCustomError(
            bondingRegistry,
            "SlashingManagerBondingMismatch",
          )
          .withArgs(candidateAddress, ethers.ZeroAddress);
      });

      it("does not call the manager while an operator registers or exits", async function () {
        const {
          bondingRegistry,
          ciphernodeBondToken,
          operator1,
          slashingManager,
        } = await loadFixture(setup);
        const bondAmount = REQUIRED_CIPHERNODE_BOND;

        await ciphernodeBondToken
          .connect(operator1)
          .approve(await bondingRegistry.getAddress(), bondAmount);
        await bondingRegistry
          .connect(operator1)
          .bondCiphernodeFor(operator1Address, bondAmount);
        await ethers.provider.send("hardhat_setCode", [
          await slashingManager.getAddress(),
          "0x",
        ]);

        await bondingRegistry
          .connect(operator1)
          .registerOperatorFor(operator1Address);
        await bondingRegistry
          .connect(operator1)
          .deregisterOperatorFor(operator1Address);
        expect(await bondingRegistry.isRegistered(operator1Address)).to.be
          .false;
      });

      it("keeps a retained manager authorized until its bans are cleared", async function () {
        const { bondingRegistry, owner, slashingManager } =
          await loadFixture(setup);
        const oldManager = await slashingManager.getAddress();
        const slashSigner = await impersonateSlashingManager(slashingManager);
        await bondingRegistry
          .connect(slashSigner)
          .setOperatorBan(operator1Address, true);
        await networkHelpers.stopImpersonatingAccount(oldManager);

        const replacement = await deploySlashingManager(
          0,
          await owner.getAddress(),
        );
        await replacement.setBondingRegistry(
          await bondingRegistry.getAddress(),
        );
        await bondingRegistry.setSlashingManager(
          await replacement.getAddress(),
        );

        await expect(bondingRegistry.revokeSlashingManager(oldManager))
          .to.be.revertedWithCustomError(
            bondingRegistry,
            "ManagerHasActiveBans",
          )
          .withArgs(oldManager, 1);

        await bondingRegistry
          .connect(owner)
          .clearSlashingManagerBan(oldManager, operator1Address);
        await bondingRegistry.revokeSlashingManager(oldManager);
        expect(await bondingRegistry.isAuthorizedSlashingManager(oldManager)).to
          .be.false;
      });
    });

    describe("setBondingAssetConfig()", function () {
      it("allows owner to set ticket price", async function () {
        const { bondingRegistry } = await loadFixture(setup);

        const newPrice = ethers.parseUnits("15", 6);
        await expect(
          setBondingAssetConfig(bondingRegistry, { ticketPrice: newPrice }),
        ).to.emit(bondingRegistry, "BondingAssetConfigUpdated");

        expect(await bondingRegistry.ticketPrice()).to.equal(newPrice);
      });

      it("reverts if price is zero", async function () {
        const { bondingRegistry } = await loadFixture(setup);

        await expect(
          setBondingAssetConfig(bondingRegistry, { ticketPrice: 0 }),
        ).to.be.revertedWithCustomError(
          bondingRegistry,
          "InvalidConfiguration",
        );
      });

      it("reverts if not owner", async function () {
        const { bondingRegistry, notTheOwner } = await loadFixture(setup);

        await expect(
          setBondingAssetConfig(bondingRegistry.connect(notTheOwner), {
            ticketPrice: ethers.parseEther("15"),
          }),
        ).to.be.revertedWithCustomError(
          bondingRegistry,
          "OwnableUnauthorizedAccount",
        );
      });

      it("updates ticket decimals and price in one transaction", async function () {
        const { bondingRegistry, ciphernodeBondToken, owner } =
          await loadFixture(setup);
        const underlying = await (
          await ethers.getContractFactory("MockLockAwareCiphernodeBondToken")
        ).deploy(0);
        const replacement = await (
          await ethers.getContractFactory("InterfoldTicketToken")
        ).deploy(
          await underlying.getAddress(),
          await bondingRegistry.getAddress(),
          owner.address,
        );
        const replacementAddress = await replacement.getAddress();
        const newPrice = ethers.parseEther("10");
        const version =
          await bondingRegistry.bondingAssetConfigurationVersion();

        await expect(
          bondingRegistry.setBondingAssetConfig({
            ticketToken: replacementAddress,
            ciphernodeBondToken: await ciphernodeBondToken.getAddress(),
            ticketPrice: newPrice,
            requiredCiphernodeBond: REQUIRED_CIPHERNODE_BOND,
            expectedTicketDecimals: 6,
            expectedCiphernodeBondDecimals: 18,
          }),
        )
          .to.be.revertedWithCustomError(
            bondingRegistry,
            "BondingAssetDecimalsMismatch",
          )
          .withArgs(replacementAddress, 6, 18);

        await setBondingAssetConfig(bondingRegistry, {
          ticketToken: replacementAddress,
          ticketPrice: newPrice,
          expectedTicketDecimals: 18,
        });
        expect(await bondingRegistry.getTicketToken()).to.equal(
          replacementAddress,
        );
        expect(await bondingRegistry.ticketPrice()).to.equal(newPrice);
        expect(
          await bondingRegistry.bondingAssetConfigurationVersion(),
        ).to.equal(version + 1n);
      });

      it("rejects a ticket token assigned to another registry", async function () {
        const { bondingRegistry, usdcToken, owner } = await loadFixture(setup);
        const replacement = await (
          await ethers.getContractFactory("InterfoldTicketToken")
        ).deploy(await usdcToken.getAddress(), AddressTwo, owner.address);

        await expect(
          setBondingAssetConfig(bondingRegistry, {
            ticketToken: await replacement.getAddress(),
          }),
        )
          .to.be.revertedWithCustomError(
            bondingRegistry,
            "TicketTokenRegistryMismatch",
          )
          .withArgs(AddressTwo, await bondingRegistry.getAddress());
      });

      it("blocks ticket registry drift while collateral is outstanding", async function () {
        const {
          bondingRegistry,
          ticketToken,
          ciphernodeBondToken,
          usdcToken,
          operator1,
        } = await loadFixture(setup);
        const bondAmount = REQUIRED_CIPHERNODE_BOND;
        const ticketAmount = TICKET_PRICE * BigInt(MIN_TICKET_BALANCE);

        await ciphernodeBondToken
          .connect(operator1)
          .approve(await bondingRegistry.getAddress(), bondAmount);
        await bondingRegistry
          .connect(operator1)
          .bondCiphernodeFor(operator1Address, bondAmount);
        await bondingRegistry
          .connect(operator1)
          .registerOperatorFor(operator1Address);
        await usdcToken
          .connect(operator1)
          .approve(await ticketToken.getAddress(), ticketAmount);
        await bondingRegistry
          .connect(operator1)
          .addTicketBalanceFor(operator1Address, ticketAmount);
        expect(await bondingRegistry.isActive(operator1Address)).to.be.true;

        await expect(ticketToken.setRegistry(AddressTwo))
          .to.be.revertedWithCustomError(ticketToken, "OutstandingTicketSupply")
          .withArgs(ticketAmount);
      });
    });

    describe("setCiphernodeBondActiveBps()", function () {
      it("allows owner to set ciphernodeBond active basis points", async function () {
        const { bondingRegistry } = await loadFixture(setup);

        const newBps = 9000;
        await expect(bondingRegistry.setCiphernodeBondActiveBps(newBps))
          .to.emit(bondingRegistry, "ConfigurationUpdated")
          .withArgs(
            ethers.encodeBytes32String("ciphernodeBondActiveBps"),
            8000,
            newBps,
          );

        expect(await bondingRegistry.ciphernodeBondActiveBps()).to.equal(
          newBps,
        );
      });

      it("reverts if bps is 0", async function () {
        const { bondingRegistry } = await loadFixture(setup);

        await expect(
          bondingRegistry.setCiphernodeBondActiveBps(0),
        ).to.be.revertedWithCustomError(
          bondingRegistry,
          "InvalidConfiguration",
        );
      });

      it("reverts if bps is greater than 10000", async function () {
        const { bondingRegistry } = await loadFixture(setup);

        await expect(
          bondingRegistry.setCiphernodeBondActiveBps(10001),
        ).to.be.revertedWithCustomError(
          bondingRegistry,
          "InvalidConfiguration",
        );
      });

      it("keeps every positive retained-bond requirement above zero", async function () {
        const { bondingRegistry } = await loadFixture(setup);

        for (const [requiredBond, activeBps] of [
          [1n, 8_000n],
          [9_999n, 1n],
          [1n, 10_000n],
        ]) {
          await setBondingAssetConfig(bondingRegistry, {
            requiredCiphernodeBond: requiredBond,
          });
          await bondingRegistry.setCiphernodeBondActiveBps(activeBps);
          expect(
            await bondingRegistry.isCiphernodeBonded(operator1Address),
          ).to.equal(false);
        }

        await setBondingAssetConfig(bondingRegistry, {
          requiredCiphernodeBond: ethers.MaxUint256,
        });
        await bondingRegistry.setCiphernodeBondActiveBps(8_000);
        expect(
          await bondingRegistry.isCiphernodeBonded(operator1Address),
        ).to.equal(false);
      });

      it("deactivates an operator that unbonds and claims its last ciphernodeBond unit", async function () {
        const {
          bondingRegistry,
          ciphernodeBondToken,
          usdcToken,
          ticketToken,
          operator1,
        } = await loadFixture(setup);
        const ticketAmount = TICKET_PRICE * BigInt(MIN_TICKET_BALANCE);

        await setBondingAssetConfig(bondingRegistry, {
          requiredCiphernodeBond: 1,
        });
        await bondingRegistry.setCiphernodeBondActiveBps(8_000);
        await ciphernodeBondToken
          .connect(operator1)
          .approve(await bondingRegistry.getAddress(), 1);
        await bondingRegistry
          .connect(operator1)
          .bondCiphernodeFor(operator1Address, 1);
        await bondingRegistry
          .connect(operator1)
          .registerOperatorFor(operator1Address);
        await usdcToken
          .connect(operator1)
          .approve(await ticketToken.getAddress(), ticketAmount);
        await bondingRegistry
          .connect(operator1)
          .addTicketBalanceFor(operator1Address, ticketAmount);

        expect(await bondingRegistry.isActive(operator1Address)).to.equal(true);
        await bondingRegistry
          .connect(operator1)
          .unbondCiphernodeFor(operator1Address, 1);
        expect(await bondingRegistry.isActive(operator1Address)).to.equal(
          false,
        );

        await time.increase(SEVEN_DAYS_IN_SECONDS + 1);
        await bondingRegistry
          .connect(operator1)
          .claimExitsFor(operator1Address, 0, 1);
        expect(await bondingRegistry.isActive(operator1Address)).to.equal(
          false,
        );
      });
    });

    it("AUD-M03: governs eligibility parameters and refreshes cached status by policy version", async function () {
      const {
        bondingRegistry,
        ciphernodeBondToken,
        usdcToken,
        ticketToken,
        operator1,
        operator2,
      } = await loadFixture(setup);
      const operator = operator1Address;

      await ciphernodeBondToken
        .connect(operator1)
        .approve(await bondingRegistry.getAddress(), REQUIRED_CIPHERNODE_BOND);
      await bondingRegistry
        .connect(operator1)
        .bondCiphernodeFor(operator1Address, REQUIRED_CIPHERNODE_BOND);
      await bondingRegistry
        .connect(operator1)
        .registerOperatorFor(operator1Address);

      const ticketAmount = TICKET_PRICE * BigInt(MIN_TICKET_BALANCE);
      await usdcToken
        .connect(operator1)
        .approve(await ticketToken.getAddress(), ticketAmount);
      await bondingRegistry
        .connect(operator1)
        .addTicketBalanceFor(operator1Address, ticketAmount);

      expect(await bondingRegistry.isActive(operator)).to.equal(true);
      expect(await bondingRegistry.numActiveOperators()).to.equal(1);

      const initialVersion =
        await bondingRegistry.eligibilityConfigurationVersion();
      await setBondingAssetConfig(bondingRegistry, {
        ticketPrice: TICKET_PRICE * 2n,
      });

      expect(await bondingRegistry.eligibilityConfigurationVersion()).to.equal(
        initialVersion + 1n,
      );
      expect(await bondingRegistry.isActive(operator)).to.equal(false);
      expect(await bondingRegistry.numActiveOperators()).to.equal(0);

      // Refresh is permissionless and evaluates the new policy. The doubled
      // ticket price leaves this operator below the five-ticket threshold.
      await bondingRegistry.connect(operator2).refreshOperatorStatus(operator);
      expect(await bondingRegistry.isActive(operator)).to.equal(false);
      expect(await bondingRegistry.numActiveOperators()).to.equal(0);

      await setBondingAssetConfig(bondingRegistry, {
        ticketPrice: TICKET_PRICE,
      });
      await bondingRegistry.refreshOperatorStatuses([operator]);
      expect(await bondingRegistry.isActive(operator)).to.equal(true);
      expect(await bondingRegistry.numActiveOperators()).to.equal(1);

      await setBondingAssetConfig(bondingRegistry, {
        requiredCiphernodeBond: REQUIRED_CIPHERNODE_BOND * 2n,
      });
      await bondingRegistry.refreshOperatorStatus(operator);
      expect(await bondingRegistry.isActive(operator)).to.equal(false);

      await setBondingAssetConfig(bondingRegistry, {
        requiredCiphernodeBond: REQUIRED_CIPHERNODE_BOND,
      });
      await bondingRegistry.setCiphernodeBondActiveBps(9_000);
      await bondingRegistry.refreshOperatorStatus(operator);
      expect(await bondingRegistry.isActive(operator)).to.equal(true);

      await bondingRegistry.setMinTicketBalance(MIN_TICKET_BALANCE + 1);
      await bondingRegistry.refreshOperatorStatus(operator);
      expect(await bondingRegistry.isActive(operator)).to.equal(false);
    });

    it("AUD-M03: rejects a zero minimum ticket requirement", async function () {
      const { bondingRegistry } = await loadFixture(setup);
      await expect(
        bondingRegistry.setMinTicketBalance(0),
      ).to.be.revertedWithCustomError(bondingRegistry, "InvalidConfiguration");
    });

    describe("bonding asset rotation", function () {
      it("requires a valid locked-balance response", async function () {
        const { bondingRegistry, usdcToken } = await loadFixture(setup);
        const plainTokenAddress = await usdcToken.getAddress();

        await expect(
          setBondingAssetConfig(bondingRegistry, {
            ciphernodeBondToken: plainTokenAddress,
            expectedCiphernodeBondDecimals: 6,
          }),
        )
          .to.be.revertedWithCustomError(
            bondingRegistry,
            "IncompatibleCiphernodeBondToken",
          )
          .withArgs(plainTokenAddress);

        const token = await (
          await ethers.getContractFactory("MockLockAwareCiphernodeBondToken")
        ).deploy(1);
        const tokenAddress = await token.getAddress();

        await expect(
          setBondingAssetConfig(bondingRegistry, {
            ciphernodeBondToken: tokenAddress,
          }),
        )
          .to.be.revertedWithCustomError(
            bondingRegistry,
            "IncompatibleCiphernodeBondToken",
          )
          .withArgs(tokenAddress);

        await token.setResponseMode(2);
        await expect(
          setBondingAssetConfig(bondingRegistry, {
            ciphernodeBondToken: tokenAddress,
          }),
        )
          .to.be.revertedWithCustomError(
            bondingRegistry,
            "IncompatibleCiphernodeBondToken",
          )
          .withArgs(tokenAddress);

        await token.setResponseMode(0);
        await expect(
          setBondingAssetConfig(bondingRegistry, {
            ciphernodeBondToken: tokenAddress,
          }),
        ).to.emit(bondingRegistry, "BondingAssetConfigUpdated");
      });

      it("reports a lock-aware token that later stops responding", async function () {
        const {
          bondingRegistry,
          operator1,
          operator2,
          operator1Address,
          operator2OwnerAddress,
        } = await loadFixture(setup);
        const token = await (
          await ethers.getContractFactory("MockLockAwareCiphernodeBondToken")
        ).deploy(0);
        const tokenAddress = await token.getAddress();
        const bondAmount = REQUIRED_CIPHERNODE_BOND;

        await setBondingAssetConfig(bondingRegistry, {
          ciphernodeBondToken: tokenAddress,
        });
        await token.mint(await operator1.getAddress(), bondAmount);
        await token.connect(operator1).getFunction("approve")(
          await bondingRegistry.getAddress(),
          bondAmount,
        );
        await bondingRegistry
          .connect(operator1)
          .bondCiphernodeFor(operator1Address, bondAmount);
        await bondingRegistry
          .connect(operator1)
          .proposeBondOwner(operator1Address, operator2OwnerAddress);

        await token.setResponseMode(1);
        await expect(
          bondingRegistry.connect(operator2).acceptBondOwner(operator1Address),
        )
          .to.be.revertedWithCustomError(
            bondingRegistry,
            "IncompatibleCiphernodeBondToken",
          )
          .withArgs(tokenAddress);
      });
    });

    describe("withdrawSlashedFunds()", function () {
      it("allows owner to withdraw slashed funds", async function () {
        const {
          bondingRegistry,
          ticketToken,
          ciphernodeBondToken,
          usdcToken,
          operator1,
          slashingManager,
          treasury,
          treasuryAddress,
        } = await loadFixture(setup);
        const bondAmount = REQUIRED_CIPHERNODE_BOND;
        const ticketAmount = ethers.parseUnits("100", 6);
        const bondSlash = bondAmount / 4n;
        const ticketSlash = ticketAmount / 4n;
        const slashReason = ethers.id("withdraw-slashed-funds");

        await ciphernodeBondToken
          .connect(operator1)
          .approve(await bondingRegistry.getAddress(), bondAmount);
        await bondingRegistry
          .connect(operator1)
          .bondCiphernodeFor(operator1Address, bondAmount);
        await bondingRegistry
          .connect(operator1)
          .registerOperatorFor(operator1Address);
        await usdcToken
          .connect(operator1)
          .approve(await ticketToken.getAddress(), ticketAmount);
        await bondingRegistry
          .connect(operator1)
          .addTicketBalanceFor(operator1Address, ticketAmount);

        const slashSigner = await impersonateSlashingManager(slashingManager);
        await bondingRegistry
          .connect(slashSigner)
          .slashTicketBalance(operator1Address, ticketSlash, slashReason);
        await bondingRegistry
          .connect(slashSigner)
          .slashCiphernodeBond(operator1Address, bondSlash, slashReason);
        await networkHelpers.stopImpersonatingAccount(
          await slashingManager.getAddress(),
        );

        expect(await bondingRegistry.slashedTicketBalance()).to.equal(
          ticketSlash,
        );
        expect(await bondingRegistry.slashedCiphernodeBond()).to.equal(
          bondSlash,
        );
        expect(await ticketToken.payableBalance()).to.equal(ticketSlash);
        expect(await bondingRegistry.totalCiphernodeBondLiability()).to.equal(
          bondAmount,
        );
        const treasuryTicketBefore = await usdcToken.balanceOf(treasuryAddress);
        const treasuryBondBefore =
          await ciphernodeBondToken.balanceOf(treasuryAddress);

        await expect(
          bondingRegistry.withdrawSlashedFunds(ticketSlash, bondSlash),
        )
          .to.emit(bondingRegistry, "SlashedFundsWithdrawn")
          .withArgs(await treasury.getAddress(), ticketSlash, bondSlash);

        expect(await usdcToken.balanceOf(treasuryAddress)).to.equal(
          treasuryTicketBefore + ticketSlash,
        );
        expect(await ciphernodeBondToken.balanceOf(treasuryAddress)).to.equal(
          treasuryBondBefore + bondSlash,
        );
        expect(await bondingRegistry.slashedTicketBalance()).to.equal(0);
        expect(await bondingRegistry.slashedCiphernodeBond()).to.equal(0);
        expect(await ticketToken.payableBalance()).to.equal(0);
        expect(await bondingRegistry.totalCiphernodeBondLiability()).to.equal(
          bondAmount - bondSlash,
        );
      });

      it("reverts if not owner", async function () {
        const { bondingRegistry, notTheOwner } = await loadFixture(setup);

        await expect(
          bondingRegistry.connect(notTheOwner).withdrawSlashedFunds(0, 0),
        ).to.be.revertedWithCustomError(
          bondingRegistry,
          "OwnableUnauthorizedAccount",
        );
      });
    });
  });

  describe("Edge Cases and Complex Scenarios", function () {
    it("handles operator becoming inactive due to ciphernodeBond reduction", async function () {
      const {
        bondingRegistry,
        ciphernodeBondToken,
        usdcToken,
        ticketToken,
        operator1,
      } = await loadFixture(setup);

      const bondAmount = REQUIRED_CIPHERNODE_BOND;
      await ciphernodeBondToken
        .connect(operator1)
        .approve(await bondingRegistry.getAddress(), bondAmount);
      await bondingRegistry
        .connect(operator1)
        .bondCiphernodeFor(operator1Address, bondAmount);
      await bondingRegistry
        .connect(operator1)
        .registerOperatorFor(operator1Address);

      const ticketAmount = ethers.parseUnits("60", 6);
      await usdcToken
        .connect(operator1)
        .approve(await ticketToken.getAddress(), ticketAmount);
      await bondingRegistry
        .connect(operator1)
        .addTicketBalanceFor(operator1Address, ticketAmount);

      expect(await bondingRegistry.isActive(operator1Address)).to.be.true;

      const unbondAmount = REQUIRED_CIPHERNODE_BOND / 5n;
      await bondingRegistry
        .connect(operator1)
        .unbondCiphernodeFor(operator1Address, unbondAmount + 1n);
      expect(await bondingRegistry.isActive(operator1Address)).to.be.false;
      expect(await bondingRegistry.isCiphernodeBonded(operator1Address)).to.be
        .false;
    });

    it("handles multiple operators with different states", async function () {
      const {
        bondingRegistry,
        ciphernodeBondToken,
        usdcToken,
        ticketToken,
        operator1,
        operator2,
      } = await loadFixture(setup);

      const bondAmount = REQUIRED_CIPHERNODE_BOND;
      await ciphernodeBondToken
        .connect(operator1)
        .approve(await bondingRegistry.getAddress(), bondAmount);
      await bondingRegistry
        .connect(operator1)
        .bondCiphernodeFor(operator1Address, bondAmount);
      await bondingRegistry
        .connect(operator1)
        .registerOperatorFor(operator1Address);

      await ciphernodeBondToken
        .connect(operator2)
        .approve(await bondingRegistry.getAddress(), bondAmount);
      await bondingRegistry
        .connect(operator2)
        .bondCiphernodeFor(operator2Address, bondAmount);
      await bondingRegistry
        .connect(operator2)
        .registerOperatorFor(operator2Address);

      const ticketAmount = ethers.parseUnits("60", 6);
      await usdcToken
        .connect(operator2)
        .approve(await ticketToken.getAddress(), ticketAmount);
      await bondingRegistry
        .connect(operator2)
        .addTicketBalanceFor(operator2Address, ticketAmount);

      expect(await bondingRegistry.isRegistered(operator1Address)).to.be.true;
      expect(await bondingRegistry.isActive(operator1Address)).to.be.false;

      expect(await bondingRegistry.isRegistered(operator2Address)).to.be.true;
      expect(await bondingRegistry.isActive(operator2Address)).to.be.true;
    });

    it("handles the complete operator lifecycle", async function () {
      const {
        bondingRegistry,
        ciphernodeBondToken,
        usdcToken,
        ticketToken,
        operator1,
      } = await loadFixture(setup);

      const bondAmount = REQUIRED_CIPHERNODE_BOND;
      await ciphernodeBondToken
        .connect(operator1)
        .approve(await bondingRegistry.getAddress(), bondAmount);
      await bondingRegistry
        .connect(operator1)
        .bondCiphernodeFor(operator1Address, bondAmount);
      expect(await bondingRegistry.isCiphernodeBonded(operator1Address)).to.be
        .true;

      await bondingRegistry
        .connect(operator1)
        .registerOperatorFor(operator1Address);
      expect(await bondingRegistry.isRegistered(operator1Address)).to.be.true;
      expect(await bondingRegistry.isActive(operator1Address)).to.be.false;

      const ticketAmount = ethers.parseUnits("60", 6);
      await usdcToken
        .connect(operator1)
        .approve(await ticketToken.getAddress(), ticketAmount);
      await bondingRegistry
        .connect(operator1)
        .addTicketBalanceFor(operator1Address, ticketAmount);
      expect(await bondingRegistry.isActive(operator1Address)).to.be.true;

      await bondingRegistry
        .connect(operator1)
        .deregisterOperatorFor(operator1Address);
      expect(await bondingRegistry.isRegistered(operator1Address)).to.be.false;
      expect(await bondingRegistry.hasExitInProgress(operator1Address)).to.be
        .true;

      await time.increase(SEVEN_DAYS_IN_SECONDS + 1);

      const initialUSDCBalance = await usdcToken.balanceOf(
        operator1OwnerAddress,
      );
      const initialFOLDBalance = await ciphernodeBondToken.balanceOf(
        operator1OwnerAddress,
      );

      await bondingRegistry
        .connect(operator1)
        .claimExitsFor(operator1Address, ticketAmount, bondAmount);

      expect(await usdcToken.balanceOf(operator1OwnerAddress)).to.equal(
        initialUSDCBalance + ticketAmount,
      );
      expect(
        await ciphernodeBondToken.balanceOf(operator1OwnerAddress),
      ).to.equal(initialFOLDBalance + bondAmount);

      await ciphernodeBondToken
        .connect(operator1)
        .approve(await bondingRegistry.getAddress(), bondAmount);
      await bondingRegistry
        .connect(operator1)
        .bondCiphernodeFor(operator1Address, bondAmount);
      await bondingRegistry
        .connect(operator1)
        .registerOperatorFor(operator1Address);
      expect(await bondingRegistry.isRegistered(operator1Address)).to.be.true;
    });
  });

  // ───────────────────────────────────────────────────────────────────────────
  // Audit regression — exit queue and ciphernode bond payout
  // See: audits/interfold-contracts-ethskills-audit-opus-v2.md
  // ───────────────────────────────────────────────────────────────────────────
  describe("audit regression — exit queue & ciphernodeBond payout", function () {
    /**
     * C-03 reproduction guard.
     *
     * Pre-fix the exit queue used a single per-operator `queueHeadIndex`
     * advanced whenever the tranche at the head was fully drained of EITHER
     * asset. A mixed queue (ticket-only tranche followed by ciphernode bond-only
     * tranche) could therefore strand the ciphernode bond assets once the tickets
     * were claimed: the shared head advanced past the second tranche while
     * its ciphernode bond balance was still pending.
     *
     * With the per-asset heads (`queueHeadIndexTicket` /
     * `queueHeadIndexCiphernodeBond`) both balances must remain claimable
     * independently.
     */
    it("C-03: per-asset heads do not strand the other asset class", async function () {
      const {
        bondingRegistry,
        ciphernodeBondToken,
        ticketToken,
        usdcToken,
        operator1,
        operator1Address,
      } = await loadFixture(setup);

      // Bond + register so we can unbond into the exit queue.
      const bondAmount = REQUIRED_CIPHERNODE_BOND;
      await ciphernodeBondToken
        .connect(operator1)
        .approve(await bondingRegistry.getAddress(), bondAmount);
      await bondingRegistry
        .connect(operator1)
        .bondCiphernodeFor(operator1Address, bondAmount);
      await bondingRegistry
        .connect(operator1)
        .registerOperatorFor(operator1Address);

      const ticketAmount = ethers.parseUnits("100", 6);
      await usdcToken
        .connect(operator1)
        .approve(await ticketToken.getAddress(), ticketAmount);
      await bondingRegistry
        .connect(operator1)
        .addTicketBalanceFor(operator1Address, ticketAmount);

      // Tranche #0 (ciphernode bond-only): unbond half the ciphernode bond.
      const halfCiphernodeBond = bondAmount / 2n;
      await bondingRegistry
        .connect(operator1)
        .unbondCiphernodeFor(operator1Address, halfCiphernodeBond);

      // Advance time so the next tranche gets a distinct unlock timestamp
      // (otherwise it would merge into tranche #0 and defeat the test).
      await time.increase(60);

      // Tranche #1 (ticket-only): remove some tickets to the queue.
      const halfTickets = ticketAmount / 2n;
      await bondingRegistry
        .connect(operator1)
        .removeTicketBalanceFor(operator1Address, halfTickets);

      // Wait past the exit delay so both tranches are unlocked.
      await time.increase(SEVEN_DAYS_IN_SECONDS + 1);

      // Claim ONLY the ticket leg from tranche #1.
      // Pre-fix: this would advance the shared head past tranche #0 too,
      // permanently stranding `halfCiphernodeBond` in the queue.
      await bondingRegistry
        .connect(operator1)
        .claimExitsFor(operator1Address, halfTickets, 0);

      // The ciphernode bond leg from tranche #0 must still be claimable.
      const [pendingTickets, pendingCiphernodeBond] =
        await bondingRegistry.pendingExits(operator1Address);
      expect(pendingTickets).to.equal(0n);
      expect(pendingCiphernodeBond).to.equal(halfCiphernodeBond);

      const beforeCiphernodeBond = await ciphernodeBondToken.balanceOf(
        operator1OwnerAddress,
      );
      await bondingRegistry
        .connect(operator1)
        .claimExitsFor(operator1Address, 0, halfCiphernodeBond);
      expect(
        await ciphernodeBondToken.balanceOf(operator1OwnerAddress),
      ).to.equal(beforeCiphernodeBond + halfCiphernodeBond);
    });

    /**
     * M-08 reproduction guard.
     *
     * Pre-fix the scan loops in `previewClaimableAmounts` and
     * `_takeAssetsFromQueue` used `break` on the first locked tranche they
     * encountered. That was sound only while `unlockTimestamp` values were
     * guaranteed to be monotonically non-decreasing across the queue —
     * an invariant `setExitDelay` can violate by reducing the delay between
     * two unbond calls. The fix replaces `break` with `continue` so locked
     * tranches no longer mask later unlocked ones.
     */
    it("M-08: reducing exitDelay does not strand later, sooner-unlocking tranches", async function () {
      const {
        bondingRegistry,
        ciphernodeBondToken,
        operator1,
        operator1Address,
      } = await loadFixture(setup);

      const bondAmount = REQUIRED_CIPHERNODE_BOND;
      await ciphernodeBondToken
        .connect(operator1)
        .approve(await bondingRegistry.getAddress(), bondAmount);
      await bondingRegistry
        .connect(operator1)
        .bondCiphernodeFor(operator1Address, bondAmount);
      await bondingRegistry
        .connect(operator1)
        .registerOperatorFor(operator1Address);

      // Tranche A: unbond with the original 7-day delay.
      const quarter = bondAmount / 4n;
      await bondingRegistry
        .connect(operator1)
        .unbondCiphernodeFor(operator1Address, quarter);

      // Governance reduces the exit delay to 1 day.
      const ONE_DAY = 24 * 60 * 60;
      await bondingRegistry.setExitDelay(ONE_DAY);
      // Advance time so tranche B gets a distinct unlock timestamp.
      await time.increase(60);

      // Tranche B: unbond under the new 1-day delay.
      await bondingRegistry
        .connect(operator1)
        .unbondCiphernodeFor(operator1Address, quarter);

      // Move ~2 days forward — B is unlocked, A is still locked.
      await time.increase(2 * ONE_DAY);

      const [, pendingCiphernodeBond] =
        await bondingRegistry.previewClaimable(operator1Address);
      // Pre-fix `break` would have returned 0; with `continue` we see B.
      expect(pendingCiphernodeBond).to.equal(quarter);

      const beforeCiphernodeBond = await ciphernodeBondToken.balanceOf(
        operator1OwnerAddress,
      );
      await bondingRegistry
        .connect(operator1)
        .claimExitsFor(operator1Address, 0, quarter);
      expect(
        await ciphernodeBondToken.balanceOf(operator1OwnerAddress),
      ).to.equal(beforeCiphernodeBond + quarter);

      // Tranche A must still be pending (and become claimable later).
      const [, stillPending] =
        await bondingRegistry.pendingExits(operator1Address);
      expect(stillPending).to.equal(quarter);
    });

    /**
     * H-21 reproduction guard (part A: queue cap).
     *
     * `MAX_ACTIVE_TRANCHES = 64` bounds the per-operator live tranche count.
     * The 65th distinct-timestamp unbond must revert with `TooManyTranches`,
     * preventing an attacker from inflating the operator's queue to OOG
     * `_takeAssetsFromQueue` during a slash.
     */
    it("H-21: queueAssetsForExit reverts after MAX_ACTIVE_TRANCHES live tranches", async function () {
      const {
        bondingRegistry,
        ciphernodeBondToken,
        ticketToken,
        usdcToken,
        operator1,
      } = await loadFixture(setup);

      // Register and fund tickets so the generic ExitQueueLib ticket path is
      // exercised directly alongside FOLD exits.
      const bondAmount = REQUIRED_CIPHERNODE_BOND;
      await ciphernodeBondToken
        .connect(operator1)
        .approve(await bondingRegistry.getAddress(), bondAmount);
      await bondingRegistry
        .connect(operator1)
        .bondCiphernodeFor(operator1Address, bondAmount);
      await bondingRegistry
        .connect(operator1)
        .registerOperatorFor(operator1Address);

      const ticketAmount = ethers.parseUnits("10000", 6);
      await usdcToken
        .connect(operator1)
        .approve(await ticketToken.getAddress(), ticketAmount);
      await bondingRegistry
        .connect(operator1)
        .addTicketBalanceFor(operator1Address, ticketAmount);

      // Fill the queue with 64 distinct-timestamp tranches.
      const step = ethers.parseUnits("1", 6);
      for (let i = 0; i < 64; i++) {
        await bondingRegistry
          .connect(operator1)
          .removeTicketBalanceFor(operator1Address, step);
        // Ensure next unlock timestamp differs (no merge).
        await time.increase(1);
      }

      // The 65th must revert.
      await expect(
        bondingRegistry
          .connect(operator1)
          .removeTicketBalanceFor(operator1Address, step),
      ).to.be.revertedWithCustomError(bondingRegistry, "TooManyTranches");

      // Draining the 64 ticket-only tranches must release all 64 slots even
      // though the independent ciphernode bond head never advanced through them.
      await time.increase(SEVEN_DAYS_IN_SECONDS + 1);
      await bondingRegistry
        .connect(operator1)
        .claimExitsFor(operator1Address, step * 64n, 0);
      await bondingRegistry
        .connect(operator1)
        .removeTicketBalanceFor(operator1Address, step);
    });

    it("AUD-M08: blocks ciphernode-bond-token rotation until old liabilities are drained", async function () {
      const { bondingRegistry, ciphernodeBondToken, operator1 } =
        await loadFixture(setup);

      const bondAmount = REQUIRED_CIPHERNODE_BOND;
      await ciphernodeBondToken
        .connect(operator1)
        .approve(await bondingRegistry.getAddress(), bondAmount);
      await bondingRegistry
        .connect(operator1)
        .bondCiphernodeFor(operator1Address, bondAmount);

      const FoTFactory = await ethers.getContractFactory(
        "MockFeeOnTransferToken",
      );
      const fot = await FoTFactory.deploy(100n); // 100 bps = 1%
      await expect(
        setBondingAssetConfig(bondingRegistry, {
          ciphernodeBondToken: ethers.ZeroAddress,
          expectedCiphernodeBondDecimals: 0,
        }),
      )
        .to.be.revertedWithCustomError(bondingRegistry, "InvalidBondingAsset")
        .withArgs(ethers.ZeroAddress);
      await expect(
        setBondingAssetConfig(bondingRegistry, {
          ciphernodeBondToken: operator1.address,
        }),
      )
        .to.be.revertedWithCustomError(bondingRegistry, "InvalidBondingAsset")
        .withArgs(operator1.address);
      await expect(
        setBondingAssetConfig(bondingRegistry, {
          ciphernodeBondToken: await fot.getAddress(),
        }),
      )
        .to.be.revertedWithCustomError(
          bondingRegistry,
          "OutstandingAssetLiabilities",
        )
        .withArgs(await ciphernodeBondToken.getAddress(), bondAmount);
    });

    it("atomically sweeps donated ciphernode bond surplus during rotation", async function () {
      const {
        bondingRegistry,
        ciphernodeBondToken,
        operator1,
        treasury,
        treasuryAddress,
      } = await loadFixture(setup);

      const registryAddress = await bondingRegistry.getAddress();
      const dust = ethers.parseEther("1");
      await ciphernodeBondToken
        .connect(operator1)
        .transfer(registryAddress, dust);

      expect(await bondingRegistry.totalCiphernodeBondLiability()).to.equal(0);

      const replacement = await (
        await ethers.getContractFactory("MockLockAwareCiphernodeBondToken")
      ).deploy(0);
      const treasuryBefore =
        await ciphernodeBondToken.balanceOf(treasuryAddress);
      await expect(
        setBondingAssetConfig(bondingRegistry, {
          ciphernodeBondToken: await replacement.getAddress(),
        }),
      )
        .to.emit(bondingRegistry, "CiphernodeBondSurplusSwept")
        .withArgs(
          await ciphernodeBondToken.getAddress(),
          treasuryAddress,
          dust,
        );
      expect(await ciphernodeBondToken.balanceOf(treasury)).to.equal(
        treasuryBefore + dust,
      );
      expect(await ciphernodeBondToken.balanceOf(registryAddress)).to.equal(0);
      expect(await bondingRegistry.getCiphernodeBondToken()).to.equal(
        await replacement.getAddress(),
      );
    });

    it("rejects sender fees during license sweeps and exit claims", async function () {
      const { bondingRegistry, operator1, owner } = await loadFixture(setup);
      const token = await new MockFeeOnTransferTokenFactory(owner).deploy(0);
      const tokenAddress = await token.getAddress();
      const registryAddress = await bondingRegistry.getAddress();
      await token.setFeeIsChargedOnTop(true);
      await setBondingAssetConfig(bondingRegistry, {
        ciphernodeBondToken: tokenAddress,
      });

      const bondAmount = ethers.parseEther("1000");
      await token.mint(operator1, bondAmount);
      await token.connect(operator1).approve(registryAddress, bondAmount);
      await bondingRegistry
        .connect(operator1)
        .bondCiphernodeFor(operator1Address, bondAmount);

      const surplus = ethers.parseEther("100");
      await token.mint(registryAddress, surplus);
      await token.setFeeBps(100);
      await expect(setBondingAssetConfig(bondingRegistry))
        .to.be.revertedWithCustomError(bondingRegistry, "AssetTransferMismatch")
        .withArgs(tokenAddress, surplus, surplus + surplus / 100n);
      expect(await token.balanceOf(registryAddress)).to.equal(
        bondAmount + surplus,
      );

      await token.setFeeBps(0);
      await bondingRegistry.sweepCiphernodeBondSurplus();
      const exitAmount = bondAmount / 2n;
      await bondingRegistry
        .connect(operator1)
        .unbondCiphernodeFor(operator1Address, exitAmount);
      await time.increase(SEVEN_DAYS_IN_SECONDS + 1);

      await token.setFeeBps(100);
      await expect(
        bondingRegistry
          .connect(operator1)
          .claimExitsFor(operator1Address, 0, exitAmount),
      )
        .to.be.revertedWithCustomError(bondingRegistry, "AssetTransferMismatch")
        .withArgs(tokenAddress, exitAmount, exitAmount + exitAmount / 100n);
      expect(await token.balanceOf(registryAddress)).to.equal(bondAmount);
      expect(await bondingRegistry.totalCiphernodeBondLiability()).to.equal(
        bondAmount,
      );
    });

    it("AUD-M08: blocks ticket-token rotation until supply and payouts are drained", async function () {
      const {
        bondingRegistry,
        ciphernodeBondToken,
        ticketToken,
        usdcToken,
        operator1,
        owner,
        slashingManager,
      } = await loadFixture(setup);

      await ciphernodeBondToken
        .connect(operator1)
        .approve(await bondingRegistry.getAddress(), REQUIRED_CIPHERNODE_BOND);
      await bondingRegistry
        .connect(operator1)
        .bondCiphernodeFor(operator1Address, REQUIRED_CIPHERNODE_BOND);
      await bondingRegistry
        .connect(operator1)
        .registerOperatorFor(operator1Address);

      const ticketAmount = ethers.parseUnits("10", 6);
      await usdcToken
        .connect(operator1)
        .approve(await ticketToken.getAddress(), ticketAmount);
      await bondingRegistry
        .connect(operator1)
        .addTicketBalanceFor(operator1Address, ticketAmount);

      const replacement = await (
        await ethers.getContractFactory("InterfoldTicketToken")
      ).deploy(
        await usdcToken.getAddress(),
        await bondingRegistry.getAddress(),
        owner.address,
      );
      await replacement.waitForDeployment();

      await expect(
        setBondingAssetConfig(bondingRegistry, {
          ticketToken: ethers.ZeroAddress,
        }),
      )
        .to.be.revertedWithCustomError(bondingRegistry, "InvalidBondingAsset")
        .withArgs(ethers.ZeroAddress);
      await expect(
        setBondingAssetConfig(bondingRegistry, {
          ticketToken: await replacement.getAddress(),
        }),
      )
        .to.be.revertedWithCustomError(
          bondingRegistry,
          "OutstandingAssetLiabilities",
        )
        .withArgs(await ticketToken.getAddress(), ticketAmount);

      const slashSigner = await impersonateSlashingManager(slashingManager);
      await bondingRegistry
        .connect(slashSigner)
        .slashTicketBalance(
          operator1Address,
          ticketAmount,
          ethers.id("ticket-rotation-liability"),
        );
      await networkHelpers.stopImpersonatingAccount(
        await slashingManager.getAddress(),
      );
      expect(await ticketToken.totalSupply()).to.equal(0);
      expect(await ticketToken.payableBalance()).to.equal(ticketAmount);

      await expect(
        setBondingAssetConfig(bondingRegistry, {
          ticketToken: await replacement.getAddress(),
        }),
      )
        .to.be.revertedWithCustomError(
          bondingRegistry,
          "OutstandingAssetLiabilities",
        )
        .withArgs(await ticketToken.getAddress(), ticketAmount);

      await bondingRegistry.withdrawSlashedFunds(ticketAmount, 0);
      expect(await ticketToken.payableBalance()).to.equal(0);
      expect(await bondingRegistry.slashedTicketBalance()).to.equal(0);

      await expect(
        setBondingAssetConfig(bondingRegistry, {
          ticketToken: await replacement.getAddress(),
        }),
      ).to.emit(bondingRegistry, "BondingAssetConfigUpdated");
      expect(await bondingRegistry.ticketToken()).to.equal(
        await replacement.getAddress(),
      );
    });
  });
});
