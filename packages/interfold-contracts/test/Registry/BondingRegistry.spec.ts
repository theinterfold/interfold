// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
import { expect } from "chai";

import {
  LICENSE_REQUIRED_BOND,
  MIN_TICKET_BALANCE,
  SEVEN_DAYS,
  TICKET_PRICE,
  deployInterfoldSystem,
  ethers,
  networkHelpers,
} from "../fixtures";

const { loadFixture, time } = networkHelpers;

const REASON_DEPOSIT = ethers.encodeBytes32String("DEPOSIT");
const REASON_WITHDRAW = ethers.encodeBytes32String("WITHDRAW");
const REASON_BOND = ethers.encodeBytes32String("BOND");
const REASON_UNBOND = ethers.encodeBytes32String("UNBOND");

describe("BondingRegistry", function () {
  const SEVEN_DAYS_IN_SECONDS = SEVEN_DAYS;
  async function setup() {
    const signers = await ethers.getSigners();
    const [owner, operator1, operator2, treasury, notTheOwner] = signers;
    const ownerAddress = await owner.getAddress();
    const operator1Address = await operator1.getAddress();
    const operator2Address = await operator2.getAddress();
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
      licenseToken,
      usdcToken,
      slashingManager,
      mockCiphernodeRegistry,
    } = sys;
    // Spec consumes the (mock) registry typed as the real interface.
    const ciphernodeRegistry = mockCiphernodeRegistry!;

    // ── Mint Tokens (owner + spec-local operator1/operator2) ─────────────────
    const USDC_AMOUNT = ethers.parseUnits("100000", 6);
    const LICENSE_AMOUNT = ethers.parseEther("100000");

    for (const address of [ownerAddress, operator1Address, operator2Address]) {
      await usdcToken.mint(address, USDC_AMOUNT);
      await licenseToken.mint(
        address,
        LICENSE_AMOUNT,
        ethers.encodeBytes32String("Test allocation"),
      );
    }

    return {
      bondingRegistry,
      ticketToken,
      licenseToken,
      usdcToken,
      slashingManager,
      ciphernodeRegistry,
      owner,
      operator1,
      operator2,
      treasury,
      notTheOwner,
      ownerAddress,
      operator1Address,
      operator2Address,
      treasuryAddress,
    };
  }
  describe("constructor / initialize()", function () {
    it("correctly sets initial parameters", async function () {
      const { bondingRegistry, ticketToken, licenseToken, treasuryAddress } =
        await loadFixture(setup);

      expect(await bondingRegistry.ticketToken()).to.equal(
        await ticketToken.getAddress(),
      );
      expect(await bondingRegistry.licenseToken()).to.equal(
        await licenseToken.getAddress(),
      );
      expect(await bondingRegistry.slashedFundsTreasury()).to.equal(
        treasuryAddress,
      );
      expect(await bondingRegistry.ticketPrice()).to.equal(TICKET_PRICE);
      expect(await bondingRegistry.licenseRequiredBond()).to.equal(
        LICENSE_REQUIRED_BOND,
      );
      expect(await bondingRegistry.minTicketBalance()).to.equal(
        MIN_TICKET_BALANCE,
      );
      expect(await bondingRegistry.exitDelay()).to.equal(SEVEN_DAYS_IN_SECONDS);
      expect(await bondingRegistry.licenseActiveBps()).to.equal(8000);
    });
  });

  describe("bondLicense()", function () {
    it("allows operators to bond license tokens", async function () {
      const { bondingRegistry, licenseToken, operator1 } =
        await loadFixture(setup);

      const bondAmount = ethers.parseEther("1000");
      await licenseToken
        .connect(operator1)
        .approve(await bondingRegistry.getAddress(), bondAmount);

      await expect(bondingRegistry.connect(operator1).bondLicense(bondAmount))
        .to.emit(bondingRegistry, "LicenseBondUpdated")
        .withArgs(
          await operator1.getAddress(),
          bondAmount,
          bondAmount,
          REASON_BOND,
        );

      expect(
        await bondingRegistry.getLicenseBond(await operator1.getAddress()),
      ).to.equal(bondAmount);
      expect(
        await bondingRegistry.totalBonded(await operator1.getAddress()),
      ).to.equal(bondAmount);
    });

    it("reverts if amount is zero", async function () {
      const { bondingRegistry, operator1 } = await loadFixture(setup);

      await expect(
        bondingRegistry.connect(operator1).bondLicense(0),
      ).to.be.revertedWithCustomError(bondingRegistry, "ZeroAmount");
    });

    it("reverts if exit is in progress", async function () {
      const { bondingRegistry, licenseToken, operator1 } =
        await loadFixture(setup);

      const bondAmount = ethers.parseEther("1000");
      await licenseToken
        .connect(operator1)
        .approve(await bondingRegistry.getAddress(), bondAmount);
      await bondingRegistry.connect(operator1).bondLicense(bondAmount);

      await bondingRegistry.connect(operator1).registerOperator();

      await bondingRegistry.connect(operator1).deregisterOperator();

      await licenseToken
        .connect(operator1)
        .approve(await bondingRegistry.getAddress(), bondAmount);
      await expect(
        bondingRegistry.connect(operator1).bondLicense(bondAmount),
      ).to.be.revertedWithCustomError(bondingRegistry, "ExitInProgress");
    });

    it("accumulates multiple bond amounts", async function () {
      const { bondingRegistry, licenseToken, operator1 } =
        await loadFixture(setup);

      const bondAmount1 = ethers.parseEther("500");
      const bondAmount2 = ethers.parseEther("300");

      await licenseToken
        .connect(operator1)
        .approve(await bondingRegistry.getAddress(), bondAmount1);
      await bondingRegistry.connect(operator1).bondLicense(bondAmount1);

      await licenseToken
        .connect(operator1)
        .approve(await bondingRegistry.getAddress(), bondAmount2);
      await bondingRegistry.connect(operator1).bondLicense(bondAmount2);

      expect(
        await bondingRegistry.getLicenseBond(await operator1.getAddress()),
      ).to.equal(bondAmount1 + bondAmount2);
    });
  });

  describe("unbondLicense()", function () {
    it("allows operators to unbond license tokens", async function () {
      const { bondingRegistry, licenseToken, operator1 } =
        await loadFixture(setup);

      const bondAmount = ethers.parseEther("1000");
      const unbondAmount = ethers.parseEther("200");

      await licenseToken
        .connect(operator1)
        .approve(await bondingRegistry.getAddress(), bondAmount);
      await bondingRegistry.connect(operator1).bondLicense(bondAmount);

      await expect(
        bondingRegistry.connect(operator1).unbondLicense(unbondAmount),
      )
        .to.emit(bondingRegistry, "LicenseBondUpdated")
        .withArgs(
          await operator1.getAddress(),
          -unbondAmount,
          bondAmount - unbondAmount,
          REASON_UNBOND,
        );

      expect(
        await bondingRegistry.getLicenseBond(await operator1.getAddress()),
      ).to.equal(bondAmount - unbondAmount);
    });

    it("reverts if amount is zero", async function () {
      const { bondingRegistry, operator1 } = await loadFixture(setup);

      await expect(
        bondingRegistry.connect(operator1).unbondLicense(0),
      ).to.be.revertedWithCustomError(bondingRegistry, "ZeroAmount");
    });

    it("reverts if insufficient balance", async function () {
      const { bondingRegistry, operator1 } = await loadFixture(setup);

      await expect(
        bondingRegistry
          .connect(operator1)
          .unbondLicense(ethers.parseEther("100")),
      ).to.be.revertedWithCustomError(bondingRegistry, "InsufficientBalance");
    });

    it("queues license tokens for exit", async function () {
      const { bondingRegistry, licenseToken, operator1 } =
        await loadFixture(setup);

      const bondAmount = ethers.parseEther("1000");
      const unbondAmount = ethers.parseEther("200");

      await licenseToken
        .connect(operator1)
        .approve(await bondingRegistry.getAddress(), bondAmount);
      await bondingRegistry.connect(operator1).bondLicense(bondAmount);

      await bondingRegistry.connect(operator1).unbondLicense(unbondAmount);

      const [, licensePending] = await bondingRegistry.pendingExits(
        await operator1.getAddress(),
      );
      expect(licensePending).to.equal(unbondAmount);
      expect(
        await bondingRegistry.totalBonded(await operator1.getAddress()),
      ).to.equal(bondAmount);
    });

    it("slashes active and pending license bond from totalBonded", async function () {
      const { bondingRegistry, licenseToken, operator1, notTheOwner } =
        await loadFixture(setup);
      const operatorAddress = await operator1.getAddress();
      const slashReason = ethers.encodeBytes32String("TEST_SLASH");

      const bondAmount = ethers.parseEther("1000");
      const unbondAmount = ethers.parseEther("300");
      const slashAmount = ethers.parseEther("800");

      await bondingRegistry.setSlashingManager(await notTheOwner.getAddress());
      await licenseToken
        .connect(operator1)
        .approve(await bondingRegistry.getAddress(), bondAmount);
      await bondingRegistry.connect(operator1).bondLicense(bondAmount);
      await bondingRegistry.connect(operator1).unbondLicense(unbondAmount);

      await expect(
        bondingRegistry
          .connect(notTheOwner)
          .slashLicenseBond(operatorAddress, slashAmount, slashReason),
      )
        .to.emit(bondingRegistry, "LicenseBondUpdated")
        .withArgs(operatorAddress, -slashAmount, 0, slashReason);

      const [, pendingLicense] =
        await bondingRegistry.pendingExits(operatorAddress);
      expect(pendingLicense).to.equal(bondAmount - slashAmount);
      expect(await bondingRegistry.totalBonded(operatorAddress)).to.equal(
        bondAmount - slashAmount,
      );
      expect(await bondingRegistry.slashedLicenseBond()).to.equal(slashAmount);
    });
  });

  describe("registerOperator()", function () {
    it("allows properly licensed operators to register", async function () {
      const { bondingRegistry, licenseToken, operator1 } =
        await loadFixture(setup);

      const bondAmount = LICENSE_REQUIRED_BOND;
      await licenseToken
        .connect(operator1)
        .approve(await bondingRegistry.getAddress(), bondAmount);
      await bondingRegistry.connect(operator1).bondLicense(bondAmount);

      await bondingRegistry.connect(operator1).registerOperator();

      expect(await bondingRegistry.isRegistered(await operator1.getAddress()))
        .to.be.true;
      expect(await bondingRegistry.isActive(await operator1.getAddress())).to.be
        .false;
    });

    it("reverts if not properly licensed", async function () {
      const { bondingRegistry, operator1 } = await loadFixture(setup);

      await expect(
        bondingRegistry.connect(operator1).registerOperator(),
      ).to.be.revertedWithCustomError(bondingRegistry, "NotLicensed");
    });

    it("reverts if already registered", async function () {
      const { bondingRegistry, licenseToken, operator1 } =
        await loadFixture(setup);

      const bondAmount = LICENSE_REQUIRED_BOND;
      await licenseToken
        .connect(operator1)
        .approve(await bondingRegistry.getAddress(), bondAmount);
      await bondingRegistry.connect(operator1).bondLicense(bondAmount);
      await bondingRegistry.connect(operator1).registerOperator();

      await expect(
        bondingRegistry.connect(operator1).registerOperator(),
      ).to.be.revertedWithCustomError(bondingRegistry, "AlreadyRegistered");
    });

    it("clears previous exit request when re-registering", async function () {
      const { bondingRegistry, licenseToken, operator1 } =
        await loadFixture(setup);

      const bondAmount = LICENSE_REQUIRED_BOND;
      await licenseToken
        .connect(operator1)
        .approve(await bondingRegistry.getAddress(), bondAmount);
      await bondingRegistry.connect(operator1).bondLicense(bondAmount);
      await bondingRegistry.connect(operator1).registerOperator();

      await bondingRegistry.connect(operator1).deregisterOperator();

      await time.increase(SEVEN_DAYS_IN_SECONDS + 1);

      await licenseToken
        .connect(operator1)
        .approve(await bondingRegistry.getAddress(), bondAmount);
      await bondingRegistry.connect(operator1).bondLicense(bondAmount);
      await bondingRegistry.connect(operator1).registerOperator();

      expect(
        await bondingRegistry.hasExitInProgress(await operator1.getAddress()),
      ).to.be.false;
    });
  });

  describe("deregisterOperator()", function () {
    it("allows registered operators to deregister", async function () {
      const { bondingRegistry, licenseToken, operator1 } =
        await loadFixture(setup);

      const bondAmount = LICENSE_REQUIRED_BOND;
      await licenseToken
        .connect(operator1)
        .approve(await bondingRegistry.getAddress(), bondAmount);
      await bondingRegistry.connect(operator1).bondLicense(bondAmount);
      await bondingRegistry.connect(operator1).registerOperator();

      const latestTime = await time.latest();
      await expect(bondingRegistry.connect(operator1).deregisterOperator())
        .to.emit(bondingRegistry, "CiphernodeDeregistrationRequested")
        .withArgs(
          await operator1.getAddress(),
          latestTime + SEVEN_DAYS_IN_SECONDS + 1,
        );

      expect(await bondingRegistry.isRegistered(await operator1.getAddress()))
        .to.be.false;
      expect(
        await bondingRegistry.hasExitInProgress(await operator1.getAddress()),
      ).to.be.true;
    });

    it("reverts if not registered", async function () {
      const { bondingRegistry, operator1 } = await loadFixture(setup);

      await expect(
        bondingRegistry.connect(operator1).deregisterOperator(),
      ).to.be.revertedWithCustomError(bondingRegistry, "NotRegistered");
    });

    it("queues assets for exit when deregistering", async function () {
      const {
        bondingRegistry,
        licenseToken,
        usdcToken,
        ticketToken,
        operator1,
      } = await loadFixture(setup);

      const bondAmount = LICENSE_REQUIRED_BOND;
      await licenseToken
        .connect(operator1)
        .approve(await bondingRegistry.getAddress(), bondAmount);
      await bondingRegistry.connect(operator1).bondLicense(bondAmount);
      await bondingRegistry.connect(operator1).registerOperator();

      const ticketAmount = ethers.parseUnits("100", 6);
      await usdcToken
        .connect(operator1)
        .approve(await ticketToken.getAddress(), ticketAmount);
      await bondingRegistry.connect(operator1).addTicketBalance(ticketAmount);

      await bondingRegistry.connect(operator1).deregisterOperator();

      const [ticketPending, licensePending] =
        await bondingRegistry.pendingExits(await operator1.getAddress());
      expect(ticketPending).to.equal(ticketAmount);
      expect(licensePending).to.equal(bondAmount);
    });
  });

  describe("addTicketBalance()", function () {
    it("allows registered operators to add ticket balance", async function () {
      const {
        bondingRegistry,
        licenseToken,
        usdcToken,
        ticketToken,
        operator1,
      } = await loadFixture(setup);

      const bondAmount = LICENSE_REQUIRED_BOND;
      await licenseToken
        .connect(operator1)
        .approve(await bondingRegistry.getAddress(), bondAmount);
      await bondingRegistry.connect(operator1).bondLicense(bondAmount);
      await bondingRegistry.connect(operator1).registerOperator();

      const ticketAmount = ethers.parseUnits("100", 6);
      await usdcToken
        .connect(operator1)
        .approve(await ticketToken.getAddress(), ticketAmount);

      await expect(
        bondingRegistry.connect(operator1).addTicketBalance(ticketAmount),
      )
        .to.emit(bondingRegistry, "TicketBalanceUpdated")
        .withArgs(
          await operator1.getAddress(),
          ticketAmount,
          ticketAmount,
          REASON_DEPOSIT,
        );

      expect(
        await bondingRegistry.getTicketBalance(await operator1.getAddress()),
      ).to.equal(ticketAmount);
    });

    it("activates operator when minimum balance is reached", async function () {
      const {
        bondingRegistry,
        licenseToken,
        usdcToken,
        ticketToken,
        operator1,
      } = await loadFixture(setup);

      const bondAmount = LICENSE_REQUIRED_BOND;
      await licenseToken
        .connect(operator1)
        .approve(await bondingRegistry.getAddress(), bondAmount);
      await bondingRegistry.connect(operator1).bondLicense(bondAmount);
      await bondingRegistry.connect(operator1).registerOperator();

      const ticketAmount = ethers.parseUnits("50", 6);
      await usdcToken
        .connect(operator1)
        .approve(await ticketToken.getAddress(), ticketAmount);

      await expect(
        bondingRegistry.connect(operator1).addTicketBalance(ticketAmount),
      )
        .to.emit(bondingRegistry, "OperatorActivationChanged")
        .withArgs(await operator1.getAddress(), true);

      expect(await bondingRegistry.isActive(await operator1.getAddress())).to.be
        .true;
    });

    it("reverts if not registered", async function () {
      const { bondingRegistry, operator1 } = await loadFixture(setup);

      await expect(
        bondingRegistry
          .connect(operator1)
          .addTicketBalance(ethers.parseUnits("100", 6)),
      ).to.be.revertedWithCustomError(bondingRegistry, "NotRegistered");
    });

    it("reverts if amount is zero", async function () {
      const { bondingRegistry, licenseToken, operator1 } =
        await loadFixture(setup);

      const bondAmount = LICENSE_REQUIRED_BOND;
      await licenseToken
        .connect(operator1)
        .approve(await bondingRegistry.getAddress(), bondAmount);
      await bondingRegistry.connect(operator1).bondLicense(bondAmount);
      await bondingRegistry.connect(operator1).registerOperator();

      await expect(
        bondingRegistry.connect(operator1).addTicketBalance(0),
      ).to.be.revertedWithCustomError(bondingRegistry, "ZeroAmount");
    });
  });

  describe("removeTicketBalance()", function () {
    it("allows operators to remove ticket balance", async function () {
      const {
        bondingRegistry,
        licenseToken,
        usdcToken,
        ticketToken,
        operator1,
      } = await loadFixture(setup);

      const bondAmount = LICENSE_REQUIRED_BOND;
      await licenseToken
        .connect(operator1)
        .approve(await bondingRegistry.getAddress(), bondAmount);
      await bondingRegistry.connect(operator1).bondLicense(bondAmount);
      await bondingRegistry.connect(operator1).registerOperator();

      const ticketAmount = ethers.parseUnits("100", 6);
      await usdcToken
        .connect(operator1)
        .approve(await ticketToken.getAddress(), ticketAmount);
      await bondingRegistry.connect(operator1).addTicketBalance(ticketAmount);

      const removeAmount = ethers.parseUnits("30", 6);
      await expect(
        bondingRegistry.connect(operator1).removeTicketBalance(removeAmount),
      )
        .to.emit(bondingRegistry, "TicketBalanceUpdated")
        .withArgs(
          await operator1.getAddress(),
          -removeAmount,
          ticketAmount - removeAmount,
          REASON_WITHDRAW,
        );

      expect(
        await bondingRegistry.getTicketBalance(await operator1.getAddress()),
      ).to.equal(ticketAmount - removeAmount);
    });

    it("queues removed tickets for exit", async function () {
      const {
        bondingRegistry,
        licenseToken,
        usdcToken,
        ticketToken,
        operator1,
      } = await loadFixture(setup);

      const bondAmount = LICENSE_REQUIRED_BOND;
      await licenseToken
        .connect(operator1)
        .approve(await bondingRegistry.getAddress(), bondAmount);
      await bondingRegistry.connect(operator1).bondLicense(bondAmount);
      await bondingRegistry.connect(operator1).registerOperator();

      const ticketAmount = ethers.parseUnits("100", 6);
      await usdcToken
        .connect(operator1)
        .approve(await ticketToken.getAddress(), ticketAmount);
      await bondingRegistry.connect(operator1).addTicketBalance(ticketAmount);

      const removeAmount = ethers.parseUnits("30", 6);
      await bondingRegistry
        .connect(operator1)
        .removeTicketBalance(removeAmount);

      const [ticketPending] = await bondingRegistry.pendingExits(
        await operator1.getAddress(),
      );
      expect(ticketPending).to.equal(removeAmount);
    });

    it("deactivates operator if balance falls below minimum", async function () {
      const {
        bondingRegistry,
        licenseToken,
        usdcToken,
        ticketToken,
        operator1,
      } = await loadFixture(setup);

      const bondAmount = LICENSE_REQUIRED_BOND;
      await licenseToken
        .connect(operator1)
        .approve(await bondingRegistry.getAddress(), bondAmount);
      await bondingRegistry.connect(operator1).bondLicense(bondAmount);
      await bondingRegistry.connect(operator1).registerOperator();

      const ticketAmount = ethers.parseUnits("60", 6);
      await usdcToken
        .connect(operator1)
        .approve(await ticketToken.getAddress(), ticketAmount);
      await bondingRegistry.connect(operator1).addTicketBalance(ticketAmount);

      const removeAmount = ethers.parseUnits("20", 6);
      await expect(
        bondingRegistry.connect(operator1).removeTicketBalance(removeAmount),
      )
        .to.emit(bondingRegistry, "OperatorActivationChanged")
        .withArgs(await operator1.getAddress(), false);

      expect(await bondingRegistry.isActive(await operator1.getAddress())).to.be
        .false;
    });

    it("reverts if insufficient balance", async function () {
      const { bondingRegistry, licenseToken, operator1 } =
        await loadFixture(setup);

      const bondAmount = LICENSE_REQUIRED_BOND;
      await licenseToken
        .connect(operator1)
        .approve(await bondingRegistry.getAddress(), bondAmount);
      await bondingRegistry.connect(operator1).bondLicense(bondAmount);
      await bondingRegistry.connect(operator1).registerOperator();

      await expect(
        bondingRegistry
          .connect(operator1)
          .removeTicketBalance(ethers.parseUnits("100", 6)),
      ).to.be.revertedWithCustomError(bondingRegistry, "InsufficientBalance");
    });
  });

  describe("claimExits()", function () {
    it("allows claiming after exit delay", async function () {
      const {
        bondingRegistry,
        licenseToken,
        usdcToken,
        ticketToken,
        operator1,
      } = await loadFixture(setup);

      const bondAmount = LICENSE_REQUIRED_BOND;
      await licenseToken
        .connect(operator1)
        .approve(await bondingRegistry.getAddress(), bondAmount);
      await bondingRegistry.connect(operator1).bondLicense(bondAmount);
      await bondingRegistry.connect(operator1).registerOperator();

      const ticketAmount = ethers.parseUnits("100", 6);
      await usdcToken
        .connect(operator1)
        .approve(await ticketToken.getAddress(), ticketAmount);
      await bondingRegistry.connect(operator1).addTicketBalance(ticketAmount);

      await bondingRegistry.connect(operator1).deregisterOperator();

      await time.increase(SEVEN_DAYS_IN_SECONDS + 1);

      const initialUSDCBalance = await usdcToken.balanceOf(
        await operator1.getAddress(),
      );
      const initialINTFBalance = await licenseToken.balanceOf(
        await operator1.getAddress(),
      );

      await bondingRegistry
        .connect(operator1)
        .claimExits(ticketAmount, bondAmount);

      expect(await usdcToken.balanceOf(await operator1.getAddress())).to.equal(
        initialUSDCBalance + ticketAmount,
      );
      expect(
        await licenseToken.balanceOf(await operator1.getAddress()),
      ).to.equal(initialINTFBalance + bondAmount);
    });

    it("reverts if exit not ready", async function () {
      const { bondingRegistry, licenseToken, operator1 } =
        await loadFixture(setup);

      const bondAmount = LICENSE_REQUIRED_BOND;
      await licenseToken
        .connect(operator1)
        .approve(await bondingRegistry.getAddress(), bondAmount);
      await bondingRegistry.connect(operator1).bondLicense(bondAmount);
      await bondingRegistry.connect(operator1).registerOperator();

      await bondingRegistry.connect(operator1).deregisterOperator();

      await expect(
        bondingRegistry.connect(operator1).claimExits(0, bondAmount),
      ).to.be.revertedWithCustomError(bondingRegistry, "ExitNotReady");
    });

    it("allows partial claims", async function () {
      const {
        bondingRegistry,
        licenseToken,
        usdcToken,
        ticketToken,
        operator1,
      } = await loadFixture(setup);

      const bondAmount = LICENSE_REQUIRED_BOND;
      await licenseToken
        .connect(operator1)
        .approve(await bondingRegistry.getAddress(), bondAmount);
      await bondingRegistry.connect(operator1).bondLicense(bondAmount);
      await bondingRegistry.connect(operator1).registerOperator();

      const ticketAmount = ethers.parseUnits("100", 6);
      await usdcToken
        .connect(operator1)
        .approve(await ticketToken.getAddress(), ticketAmount);
      await bondingRegistry.connect(operator1).addTicketBalance(ticketAmount);

      await bondingRegistry.connect(operator1).deregisterOperator();

      await time.increase(SEVEN_DAYS_IN_SECONDS + 1);

      const partialTickets = ethers.parseUnits("50", 6);
      const partialLicense = ethers.parseEther("500");

      const initialUSDCBalance = await usdcToken.balanceOf(
        await operator1.getAddress(),
      );
      const initialINTFBalance = await licenseToken.balanceOf(
        await operator1.getAddress(),
      );

      await bondingRegistry
        .connect(operator1)
        .claimExits(partialTickets, partialLicense);

      expect(await usdcToken.balanceOf(await operator1.getAddress())).to.equal(
        initialUSDCBalance + partialTickets,
      );
      expect(
        await licenseToken.balanceOf(await operator1.getAddress()),
      ).to.equal(initialINTFBalance + partialLicense);

      const [remainingTickets, remainingLicense] =
        await bondingRegistry.pendingExits(await operator1.getAddress());
      expect(remainingTickets).to.equal(ticketAmount - partialTickets);
      expect(remainingLicense).to.equal(bondAmount - partialLicense);
    });
  });

  describe("isLicensed()", function () {
    it("returns true when operator has minimum license bond", async function () {
      const { bondingRegistry, licenseToken, operator1 } =
        await loadFixture(setup);

      const minBond = (LICENSE_REQUIRED_BOND * 8000n) / 10000n;
      await licenseToken
        .connect(operator1)
        .approve(await bondingRegistry.getAddress(), minBond);
      await bondingRegistry.connect(operator1).bondLicense(minBond);

      expect(await bondingRegistry.isLicensed(await operator1.getAddress())).to
        .be.true;
    });

    it("returns false when operator has insufficient license bond", async function () {
      const { bondingRegistry, licenseToken, operator1 } =
        await loadFixture(setup);

      const insufficientBond = (LICENSE_REQUIRED_BOND * 7999n) / 10000n;
      await licenseToken
        .connect(operator1)
        .approve(await bondingRegistry.getAddress(), insufficientBond);
      await bondingRegistry.connect(operator1).bondLicense(insufficientBond);

      expect(await bondingRegistry.isLicensed(await operator1.getAddress())).to
        .be.false;
    });
  });

  describe("availableTickets()", function () {
    it("calculates available tickets correctly", async function () {
      const {
        bondingRegistry,
        licenseToken,
        usdcToken,
        ticketToken,
        operator1,
      } = await loadFixture(setup);

      const bondAmount = LICENSE_REQUIRED_BOND;
      await licenseToken
        .connect(operator1)
        .approve(await bondingRegistry.getAddress(), bondAmount);
      await bondingRegistry.connect(operator1).bondLicense(bondAmount);
      await bondingRegistry.connect(operator1).registerOperator();

      const ticketAmount = ethers.parseUnits("100", 6);
      await usdcToken
        .connect(operator1)
        .approve(await ticketToken.getAddress(), ticketAmount);
      await bondingRegistry.connect(operator1).addTicketBalance(ticketAmount);

      expect(
        await bondingRegistry.availableTickets(await operator1.getAddress()),
      ).to.equal(10);
    });

    it("returns 0 when operator has zero ticket balance", async function () {
      const { bondingRegistry, operator1 } = await loadFixture(setup);

      expect(
        await bondingRegistry.availableTickets(await operator1.getAddress()),
      ).to.equal(0);
    });
  });

  describe("Admin Functions", function () {
    describe("setTicketPrice()", function () {
      it("allows owner to set ticket price", async function () {
        const { bondingRegistry } = await loadFixture(setup);

        const newPrice = ethers.parseUnits("15", 6);
        await expect(bondingRegistry.setTicketPrice(newPrice))
          .to.emit(bondingRegistry, "ConfigurationUpdated")
          .withArgs(
            ethers.encodeBytes32String("ticketPrice"),
            TICKET_PRICE,
            newPrice,
          );

        expect(await bondingRegistry.ticketPrice()).to.equal(newPrice);
      });

      it("reverts if price is zero", async function () {
        const { bondingRegistry } = await loadFixture(setup);

        await expect(
          bondingRegistry.setTicketPrice(0),
        ).to.be.revertedWithCustomError(
          bondingRegistry,
          "InvalidConfiguration",
        );
      });

      it("reverts if not owner", async function () {
        const { bondingRegistry, notTheOwner } = await loadFixture(setup);

        await expect(
          bondingRegistry
            .connect(notTheOwner)
            .setTicketPrice(ethers.parseEther("15")),
        ).to.be.revertedWithCustomError(
          bondingRegistry,
          "OwnableUnauthorizedAccount",
        );
      });
    });

    describe("setLicenseActiveBps()", function () {
      it("allows owner to set license active basis points", async function () {
        const { bondingRegistry } = await loadFixture(setup);

        const newBps = 9000;
        await expect(bondingRegistry.setLicenseActiveBps(newBps))
          .to.emit(bondingRegistry, "ConfigurationUpdated")
          .withArgs(
            ethers.encodeBytes32String("licenseActiveBps"),
            8000,
            newBps,
          );

        expect(await bondingRegistry.licenseActiveBps()).to.equal(newBps);
      });

      it("reverts if bps is 0", async function () {
        const { bondingRegistry } = await loadFixture(setup);

        await expect(
          bondingRegistry.setLicenseActiveBps(0),
        ).to.be.revertedWithCustomError(
          bondingRegistry,
          "InvalidConfiguration",
        );
      });

      it("reverts if bps is greater than 10000", async function () {
        const { bondingRegistry } = await loadFixture(setup);

        await expect(
          bondingRegistry.setLicenseActiveBps(10001),
        ).to.be.revertedWithCustomError(
          bondingRegistry,
          "InvalidConfiguration",
        );
      });
    });

    describe("withdrawSlashedFunds()", function () {
      it("allows owner to withdraw slashed funds", async function () {
        const { bondingRegistry, treasury } = await loadFixture(setup);

        await expect(bondingRegistry.withdrawSlashedFunds(0, 0))
          .to.emit(bondingRegistry, "SlashedFundsWithdrawn")
          .withArgs(await treasury.getAddress(), 0, 0);
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
    it("handles operator becoming inactive due to license reduction", async function () {
      const {
        bondingRegistry,
        licenseToken,
        usdcToken,
        ticketToken,
        operator1,
      } = await loadFixture(setup);

      const bondAmount = LICENSE_REQUIRED_BOND;
      await licenseToken
        .connect(operator1)
        .approve(await bondingRegistry.getAddress(), bondAmount);
      await bondingRegistry.connect(operator1).bondLicense(bondAmount);
      await bondingRegistry.connect(operator1).registerOperator();

      const ticketAmount = ethers.parseUnits("60", 6);
      await usdcToken
        .connect(operator1)
        .approve(await ticketToken.getAddress(), ticketAmount);
      await bondingRegistry.connect(operator1).addTicketBalance(ticketAmount);

      expect(await bondingRegistry.isActive(await operator1.getAddress())).to.be
        .true;

      const unbondAmount = LICENSE_REQUIRED_BOND / 5n;
      await bondingRegistry.connect(operator1).unbondLicense(unbondAmount + 1n);
      expect(await bondingRegistry.isActive(await operator1.getAddress())).to.be
        .false;
      expect(await bondingRegistry.isLicensed(await operator1.getAddress())).to
        .be.false;
    });

    it("handles multiple operators with different states", async function () {
      const {
        bondingRegistry,
        licenseToken,
        usdcToken,
        ticketToken,
        operator1,
        operator2,
      } = await loadFixture(setup);

      const bondAmount = LICENSE_REQUIRED_BOND;
      await licenseToken
        .connect(operator1)
        .approve(await bondingRegistry.getAddress(), bondAmount);
      await bondingRegistry.connect(operator1).bondLicense(bondAmount);
      await bondingRegistry.connect(operator1).registerOperator();

      await licenseToken
        .connect(operator2)
        .approve(await bondingRegistry.getAddress(), bondAmount);
      await bondingRegistry.connect(operator2).bondLicense(bondAmount);
      await bondingRegistry.connect(operator2).registerOperator();

      const ticketAmount = ethers.parseUnits("60", 6);
      await usdcToken
        .connect(operator2)
        .approve(await ticketToken.getAddress(), ticketAmount);
      await bondingRegistry.connect(operator2).addTicketBalance(ticketAmount);

      expect(await bondingRegistry.isRegistered(await operator1.getAddress()))
        .to.be.true;
      expect(await bondingRegistry.isActive(await operator1.getAddress())).to.be
        .false;

      expect(await bondingRegistry.isRegistered(await operator2.getAddress()))
        .to.be.true;
      expect(await bondingRegistry.isActive(await operator2.getAddress())).to.be
        .true;
    });

    it("handles the complete operator lifecycle", async function () {
      const {
        bondingRegistry,
        licenseToken,
        usdcToken,
        ticketToken,
        operator1,
      } = await loadFixture(setup);

      const bondAmount = LICENSE_REQUIRED_BOND;
      await licenseToken
        .connect(operator1)
        .approve(await bondingRegistry.getAddress(), bondAmount);
      await bondingRegistry.connect(operator1).bondLicense(bondAmount);
      expect(await bondingRegistry.isLicensed(await operator1.getAddress())).to
        .be.true;

      await bondingRegistry.connect(operator1).registerOperator();
      expect(await bondingRegistry.isRegistered(await operator1.getAddress()))
        .to.be.true;
      expect(await bondingRegistry.isActive(await operator1.getAddress())).to.be
        .false;

      const ticketAmount = ethers.parseUnits("60", 6);
      await usdcToken
        .connect(operator1)
        .approve(await ticketToken.getAddress(), ticketAmount);
      await bondingRegistry.connect(operator1).addTicketBalance(ticketAmount);
      expect(await bondingRegistry.isActive(await operator1.getAddress())).to.be
        .true;

      await bondingRegistry.connect(operator1).deregisterOperator();
      expect(await bondingRegistry.isRegistered(await operator1.getAddress()))
        .to.be.false;
      expect(
        await bondingRegistry.hasExitInProgress(await operator1.getAddress()),
      ).to.be.true;

      await time.increase(SEVEN_DAYS_IN_SECONDS + 1);

      const initialUSDCBalance = await usdcToken.balanceOf(
        await operator1.getAddress(),
      );
      const initialINTFBalance = await licenseToken.balanceOf(
        await operator1.getAddress(),
      );

      await bondingRegistry
        .connect(operator1)
        .claimExits(ticketAmount, bondAmount);

      expect(await usdcToken.balanceOf(await operator1.getAddress())).to.equal(
        initialUSDCBalance + ticketAmount,
      );
      expect(
        await licenseToken.balanceOf(await operator1.getAddress()),
      ).to.equal(initialINTFBalance + bondAmount);

      await licenseToken
        .connect(operator1)
        .approve(await bondingRegistry.getAddress(), bondAmount);
      await bondingRegistry.connect(operator1).bondLicense(bondAmount);
      await bondingRegistry.connect(operator1).registerOperator();
      expect(await bondingRegistry.isRegistered(await operator1.getAddress()))
        .to.be.true;
    });
  });

  // ───────────────────────────────────────────────────────────────────────────
  // Audit regression — exit queue and license payout
  // See: audits/interfold-contracts-ethskills-audit-opus-v2.md
  // ───────────────────────────────────────────────────────────────────────────
  describe("audit regression — exit queue & license payout", function () {
    /**
     * C-03 reproduction guard.
     *
     * Pre-fix the exit queue used a single per-operator `queueHeadIndex`
     * advanced whenever the tranche at the head was fully drained of EITHER
     * asset. A mixed queue (ticket-only tranche followed by license-only
     * tranche) could therefore strand the license assets once the tickets
     * were claimed: the shared head advanced past the second tranche while
     * its license balance was still pending.
     *
     * With the per-asset heads (`queueHeadIndexTicket` /
     * `queueHeadIndexLicense`) both balances must remain claimable
     * independently.
     */
    it("C-03: per-asset heads do not strand the other asset class", async function () {
      const {
        bondingRegistry,
        licenseToken,
        ticketToken,
        usdcToken,
        operator1,
        operator1Address,
      } = await loadFixture(setup);

      // Bond + register so we can unbond into the exit queue.
      const bondAmount = LICENSE_REQUIRED_BOND;
      await licenseToken
        .connect(operator1)
        .approve(await bondingRegistry.getAddress(), bondAmount);
      await bondingRegistry.connect(operator1).bondLicense(bondAmount);
      await bondingRegistry.connect(operator1).registerOperator();

      const ticketAmount = ethers.parseUnits("100", 6);
      await usdcToken
        .connect(operator1)
        .approve(await ticketToken.getAddress(), ticketAmount);
      await bondingRegistry.connect(operator1).addTicketBalance(ticketAmount);

      // Tranche #0 (license-only): unbond half the license.
      const halfLicense = bondAmount / 2n;
      await bondingRegistry.connect(operator1).unbondLicense(halfLicense);

      // Advance time so the next tranche gets a distinct unlock timestamp
      // (otherwise it would merge into tranche #0 and defeat the test).
      await time.increase(60);

      // Tranche #1 (ticket-only): remove some tickets to the queue.
      const halfTickets = ticketAmount / 2n;
      await bondingRegistry.connect(operator1).removeTicketBalance(halfTickets);

      // Wait past the exit delay so both tranches are unlocked.
      await time.increase(SEVEN_DAYS_IN_SECONDS + 1);

      // Claim ONLY the ticket leg from tranche #1.
      // Pre-fix: this would advance the shared head past tranche #0 too,
      // permanently stranding `halfLicense` in the queue.
      await bondingRegistry.connect(operator1).claimExits(halfTickets, 0);

      // The license leg from tranche #0 must still be claimable.
      const [pendingTickets, pendingLicense] =
        await bondingRegistry.pendingExits(operator1Address);
      expect(pendingTickets).to.equal(0n);
      expect(pendingLicense).to.equal(halfLicense);

      const beforeLicense = await licenseToken.balanceOf(operator1Address);
      await bondingRegistry.connect(operator1).claimExits(0, halfLicense);
      expect(await licenseToken.balanceOf(operator1Address)).to.equal(
        beforeLicense + halfLicense,
      );
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
      const { bondingRegistry, licenseToken, operator1, operator1Address } =
        await loadFixture(setup);

      const bondAmount = LICENSE_REQUIRED_BOND;
      await licenseToken
        .connect(operator1)
        .approve(await bondingRegistry.getAddress(), bondAmount);
      await bondingRegistry.connect(operator1).bondLicense(bondAmount);
      await bondingRegistry.connect(operator1).registerOperator();

      // Tranche A: unbond with the original 7-day delay.
      const quarter = bondAmount / 4n;
      await bondingRegistry.connect(operator1).unbondLicense(quarter);

      // Governance reduces the exit delay to 1 day.
      const ONE_DAY = 24 * 60 * 60;
      await bondingRegistry.setExitDelay(ONE_DAY);
      // Advance time so tranche B gets a distinct unlock timestamp.
      await time.increase(60);

      // Tranche B: unbond under the new 1-day delay.
      await bondingRegistry.connect(operator1).unbondLicense(quarter);

      // Move ~2 days forward — B is unlocked, A is still locked.
      await time.increase(2 * ONE_DAY);

      const [, pendingLicense] =
        await bondingRegistry.previewClaimable(operator1Address);
      // Pre-fix `break` would have returned 0; with `continue` we see B.
      expect(pendingLicense).to.equal(quarter);

      const beforeLicense = await licenseToken.balanceOf(operator1Address);
      await bondingRegistry.connect(operator1).claimExits(0, quarter);
      expect(await licenseToken.balanceOf(operator1Address)).to.equal(
        beforeLicense + quarter,
      );

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
        licenseToken,
        ticketToken,
        usdcToken,
        operator1,
      } = await loadFixture(setup);

      // Register and fund tickets so the generic ExitQueueLib ticket path is
      // exercised directly alongside INTF exits.
      const bondAmount = LICENSE_REQUIRED_BOND;
      await licenseToken
        .connect(operator1)
        .approve(await bondingRegistry.getAddress(), bondAmount);
      await bondingRegistry.connect(operator1).bondLicense(bondAmount);
      await bondingRegistry.connect(operator1).registerOperator();

      const ticketAmount = ethers.parseUnits("10000", 6);
      await usdcToken
        .connect(operator1)
        .approve(await ticketToken.getAddress(), ticketAmount);
      await bondingRegistry.connect(operator1).addTicketBalance(ticketAmount);

      // Fill the queue with 64 distinct-timestamp tranches.
      const step = ethers.parseUnits("1", 6);
      for (let i = 0; i < 64; i++) {
        await bondingRegistry.connect(operator1).removeTicketBalance(step);
        // Ensure next unlock timestamp differs (no merge).
        await time.increase(1);
      }

      // The 65th must revert.
      await expect(
        bondingRegistry.connect(operator1).removeTicketBalance(step),
      ).to.be.revertedWithCustomError(bondingRegistry, "TooManyTranches");
    });

    /**
     * M-13 reproduction guard.
     *
     * `claimExits` / `withdrawSlashedFunds` previously called
     * `licenseToken.safeTransfer` without measuring the registry's
     * own balance delta. A fee-on-transfer / rebasing token configured
     * via `setLicenseToken` would silently underpay the recipient while
     * the registry's internal accounting was still decremented by the
     * requested amount. The fix measures the delta and emits
     * `LicenseTransferShortfall(recipient, expected, actual)`.
     */
    it("M-13: emits LicenseTransferShortfall when license token charges a transfer fee", async function () {
      const { bondingRegistry, licenseToken, operator1, operator1Address } =
        await loadFixture(setup);

      // Bond + queue a license exit with the well-behaved token.
      const bondAmount = LICENSE_REQUIRED_BOND;
      await licenseToken
        .connect(operator1)
        .approve(await bondingRegistry.getAddress(), bondAmount);
      await bondingRegistry.connect(operator1).bondLicense(bondAmount);
      await bondingRegistry.connect(operator1).registerOperator();
      await bondingRegistry.connect(operator1).unbondLicense(bondAmount);
      await time.increase(SEVEN_DAYS_IN_SECONDS + 1);

      // Swap the license token for a 1% fee-on-transfer token.
      const FoTFactory = await ethers.getContractFactory(
        "MockFeeOnTransferToken",
      );
      const fot = await FoTFactory.deploy(100n); // 100 bps = 1%
      // Seed the registry with enough FoT tokens to honor the (gross) claim
      // amount: tests need to verify the delta-detection emits, not that the
      // registry magically conjures tokens. We mint `bondAmount` directly to
      // the registry's address.
      await fot.mint(await bondingRegistry.getAddress(), bondAmount);
      await bondingRegistry.setLicenseToken(await fot.getAddress());

      // Claim — the safeTransfer will short by 1%.
      const expectedFee = bondAmount / 100n;
      const expectedActual = bondAmount - expectedFee;

      await expect(bondingRegistry.connect(operator1).claimExits(0, bondAmount))
        .to.emit(bondingRegistry, "LicenseTransferShortfall")
        .withArgs(operator1Address, bondAmount, expectedActual);

      // Operator received the net (post-fee) amount.
      expect(await fot.balanceOf(operator1Address)).to.equal(expectedActual);
    });
  });
});
