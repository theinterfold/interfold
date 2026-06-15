// SPDX-License-Identifier: LGPL-3.0-only
//
// Sortition & E3 lifecycle regression tests:
//   * `markE3Failed` grace period restricts callers inside the
//     `[deadline, deadline + markFailedGracePeriod)` window to the
//     requester / owner / committee members; permissionless afterwards.
//   * `Committee.requestBlock` stores `block.timestamp` so it
//     resolves consistently against the ticket-token EIP-6372 clock.
//   * `_validateNodeEligibility` derives weight from the
//     `getTicketBalanceAtBlock(operator, requestBlock - 1)` snapshot, so
//     operators cannot top up tickets after `requestCommittee` to inflate
//     their selection weight.
import { expect } from "chai";
import type { Signer } from "ethers";

import { deployInterfoldSystem, ethers, networkHelpers } from "../fixtures";

const { loadFixture, time, mine } = networkHelpers;

const inputWindowDuration = 300;
const abiCoder = ethers.AbiCoder.defaultAbiCoder();

// Local helper — allows ticketAmount = 0 (the snapshot-eligibility test
// registers a latecomer with zero tickets, which the shared fixture
// helper does not support).
async function fundOperator(
  operator: Signer,
  bondingRegistry: any,
  licenseToken: any,
  feeToken: any,
  ticketToken: any,
  registry: any,
  ticketAmount: bigint,
) {
  const operatorAddress = await operator.getAddress();
  await licenseToken.mint(
    operatorAddress,
    ethers.parseEther("10000"),
    ethers.encodeBytes32String("Test allocation"),
  );
  await feeToken.mint(operatorAddress, ethers.parseUnits("1000000", 6));
  await licenseToken
    .connect(operator)
    .approve(await bondingRegistry.getAddress(), ethers.parseEther("2000"));
  await bondingRegistry
    .connect(operator)
    .bondLicense(ethers.parseEther("1000"));
  await bondingRegistry.connect(operator).registerOperator();
  if (ticketAmount > 0n) {
    await feeToken
      .connect(operator)
      .approve(await ticketToken.getAddress(), ticketAmount);
    await bondingRegistry.connect(operator).addTicketBalance(ticketAmount);
  }
  await registry.addCiphernode(operatorAddress);
}

async function deployStack() {
  const sys = await deployInterfoldSystem({
    committeeThresholds: [[0, [1, 3]]],
  });
  const {
    owner,
    notTheOwner: requester,
    operator1: op1,
    operator2: op2,
    operator3: op3,
    interfold,
    ciphernodeRegistry,
    bondingRegistry,
    ticketToken,
    licenseToken,
    usdcToken: feeToken,
    mocks: { e3Program, decryptionVerifier },
  } = sys;
  const [, , , , , treasury, other] = await ethers.getSigners();
  const treasuryAddress = await treasury.getAddress();
  const interfoldAddress = await interfold.getAddress();

  await interfold.setPricingConfig({
    keyGenFixedPerNode: 0n,
    keyGenPerEncryptionProof: 0n,
    coordinationPerPair: 0n,
    availabilityPerNodePerSec: 0n,
    decryptionPerNode: 0n,
    publicationBase: 1n,
    verificationPerProof: 0n,
    protocolTreasury: treasuryAddress,
    marginBps: 0,
    protocolShareBps: 0,
    dkgUtilizationBps: 2500,
    computeUtilizationBps: 5000,
    decryptUtilizationBps: 2500,
    minCommitteeSize: 0,
    minThreshold: 0,
  });

  await feeToken
    .connect(requester)
    .approve(interfoldAddress, ethers.MaxUint256);

  const makeRequest = async () => {
    const now = await time.latest();
    const req = {
      committeeSize: 0,
      inputWindow: [now + 10, now + inputWindowDuration] as [number, number],
      e3Program: await e3Program.getAddress(),
      paramSet: 0,
      computeProviderParams: abiCoder.encode(
        ["address"],
        [await decryptionVerifier.getAddress()],
      ),
      customParams: abiCoder.encode(
        ["address"],
        ["0x1234567890123456789012345678901234567890"],
      ),
      proofAggregationEnabled: false,
    } as any;
    return interfold.connect(requester).request(req);
  };

  return {
    owner,
    requester,
    op1,
    op2,
    op3,
    other,
    interfold,
    ciphernodeRegistry,
    bondingRegistry,
    ticketToken,
    licenseToken,
    feeToken,
    makeRequest,
  };
}

describe("Sortition & E3 lifecycle", function () {
  describe("Committee.requestBlock uses block.timestamp", function () {
    it("stores block.timestamp (not block.number) in requestBlock", async function () {
      const ctx = await loadFixture(deployStack);
      const { ciphernodeRegistry, makeRequest } = ctx;

      const tx = await makeRequest();
      const receipt = await tx.wait();
      const block = await ethers.provider.getBlock(receipt!.blockNumber);

      const iface = ciphernodeRegistry.interface;
      const evt = receipt!.logs
        .map((l) => {
          try {
            return iface.parseLog(l);
          } catch {
            return null;
          }
        })
        .find((p) => p && p.name === "CommitteeRequested");
      expect(evt, "CommitteeRequested not emitted").to.not.equal(null);
      const requestBlock = evt!.args.requestBlock as bigint;
      expect(requestBlock).to.equal(BigInt(block!.timestamp));
      expect(requestBlock).to.not.equal(BigInt(receipt!.blockNumber));
    });
  });

  describe("markE3Failed grace period", function () {
    it("inside grace window: third party reverts, requester succeeds", async function () {
      const ctx = await loadFixture(deployStack);
      const { interfold, requester, other, makeRequest } = ctx;

      const grace = 600;
      await interfold.setMarkFailedGracePeriod(grace);
      await makeRequest();
      const e3Id = 0;

      const deadline = await ctx.ciphernodeRegistry.getCommitteeDeadline(e3Id);
      // Move just past the deadline, still inside the grace window.
      await time.increaseTo(deadline + 1n);

      await expect(
        interfold.connect(other).markE3Failed(e3Id),
      ).to.be.revertedWithCustomError(interfold, "MarkE3FailedInGracePeriod");

      await expect(interfold.connect(requester).markE3Failed(e3Id)).to.emit(
        interfold,
        "E3Failed",
      );
    });

    it("after grace window: anyone can call markE3Failed", async function () {
      const ctx = await loadFixture(deployStack);
      const { interfold, other, makeRequest } = ctx;

      const grace = 600;
      await interfold.setMarkFailedGracePeriod(grace);
      await makeRequest();
      const e3Id = 0;

      const deadline = await ctx.ciphernodeRegistry.getCommitteeDeadline(e3Id);
      await time.increaseTo(deadline + BigInt(grace) + 1n);

      await expect(interfold.connect(other).markE3Failed(e3Id)).to.emit(
        interfold,
        "E3Failed",
      );
    });

    it("setMarkFailedGracePeriod is owner-only and emits event", async function () {
      const ctx = await loadFixture(deployStack);
      const { interfold, other } = ctx;

      await expect(
        interfold.connect(other).setMarkFailedGracePeriod(42),
      ).to.be.revertedWithCustomError(interfold, "OwnableUnauthorizedAccount");

      await expect(interfold.setMarkFailedGracePeriod(42))
        .to.emit(interfold, "MarkFailedGracePeriodSet")
        .withArgs(42);
      expect(await interfold.markFailedGracePeriod()).to.equal(42n);
    });
  });

  describe("snapshot-based ticket eligibility", function () {
    it("operator cannot inflate ticket weight after request via post-request deposits", async function () {
      // Set the operator's snapshot ticket balance to zero, request a
      // committee, then top them up to a passing balance. The
      // `_validateNodeEligibility` snapshot at `requestBlock - 1` must
      // still see zero and reject submission.
      const ctx = await loadFixture(deployStack);
      const {
        ciphernodeRegistry,
        bondingRegistry,
        ticketToken,
        feeToken,
        licenseToken,
        makeRequest,
      } = ctx;

      const allSigners = await ethers.getSigners();
      const latecomer = allSigners[allSigners.length - 1];
      const latecomerAddress = await latecomer.getAddress();

      // Register the latecomer with ZERO tickets (still licensed + registered)
      // so they appear in the ciphernode set but have no snapshot weight.
      await fundOperator(
        latecomer,
        bondingRegistry,
        licenseToken,
        feeToken,
        ticketToken,
        ciphernodeRegistry,
        0n,
      );
      await mine(1);

      const tx = await makeRequest();
      const receipt = await tx.wait();
      const e3Id = 0;

      const iface = ciphernodeRegistry.interface;
      const evt = receipt!.logs
        .map((l) => {
          try {
            return iface.parseLog(l);
          } catch {
            return null;
          }
        })
        .find((p) => p && p.name === "CommitteeRequested");
      const requestBlock = evt!.args.requestBlock as bigint;

      // Now the latecomer adds tickets *after* requestBlock — the snapshot
      // at requestBlock - 1 should still be zero.
      const ticketAmount = ethers.parseUnits("100", 6);
      await feeToken
        .connect(latecomer)
        .approve(await ticketToken.getAddress(), ticketAmount);
      await bondingRegistry.connect(latecomer).addTicketBalance(ticketAmount);

      // Confirm snapshot returns zero at requestBlock - 1.
      const snapshot = await bondingRegistry.getTicketBalanceAtBlock(
        latecomerAddress,
        requestBlock - 1n,
      );
      expect(snapshot).to.equal(0n);

      await expect(
        ciphernodeRegistry.connect(latecomer).submitTicket(e3Id, 1),
      ).to.be.revertedWithCustomError(ciphernodeRegistry, "NodeNotEligible");
    });
  });
});
