// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
import { expect } from "chai";

import {
  InterfoldToken__factory as InterfoldTokenFactory,
  MockBondingRegistry__factory as MockBondingRegistryFactory,
} from "../../types";
import { deployInterfoldSystem, ethers, networkHelpers } from "../fixtures";

const { loadFixture, time } = networkHelpers;

const DAY = 24n * 60n * 60n;
const YEAR = 365n * DAY;
const MONTH = 30n * DAY;
const NO_MORE_LOCKS_DELAY = 4n * YEAR + MONTH;
const TGE_COOLDOWN = 40n * DAY;

function noMoreLocksFor(ccaEnd: bigint) {
  return ccaEnd + TGE_COOLDOWN + NO_MORE_LOCKS_DELAY;
}

describe("InterfoldToken", function () {
  // ── Helpers ─────────────────────────────────────────────────────────────

  /// Deploy a minimal MockBondingRegistry + InterfoldToken for standalone tests.
  /// CCA window starts far in the future so tests control the phase via
  /// `time.increaseTo` / `time.increase`.
  async function deploy() {
    const [
      deployer,
      admin,
      minter,
      whitelister,
      lockManager,
      alice,
      bob,
      claimSource,
    ] = await ethers.getSigners();

    // Deploy a minimal mock BondingRegistry that returns 0 for totalBonded.
    const mockRegistry = await new MockBondingRegistryFactory(
      deployer,
    ).deploy();
    await mockRegistry.waitForDeployment();

    const now = BigInt(await time.latest());
    const ccaStart = now + 10n * DAY; // far future — Virtual phase
    const ccaEnd = ccaStart + 7n * DAY;
    const noMoreLocks = noMoreLocksFor(ccaEnd);

    const token = await new InterfoldTokenFactory(deployer).deploy(
      await admin.getAddress(),
      ccaStart,
      ccaEnd,
      noMoreLocks,
      await mockRegistry.getAddress(),
    );
    await token.connect(admin).setClaimSource(await claimSource.getAddress());
    // Dedicated holders, so role tests prove the exact role gates each action.
    for (const [role, holder] of [
      [await token.MINTER_ROLE(), minter],
      [await token.WHITELIST_ROLE(), whitelister],
      [await token.LOCK_MANAGER_ROLE(), lockManager],
    ] as const) {
      await token.connect(admin).grantRole(role, await holder.getAddress());
    }

    return {
      deployer,
      admin,
      minter,
      whitelister,
      lockManager,
      alice,
      bob,
      claimSource,
      token,
      mockRegistry,
      ccaStart,
      ccaEnd,
      noMoreLocks,
    };
  }

  /// Deploy, create a policy, mint locked tokens, THEN fire TGE.
  /// Returns everything needed for transfer-enforcement tests.
  async function deployWithLockAndTge(
    opts: {
      policyName?: string;
      mintAmount?: bigint;
      vestDuration?: bigint;
      holdUntil?: bigint;
      recipient?: "alice" | "claimSource";
    } = {},
  ) {
    const fixture = await loadFixture(deploy);
    const { token, admin, alice, claimSource, ccaEnd } = fixture;
    const recipient = opts.recipient === "claimSource" ? claimSource : alice;
    const recipientAddress = await recipient.getAddress();
    const policyId = await createLinearPolicy(
      token,
      admin,
      opts.policyName ?? "TEST_LOCK",
      {
        vestDuration: opts.vestDuration ?? 2n * YEAR,
        holdUntil: opts.holdUntil,
      },
    );
    const amount = opts.mintAmount ?? ethers.parseEther("1000");

    // Mint during Virtual phase.
    await token.connect(admin).mintAllocations([
      {
        recipient: recipientAddress,
        amount,
        policyId,
        label: ethers.encodeBytes32String("test"),
      },
    ]);

    // Fire TGE.
    const TGE_COOLDOWN = 40n * DAY;
    await time.increaseTo(ccaEnd + TGE_COOLDOWN + 1n);
    const tgeTx = await token.tge();
    const receipt = await tgeTx.wait();
    const tgeBlock = await ethers.provider.getBlock(receipt!.blockNumber);
    const tgeTimestamp = BigInt(tgeBlock!.timestamp);

    return { ...fixture, policyId, amount, tgeTimestamp, recipientAddress };
  }

  /// Deploy, mint unlocked tokens to alice, THEN fire TGE.
  async function deployWithUnlockedAndTge(mintAmount?: bigint) {
    const fixture = await loadFixture(deploy);
    const { token, admin, alice, ccaEnd } = fixture;
    const amount = mintAmount ?? ethers.parseEther("500");

    await token
      .connect(admin)
      .mint(await alice.getAddress(), amount, ethers.ZeroHash);

    const TGE_COOLDOWN = 40n * DAY;
    await time.increaseTo(ccaEnd + TGE_COOLDOWN + 1n);
    await token.tge();

    return { ...fixture, amount };
  }

  // ── Helpers for lock policies ───────────────────────────────────────────

  /// Create a standard linear lock policy and return its id.
  async function createLinearPolicy(
    token: Awaited<ReturnType<typeof deploy>>["token"],
    admin: Awaited<ReturnType<typeof deploy>>["admin"],
    policyId: string,
    opts: {
      anchor?: number; // 0 = Absolute, 1 = Tge
      start?: bigint;
      cliffDuration?: bigint;
      vestDuration?: bigint;
      holdUntil?: bigint;
    } = {},
  ) {
    const id = ethers.encodeBytes32String(policyId);
    const anchor = opts.anchor ?? 1; // default Tge-anchored
    const start = opts.start ?? 0n;
    const cliffDuration = opts.cliffDuration ?? 0n;
    const vestDuration = opts.vestDuration ?? 2n * YEAR;
    await token.connect(admin).createLockPolicy(id, {
      holdUntil: opts.holdUntil ?? 0n,
      unlock: { anchor, start, cliffDuration, vestDuration },
    });
    return id;
  }

  // ═════════════════════════════════════════════════════════════════════════
  // Deployment & Constructor
  // ═════════════════════════════════════════════════════════════════════════

  describe("constructor", function () {
    it("lets the owner set CLAIM_SOURCE once", async function () {
      const { token, admin, alice, claimSource } = await loadFixture(deploy);
      expect(await token.CLAIM_SOURCE()).to.equal(
        await claimSource.getAddress(),
      );

      await expect(
        token.connect(alice).setClaimSource(await alice.getAddress()),
      ).to.be.revertedWithCustomError(token, "OwnableUnauthorizedAccount");

      await expect(
        token.connect(admin).setClaimSource(await alice.getAddress()),
      ).to.be.revertedWithCustomError(token, "ClaimSourceAlreadySet");
    });

    it("reverts when setClaimSource is zero address", async function () {
      const [deployer] = await ethers.getSigners();
      const mockRegistry = await new MockBondingRegistryFactory(
        deployer,
      ).deploy();
      await mockRegistry.waitForDeployment();
      const now = BigInt(await time.latest());
      const ccaStart = now + DAY;
      const ccaEnd = ccaStart + 7n * DAY;
      const noMoreLocks = noMoreLocksFor(ccaEnd);

      const token = await new InterfoldTokenFactory(deployer).deploy(
        await deployer.getAddress(),
        ccaStart,
        ccaEnd,
        noMoreLocks,
        await mockRegistry.getAddress(),
      );
      expect(await token.CLAIM_SOURCE()).to.equal(ethers.ZeroAddress);

      await expect(
        token.setClaimSource(ethers.ZeroAddress),
      ).to.be.revertedWithCustomError(token, "ZeroAddress");
    });

    it("reverts when bondingRegistry is zero address", async function () {
      const [deployer] = await ethers.getSigners();
      const now = BigInt(await time.latest());
      const ccaStart = now + DAY;
      const ccaEnd = ccaStart + 7n * DAY;
      const noMoreLocks = noMoreLocksFor(ccaEnd);

      await expect(
        new InterfoldTokenFactory(deployer).deploy(
          await deployer.getAddress(),
          ccaStart,
          ccaEnd,
          noMoreLocks,
          ethers.ZeroAddress,
        ),
      ).to.be.revertedWithCustomError(
        { interface: InterfoldTokenFactory.createInterface() },
        "ZeroAddress",
      );
    });

    it("reverts when bondingRegistry has no code (EOA)", async function () {
      const [deployer, admin] = await ethers.getSigners();
      const now = BigInt(await time.latest());
      const ccaStart = now + DAY;
      const ccaEnd = ccaStart + 7n * DAY;
      const noMoreLocks = noMoreLocksFor(ccaEnd);

      await expect(
        new InterfoldTokenFactory(deployer).deploy(
          await admin.getAddress(),
          ccaStart,
          ccaEnd,
          noMoreLocks,
          await admin.getAddress(), // EOA, not a contract
        ),
      ).to.be.revertedWithCustomError(
        { interface: InterfoldTokenFactory.createInterface() },
        "InvalidBondingRegistry",
      );
    });

    it("reverts when CCA start is in the past", async function () {
      const [deployer] = await ethers.getSigners();
      const mockRegistry = await new MockBondingRegistryFactory(
        deployer,
      ).deploy();
      await mockRegistry.waitForDeployment();
      const now = BigInt(await time.latest());

      await expect(
        new InterfoldTokenFactory(deployer).deploy(
          await deployer.getAddress(),
          now, // in the past (or now)
          now + 7n * DAY,
          noMoreLocksFor(now + 7n * DAY),
          await mockRegistry.getAddress(),
        ),
      ).to.be.revertedWithCustomError(
        { interface: InterfoldTokenFactory.createInterface() },
        "InvalidCcaWindow",
      );
    });

    it("reverts when CCA end is not after start", async function () {
      const [deployer] = await ethers.getSigners();
      const mockRegistry = await new MockBondingRegistryFactory(
        deployer,
      ).deploy();
      await mockRegistry.waitForDeployment();
      const now = BigInt(await time.latest());
      const ccaStart = now + DAY;
      const ccaEnd = ccaStart; // equal, not greater
      const noMoreLocks = noMoreLocksFor(ccaEnd);

      await expect(
        new InterfoldTokenFactory(deployer).deploy(
          await deployer.getAddress(),
          ccaStart,
          ccaEnd,
          noMoreLocks,
          await mockRegistry.getAddress(),
        ),
      ).to.be.revertedWithCustomError(
        { interface: InterfoldTokenFactory.createInterface() },
        "InvalidCcaWindow",
      );
    });

    it("reverts when noMoreLocks is zero", async function () {
      const [deployer] = await ethers.getSigners();
      const mockRegistry = await new MockBondingRegistryFactory(
        deployer,
      ).deploy();
      await mockRegistry.waitForDeployment();
      const now = BigInt(await time.latest());
      const ccaStart = now + DAY;
      const ccaEnd = ccaStart + 7n * DAY;

      await expect(
        new InterfoldTokenFactory(deployer).deploy(
          await deployer.getAddress(),
          ccaStart,
          ccaEnd,
          0n,
          await mockRegistry.getAddress(),
        ),
      ).to.be.revertedWithCustomError(
        { interface: InterfoldTokenFactory.createInterface() },
        "ZeroAmount",
      );
    });

    it("reverts when noMoreLocks is not after the earliest TGE", async function () {
      const [deployer] = await ethers.getSigners();
      const mockRegistry = await new MockBondingRegistryFactory(
        deployer,
      ).deploy();
      await mockRegistry.waitForDeployment();
      const now = BigInt(await time.latest());
      const ccaStart = now + DAY;
      const ccaEnd = ccaStart + 7n * DAY;
      const earliestTge = ccaEnd + TGE_COOLDOWN;

      await expect(
        new InterfoldTokenFactory(deployer).deploy(
          await deployer.getAddress(),
          ccaStart,
          ccaEnd,
          earliestTge, // must be strictly after
          await mockRegistry.getAddress(),
        ),
      ).to.be.revertedWithCustomError(
        { interface: InterfoldTokenFactory.createInterface() },
        "InvalidNoMoreLocks",
      );
    });

    it("initial owner receives all roles", async function () {
      const { token, admin } = await loadFixture(deploy);
      const adminAddress = await admin.getAddress();
      expect(
        await token.hasRole(await token.DEFAULT_ADMIN_ROLE(), adminAddress),
      ).to.be.true;
      expect(await token.hasRole(await token.MINTER_ROLE(), adminAddress)).to.be
        .true;
      expect(await token.hasRole(await token.WHITELIST_ROLE(), adminAddress)).to
        .be.true;
      expect(await token.hasRole(await token.LOCK_MANAGER_ROLE(), adminAddress))
        .to.be.true;
    });
  });

  // ═════════════════════════════════════════════════════════════════════════
  // Phase lifecycle
  // ═════════════════════════════════════════════════════════════════════════

  describe("phase()", function () {
    it("starts in Virtual phase", async function () {
      const { token } = await loadFixture(deploy);
      expect(await token.phase()).to.equal(0); // Phase.Virtual
    });

    it("enters CCA during CCA window", async function () {
      const { token, ccaStart } = await loadFixture(deploy);
      await time.increaseTo(ccaStart);
      expect(await token.phase()).to.equal(1); // Phase.CCA
    });

    it("enters Cooldown after CCA_END before TGE", async function () {
      const { token, ccaEnd } = await loadFixture(deploy);
      await time.increaseTo(ccaEnd);
      expect(await token.phase()).to.equal(2); // Phase.Cooldown
    });

    it("enters Live phase after TGE", async function () {
      const { token, ccaEnd } = await loadFixture(deploy);
      const TGE_COOLDOWN = 40n * DAY;
      await time.increaseTo(ccaEnd + TGE_COOLDOWN + 1n);
      await token.tge();
      expect(await token.phase()).to.equal(3); // Phase.Live
    });
  });

  // ═════════════════════════════════════════════════════════════════════════
  // Minting
  // ═════════════════════════════════════════════════════════════════════════

  describe("mint", function () {
    it("DEFAULT_ADMIN_ROLE can mint unlocked tokens during Virtual", async function () {
      const { token, admin, alice } = await loadFixture(deploy);
      const amount = ethers.parseEther("100");
      await expect(
        token
          .connect(admin)
          .mint(
            await alice.getAddress(),
            amount,
            ethers.encodeBytes32String("test"),
          ),
      )
        .to.emit(token, "AllocationMinted")
        .withArgs(
          await alice.getAddress(),
          amount,
          ethers.ZeroHash,
          ethers.encodeBytes32String("test"),
        );
      expect(await token.balanceOf(await alice.getAddress())).to.equal(amount);
    });

    it("allows authorized minting throughout pre-TGE phases", async function () {
      const { token, admin, alice, bob, ccaStart, ccaEnd } =
        await loadFixture(deploy);
      const amount = ethers.parseEther("100");
      const policyId = await createLinearPolicy(token, admin, "PRE_TGE_POLICY");
      const mintBoth = async (recipient: string) => {
        await token.connect(admin).mint(recipient, amount, ethers.ZeroHash);
        await token
          .connect(admin)
          .mintAllocations([
            { recipient, amount, policyId, label: ethers.ZeroHash },
          ]);
      };

      await time.increaseTo(ccaStart);
      await mintBoth(await alice.getAddress());

      await time.increaseTo(ccaEnd);
      await mintBoth(await bob.getAddress());

      expect(await token.totalSupply()).to.equal(amount * 4n);
    });

    it("mint reverts after TGE (Live phase)", async function () {
      const { token, admin, alice, ccaEnd } = await loadFixture(deploy);
      await time.increaseTo(ccaEnd + TGE_COOLDOWN + 1n);
      await token.tge();
      await expect(
        token
          .connect(admin)
          .mint(
            await alice.getAddress(),
            ethers.parseEther("1"),
            ethers.encodeBytes32String("test"),
          ),
      ).to.be.revertedWithCustomError(token, "MintingClosed");
    });

    it("reverts with zero amount", async function () {
      const { token, admin, alice } = await loadFixture(deploy);
      await expect(
        token
          .connect(admin)
          .mint(
            await alice.getAddress(),
            0n,
            ethers.encodeBytes32String("test"),
          ),
      ).to.be.revertedWithCustomError(token, "ZeroAmount");
    });

    it("reverts when MAX_SUPPLY would be exceeded", async function () {
      const { token, admin, alice } = await loadFixture(deploy);
      const maxSupply = await token.MAX_SUPPLY();
      await expect(
        token
          .connect(admin)
          .mint(await alice.getAddress(), maxSupply + 1n, ethers.ZeroHash),
      ).to.be.revertedWithCustomError(token, "MaxSupplyExceeded");
    });
  });

  describe("mintAllocations", function () {
    it("MINTER_ROLE can mint locked allocations during Virtual", async function () {
      const { token, admin, minter, alice } = await loadFixture(deploy);
      const policyId = await createLinearPolicy(token, admin, "TEST_POLICY");
      const amount = ethers.parseEther("1000");

      await expect(
        token.connect(minter).mintAllocations([
          {
            recipient: await alice.getAddress(),
            amount,
            policyId,
            label: ethers.encodeBytes32String("test"),
          },
        ]),
      )
        .to.emit(token, "AllocationMinted")
        .withArgs(
          await alice.getAddress(),
          amount,
          policyId,
          ethers.encodeBytes32String("test"),
        );

      // Tokens are locked — lockedBalanceOf should be > 0.
      expect(await token.lockedBalanceOf(await alice.getAddress())).to.equal(
        amount,
      );
      expect(await token.balanceOf(await alice.getAddress())).to.equal(amount);
    });

    it("reverts with zero policyId", async function () {
      const { token, admin, alice } = await loadFixture(deploy);
      await expect(
        token.connect(admin).mintAllocations([
          {
            recipient: await alice.getAddress(),
            amount: ethers.parseEther("1"),
            policyId: ethers.ZeroHash,
            label: ethers.encodeBytes32String("test"),
          },
        ]),
      ).to.be.revertedWithCustomError(token, "InvalidPolicy");
    });

    it("reverts with undefined policy", async function () {
      const { token, admin, alice } = await loadFixture(deploy);
      await expect(
        token.connect(admin).mintAllocations([
          {
            recipient: await alice.getAddress(),
            amount: ethers.parseEther("1"),
            policyId: ethers.encodeBytes32String("UNDEFINED"),
            label: ethers.encodeBytes32String("test"),
          },
        ]),
      ).to.be.revertedWithCustomError(token, "PolicyNotDefined");
    });

    it("mintAllocations reverts after TGE (Live phase)", async function () {
      const { token, admin, alice, ccaEnd } = await loadFixture(deploy);
      const policyId = await createLinearPolicy(token, admin, "TEST_POLICY");
      await time.increaseTo(ccaEnd + TGE_COOLDOWN + 1n);
      await token.tge();
      await expect(
        token.connect(admin).mintAllocations([
          {
            recipient: await alice.getAddress(),
            amount: ethers.parseEther("1"),
            policyId,
            label: ethers.ZeroHash,
          },
        ]),
      ).to.be.revertedWithCustomError(token, "MintingClosed");
    });

    it("handles mixed recipients and mixed policies in one batch", async function () {
      const { token, admin, alice, bob } = await loadFixture(deploy);
      const aliceAddress = await alice.getAddress();
      const bobAddress = await bob.getAddress();

      const saftPolicy = await createLinearPolicy(token, admin, "SAFT_BATCH", {
        vestDuration: 2n * YEAR,
      });
      const teamPolicy = await createLinearPolicy(token, admin, "TEAM_BATCH", {
        vestDuration: 3n * YEAR,
      });
      const ccaPolicy = await createLinearPolicy(token, admin, "CCA_BATCH", {
        vestDuration: 1n * YEAR,
      });

      // One batch: Alice gets SAFT + TEAM, Bob gets CCA.
      const saftAmount = ethers.parseEther("1000");
      const teamAmount = ethers.parseEther("500");
      const ccaAmount = ethers.parseEther("700");

      await token.connect(admin).mintAllocations([
        {
          recipient: aliceAddress,
          amount: saftAmount,
          policyId: saftPolicy,
          label: ethers.encodeBytes32String("saft"),
        },
        {
          recipient: aliceAddress,
          amount: teamAmount,
          policyId: teamPolicy,
          label: ethers.encodeBytes32String("team"),
        },
        {
          recipient: bobAddress,
          amount: ccaAmount,
          policyId: ccaPolicy,
          label: ethers.encodeBytes32String("cca"),
        },
      ]);

      // Alice: 2 locks, 1500 total.
      expect(await token.lockCount(aliceAddress)).to.equal(2n);
      expect(await token.lockedBalanceOf(aliceAddress)).to.equal(
        saftAmount + teamAmount,
      );
      expect(await token.balanceOf(aliceAddress)).to.equal(
        saftAmount + teamAmount,
      );

      // Bob: 1 lock, 700 total.
      expect(await token.lockCount(bobAddress)).to.equal(1n);
      expect(await token.lockedBalanceOf(bobAddress)).to.equal(ccaAmount);
      expect(await token.balanceOf(bobAddress)).to.equal(ccaAmount);

      // Verify Alice's locks have the correct policies.
      const aliceLock0 = await token.locks(aliceAddress, 0);
      const aliceLock1 = await token.locks(aliceAddress, 1);
      const alicePolicies = new Set([aliceLock0.policyId, aliceLock1.policyId]);
      expect(alicePolicies.has(saftPolicy)).to.be.true;
      expect(alicePolicies.has(teamPolicy)).to.be.true;

      // Bob's lock is CCA.
      const bobLock = await token.locks(bobAddress, 0);
      expect(bobLock.policyId).to.equal(ccaPolicy);
      expect(bobLock.amount).to.equal(ccaAmount);
    });
  });

  // ═════════════════════════════════════════════════════════════════════════
  // TGE
  // ═════════════════════════════════════════════════════════════════════════

  describe("tge()", function () {
    it("reverts before CCA_END + TGE_COOLDOWN", async function () {
      const { token, ccaEnd } = await loadFixture(deploy);
      await time.increaseTo(ccaEnd); // Cooldown phase but not enough
      await expect(token.tge()).to.be.revertedWithCustomError(
        token,
        "TgeTooEarly",
      );
    });

    it("anyone can trigger TGE after cooldown", async function () {
      const { token, ccaEnd, alice } = await loadFixture(deploy);
      const TGE_COOLDOWN = 40n * DAY;
      await time.increaseTo(ccaEnd + TGE_COOLDOWN + 1n);
      await expect(token.connect(alice).tge()).to.emit(token, "TgeTriggered");
      expect(await token.tgeTimestamp()).to.be.gt(0);
      expect(await token.phase()).to.equal(3); // Live
    });

    it("reverts if already live", async function () {
      const { token, ccaEnd } = await loadFixture(deploy);
      const TGE_COOLDOWN = 40n * DAY;
      await time.increaseTo(ccaEnd + TGE_COOLDOWN + 1n);
      await token.tge();
      await expect(token.tge()).to.be.revertedWithCustomError(
        token,
        "AlreadyLive",
      );
    });
  });

  // ═════════════════════════════════════════════════════════════════════════
  // Whitelisting
  // ═════════════════════════════════════════════════════════════════════════

  describe("setTransferWhitelisted", function () {
    it("WHITELIST_ROLE can whitelist an address", async function () {
      const { token, whitelister, alice } = await loadFixture(deploy);
      await expect(
        token
          .connect(whitelister)
          .setTransferWhitelisted(await alice.getAddress(), true),
      )
        .to.emit(token, "TransferWhitelistUpdated")
        .withArgs(await alice.getAddress(), true);
      expect(await token.transferWhitelist(await alice.getAddress())).to.be
        .true;
    });

    it("non-WHITELIST_ROLE cannot whitelist", async function () {
      const { token, alice } = await loadFixture(deploy);
      await expect(
        token
          .connect(alice)
          .setTransferWhitelisted(await alice.getAddress(), true),
      ).to.be.revertedWithCustomError(
        token,
        "AccessControlUnauthorizedAccount",
      );
    });

    it("reverts with zero address", async function () {
      const { token, admin } = await loadFixture(deploy);
      await expect(
        token.connect(admin).setTransferWhitelisted(ethers.ZeroAddress, true),
      ).to.be.revertedWithCustomError(token, "ZeroAddress");
    });
  });

  describe("setClaimLockExempt", function () {
    it("LOCK_MANAGER_ROLE can manage claim-lock exemption", async function () {
      const { token, lockManager, alice } = await loadFixture(deploy);
      await expect(
        token
          .connect(lockManager)
          .setClaimLockExempt(await alice.getAddress(), true),
      )
        .to.emit(token, "ClaimLockExemptUpdated")
        .withArgs(await alice.getAddress(), true);
    });

    it("non-LOCK_MANAGER_ROLE cannot manage claim-lock exemption", async function () {
      const { token, alice } = await loadFixture(deploy);
      await expect(
        token.connect(alice).setClaimLockExempt(await alice.getAddress(), true),
      ).to.be.revertedWithCustomError(
        token,
        "AccessControlUnauthorizedAccount",
      );
    });

    it("cannot enable claim-lock exemption while queued locks exist", async function () {
      const { token, admin, alice } = await loadFixture(deploy);
      const aliceAddress = await alice.getAddress();
      const policyId = await createLinearPolicy(token, admin, "EXEMPT_QUEUE", {
        vestDuration: 2n * YEAR,
      });

      await token.connect(admin).linkClaim(aliceAddress, 100n, policyId);

      await expect(token.connect(admin).setClaimLockExempt(aliceAddress, true))
        .to.be.revertedWithCustomError(token, "ClaimLockExemptQueuedLocks")
        .withArgs(aliceAddress);
    });
  });

  // ═════════════════════════════════════════════════════════════════════════
  // Lock Policies
  // ═════════════════════════════════════════════════════════════════════════

  describe("createLockPolicy", function () {
    it("LOCK_MANAGER_ROLE can create a policy", async function () {
      const { token, lockManager } = await loadFixture(deploy);
      const policyId = ethers.encodeBytes32String("MY_POLICY");
      await expect(
        token.connect(lockManager).createLockPolicy(policyId, {
          holdUntil: 0n,
          unlock: {
            anchor: 1, // Tge
            start: 0n,
            cliffDuration: 0n,
            vestDuration: 2n * YEAR,
          },
        }),
      ).to.emit(token, "PolicyDefined");
    });

    it("reverts on duplicate policy id (write-once)", async function () {
      const { token, admin } = await loadFixture(deploy);
      const policyId = ethers.encodeBytes32String("MY_POLICY");
      await token.connect(admin).createLockPolicy(policyId, {
        holdUntil: 0n,
        unlock: {
          anchor: 1,
          start: 0n,
          cliffDuration: 0n,
          vestDuration: YEAR,
        },
      });
      await expect(
        token.connect(admin).createLockPolicy(policyId, {
          holdUntil: 0n,
          unlock: {
            anchor: 0,
            start: 1n,
            cliffDuration: 1n,
            vestDuration: 0n,
          },
        }),
      ).to.be.revertedWithCustomError(token, "PolicyAlreadyDefined");
    });

    it("reverts with zero policyId", async function () {
      const { token, admin } = await loadFixture(deploy);
      await expect(
        token.connect(admin).createLockPolicy(ethers.ZeroHash, {
          holdUntil: 0n,
          unlock: {
            anchor: 1,
            start: 0n,
            cliffDuration: 0n,
            vestDuration: YEAR,
          },
        }),
      ).to.be.revertedWithCustomError(token, "InvalidPolicy");
    });

    it("reverts with PENDING policyId", async function () {
      const { token, admin } = await loadFixture(deploy);
      await expect(
        token
          .connect(admin)
          .createLockPolicy(ethers.encodeBytes32String("PENDING"), {
            holdUntil: 0n,
            unlock: {
              anchor: 1,
              start: 0n,
              cliffDuration: 0n,
              vestDuration: YEAR,
            },
          }),
      ).to.be.revertedWithCustomError(token, "InvalidPolicy");
    });

    it("reverts when both cliff and vest are zero", async function () {
      const { token, admin } = await loadFixture(deploy);
      await expect(
        token
          .connect(admin)
          .createLockPolicy(ethers.encodeBytes32String("BAD"), {
            holdUntil: 0n,
            unlock: {
              anchor: 1,
              start: 0n,
              cliffDuration: 0n,
              vestDuration: 0n,
            },
          }),
      ).to.be.revertedWithCustomError(token, "InvalidPolicy");
    });

    it("reverts when Absolute anchor has zero start", async function () {
      const { token, admin } = await loadFixture(deploy);
      await expect(
        token
          .connect(admin)
          .createLockPolicy(ethers.encodeBytes32String("BAD"), {
            holdUntil: 0n,
            unlock: {
              anchor: 0,
              start: 0n,
              cliffDuration: 1n,
              vestDuration: 0n,
            },
          }),
      ).to.be.revertedWithCustomError(token, "InvalidPolicy");
    });

    it("reverts when Tge anchor has non-zero start", async function () {
      const { token, admin } = await loadFixture(deploy);
      await expect(
        token
          .connect(admin)
          .createLockPolicy(ethers.encodeBytes32String("BAD"), {
            holdUntil: 0n,
            unlock: {
              anchor: 1,
              start: 1n,
              cliffDuration: 1n,
              vestDuration: 0n,
            },
          }),
      ).to.be.revertedWithCustomError(token, "InvalidPolicy");
    });

    it("reverts when cliff exceeds vest duration", async function () {
      const { token, admin } = await loadFixture(deploy);
      await expect(
        token
          .connect(admin)
          .createLockPolicy(ethers.encodeBytes32String("BAD"), {
            holdUntil: 0n,
            unlock: {
              anchor: 1,
              start: 0n,
              cliffDuration: 2n * YEAR,
              vestDuration: YEAR,
            },
          }),
      ).to.be.revertedWithCustomError(token, "InvalidPolicy");
    });

    it("non-LOCK_MANAGER_ROLE cannot create a policy", async function () {
      const { token, alice } = await loadFixture(deploy);
      await expect(
        token
          .connect(alice)
          .createLockPolicy(ethers.encodeBytes32String("MY_POLICY"), {
            holdUntil: 0n,
            unlock: {
              anchor: 1,
              start: 0n,
              cliffDuration: 0n,
              vestDuration: YEAR,
            },
          }),
      ).to.be.revertedWithCustomError(
        token,
        "AccessControlUnauthorizedAccount",
      );
    });

    it("reverts when Tge-anchored vest outlasts noMoreLocks", async function () {
      const { token, admin } = await loadFixture(deploy);
      await expect(
        token
          .connect(admin)
          .createLockPolicy(ethers.encodeBytes32String("TOO_LONG"), {
            holdUntil: 0n,
            unlock: {
              anchor: 1,
              start: 0n,
              cliffDuration: 0n,
              vestDuration: NO_MORE_LOCKS_DELAY + 1n,
            },
          }),
      ).to.be.revertedWithCustomError(token, "InvalidPolicy");
    });

    it("reverts when Tge-anchored cliff-only release outlasts noMoreLocks", async function () {
      const { token, admin } = await loadFixture(deploy);
      await expect(
        token
          .connect(admin)
          .createLockPolicy(ethers.encodeBytes32String("TOO_LONG"), {
            holdUntil: 0n,
            unlock: {
              anchor: 1,
              start: 0n,
              cliffDuration: NO_MORE_LOCKS_DELAY + 1n,
              vestDuration: 0n,
            },
          }),
      ).to.be.revertedWithCustomError(token, "InvalidPolicy");
    });

    it("accepts Tge-anchored vest of exactly noMoreLocks", async function () {
      const { token, admin } = await loadFixture(deploy);
      await expect(
        token
          .connect(admin)
          .createLockPolicy(ethers.encodeBytes32String("FULL_TAIL"), {
            holdUntil: 0n,
            unlock: {
              anchor: 1,
              start: 0n,
              cliffDuration: 0n,
              vestDuration: NO_MORE_LOCKS_DELAY,
            },
          }),
      ).to.emit(token, "PolicyDefined");
    });

    it("reverts when Absolute curve ends past the earliest sunset", async function () {
      const { token, admin, ccaEnd } = await loadFixture(deploy);
      const earliestMaturity = noMoreLocksFor(ccaEnd);
      await expect(
        token
          .connect(admin)
          .createLockPolicy(ethers.encodeBytes32String("TOO_LONG"), {
            holdUntil: 0n,
            unlock: {
              anchor: 0,
              start: earliestMaturity - YEAR,
              cliffDuration: 0n,
              vestDuration: YEAR + 1n,
            },
          }),
      ).to.be.revertedWithCustomError(token, "InvalidPolicy");
    });

    it("reverts when an Absolute policy is already fully matured", async function () {
      const { token, admin } = await loadFixture(deploy);
      const now = BigInt(await time.latest());

      await expect(
        token
          .connect(admin)
          .createLockPolicy(ethers.encodeBytes32String("STALE_ABS"), {
            holdUntil: 0n,
            unlock: {
              anchor: 0,
              start: now - 2n * DAY,
              cliffDuration: DAY,
              vestDuration: 0n,
            },
          }),
      ).to.be.revertedWithCustomError(token, "InvalidPolicy");
    });

    it("accepts an old Absolute curve when holdUntil still locks", async function () {
      const { token, admin } = await loadFixture(deploy);
      const now = BigInt(await time.latest());

      await expect(
        token
          .connect(admin)
          .createLockPolicy(ethers.encodeBytes32String("HELD_ABS"), {
            holdUntil: now + DAY,
            unlock: {
              anchor: 0,
              start: now - 2n * DAY,
              cliffDuration: DAY,
              vestDuration: 0n,
            },
          }),
      ).to.emit(token, "PolicyDefined");
    });

    it("reverts when holdUntil is past the earliest sunset", async function () {
      const { token, admin, ccaEnd } = await loadFixture(deploy);
      const earliestMaturity = noMoreLocksFor(ccaEnd);
      await expect(
        token
          .connect(admin)
          .createLockPolicy(ethers.encodeBytes32String("TOO_LONG"), {
            holdUntil: earliestMaturity + 1n,
            unlock: {
              anchor: 1,
              start: 0n,
              cliffDuration: 0n,
              vestDuration: YEAR,
            },
          }),
      ).to.be.revertedWithCustomError(token, "InvalidPolicy");
    });
  });

  // ═════════════════════════════════════════════════════════════════════════
  // Lock enforcement
  // ═════════════════════════════════════════════════════════════════════════

  describe("lockedBalanceOf / lockedBalanceAt / transferableBalanceOf", function () {
    it("lockedBalanceOf returns 0 for accounts with no locks", async function () {
      const { token, alice } = await loadFixture(deploy);
      expect(await token.lockedBalanceOf(await alice.getAddress())).to.equal(
        0n,
      );
    });

    it("TGE-anchored policy releases nothing before TGE timestamp", async function () {
      const { token, admin, alice } = await loadFixture(deploy);
      const policyId = await createLinearPolicy(token, admin, "TEST_POLICY", {
        vestDuration: 2n * YEAR,
      });
      const amount = ethers.parseEther("2400");

      await token.connect(admin).mintAllocations([
        {
          recipient: await alice.getAddress(),
          amount,
          policyId,
          label: ethers.encodeBytes32String("test"),
        },
      ]);

      // TGE not fired yet, Tge-anchored curve should keep everything locked.
      expect(await token.lockedBalanceOf(await alice.getAddress())).to.equal(
        amount,
      );
    });

    it("linear unlock over time after TGE", async function () {
      const { token, admin, alice, ccaEnd } = await loadFixture(deploy);
      const policyId = await createLinearPolicy(token, admin, "TEST_POLICY", {
        vestDuration: 2n * YEAR,
      });
      const amount = ethers.parseEther("2400");

      await token.connect(admin).mintAllocations([
        {
          recipient: await alice.getAddress(),
          amount,
          policyId,
          label: ethers.encodeBytes32String("test"),
        },
      ]);

      // Fire TGE.
      const TGE_COOLDOWN = 40n * DAY;
      await time.increaseTo(ccaEnd + TGE_COOLDOWN + 1n);
      const tgeTx = await token.tge();
      const receipt = await tgeTx.wait();
      const tgeBlock = await ethers.provider.getBlock(receipt!.blockNumber);
      const tgeTimestamp = BigInt(tgeBlock!.timestamp);

      // Right at TGE: everything still locked (cliffDuration = 0 so it starts
      // vesting immediately — but at timestamp == anchor, nothing has accrued).
      expect(await token.lockedBalanceOf(await alice.getAddress())).to.equal(
        amount,
      );

      // Halfway through vesting: half unlocked.
      await time.increaseTo(tgeTimestamp + YEAR);
      expect(await token.lockedBalanceOf(await alice.getAddress())).to.equal(
        amount / 2n,
      );

      // Past vest end: fully unlocked.
      await time.increaseTo(tgeTimestamp + 2n * YEAR);
      expect(await token.lockedBalanceOf(await alice.getAddress())).to.equal(
        0n,
      );
    });

    it("lockedBalanceAt follows the TGE-linear curve over time", async function () {
      // Use deployWithLockAndTge which creates a Tge-anchored lock with holdUntil=0.
      // Then verify lockedBalanceAt at various timestamps.
      const { token, alice, amount, tgeTimestamp } = await deployWithLockAndTge(
        { mintAmount: ethers.parseEther("1000") },
      );
      const aliceAddress = await alice.getAddress();

      // At tgeTimestamp, lock is fully locked (no time elapsed).
      expect(await token.lockedBalanceAt(aliceAddress, tgeTimestamp)).to.equal(
        amount,
      );

      // At tgeTimestamp + YEAR, half is unlocked (linear vest over 2Y).
      expect(
        await token.lockedBalanceAt(aliceAddress, tgeTimestamp + YEAR),
      ).to.equal(amount / 2n);

      // At tgeTimestamp + 2*YEAR, fully unlocked.
      expect(
        await token.lockedBalanceAt(aliceAddress, tgeTimestamp + 2n * YEAR),
      ).to.equal(0n);
    });

    it("sums multiple active locks with different curves correctly over time", async function () {
      const { token, admin, alice, ccaEnd } = await loadFixture(deploy);
      const aliceAddress = await alice.getAddress();

      // Alice receives three locks with different vesting curves.
      const policy24m = await createLinearPolicy(token, admin, "VEST_24M", {
        vestDuration: 2n * YEAR,
      });
      const policy12m = await createLinearPolicy(token, admin, "VEST_12M", {
        vestDuration: 1n * YEAR,
      });
      // Absolute policy: unlocks at a specific timestamp (ccaEnd + 180 days).
      // Use cliffDuration=1 (1 second) — zero cliff+vest together is invalid.
      const policyAbs = await createLinearPolicy(token, admin, "VEST_ABS", {
        anchor: 0,
        start: ccaEnd + 180n * DAY,
        cliffDuration: 1n,
        vestDuration: 0n,
      });

      const amount24m = ethers.parseEther("1000");
      const amount12m = ethers.parseEther("600");
      const amountAbs = ethers.parseEther("400");
      const total = amount24m + amount12m + amountAbs;

      await token.connect(admin).mintAllocations([
        {
          recipient: aliceAddress,
          amount: amount24m,
          policyId: policy24m,
          label: ethers.encodeBytes32String("v24"),
        },
        {
          recipient: aliceAddress,
          amount: amount12m,
          policyId: policy12m,
          label: ethers.encodeBytes32String("v12"),
        },
        {
          recipient: aliceAddress,
          amount: amountAbs,
          policyId: policyAbs,
          label: ethers.encodeBytes32String("abs"),
        },
      ]);

      // Fire TGE.
      const TGE_COOLDOWN = 40n * DAY;
      await time.increaseTo(ccaEnd + TGE_COOLDOWN + 1n);
      const tgeTx = await token.tge();
      const receipt = await tgeTx.wait();
      const tgeBlock = await ethers.provider.getBlock(receipt!.blockNumber);
      const tgeTimestamp = BigInt(tgeBlock!.timestamp);

      // At TGE: everything fully locked (all Tge-anchored + absolute cliff not yet).
      expect(await token.lockedBalanceOf(aliceAddress)).to.equal(total);

      // TGE + 6 months:
      //   24m policy: 6/24 = 25% unlocked → 750 locked
      //   12m policy: 6/12 = 50% unlocked → 300 locked
      //   Absolute: start=ccaEnd+180d, TGE+6m past that → 0 locked
      //   Total locked ≈ 750 + 300 + 0 = 1050
      await time.increaseTo(tgeTimestamp + YEAR / 2n);
      let locked = await token.lockedBalanceOf(aliceAddress);
      expect(locked).to.be.closeTo(
        ethers.parseEther("1050"),
        ethers.parseEther("0.02"),
      );

      // TGE + 12 months:
      //   24m policy: 12/24 = 50% unlocked → 500 locked
      //   12m policy: 100% unlocked → 0 locked
      //   Absolute: unlocked → 0 locked
      //   Total locked ≈ 500
      await time.increaseTo(tgeTimestamp + YEAR);
      locked = await token.lockedBalanceOf(aliceAddress);
      expect(locked).to.be.closeTo(
        ethers.parseEther("500"),
        ethers.parseEther("0.02"),
      );
    });

    it("transferableBalanceOf returns full balance when nothing locked", async function () {
      const { token, alice, amount } = await deployWithUnlockedAndTge(
        ethers.parseEther("100"),
      );
      expect(
        await token.transferableBalanceOf(await alice.getAddress()),
      ).to.equal(amount);
    });

    it("transferableBalanceOf = 0 when fully locked and no bond", async function () {
      const { token, alice } = await deployWithLockAndTge({
        mintAmount: ethers.parseEther("1000"),
      });
      expect(
        await token.transferableBalanceOf(await alice.getAddress()),
      ).to.equal(0n);
    });

    it("holdUntil keeps everything locked regardless of curve", async function () {
      const { token, admin, alice, ccaEnd } = await loadFixture(deploy);
      const aliceAddress = await alice.getAddress();

      // Compute the intended TGE timestamp before firing it.
      const TGE_COOLDOWN = 40n * DAY;
      const intendedTge = ccaEnd + TGE_COOLDOWN + 1n;

      // Policy: 1-year linear vest, holdUntil = intended TGE + 2 years.
      const policyId = await createLinearPolicy(token, admin, "HOLD_TEST", {
        vestDuration: 1n * YEAR,
        holdUntil: intendedTge + 2n * YEAR,
      });

      // Mint locked allocation DURING Virtual phase.
      const amount = ethers.parseEther("1000");
      await token.connect(admin).mintAllocations([
        {
          recipient: aliceAddress,
          amount,
          policyId,
          label: ethers.encodeBytes32String("hold"),
        },
      ]);

      // Fire TGE.
      await time.increaseTo(intendedTge);
      const tgeTx = await token.tge();
      const receipt = await tgeTx.wait();
      const tgeBlock = await ethers.provider.getBlock(receipt!.blockNumber);
      const tgeTimestamp = BigInt(tgeBlock!.timestamp);

      // At TGE + 1.5 years: curve says fully unlocked (vestDuration = 1Y),
      // but holdUntil = TGE + 2Y keeps everything locked.
      await time.increaseTo(tgeTimestamp + (1n * YEAR + YEAR / 2n));
      expect(await token.lockedBalanceOf(aliceAddress)).to.equal(amount);

      // At TGE + 2 years (holdUntil): hold lifts, curve already fully vested.
      await time.increaseTo(tgeTimestamp + 2n * YEAR);
      expect(await token.lockedBalanceOf(aliceAddress)).to.equal(0n);
    });

    it("MAX_LOCKS_PER_ACCOUNT: 9th active policy reverts", async function () {
      const { token, admin, alice } = await loadFixture(deploy);
      const aliceAddress = await alice.getAddress();
      const maxLocks = Number(await token.MAX_LOCKS_PER_ACCOUNT());

      // Create 8 distinct policies and mint 1 wei under each.
      for (let i = 0; i < maxLocks; i++) {
        const policyId = ethers.encodeBytes32String(`CAP_${i}`);
        await createLinearPolicy(token, admin, `CAP_${i}`, {
          vestDuration: 1n * YEAR,
        });
        await token.connect(admin).mintAllocations([
          {
            recipient: aliceAddress,
            amount: 1n,
            policyId,
            label: ethers.encodeBytes32String(`cap${i}`),
          },
        ]);
      }
      expect(await token.lockCount(aliceAddress)).to.equal(BigInt(maxLocks));

      // 9th policy should revert.
      const ninthId = ethers.encodeBytes32String("CAP_9");
      await createLinearPolicy(token, admin, "CAP_9", {
        vestDuration: 1n * YEAR,
      });
      await expect(
        token.connect(admin).mintAllocations([
          {
            recipient: aliceAddress,
            amount: 1n,
            policyId: ninthId,
            label: ethers.encodeBytes32String("toomany"),
          },
        ]),
      ).to.be.revertedWithCustomError(token, "TooManyLocks");
    });

    it("prunes matured active locks before enforcing the active lock cap", async function () {
      const { token, admin, alice, claimSource } = await loadFixture(deploy);
      const aliceAddress = await alice.getAddress();
      const claimSourceAddress = await claimSource.getAddress();
      const maxLocks = Number(await token.MAX_LOCKS_PER_ACCOUNT());
      const start = BigInt(await time.latest()) + DAY;

      for (let i = 0; i < maxLocks; i++) {
        const policyId = ethers.encodeBytes32String(`OLD_${i}`);
        await createLinearPolicy(token, admin, `OLD_${i}`, {
          anchor: 0,
          start,
          cliffDuration: 1n,
          vestDuration: 0n,
        });
        await token.connect(admin).mintAllocations([
          {
            recipient: aliceAddress,
            amount: 1n,
            policyId,
            label: ethers.encodeBytes32String(`old${i}`),
          },
        ]);
      }
      expect(await token.lockCount(aliceAddress)).to.equal(BigInt(maxLocks));

      const claimAmount = ethers.parseEther("10");
      await token
        .connect(admin)
        .mint(claimSourceAddress, claimAmount, ethers.ZeroHash);
      await time.increaseTo(start + 2n);
      expect(await token.lockedBalanceOf(aliceAddress)).to.equal(0n);

      await token.connect(claimSource).transfer(aliceAddress, claimAmount);

      expect(await token.lockCount(aliceAddress)).to.equal(1n);
      const lock = await token.locks(aliceAddress, 0);
      expect(lock.policyId).to.equal(await token.PENDING_LOCK_POLICY_ID());
      expect(lock.amount).to.equal(claimAmount);
    });

    it("repeated queued links under one policy increment one queued bucket", async function () {
      const { token, admin, alice } = await loadFixture(deploy);
      const aliceAddress = await alice.getAddress();
      const maxQueued = Number(await token.MAX_QUEUED_LOCKS_PER_ACCOUNT());
      const policyId = await createLinearPolicy(token, admin, "QCAP", {
        vestDuration: 1n * YEAR,
      });

      for (let i = 0; i < maxQueued + 1; i++) {
        await token.connect(admin).linkClaim(aliceAddress, 1n, policyId);
      }

      expect(await token.queuedLockCount(aliceAddress)).to.equal(1n);
      const queuedLock = await token.queuedLocks(aliceAddress, 0);
      expect(queuedLock.policyId).to.equal(policyId);
      expect(queuedLock.amount).to.equal(BigInt(maxQueued + 1));
    });

    it("incrementing an existing policy does not count as a new entry", async function () {
      const { token, admin, alice } = await loadFixture(deploy);
      const aliceAddress = await alice.getAddress();
      const policyId = await createLinearPolicy(token, admin, "INCREMENT", {
        vestDuration: 1n * YEAR,
      });

      // One allocation under the policy.
      await token.connect(admin).mintAllocations([
        {
          recipient: aliceAddress,
          amount: ethers.parseEther("100"),
          policyId,
          label: ethers.encodeBytes32String("first"),
        },
      ]);
      expect(await token.lockCount(aliceAddress)).to.equal(1n);

      // Second allocation under the SAME policy -- increments amount, not a new entry.
      await token.connect(admin).mintAllocations([
        {
          recipient: aliceAddress,
          amount: ethers.parseEther("100"),
          policyId,
          label: ethers.encodeBytes32String("second"),
        },
      ]);
      expect(await token.lockCount(aliceAddress)).to.equal(1n);

      const lock = await token.locks(aliceAddress, 0);
      expect(lock.amount).to.equal(ethers.parseEther("200"));
    });
  });

  // ═════════════════════════════════════════════════════════════════════════
  // Transfer enforcement
  // ═════════════════════════════════════════════════════════════════════════

  describe("transfer enforcement", function () {
    it("blocks transfer that would drop below locked balance", async function () {
      const { token, alice, bob, amount } = await deployWithLockAndTge({
        mintAmount: ethers.parseEther("1000"),
      });
      // After TGE, a tiny fraction may have unlocked (1-2 seconds of vesting).
      // transferableBalance should be far less than the full amount.
      const transferable = await token.transferableBalanceOf(
        await alice.getAddress(),
      );
      expect(transferable).to.be.lt(amount / 2n);
      // Attempting to transfer the full amount should revert.
      await expect(
        token.connect(alice).transfer(await bob.getAddress(), amount),
      ).to.be.revertedWithCustomError(token, "InsufficientUnlockedBalance");
    });

    it("allows transfer of unlocked portion", async function () {
      const { token, alice, bob, amount, tgeTimestamp } =
        await deployWithLockAndTge({
          mintAmount: ethers.parseEther("1000"),
          vestDuration: 2n * YEAR,
        });

      await time.increaseTo(tgeTimestamp + YEAR);

      // Half unlocked.
      const half = amount / 2n;
      expect(
        await token.transferableBalanceOf(await alice.getAddress()),
      ).to.equal(half);

      await token.connect(alice).transfer(await bob.getAddress(), half);
    });

    it("pre-TGE: bonding registry transfers are allowed", async function () {
      const { token, admin, alice, mockRegistry } = await loadFixture(deploy);
      const amount = ethers.parseEther("100");
      const registryAddress = await mockRegistry.getAddress();

      await token
        .connect(admin)
        .mint(await alice.getAddress(), amount, ethers.ZeroHash);

      // Transfer TO bonding registry — should work pre-TGE.
      await token.connect(alice).transfer(registryAddress, amount);
    });

    it("pre-TGE: whitelisted addresses can transfer", async function () {
      const { token, admin, alice, bob } = await loadFixture(deploy);
      const amount = ethers.parseEther("100");

      await token
        .connect(admin)
        .mint(await alice.getAddress(), amount, ethers.ZeroHash);
      await token
        .connect(admin)
        .setTransferWhitelisted(await alice.getAddress(), true);

      await token.connect(alice).transfer(await bob.getAddress(), amount);
    });

    it("pre-TGE: regular transfers are blocked", async function () {
      const { token, admin, alice, bob } = await loadFixture(deploy);
      const amount = ethers.parseEther("100");

      await token
        .connect(admin)
        .mint(await alice.getAddress(), amount, ethers.ZeroHash);

      await expect(
        token.connect(alice).transfer(await bob.getAddress(), amount),
      ).to.be.revertedWithCustomError(token, "TransferRestricted");
    });

    it("pre-TGE: whitelist does NOT bypass locked-balance invariant", async function () {
      const { token, admin, alice, bob } = await loadFixture(deploy);
      const aliceAddress = await alice.getAddress();
      const policyId = await createLinearPolicy(
        token,
        admin,
        "WHITELIST_LOCK",
        {
          vestDuration: 2n * YEAR,
        },
      );
      const amount = ethers.parseEther("1000");

      // Mint locked allocation to Alice.
      await token.connect(admin).mintAllocations([
        {
          recipient: aliceAddress,
          amount,
          policyId,
          label: ethers.encodeBytes32String("locked"),
        },
      ]);

      // Whitelist Alice.
      await token.connect(admin).setTransferWhitelisted(aliceAddress, true);

      // Pre-TGE, whitelist bypasses the transfer gate but NOT the lock invariant.
      // Alice has all tokens locked -> transferableBalance is 0 -> transfer reverts.
      await expect(
        token.connect(alice).transfer(await bob.getAddress(), amount),
      ).to.be.revertedWithCustomError(token, "InsufficientUnlockedBalance");
    });

    it("pre-TGE: CLAIM_SOURCE transfer creates PENDING lock on recipient", async function () {
      const { token, admin, alice, claimSource } = await loadFixture(deploy);
      const aliceAddress = await alice.getAddress();
      const amount = ethers.parseEther("500");

      // Mint unlocked tokens to claimSource during Virtual phase.
      await token
        .connect(admin)
        .mint(await claimSource.getAddress(), amount, ethers.ZeroHash);

      // Pre-TGE claim-source transfer to Alice.
      await token.connect(claimSource).transfer(aliceAddress, amount);

      // Alice received a PENDING lock (pre-TGE, no bond, so fully locked).
      expect(await token.lockedBalanceOf(aliceAddress)).to.equal(amount);
      expect(await token.lockCount(aliceAddress)).to.equal(1n);

      const lock = await token.locks(aliceAddress, 0);
      expect(lock.policyId).to.equal(ethers.encodeBytes32String("PENDING"));
      expect(lock.amount).to.equal(amount);

      // Pre-TGE, Alice cannot transfer it onward at all (transfer gate).
      // The locked-balance invariant would also block it, but the pre-TGE
      // gate catches it first. Both protections are correct.
      await expect(
        token.connect(alice).transfer(await claimSource.getAddress(), amount),
      ).to.be.revertedWithCustomError(token, "TransferRestricted");
    });
  });

  // ═════════════════════════════════════════════════════════════════════════
  // Lock sunset
  // ═════════════════════════════════════════════════════════════════════════

  describe("lock sunset", function () {
    it("NO_MORE_LOCKS is fixed at deployment", async function () {
      const { token, noMoreLocks } = await loadFixture(deploy);
      expect(await token.NO_MORE_LOCKS()).to.equal(noMoreLocks);
    });

    it("locked balance becomes fully transferable at the sunset", async function () {
      const { token, alice, bob, amount, noMoreLocks } =
        await deployWithLockAndTge({ mintAmount: ethers.parseEther("1000") });
      const aliceAddress = await alice.getAddress();

      await time.increaseTo(noMoreLocks);

      expect(await token.lockedBalanceOf(aliceAddress)).to.equal(0n);
      expect(await token.transferableBalanceOf(aliceAddress)).to.equal(amount);
      await token.connect(alice).transfer(await bob.getAddress(), amount);
    });

    it("unlinked PENDING locks sunset too", async function () {
      const { token, alice, bob, claimSource, amount } =
        await deployWithUnlockedAndTge(ethers.parseEther("500"));
      const aliceAddress = await alice.getAddress();

      await token
        .connect(alice)
        .transfer(await claimSource.getAddress(), amount);
      await token.connect(claimSource).transfer(aliceAddress, amount);
      expect(await token.lockedBalanceOf(aliceAddress)).to.equal(amount);

      await time.increaseTo(await token.NO_MORE_LOCKS());

      expect(await token.lockedBalanceOf(aliceAddress)).to.equal(0n);
      await token.connect(alice).transfer(await bob.getAddress(), amount);
    });

    it("lockedBalanceAt reports 0 from the sunset onwards", async function () {
      const { token, alice, claimSource, amount } =
        await deployWithUnlockedAndTge(ethers.parseEther("500"));
      const aliceAddress = await alice.getAddress();

      await token
        .connect(alice)
        .transfer(await claimSource.getAddress(), amount);
      await token.connect(claimSource).transfer(aliceAddress, amount);

      const maturity = await token.NO_MORE_LOCKS();
      expect(await token.lockedBalanceAt(aliceAddress, maturity - 1n)).to.equal(
        amount,
      );
      expect(await token.lockedBalanceAt(aliceAddress, maturity)).to.equal(0n);
    });

    it("CLAIM_SOURCE transfers past the sunset create no locks", async function () {
      const { token, alice, claimSource, amount } =
        await deployWithUnlockedAndTge(ethers.parseEther("500"));
      const aliceAddress = await alice.getAddress();

      await token
        .connect(alice)
        .transfer(await claimSource.getAddress(), amount);

      await time.increaseTo(await token.NO_MORE_LOCKS());

      await token.connect(claimSource).transfer(aliceAddress, amount);
      expect(await token.lockCount(aliceAddress)).to.equal(0n);
      expect(await token.lockedBalanceOf(aliceAddress)).to.equal(0n);
    });

    it("late TGE: max-length policy tail is truncated at NO_MORE_LOCKS", async function () {
      const { token, admin, alice, ccaEnd } = await loadFixture(deploy);
      const aliceAddress = await alice.getAddress();

      // Create a policy whose natural end lands exactly at NO_MORE_LOCKS
      // (using the earliest possible TGE: ccaEnd + TGE_COOLDOWN).
      const earliestTge = ccaEnd + TGE_COOLDOWN;
      // The tail after earliestTge is NO_MORE_LOCKS_DELAY = 4 years + 30 days.
      const policyId = await createLinearPolicy(token, admin, "MAX_TAIL", {
        vestDuration: NO_MORE_LOCKS_DELAY,
      });
      const amount = ethers.parseEther("1000");
      await token.connect(admin).mintAllocations([
        {
          recipient: aliceAddress,
          amount,
          policyId,
          label: ethers.encodeBytes32String("tail"),
        },
      ]);

      // Call TGE slightly late -- 1 day past the earliest possible TGE.
      await time.increaseTo(earliestTge + 1n * DAY);
      await token.tge();

      // Advance to NO_MORE_LOCKS. The natural unlock tail would extend 1 day
      // past NO_MORE_LOCKS (since TGE was 1 day late), but NO_MORE_LOCKS
      // overrides -- locked balance MUST be 0.
      await time.increaseTo(await token.NO_MORE_LOCKS());
      expect(await token.lockedBalanceOf(aliceAddress)).to.equal(0n);
    });

    it("absolute sunset without TGE: transfers succeed and no locks are created", async function () {
      const { token, admin, alice, bob, claimSource, noMoreLocks } =
        await loadFixture(deploy);
      const aliceAddress = await alice.getAddress();
      const claimSourceAddress = await claimSource.getAddress();
      const amount = ethers.parseEther("500");

      // Mint unlocked tokens during Virtual phase (before time advance).
      await token.connect(admin).mint(aliceAddress, amount, ethers.ZeroHash);
      await token
        .connect(admin)
        .mint(claimSourceAddress, amount, ethers.ZeroHash);

      // Do NOT call tge(). Advance straight to NO_MORE_LOCKS.
      await time.increaseTo(noMoreLocks);

      // Regular transfer succeeds.
      await token.connect(alice).transfer(await bob.getAddress(), amount);
      expect(await token.balanceOf(aliceAddress)).to.equal(0n);

      // lockedBalanceOf returns 0.
      expect(await token.lockedBalanceOf(aliceAddress)).to.equal(0n);

      // CLAIM_SOURCE transfer creates no lock.
      await token.connect(claimSource).transfer(aliceAddress, amount);
      expect(await token.lockedBalanceOf(aliceAddress)).to.equal(0n);
      expect(await token.lockCount(aliceAddress)).to.equal(0n);
    });
  });

  // ═════════════════════════════════════════════════════════════════════════
  // Claim-source auto-lock & linkClaim
  // ═════════════════════════════════════════════════════════════════════════

  describe("claim-source auto-lock & linkClaim", function () {
    it("claimLockExempt exempts from auto-lock on claim-source transfer", async function () {
      const { token, admin, alice, claimSource, amount } =
        await deployWithUnlockedAndTge(ethers.parseEther("500"));

      await token
        .connect(admin)
        .setClaimLockExempt(await alice.getAddress(), true);

      // Transfer tokens from alice to claimSource so claimSource can send.
      await token
        .connect(alice)
        .transfer(await claimSource.getAddress(), amount);

      await token
        .connect(claimSource)
        .transfer(await alice.getAddress(), amount);

      // No lock created because recipient is claim-lock exempt.
      expect(await token.lockedBalanceOf(await alice.getAddress())).to.equal(
        0n,
      );
      expect(await token.balanceOf(await alice.getAddress())).to.equal(amount);
    });

    it("linkClaim moves PENDING to a real policy", async function () {
      const { token, admin, alice, claimSource, amount } =
        await deployWithUnlockedAndTge(ethers.parseEther("500"));
      const aliceAddress = await alice.getAddress();
      const policyId = await createLinearPolicy(token, admin, "REAL_POLICY", {
        vestDuration: 2n * YEAR,
      });

      // Transfer from alice to claimSource so claimSource can send.
      await token
        .connect(alice)
        .transfer(await claimSource.getAddress(), amount);
      await token
        .connect(claimSource)
        .transfer(await alice.getAddress(), amount);

      // Now link the claim to the real policy.
      await token.connect(admin).linkClaim(aliceAddress, amount, policyId);

      expect(await token.queuedLockCount(aliceAddress)).to.equal(0n);
      expect(await token.lockCount(aliceAddress)).to.equal(1n);
      const lock = await token.locks(aliceAddress, 0);
      expect(lock.policyId).to.equal(policyId);
      expect(lock.amount).to.equal(amount);
    });

    it("linkClaim rejects a conflicting queued policy for the same account", async function () {
      const { token, admin, alice } = await loadFixture(deploy);
      const aliceAddress = await alice.getAddress();
      const policyA = await createLinearPolicy(token, admin, "QUEUE_A", {
        vestDuration: 2n * YEAR,
      });
      const policyB = await createLinearPolicy(token, admin, "QUEUE_B", {
        vestDuration: 4n * YEAR,
      });

      await token.connect(admin).linkClaim(aliceAddress, 100n, policyA);

      await expect(token.connect(admin).linkClaim(aliceAddress, 100n, policyB))
        .to.be.revertedWithCustomError(token, "ConflictingQueuedClaimPolicy")
        .withArgs(policyA, policyB);
    });

    it("linkClaim can increment the existing queued policy", async function () {
      const { token, admin, alice } = await loadFixture(deploy);
      const aliceAddress = await alice.getAddress();
      const policyId = await createLinearPolicy(token, admin, "QUEUE_SAME", {
        vestDuration: 2n * YEAR,
      });

      await token.connect(admin).linkClaim(aliceAddress, 100n, policyId);
      await token.connect(admin).linkClaim(aliceAddress, 200n, policyId);

      expect(await token.queuedLockCount(aliceAddress)).to.equal(1n);
      const queuedLock = await token.queuedLocks(aliceAddress, 0);
      expect(queuedLock.policyId).to.equal(policyId);
      expect(queuedLock.amount).to.equal(300n);
    });

    it("linkClaim cannot create queued locks for a claim-lock exempt account", async function () {
      const { token, admin, alice } = await loadFixture(deploy);
      const aliceAddress = await alice.getAddress();
      const policyId = await createLinearPolicy(token, admin, "EXEMPT_LINK", {
        vestDuration: 2n * YEAR,
      });

      await token.connect(admin).setClaimLockExempt(aliceAddress, true);

      await expect(token.connect(admin).linkClaim(aliceAddress, 100n, policyId))
        .to.be.revertedWithCustomError(token, "ClaimLockExemptQueuedLocks")
        .withArgs(aliceAddress);
    });

    it("linkClaim partly consumes PENDING and queues the remainder", async function () {
      const { token, admin, alice, claimSource, amount } =
        await deployWithUnlockedAndTge(ethers.parseEther("300"));
      const aliceAddress = await alice.getAddress();
      const policyId = await createLinearPolicy(token, admin, "PART_QUEUE", {
        vestDuration: 2n * YEAR,
      });

      await token
        .connect(alice)
        .transfer(await claimSource.getAddress(), amount);

      expect(await token.lockCount(aliceAddress)).to.equal(0n);
      expect(await token.queuedLockCount(aliceAddress)).to.equal(0n);

      await token.connect(claimSource).transfer(aliceAddress, amount);

      const linkAmount = ethers.parseEther("1000");
      await token.connect(admin).linkClaim(aliceAddress, linkAmount, policyId);

      expect(await token.lockCount(aliceAddress)).to.equal(1n);
      expect(await token.queuedLockCount(aliceAddress)).to.equal(1n);

      const activeLock = await token.locks(aliceAddress, 0);
      expect(activeLock.policyId).to.equal(policyId);
      expect(activeLock.amount).to.equal(amount);

      const queuedLock = await token.queuedLocks(aliceAddress, 0);
      expect(queuedLock.policyId).to.equal(policyId);
      expect(queuedLock.amount).to.equal(linkAmount - amount);
    });

    it("claim after link consumes the queued link", async function () {
      const fixture = await loadFixture(deploy);
      const { token, admin, alice, claimSource, ccaEnd } = fixture;
      const aliceAddress = await alice.getAddress();
      const policyId = await createLinearPolicy(token, admin, "CLAIM_LINK", {
        vestDuration: 2n * YEAR,
      });
      const linkAmount = ethers.parseEther("500");

      await token.connect(admin).linkClaim(aliceAddress, linkAmount, policyId);
      expect(await token.queuedLockCount(aliceAddress)).to.equal(1n);
      expect(await token.lockedBalanceOf(aliceAddress)).to.equal(0n);

      await token
        .connect(admin)
        .mint(await claimSource.getAddress(), linkAmount, ethers.ZeroHash);

      const TGE_COOLDOWN = 40n * DAY;
      await time.increaseTo(ccaEnd + TGE_COOLDOWN + 1n);
      await token.tge();

      await token.connect(claimSource).transfer(aliceAddress, linkAmount);

      expect(await token.queuedLockCount(aliceAddress)).to.equal(0n);
      expect(await token.lockCount(aliceAddress)).to.equal(1n);

      const activeLock = await token.locks(aliceAddress, 0);
      expect(activeLock.policyId).to.equal(policyId);
      expect(activeLock.amount).to.equal(linkAmount);
    });

    it("claim after link fully consumes queued link and adds excess as PENDING", async function () {
      const fixture = await loadFixture(deploy);
      const { token, admin, alice, claimSource, ccaEnd } = fixture;
      const aliceAddress = await alice.getAddress();
      const policyId = await createLinearPolicy(token, admin, "LINK_PENDING", {
        vestDuration: 2n * YEAR,
      });
      const linkAmount = ethers.parseEther("500");
      const claimAmount = ethers.parseEther("700");
      const pendingPolicyId = await token.PENDING_LOCK_POLICY_ID();

      await token.connect(admin).linkClaim(aliceAddress, linkAmount, policyId);
      await token
        .connect(admin)
        .mint(await claimSource.getAddress(), claimAmount, ethers.ZeroHash);

      const TGE_COOLDOWN = 40n * DAY;
      await time.increaseTo(ccaEnd + TGE_COOLDOWN + 1n);
      await token.tge();

      await token.connect(claimSource).transfer(aliceAddress, claimAmount);

      expect(await token.queuedLockCount(aliceAddress)).to.equal(0n);
      expect(await token.lockCount(aliceAddress)).to.equal(2n);

      const firstLock = await token.locks(aliceAddress, 0);
      const secondLock = await token.locks(aliceAddress, 1);
      const locksByPolicy = new Map([
        [firstLock.policyId, firstLock.amount],
        [secondLock.policyId, secondLock.amount],
      ]);

      expect(locksByPolicy.get(policyId)).to.equal(linkAmount);
      expect(locksByPolicy.get(pendingPolicyId)).to.equal(
        claimAmount - linkAmount,
      );
    });

    it("linkClaim reverts with undefined policy", async function () {
      const { token, admin, alice } = await loadFixture(deploy);
      await expect(
        token
          .connect(admin)
          .linkClaim(
            await alice.getAddress(),
            ethers.parseEther("1"),
            ethers.encodeBytes32String("UNDEFINED"),
          ),
      ).to.be.revertedWithCustomError(token, "PolicyNotDefined");
    });

    it("linkClaim reverts with zero amount", async function () {
      const { token, admin, alice } = await loadFixture(deploy);
      const policyId = await createLinearPolicy(token, admin, "REAL_POLICY");
      await expect(
        token.connect(admin).linkClaim(await alice.getAddress(), 0n, policyId),
      ).to.be.revertedWithCustomError(token, "ZeroAmount");
    });

    it("non-LOCK_MANAGER_ROLE cannot linkClaim", async function () {
      const { token, alice } = await loadFixture(deploy);
      await expect(
        token
          .connect(alice)
          .linkClaim(
            await alice.getAddress(),
            ethers.parseEther("1"),
            ethers.encodeBytes32String("ANY"),
          ),
      ).to.be.revertedWithCustomError(
        token,
        "AccessControlUnauthorizedAccount",
      );
    });

    it("queued locks survive multiple partial claims", async function () {
      const fixture = await loadFixture(deploy);
      const { token, admin, alice, claimSource, ccaEnd } = fixture;
      const aliceAddress = await alice.getAddress();
      const policyId = await createLinearPolicy(token, admin, "PARTIAL", {
        vestDuration: 2n * YEAR,
      });
      const linkAmount = ethers.parseEther("1000");

      // Queue a large amount.
      await token.connect(admin).linkClaim(aliceAddress, linkAmount, policyId);

      // Mint all claim tokens during Virtual phase.
      const totalClaim = ethers.parseEther("700");
      await token
        .connect(admin)
        .mint(await claimSource.getAddress(), totalClaim, ethers.ZeroHash);

      // Fire TGE.
      const TGE_COOLDOWN = 40n * DAY;
      await time.increaseTo(ccaEnd + TGE_COOLDOWN + 1n);
      await token.tge();

      // Send a partial claim.
      const partialAmount = ethers.parseEther("400");
      await token.connect(claimSource).transfer(aliceAddress, partialAmount);

      expect(await token.lockCount(aliceAddress)).to.equal(1n);
      let activeLock = await token.locks(aliceAddress, 0);
      expect(activeLock.policyId).to.equal(policyId);
      expect(activeLock.amount).to.equal(partialAmount);
      expect(await token.queuedLockCount(aliceAddress)).to.equal(1n);
      let queuedLock = await token.queuedLocks(aliceAddress, 0);
      expect(queuedLock.policyId).to.equal(policyId);
      expect(queuedLock.amount).to.equal(linkAmount - partialAmount);

      // Send another claim.
      const anotherAmount = ethers.parseEther("300");
      await token.connect(claimSource).transfer(aliceAddress, anotherAmount);

      activeLock = await token.locks(aliceAddress, 0);
      expect(activeLock.policyId).to.equal(policyId);
      expect(activeLock.amount).to.equal(partialAmount + anotherAmount);
      expect(await token.queuedLockCount(aliceAddress)).to.equal(1n);
      queuedLock = await token.queuedLocks(aliceAddress, 0);
      expect(queuedLock.policyId).to.equal(policyId);
      expect(queuedLock.amount).to.equal(
        linkAmount - partialAmount - anotherAmount,
      );
    });

    it("links CCA claim without disturbing existing non-CCA locks", async function () {
      const fixture = await loadFixture(deploy);
      const { token, admin, alice, claimSource, ccaEnd } = fixture;
      const aliceAddress = await alice.getAddress();

      // Alice already has a Legion/SAFT lock — mint BEFORE TGE.
      const legionPolicy = await createLinearPolicy(token, admin, "LEGION", {
        vestDuration: 2n * YEAR,
      });
      const legionAmount = ethers.parseEther("1000");

      // Mint extra unlocked tokens to fund the claim transfer.
      const claimAmount = ethers.parseEther("500");
      await token
        .connect(admin)
        .mint(aliceAddress, claimAmount, ethers.ZeroHash);

      await token.connect(admin).mintAllocations([
        {
          recipient: aliceAddress,
          amount: legionAmount,
          policyId: legionPolicy,
          label: ethers.encodeBytes32String("legion"),
        },
      ]);

      // Fire TGE.
      const TGE_COOLDOWN = 40n * DAY;
      await time.increaseTo(ccaEnd + TGE_COOLDOWN + 1n);
      await token.tge();

      // Now CLAIM_SOURCE sends tokens — becomes PENDING.
      await token
        .connect(alice)
        .transfer(await claimSource.getAddress(), claimAmount);
      await token.connect(claimSource).transfer(aliceAddress, claimAmount);

      // Lock before link: LEGION active + PENDING.
      expect(await token.lockCount(aliceAddress)).to.equal(2n);

      // linkClaim the PENDING to CCA_POLICY.
      const ccaPolicy = await createLinearPolicy(token, admin, "CCA", {
        vestDuration: 1n * YEAR,
      });
      await token
        .connect(admin)
        .linkClaim(aliceAddress, claimAmount, ccaPolicy);

      // LEGION still has 1,000; CCA now has 500; no PENDING remains.
      expect(await token.lockCount(aliceAddress)).to.equal(2n);
      const locks = [
        await token.locks(aliceAddress, 0),
        await token.locks(aliceAddress, 1),
      ];
      const byPolicy = new Map(
        locks.map((l: { policyId: string; amount: bigint }) => [
          l.policyId,
          l.amount,
        ]),
      );
      expect(byPolicy.get(legionPolicy)).to.equal(legionAmount);
      expect(byPolicy.get(ccaPolicy)).to.equal(claimAmount);

      // lockedBalanceOf equals sum of both (allow tiny vesting rounding).
      const lb = await token.lockedBalanceOf(aliceAddress);
      expect(lb).to.be.closeTo(
        legionAmount + claimAmount,
        ethers.parseEther("0.02"),
      );
    });

    it("supports mixed allocation types for one wallet: unlocked grant + vested allocation + CCA claim", async function () {
      const fixture = await loadFixture(deploy);
      const { token, admin, alice, claimSource, ccaEnd } = fixture;
      const aliceAddress = await alice.getAddress();

      // 1. Unlocked grant.
      const grantAmount = ethers.parseEther("100");
      await token
        .connect(admin)
        .mint(aliceAddress, grantAmount, ethers.ZeroHash);

      // 2. Legion/SAFT vested allocation.
      const legionPolicy = await createLinearPolicy(token, admin, "SAFT", {
        vestDuration: 2n * YEAR,
      });
      const legionAmount = ethers.parseEther("1000");
      await token.connect(admin).mintAllocations([
        {
          recipient: aliceAddress,
          amount: legionAmount,
          policyId: legionPolicy,
          label: ethers.encodeBytes32String("saft"),
        },
      ]);

      // 3. CCA claim tokens: mint to claimSource, then later transfer back.
      const ccaAmount = ethers.parseEther("500");
      await token
        .connect(admin)
        .mint(await claimSource.getAddress(), ccaAmount, ethers.ZeroHash);

      // Fire TGE.
      const TGE_COOLDOWN = 40n * DAY;
      await time.increaseTo(ccaEnd + TGE_COOLDOWN + 1n);
      await token.tge();

      // Now CLAIM_SOURCE sends tokens — becomes PENDING.
      await token.connect(claimSource).transfer(aliceAddress, ccaAmount);

      // Link CCA PENDING to a CCA policy.
      const ccaPolicy = await createLinearPolicy(token, admin, "CCA_VEST", {
        vestDuration: 1n * YEAR,
      });
      await token.connect(admin).linkClaim(aliceAddress, ccaAmount, ccaPolicy);

      // Assertions after all allocations are in place.
      const totalBalance = grantAmount + legionAmount + ccaAmount;
      expect(await token.balanceOf(aliceAddress)).to.equal(totalBalance);
      expect(await token.lockCount(aliceAddress)).to.equal(2n);

      // Sum of locked: SAFT locked + CCA locked (grant is unlocked).
      const lb = await token.lockedBalanceOf(aliceAddress);
      expect(lb).to.be.closeTo(
        legionAmount + ccaAmount,
        ethers.parseEther("0.02"),
      );

      // Grant portion (100) is unlocked and transferable subject to floor.
      // With no bond, floor = lockedBalance ≈ 1500. Wallet = 1600.
      // transferable ≈ 1600 - 1500 = 100 (the grant portion).
      const tb = await token.transferableBalanceOf(aliceAddress);
      expect(tb).to.be.closeTo(grantAmount, ethers.parseEther("0.02"));
    });
  });

  // ═════════════════════════════════════════════════════════════════════════
  // relinkActiveLock
  // ═════════════════════════════════════════════════════════════════════════

  describe("relinkActiveLock", function () {
    it("relink works before TGE", async function () {
      const { token, admin, alice } = await loadFixture(deploy);
      const aliceAddress = await alice.getAddress();

      const fromPolicy = await createLinearPolicy(token, admin, "FROM_POL", {
        vestDuration: 1n * YEAR,
      });
      const toPolicy = await createLinearPolicy(token, admin, "TO_POL", {
        vestDuration: 2n * YEAR,
      });
      const amount = ethers.parseEther("1000");

      await token.connect(admin).mintAllocations([
        {
          recipient: aliceAddress,
          amount,
          policyId: fromPolicy,
          label: ethers.encodeBytes32String("src"),
        },
      ]);

      // Relink 400 from FROM_POL to TO_POL.
      const relinkAmount = ethers.parseEther("400");
      await expect(
        token
          .connect(admin)
          .relinkActiveLock(aliceAddress, fromPolicy, toPolicy, relinkAmount),
      )
        .to.emit(token, "ActiveLockRelinked")
        .withArgs(aliceAddress, fromPolicy, toPolicy, relinkAmount);

      // FROM_POL should now have 600, TO_POL should have 400.
      const locks = [
        await token.locks(aliceAddress, 0),
        await token.locks(aliceAddress, 1),
      ];
      const byPolicy = new Map(
        locks.map((l: { policyId: string; amount: bigint }) => [
          l.policyId,
          l.amount,
        ]),
      );
      expect(byPolicy.get(fromPolicy)).to.equal(ethers.parseEther("600"));
      expect(byPolicy.get(toPolicy)).to.equal(relinkAmount);
    });

    it("relink allows an unvested Absolute source policy", async function () {
      const { token, admin, alice } = await loadFixture(deploy);
      const aliceAddress = await alice.getAddress();
      const start = BigInt(await time.latest()) + DAY;

      const fromPolicy = await createLinearPolicy(token, admin, "ABS_UNVEST", {
        anchor: 0,
        start,
        vestDuration: 10n * DAY,
      });
      const toPolicy = await createLinearPolicy(token, admin, "ABS_DST", {
        vestDuration: 2n * YEAR,
      });
      const amount = ethers.parseEther("1000");

      await token.connect(admin).mintAllocations([
        {
          recipient: aliceAddress,
          amount,
          policyId: fromPolicy,
          label: ethers.encodeBytes32String("abs"),
        },
      ]);

      await expect(
        token
          .connect(admin)
          .relinkActiveLock(
            aliceAddress,
            fromPolicy,
            toPolicy,
            ethers.parseEther("100"),
          ),
      ).to.emit(token, "ActiveLockRelinked");
    });

    it("relink rejects an Absolute source policy with vested principal", async function () {
      const { token, admin, alice } = await loadFixture(deploy);
      const aliceAddress = await alice.getAddress();
      const start = BigInt(await time.latest()) + DAY;

      const fromPolicy = await createLinearPolicy(token, admin, "ABS_VEST", {
        anchor: 0,
        start,
        vestDuration: 10n * DAY,
      });
      const toPolicy = await createLinearPolicy(token, admin, "ABS_TO", {
        vestDuration: 2n * YEAR,
      });
      const amount = ethers.parseEther("1000");

      await token.connect(admin).mintAllocations([
        {
          recipient: aliceAddress,
          amount,
          policyId: fromPolicy,
          label: ethers.encodeBytes32String("abs"),
        },
      ]);
      await time.increaseTo(start + 5n * DAY);

      await expect(
        token
          .connect(admin)
          .relinkActiveLock(
            aliceAddress,
            fromPolicy,
            toPolicy,
            ethers.parseEther("100"),
          ),
      )
        .to.be.revertedWithCustomError(token, "RelinkSourceAlreadyVested")
        .withArgs(fromPolicy);
    });

    it("relink reverts after TGE", async function () {
      const { token, admin, alice, ccaEnd } = await loadFixture(deploy);
      const aliceAddress = await alice.getAddress();

      const fromPolicy = await createLinearPolicy(token, admin, "FROM_AFTER", {
        vestDuration: 1n * YEAR,
      });
      const toPolicy = await createLinearPolicy(token, admin, "TO_AFTER", {
        vestDuration: 2n * YEAR,
      });
      const amount = ethers.parseEther("1000");
      await token.connect(admin).mintAllocations([
        {
          recipient: aliceAddress,
          amount,
          policyId: fromPolicy,
          label: ethers.encodeBytes32String("src"),
        },
      ]);

      // Fire TGE.
      const TGE_COOLDOWN = 40n * DAY;
      await time.increaseTo(ccaEnd + TGE_COOLDOWN + 1n);
      await token.tge();

      await expect(
        token
          .connect(admin)
          .relinkActiveLock(
            aliceAddress,
            fromPolicy,
            toPolicy,
            ethers.parseEther("100"),
          ),
      ).to.be.revertedWithCustomError(token, "AlreadyLive");
    });

    it("relink reverts when amount exceeds source lock", async function () {
      const { token, admin, alice } = await loadFixture(deploy);
      const aliceAddress = await alice.getAddress();

      const fromPolicy = await createLinearPolicy(token, admin, "SRC_SMALL", {
        vestDuration: 1n * YEAR,
      });
      const toPolicy = await createLinearPolicy(token, admin, "DST_BIG", {
        vestDuration: 2n * YEAR,
      });
      const amount = ethers.parseEther("100");
      await token.connect(admin).mintAllocations([
        {
          recipient: aliceAddress,
          amount,
          policyId: fromPolicy,
          label: ethers.encodeBytes32String("small"),
        },
      ]);

      await expect(
        token
          .connect(admin)
          .relinkActiveLock(
            aliceAddress,
            fromPolicy,
            toPolicy,
            ethers.parseEther("200"),
          ),
      ).to.be.revertedWithCustomError(token, "RelinkAmountExceeded");
    });

    it("relink from PENDING reverts", async function () {
      const { token, admin, alice } = await loadFixture(deploy);
      const aliceAddress = await alice.getAddress();
      const pendingId = ethers.encodeBytes32String("PENDING");
      const toPolicy = await createLinearPolicy(token, admin, "TO_REAL", {
        vestDuration: 2n * YEAR,
      });

      await expect(
        token
          .connect(admin)
          .relinkActiveLock(
            aliceAddress,
            pendingId,
            toPolicy,
            ethers.parseEther("1"),
          ),
      ).to.be.revertedWithCustomError(token, "InvalidPolicy");
    });

    it("relink to PENDING reverts", async function () {
      const { token, admin, alice } = await loadFixture(deploy);
      const aliceAddress = await alice.getAddress();
      const pendingId = ethers.encodeBytes32String("PENDING");
      const fromPolicy = await createLinearPolicy(token, admin, "FROM_REAL", {
        vestDuration: 1n * YEAR,
      });
      const amount = ethers.parseEther("100");
      await token.connect(admin).mintAllocations([
        {
          recipient: aliceAddress,
          amount,
          policyId: fromPolicy,
          label: ethers.encodeBytes32String("real"),
        },
      ]);

      await expect(
        token
          .connect(admin)
          .relinkActiveLock(
            aliceAddress,
            fromPolicy,
            pendingId,
            ethers.parseEther("50"),
          ),
      ).to.be.revertedWithCustomError(token, "InvalidPolicy");
    });

    it("relink source == target reverts", async function () {
      const { token, admin, alice } = await loadFixture(deploy);
      const aliceAddress = await alice.getAddress();
      const policyId = await createLinearPolicy(token, admin, "SAME_POL", {
        vestDuration: 1n * YEAR,
      });
      const amount = ethers.parseEther("100");
      await token.connect(admin).mintAllocations([
        {
          recipient: aliceAddress,
          amount,
          policyId,
          label: ethers.encodeBytes32String("same"),
        },
      ]);

      await expect(
        token
          .connect(admin)
          .relinkActiveLock(
            aliceAddress,
            policyId,
            policyId,
            ethers.parseEther("50"),
          ),
      ).to.be.revertedWithCustomError(token, "InvalidPolicy");
    });

    it("non-LOCK_MANAGER_ROLE cannot relink", async function () {
      const { token, alice } = await loadFixture(deploy);
      await expect(
        token
          .connect(alice)
          .relinkActiveLock(
            await alice.getAddress(),
            ethers.encodeBytes32String("A"),
            ethers.encodeBytes32String("B"),
            ethers.parseEther("1"),
          ),
      ).to.be.revertedWithCustomError(
        token,
        "AccessControlUnauthorizedAccount",
      );
    });
  });

  // ═════════════════════════════════════════════════════════════════════════
  // BondingRegistry integration (uses deployInterfoldSystem)
  // ═════════════════════════════════════════════════════════════════════════

  describe("BondingRegistry integration", function () {
    async function impersonateSlashingManager(slashingManager: {
      getAddress(): Promise<string>;
    }) {
      const managerAddress = await slashingManager.getAddress();
      await networkHelpers.setBalance(managerAddress, ethers.parseEther("1"));
      await networkHelpers.impersonateAccount(managerAddress);
      return ethers.getSigner(managerAddress);
    }

    it("bonded balance covers aggregate mixed locks without affecting grant accounting", async function () {
      const signers = await ethers.getSigners();
      const [, beneficiary, , operator] = signers;
      const beneficiaryAddress = await beneficiary.getAddress();
      const operatorAddress = await operator.getAddress();
      const sys = await deployInterfoldSystem({
        useMockCiphernodeRegistry: true,
        setupOperators: 0,
        wireSlashingManager: false,
        mintUsdcTo: [],
      });
      const { bondingRegistry, ciphernodeBondToken } = sys;
      const bondingRegistryAddress = await bondingRegistry.getAddress();

      // Alice has a mixed allocation: 200 unlocked grant + 1000 SAFT + 500 CCA.
      const grantAmount = ethers.parseEther("200");
      const saftAmount = ethers.parseEther("1000");
      const ccaAmount = ethers.parseEther("500");
      const totalTokens = grantAmount + saftAmount + ccaAmount;

      // Mint unlocked grant (NOT locked).
      await ciphernodeBondToken.mint(
        beneficiaryAddress,
        grantAmount,
        ethers.encodeBytes32String("grant"),
      );

      // SAFT vested allocation: mintAllocations creates AND locks tokens.
      const saftPolicy = ethers.encodeBytes32String("SAFT_MIX");
      await ciphernodeBondToken.createLockPolicy(saftPolicy, {
        holdUntil: 0n,
        unlock: {
          anchor: 1,
          start: 0n,
          cliffDuration: 0n,
          vestDuration: 2n * YEAR,
        },
      });
      await ciphernodeBondToken.mintAllocations([
        {
          recipient: beneficiaryAddress,
          amount: saftAmount,
          policyId: saftPolicy,
          label: ethers.encodeBytes32String("saft"),
        },
      ]);

      // CCA vested allocation.
      const ccaPolicy = ethers.encodeBytes32String("CCA_MIX");
      await ciphernodeBondToken.createLockPolicy(ccaPolicy, {
        holdUntil: 0n,
        unlock: {
          anchor: 1,
          start: 0n,
          cliffDuration: 0n,
          vestDuration: 1n * YEAR,
        },
      });
      await ciphernodeBondToken.mintAllocations([
        {
          recipient: beneficiaryAddress,
          amount: ccaAmount,
          policyId: ccaPolicy,
          label: ethers.encodeBytes32String("cca"),
        },
      ]);

      // Total tokens: grant(200) + SAFT(1000) + CCA(500) = 1700.

      // Bond 1000.
      const bondAmount = ethers.parseEther("1000");
      await ciphernodeBondToken
        .connect(beneficiary)
        .approve(bondingRegistryAddress, bondAmount);
      await bondingRegistry.connect(operator).setBondOwner(beneficiaryAddress);
      await bondingRegistry
        .connect(beneficiary)
        .bondCiphernodeFor(operatorAddress, bondAmount);

      // Wallet = totalTokens - bondAmount = 1700 - 1000 = 700.
      expect(await ciphernodeBondToken.balanceOf(beneficiaryAddress)).to.equal(
        totalTokens - bondAmount,
      );

      // Locked ≈ SAFT locked + CCA locked ≈ 1500 (Tge-anchored, no time passed).
      const locked =
        await ciphernodeBondToken.lockedBalanceOf(beneficiaryAddress);
      expect(locked).to.be.closeTo(
        saftAmount + ccaAmount,
        ethers.parseEther("0.01"),
      );

      // Bonded = 1000 covers 1000 / 1500 of the lock floor.
      // mustRetain = max(0, locked - bonded) ≈ 500.
      // transferable = max(0, wallet - mustRetain) = 700 - 500 = 200.
      // The grant portion (200) is transferable.
      const tb =
        await ciphernodeBondToken.transferableBalanceOf(beneficiaryAddress);
      expect(tb).to.be.closeTo(grantAmount, ethers.parseEther("0.02"));
    });

    it("transferableBalanceOf counts bonded FOLD toward the locked floor", async function () {
      const signers = await ethers.getSigners();
      const [, beneficiary, , operator] = signers;
      const beneficiaryAddress = await beneficiary.getAddress();
      const operatorAddress = await operator.getAddress();
      const sys = await deployInterfoldSystem({
        useMockCiphernodeRegistry: true,
        setupOperators: 0,
        wireSlashingManager: false,
        mintUsdcTo: [],
      });
      const { bondingRegistry, ciphernodeBondToken } = sys;
      const bondingRegistryAddress = await bondingRegistry.getAddress();
      const totalAmount = ethers.parseEther("1000");
      const bondAmount = ethers.parseEther("800");

      // Mint unlocked tokens and bond some.
      await ciphernodeBondToken.mint(
        beneficiaryAddress,
        totalAmount,
        ethers.encodeBytes32String("test"),
      );
      await ciphernodeBondToken
        .connect(beneficiary)
        .approve(bondingRegistryAddress, bondAmount);
      await bondingRegistry.connect(operator).setBondOwner(beneficiaryAddress);
      await bondingRegistry
        .connect(beneficiary)
        .bondCiphernodeFor(operatorAddress, bondAmount);

      // Wallet balance is totalAmount - bondAmount, bonded = bondAmount.
      // No locks so everything is transferable.
      expect(await ciphernodeBondToken.balanceOf(beneficiaryAddress)).to.equal(
        totalAmount - bondAmount,
      );
      expect(
        await ciphernodeBondToken.transferableBalanceOf(beneficiaryAddress),
      ).to.equal(totalAmount - bondAmount);

      // Now create a lock policy and mint a locked allocation.
      const policyId = ethers.encodeBytes32String("BOND_TEST");
      await ciphernodeBondToken.createLockPolicy(policyId, {
        holdUntil: 0n,
        unlock: {
          anchor: 1,
          start: 0n,
          cliffDuration: 0n,
          vestDuration: 2n * YEAR,
        },
      });
      const lockAmount = ethers.parseEther("400");
      // Mint extra unlocked tokens to fund the lock.
      await ciphernodeBondToken.mint(
        beneficiaryAddress,
        lockAmount,
        ethers.encodeBytes32String("extra"),
      );
      await ciphernodeBondToken.mintAllocations([
        {
          recipient: beneficiaryAddress,
          amount: lockAmount,
          policyId,
          label: ethers.encodeBytes32String("locked"),
        },
      ]);

      // Locked balance ≈ lockAmount (400) — Tge-anchored with tiny vesting.
      // Bonded balance = bondAmount (800).
      // Since bonded > locked, the bond covers all locks.
      // Wallet = totalAmount - bondAmount + lockAmount + lockAmount
      //        = 1000 - 800 + 400 + 400 = 1000.
      // transferable = balance - max(0, locked - bonded) ≈ 1000 - 0 = 1000.
      const tb =
        await ciphernodeBondToken.transferableBalanceOf(beneficiaryAddress);
      expect(tb).to.be.closeTo(
        totalAmount - bondAmount + lockAmount + lockAmount,
        ethers.parseEther("0.01"),
      );
    });

    it("bonding registry transfers are allowed pre-TGE", async function () {
      const sys = await deployInterfoldSystem({
        useMockCiphernodeRegistry: true,
        setupOperators: 0,
        mintUsdcTo: [],
      });
      const { bondingRegistry, ciphernodeBondToken, owner } = sys;
      const bondingRegistryAddress = await bondingRegistry.getAddress();
      const bondAmount = ethers.parseEther("100");
      const [, operator] = await ethers.getSigners();

      await ciphernodeBondToken.mint(
        await owner.getAddress(),
        bondAmount,
        ethers.encodeBytes32String("test"),
      );
      await ciphernodeBondToken
        .connect(owner)
        .approve(bondingRegistryAddress, bondAmount);
      // Bonding transfer should succeed.
      await bondingRegistry
        .connect(operator)
        .setBondOwner(await owner.getAddress());
      await bondingRegistry
        .connect(owner)
        .bondCiphernodeFor(await operator.getAddress(), bondAmount);
    });

    it("locked tokens can be bonded (pre-credit visible to token)", async function () {
      const signers = await ethers.getSigners();
      const [, beneficiary, , operator] = signers;
      const beneficiaryAddress = await beneficiary.getAddress();
      const operatorAddress = await operator.getAddress();
      const sys = await deployInterfoldSystem({
        useMockCiphernodeRegistry: true,
        setupOperators: 0,
        wireSlashingManager: false,
        mintUsdcTo: [],
      });
      const { bondingRegistry, ciphernodeBondToken } = sys;
      const bondingRegistryAddress = await bondingRegistry.getAddress();

      // Create a lock policy and mint locked tokens.
      const policyId = ethers.encodeBytes32String("LOCKED_BOND");
      await ciphernodeBondToken.createLockPolicy(policyId, {
        holdUntil: 0n,
        unlock: {
          anchor: 1, // Tge-anchored
          start: 0n,
          cliffDuration: 0n,
          vestDuration: 2n * YEAR,
        },
      });
      const lockAmount = ethers.parseEther("1000");
      // Mint locked allocation directly (balance = locked).
      await ciphernodeBondToken.mintAllocations([
        {
          recipient: beneficiaryAddress,
          amount: lockAmount,
          policyId,
          label: ethers.encodeBytes32String("locked"),
        },
      ]);

      // Before bonding: balance = 1000, locked ≈ 1000, bonded = 0.
      // transferable ≈ 0 (Tge-anchored, no time has passed).
      const tbBefore =
        await ciphernodeBondToken.transferableBalanceOf(beneficiaryAddress);
      expect(tbBefore).to.be.lt(ethers.parseEther("0.01"));

      // Bond all locked tokens. Should succeed because BondingRegistry
      // pre-credits `operators[beneficiary].ciphernodeBond` before calling
      // `safeTransferFrom`, so the token sees bonded = lockAmount during
      // `_update()`.
      await ciphernodeBondToken
        .connect(beneficiary)
        .approve(bondingRegistryAddress, lockAmount);
      await bondingRegistry.connect(operator).setBondOwner(beneficiaryAddress);
      await bondingRegistry
        .connect(beneficiary)
        .bondCiphernodeFor(operatorAddress, lockAmount);

      // After bonding: wallet = 0, locked ≈ 1000, bonded = 1000.
      // Bond covers lock, so no mustRetain.
      expect(await ciphernodeBondToken.balanceOf(beneficiaryAddress)).to.equal(
        0n,
      );
      expect(await bondingRegistry.totalBonded(beneficiaryAddress)).to.equal(
        lockAmount,
      );
    });

    it("locked tokens can fund a distinct operator key", async function () {
      const signers = await ethers.getSigners();
      const [, beneficiary, operator] = signers;
      const beneficiaryAddress = await beneficiary.getAddress();
      const operatorAddress = await operator.getAddress();
      const sys = await deployInterfoldSystem({
        useMockCiphernodeRegistry: true,
        setupOperators: 0,
        mintUsdcTo: [],
      });
      const { bondingRegistry, ciphernodeBondToken } = sys;
      const bondingRegistryAddress = await bondingRegistry.getAddress();

      const policyId = ethers.encodeBytes32String("DELEGATED_LOCKED_BOND");
      await ciphernodeBondToken.createLockPolicy(policyId, {
        holdUntil: 0n,
        unlock: {
          anchor: 1,
          start: 0n,
          cliffDuration: 0n,
          vestDuration: 2n * YEAR,
        },
      });
      const lockAmount = ethers.parseEther("1000");
      await ciphernodeBondToken.mintAllocations([
        {
          recipient: beneficiaryAddress,
          amount: lockAmount,
          policyId,
          label: ethers.encodeBytes32String("delegated locked"),
        },
      ]);

      await bondingRegistry.connect(operator).setBondOwner(beneficiaryAddress);
      await ciphernodeBondToken
        .connect(beneficiary)
        .approve(bondingRegistryAddress, lockAmount);
      await bondingRegistry
        .connect(beneficiary)
        .bondCiphernodeFor(operatorAddress, lockAmount);

      expect(await ciphernodeBondToken.balanceOf(beneficiaryAddress)).to.equal(
        0n,
      );
      expect(await bondingRegistry.totalBonded(beneficiaryAddress)).to.equal(
        lockAmount,
      );
      expect(await bondingRegistry.totalBonded(operatorAddress)).to.equal(0n);
      expect(await bondingRegistry.getCiphernodeBond(operatorAddress)).to.equal(
        lockAmount,
      );
    });

    it("blocks bond-owner rotation that would detach locked FOLD", async function () {
      const signers = await ethers.getSigners();
      const [, beneficiary, newOwner, operator] = signers;
      const beneficiaryAddress = await beneficiary.getAddress();
      const newOwnerAddress = await newOwner.getAddress();
      const operatorAddress = await operator.getAddress();
      const sys = await deployInterfoldSystem({
        useMockCiphernodeRegistry: true,
        setupOperators: 0,
        mintUsdcTo: [],
      });
      const { bondingRegistry, ciphernodeBondToken } = sys;
      const bondingRegistryAddress = await bondingRegistry.getAddress();

      const policyId = ethers.encodeBytes32String("ROTATION_LOCK");
      await ciphernodeBondToken.createLockPolicy(policyId, {
        holdUntil: 0n,
        unlock: {
          anchor: 1,
          start: 0n,
          cliffDuration: 0n,
          vestDuration: 2n * YEAR,
        },
      });
      const lockAmount = ethers.parseEther("1000");
      await ciphernodeBondToken.mintAllocations([
        {
          recipient: beneficiaryAddress,
          amount: lockAmount,
          policyId,
          label: ethers.encodeBytes32String("rotation locked"),
        },
      ]);

      await bondingRegistry.connect(operator).setBondOwner(beneficiaryAddress);
      await ciphernodeBondToken
        .connect(beneficiary)
        .approve(bondingRegistryAddress, lockAmount);
      await bondingRegistry
        .connect(beneficiary)
        .bondCiphernodeFor(operatorAddress, lockAmount);
      await bondingRegistry
        .connect(beneficiary)
        .proposeBondOwner(operatorAddress, newOwnerAddress);

      await expect(
        bondingRegistry.connect(newOwner).acceptBondOwner(operatorAddress),
      )
        .to.be.revertedWithCustomError(
          bondingRegistry,
          "BondOwnerTransferViolatesLock",
        )
        .withArgs(beneficiaryAddress, lockAmount, 0);

      expect(await bondingRegistry.bondOwnerOf(operatorAddress)).to.equal(
        beneficiaryAddress,
      );
      expect(await bondingRegistry.totalBonded(beneficiaryAddress)).to.equal(
        lockAmount,
      );
      expect(await bondingRegistry.totalBonded(newOwnerAddress)).to.equal(0);

      await bondingRegistry
        .connect(beneficiary)
        .unbondCiphernodeFor(operatorAddress, lockAmount);
      await time.increase(Number(await bondingRegistry.exitDelay()) + 1);
      await bondingRegistry
        .connect(beneficiary)
        .claimExitsFor(operatorAddress, 0, lockAmount);

      await expect(
        bondingRegistry.connect(newOwner).acceptBondOwner(operatorAddress),
      )
        .to.emit(bondingRegistry, "BondOwnerSet")
        .withArgs(operatorAddress, newOwnerAddress);
      expect(await ciphernodeBondToken.balanceOf(beneficiaryAddress)).to.equal(
        lockAmount,
      );
      expect(
        await ciphernodeBondToken.transferableBalanceOf(beneficiaryAddress),
      ).to.equal(0);
    });

    it("after bonding locked tokens, cannot transfer below locked floor", async function () {
      const signers = await ethers.getSigners();
      const [, beneficiary, , operator] = signers;
      const beneficiaryAddress = await beneficiary.getAddress();
      const operatorAddress = await operator.getAddress();
      const sys = await deployInterfoldSystem({
        useMockCiphernodeRegistry: true,
        setupOperators: 0,
        wireSlashingManager: false,
        mintUsdcTo: [],
      });
      const { bondingRegistry, ciphernodeBondToken } = sys;
      const bondingRegistryAddress = await bondingRegistry.getAddress();

      const policyId = ethers.encodeBytes32String("LOCKED_FLOOR");
      await ciphernodeBondToken.createLockPolicy(policyId, {
        holdUntil: 0n,
        unlock: {
          anchor: 1,
          start: 0n,
          cliffDuration: 0n,
          vestDuration: 2n * YEAR,
        },
      });
      const lockAmount = ethers.parseEther("1000");
      await ciphernodeBondToken.mintAllocations([
        {
          recipient: beneficiaryAddress,
          amount: lockAmount,
          policyId,
          label: ethers.encodeBytes32String("locked"),
        },
      ]);

      // Bond 600 out of 1000 locked.
      const bondAmount = ethers.parseEther("600");
      await ciphernodeBondToken
        .connect(beneficiary)
        .approve(bondingRegistryAddress, bondAmount);
      await bondingRegistry.connect(operator).setBondOwner(beneficiaryAddress);
      await bondingRegistry
        .connect(beneficiary)
        .bondCiphernodeFor(operatorAddress, bondAmount);

      // Wallet = 400, locked ≈ 1000, bonded = 600.
      // mustRetain = max(0, 1000 - 600) = 400.
      // transferable = max(0, 400 - 400) = 0.
      const tb =
        await ciphernodeBondToken.transferableBalanceOf(beneficiaryAddress);
      expect(tb).to.equal(0n);
    });

    it("slashing does not reduce locked balance", async function () {
      const signers = await ethers.getSigners();
      const [, beneficiary, , operator] = signers;
      const beneficiaryAddress = await beneficiary.getAddress();
      const operatorAddress = await operator.getAddress();
      const sys = await deployInterfoldSystem({
        useMockCiphernodeRegistry: true,
        setupOperators: 0,
        wireSlashingManager: false,
        mintUsdcTo: [],
      });
      const { bondingRegistry, ciphernodeBondToken, slashingManager } = sys;
      const bondingRegistryAddress = await bondingRegistry.getAddress();

      const policyId = ethers.encodeBytes32String("SLASH_LOCK");
      await ciphernodeBondToken.createLockPolicy(policyId, {
        holdUntil: 0n,
        unlock: {
          anchor: 1,
          start: 0n,
          cliffDuration: 0n,
          vestDuration: 2n * YEAR,
        },
      });
      const lockAmount = ethers.parseEther("1000");
      await ciphernodeBondToken.mintAllocations([
        {
          recipient: beneficiaryAddress,
          amount: lockAmount,
          policyId,
          label: ethers.encodeBytes32String("locked"),
        },
      ]);

      // Bond everything.
      await ciphernodeBondToken
        .connect(beneficiary)
        .approve(bondingRegistryAddress, lockAmount);
      await bondingRegistry.connect(operator).setBondOwner(beneficiaryAddress);
      await bondingRegistry
        .connect(beneficiary)
        .bondCiphernodeFor(operatorAddress, lockAmount);

      const lockedBefore =
        await ciphernodeBondToken.lockedBalanceOf(beneficiaryAddress);
      expect(lockedBefore).to.be.closeTo(lockAmount, ethers.parseEther("0.01"));

      // Slash 500 ciphernode bond.
      const slashAmount = ethers.parseEther("500");
      const slashSigner = await impersonateSlashingManager(slashingManager);
      await bondingRegistry
        .connect(slashSigner)
        .slashCiphernodeBond(
          operatorAddress,
          slashAmount,
          ethers.encodeBytes32String("SLASH"),
        );
      await networkHelpers.stopImpersonatingAccount(
        await slashingManager.getAddress(),
      );

      // Bonded is now 500.
      expect(await bondingRegistry.totalBonded(beneficiaryAddress)).to.equal(
        lockAmount - slashAmount,
      );

      // Locked balance must NOT change due to slashing.
      const lockedAfter =
        await ciphernodeBondToken.lockedBalanceOf(beneficiaryAddress);
      expect(lockedAfter).to.equal(lockedBefore);
    });

    it("after slashing, incoming tokens are retained by lock-floor invariant", async function () {
      const signers = await ethers.getSigners();
      const [, beneficiary, , operator] = signers;
      const beneficiaryAddress = await beneficiary.getAddress();
      const operatorAddress = await operator.getAddress();
      const sys = await deployInterfoldSystem({
        useMockCiphernodeRegistry: true,
        setupOperators: 0,
        wireSlashingManager: false,
        mintUsdcTo: [],
      });
      const { bondingRegistry, ciphernodeBondToken, owner, slashingManager } =
        sys;
      const bondingRegistryAddress = await bondingRegistry.getAddress();

      const policyId = ethers.encodeBytes32String("SLASH_FLOOR");
      await ciphernodeBondToken.createLockPolicy(policyId, {
        holdUntil: 0n,
        unlock: {
          anchor: 1,
          start: 0n,
          cliffDuration: 0n,
          vestDuration: 2n * YEAR,
        },
      });
      const lockAmount = ethers.parseEther("1000");
      await ciphernodeBondToken.mintAllocations([
        {
          recipient: beneficiaryAddress,
          amount: lockAmount,
          policyId,
          label: ethers.encodeBytes32String("locked"),
        },
      ]);

      // Bond everything, then slash half.
      await ciphernodeBondToken
        .connect(beneficiary)
        .approve(bondingRegistryAddress, lockAmount);
      await bondingRegistry.connect(operator).setBondOwner(beneficiaryAddress);
      await bondingRegistry
        .connect(beneficiary)
        .bondCiphernodeFor(operatorAddress, lockAmount);
      const slashAmount = ethers.parseEther("500");
      const slashSigner = await impersonateSlashingManager(slashingManager);
      await bondingRegistry
        .connect(slashSigner)
        .slashCiphernodeBond(
          operatorAddress,
          slashAmount,
          ethers.encodeBytes32String("SLASH"),
        );
      await networkHelpers.stopImpersonatingAccount(
        await slashingManager.getAddress(),
      );

      // Now: wallet = 0, locked ≈ 1000, bonded = 500.
      // mustRetain = 1000 - 500 = 500. Wallet is 500 below floor.
      expect(
        await ciphernodeBondToken.transferableBalanceOf(beneficiaryAddress),
      ).to.equal(0n);

      // Send 200 unlocked tokens to beneficiary. They should be retained
      // (non-transferable) because wallet is still below floor.
      await ciphernodeBondToken
        .connect(owner)
        .mint(beneficiaryAddress, ethers.parseEther("200"), ethers.ZeroHash);
      expect(await ciphernodeBondToken.balanceOf(beneficiaryAddress)).to.equal(
        ethers.parseEther("200"),
      );
      expect(
        await ciphernodeBondToken.transferableBalanceOf(beneficiaryAddress),
      ).to.equal(0n);

      // Send enough to fill the floor gap (300 more = 500 total).
      await ciphernodeBondToken
        .connect(owner)
        .mint(beneficiaryAddress, ethers.parseEther("300"), ethers.ZeroHash);
      expect(await ciphernodeBondToken.balanceOf(beneficiaryAddress)).to.equal(
        ethers.parseEther("500"),
      );
      // Now wallet = 500, locked ≈ 1000, bonded = 500 → transferable = 0.
      expect(
        await ciphernodeBondToken.transferableBalanceOf(beneficiaryAddress),
      ).to.equal(0n);

      // Send one more wei above the floor.
      await ciphernodeBondToken
        .connect(owner)
        .mint(beneficiaryAddress, 1n, ethers.ZeroHash);
      // Now wallet = 500 + 1, mustRetain = 500 → transferable = 1.
      expect(
        await ciphernodeBondToken.transferableBalanceOf(beneficiaryAddress),
      ).to.equal(1n);
    });
  });

  // ═════════════════════════════════════════════════════════════════════════
  // Ownership
  // ═════════════════════════════════════════════════════════════════════════

  describe("ownership", function () {
    it("renounceOwnership is disabled", async function () {
      const { token, admin } = await loadFixture(deploy);
      await expect(
        token.connect(admin).renounceOwnership(),
      ).to.be.revertedWithCustomError(token, "RenounceOwnershipDisabled");
    });

    it("owner cannot renounce AccessControl roles directly", async function () {
      const { token, admin } = await loadFixture(deploy);
      const adminAddress = await admin.getAddress();

      await expect(
        token
          .connect(admin)
          .renounceRole(await token.DEFAULT_ADMIN_ROLE(), adminAddress),
      ).to.be.revertedWithCustomError(token, "RenounceRoleDisabledForOwner");
    });

    it("non-owner role holders can still renounce roles", async function () {
      const { token, admin, alice } = await loadFixture(deploy);
      const aliceAddress = await alice.getAddress();
      const minterRole = await token.MINTER_ROLE();

      await token.connect(admin).grantRole(minterRole, aliceAddress);
      expect(await token.hasRole(minterRole, aliceAddress)).to.be.true;

      await token.connect(alice).renounceRole(minterRole, aliceAddress);

      expect(await token.hasRole(minterRole, aliceAddress)).to.be.false;
    });

    it("ownership transfer syncs AccessControl roles", async function () {
      const { token, admin, alice } = await loadFixture(deploy);
      const adminAddress = await admin.getAddress();
      const aliceAddress = await alice.getAddress();

      // Transfer ownership to alice via 2-step.
      await token.connect(admin).transferOwnership(aliceAddress);
      await token.connect(alice).acceptOwnership();

      // Old owner loses all roles.
      expect(
        await token.hasRole(await token.DEFAULT_ADMIN_ROLE(), adminAddress),
      ).to.be.false;
      expect(await token.hasRole(await token.MINTER_ROLE(), adminAddress)).to.be
        .false;
      expect(await token.hasRole(await token.WHITELIST_ROLE(), adminAddress)).to
        .be.false;
      expect(await token.hasRole(await token.LOCK_MANAGER_ROLE(), adminAddress))
        .to.be.false;

      // New owner gains all roles.
      expect(
        await token.hasRole(await token.DEFAULT_ADMIN_ROLE(), aliceAddress),
      ).to.be.true;
      expect(await token.hasRole(await token.MINTER_ROLE(), aliceAddress)).to.be
        .true;
      expect(await token.hasRole(await token.WHITELIST_ROLE(), aliceAddress)).to
        .be.true;
      expect(await token.hasRole(await token.LOCK_MANAGER_ROLE(), aliceAddress))
        .to.be.true;
    });
  });

  // ═════════════════════════════════════════════════════════════════════════
  // EIP-6372
  // ═════════════════════════════════════════════════════════════════════════

  describe("EIP-6372", function () {
    it("clock() returns block.timestamp and CLOCK_MODE() is mode=timestamp", async function () {
      const { token } = await loadFixture(deploy);
      expect(await token.clock()).to.equal(await time.latest());
      expect(await token.CLOCK_MODE()).to.equal("mode=timestamp");
    });
  });
});
