// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
import { expect } from "chai";

import {
  SEVEN_DAYS,
  deployInterfoldSystem,
  ethers,
  networkHelpers,
  setBondingAssetConfig,
} from "../fixtures";

const { loadFixture, time } = networkHelpers;

/// Bonded FOLD is transferred to `BondingRegistry`, which never delegates it. Under ERC20Votes an
/// undelegated balance carries no voting power, so an operator forfeits that weight entirely —
/// while the bonded tokens still count in `getPastTotalSupply` and so raise the quorum
/// denominator they cannot help meet.
///
/// `BondedCheckpoints` records bonded totals over time and `BondedVotes` sums both sources at the
/// same timepoint. These tests cover what an operator's voting power is across the bonding
/// lifecycle: bonded, unbonded, mid-exit, slashed, transferred, and delegated.
describe("BondedVotes", function () {
  this.timeout(120000);

  const BOND = ethers.parseEther("1000");
  const MINTED = ethers.parseEther("100000");

  async function setup() {
    const [, operatorKey, bondOwner, otherHolder, newOwner] =
      await ethers.getSigners();

    const sys = await deployInterfoldSystem({
      useMockCiphernodeRegistry: true,
      setupOperators: 0,
      wireSlashingManager: false,
      mintUsdcTo: [],
    });
    const { bondingRegistry, ciphernodeBondToken, slashingManager } = sys;

    const bondOwnerAddress = await bondOwner.getAddress();
    const operatorAddress = await operatorKey.getAddress();
    const otherHolderAddress = await otherHolder.getAddress();
    const newOwnerAddress = await newOwner.getAddress();
    const registryAddress = await bondingRegistry.getAddress();

    for (const who of [bondOwnerAddress, otherHolderAddress, newOwnerAddress]) {
      await ciphernodeBondToken.mint(
        who,
        MINTED,
        ethers.encodeBytes32String("Test allocation"),
      );
    }
    await bondingRegistry.connect(operatorKey).setBondOwner(bondOwnerAddress);

    // Self-delegate, or the wallet half of the sum is zero and nothing is being measured.
    await ciphernodeBondToken.connect(bondOwner).delegate(bondOwnerAddress);
    await ciphernodeBondToken.connect(otherHolder).delegate(otherHolderAddress);
    await ciphernodeBondToken.connect(newOwner).delegate(newOwnerAddress);

    const checkpoints = await ethers.deployContract("BondedCheckpoints", [
      registryAddress,
    ]);
    await bondingRegistry.setBondedCheckpoints(await checkpoints.getAddress());

    const bondedVotes = await ethers.deployContract("BondedVotes", [
      await ciphernodeBondToken.getAddress(),
      // Votes source == the token: wallet-held FOLD votes, the original behaviour.
      await ciphernodeBondToken.getAddress(),
      await checkpoints.getAddress(),
    ]);

    const bond = async (amount: bigint) => {
      await ciphernodeBondToken
        .connect(bondOwner)
        .approve(registryAddress, amount);
      await bondingRegistry
        .connect(bondOwner)
        .bondCiphernodeFor(operatorAddress, amount);
    };

    const unbond = (amount: bigint) =>
      bondingRegistry
        .connect(bondOwner)
        .unbondCiphernodeFor(operatorAddress, amount);

    const claim = (amount: bigint) =>
      bondingRegistry
        .connect(bondOwner)
        .claimExitsFor(operatorAddress, 0, amount);

    const slash = async (amount: bigint) => {
      const managerAddress = await slashingManager.getAddress();
      await networkHelpers.setBalance(managerAddress, ethers.parseEther("1"));
      await networkHelpers.impersonateAccount(managerAddress);
      const signer = await ethers.getSigner(managerAddress);
      await bondingRegistry
        .connect(signer)
        .slashCiphernodeBond(
          operatorAddress,
          amount,
          ethers.encodeBytes32String("TEST_SLASH"),
        );
      await networkHelpers.stopImpersonatingAccount(managerAddress);
    };

    /// Advance one second and read at the last settled timepoint. Every read goes through here so
    /// no test accidentally asks about a timepoint that has not settled.
    const settledVotes = async (who: string) => {
      await time.increase(1);
      return bondedVotes.getPastVotes(who, (await time.latest()) - 1);
    };

    return {
      bondingRegistry,
      ciphernodeBondToken,
      checkpoints,
      bondedVotes,
      bondOwner,
      bondOwnerAddress,
      operatorKey,
      operatorAddress,
      otherHolder,
      otherHolderAddress,
      newOwner,
      newOwnerAddress,
      registryAddress,
      bond,
      unbond,
      claim,
      slash,
      settledVotes,
    };
  }

  describe("holders who never bond", function () {
    it("counts wallet FOLD exactly as the token does", async function () {
      const { ciphernodeBondToken, otherHolderAddress, settledVotes } =
        await loadFixture(setup);

      expect(await settledVotes(otherHolderAddress)).to.equal(MINTED);
      expect(
        await ciphernodeBondToken.getPastVotes(
          otherHolderAddress,
          (await time.latest()) - 1,
        ),
      ).to.equal(MINTED);
    });

    it("gives an address that holds nothing no power", async function () {
      const { settledVotes } = await loadFixture(setup);

      expect(await settledVotes(ethers.ZeroAddress)).to.equal(0n);
    });
  });

  describe("bonding", function () {
    it("keeps an operator's total power unchanged when it bonds", async function () {
      const {
        bondedVotes,
        ciphernodeBondToken,
        bondOwnerAddress,
        bond,
        settledVotes,
      } = await loadFixture(setup);

      expect(await settledVotes(bondOwnerAddress)).to.equal(MINTED);

      await bond(BOND);

      // The whole point: bonding moves weight from wallet to bond, it does not destroy it.
      expect(await settledVotes(bondOwnerAddress)).to.equal(MINTED);

      const at = (await time.latest()) - 1;
      expect(
        await ciphernodeBondToken.getPastVotes(bondOwnerAddress, at),
      ).to.equal(MINTED - BOND);
      expect(await bondedVotes.getPastVotes(bondOwnerAddress, at)).to.equal(
        MINTED,
      );
    });

    it("counts an owner whose FOLD is entirely bonded", async function () {
      const { ciphernodeBondToken, bondOwnerAddress, bond, settledVotes } =
        await loadFixture(setup);

      await bond(MINTED);

      expect(await settledVotes(bondOwnerAddress)).to.equal(MINTED);
      expect(
        await ciphernodeBondToken.getPastVotes(
          bondOwnerAddress,
          (await time.latest()) - 1,
        ),
      ).to.equal(0n);
    });

    it("adds up across several bonds", async function () {
      const { bondOwnerAddress, bond, settledVotes } = await loadFixture(setup);

      await bond(BOND);
      await bond(BOND);
      await bond(BOND);

      expect(await settledVotes(bondOwnerAddress)).to.equal(MINTED);
    });
  });

  describe("unbonding and exit", function () {
    /// Unbonding queues the bond for exit. The FOLD is still held by the registry, so the weight
    /// stays with the owner — counting it as wallet FOLD as well would double it.
    it("keeps power while the bond sits in the exit queue", async function () {
      const { checkpoints, bondOwnerAddress, bond, unbond, settledVotes } =
        await loadFixture(setup);

      await bond(BOND);
      await unbond(BOND);

      expect(await settledVotes(bondOwnerAddress)).to.equal(MINTED);
      expect(
        await checkpoints.getPastBonded(
          bondOwnerAddress,
          (await time.latest()) - 1,
        ),
      ).to.equal(BOND);
    });

    it("moves power back to the wallet once the exit is claimed", async function () {
      const {
        checkpoints,
        ciphernodeBondToken,
        bondOwnerAddress,
        bond,
        unbond,
        claim,
        settledVotes,
      } = await loadFixture(setup);

      await bond(BOND);
      await unbond(BOND);
      await time.increase(SEVEN_DAYS + 1);
      await claim(BOND);

      // Unchanged throughout: the FOLD only ever moved between wallet and registry.
      expect(await settledVotes(bondOwnerAddress)).to.equal(MINTED);

      const at = (await time.latest()) - 1;
      expect(await checkpoints.getPastBonded(bondOwnerAddress, at)).to.equal(
        0n,
      );
      expect(
        await ciphernodeBondToken.getPastVotes(bondOwnerAddress, at),
      ).to.equal(MINTED);
    });
  });

  describe("slashing", function () {
    it("reduces power by the slashed amount", async function () {
      const { checkpoints, bondOwnerAddress, bond, slash, settledVotes } =
        await loadFixture(setup);

      await bond(BOND);
      const slashAmount = BOND / 4n;
      await slash(slashAmount);

      // Slashed FOLD is gone from the owner's control, so its weight goes with it.
      expect(await settledVotes(bondOwnerAddress)).to.equal(
        MINTED - slashAmount,
      );
      expect(
        await checkpoints.getPastBonded(
          bondOwnerAddress,
          (await time.latest()) - 1,
        ),
      ).to.equal(BOND - slashAmount);
    });
  });

  describe("history", function () {
    /// A vote reads power at a snapshot. Bonding after that snapshot must not change the answer,
    /// or an owner could hold FOLD at the snapshot, bond it afterwards, and be counted twice.
    it("does not let a later bond change an earlier answer", async function () {
      const { bondedVotes, bondOwnerAddress, bond } = await loadFixture(setup);

      await time.increase(1);
      const snapshot = (await time.latest()) - 1;
      const before = await bondedVotes.getPastVotes(bondOwnerAddress, snapshot);

      await bond(BOND);
      await time.increase(1);

      expect(
        await bondedVotes.getPastVotes(bondOwnerAddress, snapshot),
      ).to.equal(before);
    });

    it("answers each timepoint with the bond held at the time", async function () {
      const { checkpoints, bondOwnerAddress, bond } = await loadFixture(setup);

      await bond(BOND);
      await time.increase(1);
      const afterFirst = (await time.latest()) - 1;

      await bond(BOND);
      await time.increase(1);
      const afterSecond = (await time.latest()) - 1;

      expect(
        await checkpoints.getPastBonded(bondOwnerAddress, afterFirst),
      ).to.equal(BOND);
      expect(
        await checkpoints.getPastBonded(bondOwnerAddress, afterSecond),
      ).to.equal(BOND * 2n);
    });

    it("reports nothing bonded before the first bond", async function () {
      const { checkpoints, bondOwnerAddress } = await loadFixture(setup);

      await time.increase(1);
      expect(
        await checkpoints.getPastBonded(
          bondOwnerAddress,
          (await time.latest()) - 1,
        ),
      ).to.equal(0n);
    });

    it("rejects a timepoint that has not settled", async function () {
      const { checkpoints, bondOwnerAddress } = await loadFixture(setup);

      await expect(
        checkpoints.getPastBonded(bondOwnerAddress, await checkpoints.clock()),
      ).to.be.revertedWithCustomError(checkpoints, "FutureLookup");
    });

    it("reports timestamps as its clock", async function () {
      const { checkpoints } = await loadFixture(setup);

      // Must match InterfoldToken, or the adapter sums two unrelated points in time.
      expect(await checkpoints.CLOCK_MODE()).to.equal("mode=timestamp");
      expect(await checkpoints.clock()).to.equal(await time.latest());
    });

    /// The invariant that catches a mutation site nobody remembered to checkpoint. The history
    /// mirrors `totalBonded` rather than replaying deltas, so a missed site shows up here rather
    /// than as silently wrong voting weight later.
    it("keeps the history equal to the live total across the whole lifecycle", async function () {
      const {
        bondingRegistry,
        checkpoints,
        bondOwnerAddress,
        bond,
        unbond,
        claim,
        slash,
      } = await loadFixture(setup);

      const assertInSync = async (label: string) => {
        await time.increase(1);
        expect(
          await checkpoints.getPastBonded(
            bondOwnerAddress,
            (await time.latest()) - 1,
          ),
          `checkpoint drifted from totalBonded after ${label}`,
        ).to.equal(await bondingRegistry.totalBonded(bondOwnerAddress));
      };

      await bond(BOND);
      await assertInSync("bond");
      await bond(BOND);
      await assertInSync("second bond");
      await slash(BOND / 2n);
      await assertInSync("slash");
      await unbond(BOND);
      await assertInSync("unbond");
      await time.increase(SEVEN_DAYS + 1);
      await claim(BOND);
      await assertInSync("claim");
    });
  });

  describe("bond-owner transfer", function () {
    it("moves bonded power to the new owner", async function () {
      const {
        bondingRegistry,
        checkpoints,
        bondOwner,
        bondOwnerAddress,
        operatorAddress,
        newOwner,
        newOwnerAddress,
        bond,
        settledVotes,
      } = await loadFixture(setup);

      await bond(BOND);
      await bondingRegistry
        .connect(bondOwner)
        .proposeBondOwner(operatorAddress, newOwnerAddress);
      await bondingRegistry.connect(newOwner).acceptBondOwner(operatorAddress);

      await time.increase(1);
      const at = (await time.latest()) - 1;

      // Both histories move together. Checkpointing only the receiver would leave the previous
      // owner voting with weight it no longer holds.
      expect(await checkpoints.getPastBonded(bondOwnerAddress, at)).to.equal(
        0n,
      );
      expect(await checkpoints.getPastBonded(newOwnerAddress, at)).to.equal(
        BOND,
      );

      expect(await settledVotes(bondOwnerAddress)).to.equal(MINTED - BOND);
      expect(await settledVotes(newOwnerAddress)).to.equal(MINTED + BOND);
    });
  });

  describe("delegation", function () {
    /// Wallet FOLD follows the token's delegation. Bonded FOLD cannot be delegated — the registry
    /// holds it — so it stays with the bond owner regardless.
    it("sends wallet weight to the delegate but keeps bonded weight", async function () {
      const {
        ciphernodeBondToken,
        bondOwner,
        bondOwnerAddress,
        otherHolderAddress,
        bond,
        settledVotes,
      } = await loadFixture(setup);

      await bond(BOND);
      await ciphernodeBondToken.connect(bondOwner).delegate(otherHolderAddress);

      expect(await settledVotes(bondOwnerAddress)).to.equal(BOND);
      expect(await settledVotes(otherHolderAddress)).to.equal(
        MINTED + (MINTED - BOND),
      );
    });

    /// Worth pinning: an owner who never self-delegated still gets its bonded weight, because
    /// that weight never passes through the token's delegation at all.
    it("counts bonded weight for an owner that never self-delegated", async function () {
      const {
        ciphernodeBondToken,
        bondOwner,
        bondOwnerAddress,
        bond,
        settledVotes,
      } = await loadFixture(setup);

      await bond(BOND);
      await ciphernodeBondToken.connect(bondOwner).delegate(ethers.ZeroAddress);

      expect(await settledVotes(bondOwnerAddress)).to.equal(BOND);
    });

    it("refuses to delegate through the adapter", async function () {
      const { bondedVotes, bondOwnerAddress } = await loadFixture(setup);

      // Reverting stops a caller believing it moved weight that never moved.
      await expect(
        bondedVotes.delegate(bondOwnerAddress),
      ).to.be.revertedWithCustomError(bondedVotes, "DelegationNotSupported");
    });
  });

  describe("total supply", function () {
    /// Bonded FOLD was transferred, not burned, so it is already in the supply. Adding it again
    /// would inflate every quorum denominator — the opposite of the problem being fixed.
    it("passes total supply through unchanged while bonded", async function () {
      const { bondedVotes, ciphernodeBondToken, bond } =
        await loadFixture(setup);

      const before = await ciphernodeBondToken.totalSupply();
      await bond(BOND);
      await time.increase(1);

      const at = (await time.latest()) - 1;
      expect(await bondedVotes.getPastTotalSupply(at)).to.equal(before);
      expect(await bondedVotes.getPastTotalSupply(at)).to.equal(
        await ciphernodeBondToken.getPastTotalSupply(at),
      );
    });

    /// Quorum is a fraction of supply, so summed power must never exceed it — counting the same
    /// FOLD twice is the failure this whole design exists to avoid.
    it("never lets summed power exceed total supply", async function () {
      const {
        bondedVotes,
        ciphernodeBondToken,
        bondOwnerAddress,
        otherHolderAddress,
        newOwnerAddress,
        bond,
      } = await loadFixture(setup);

      await bond(BOND);
      await time.increase(1);
      const at = (await time.latest()) - 1;

      const summed =
        (await bondedVotes.getPastVotes(bondOwnerAddress, at)) +
        (await bondedVotes.getPastVotes(otherHolderAddress, at)) +
        (await bondedVotes.getPastVotes(newOwnerAddress, at));

      expect(summed).to.be.lessThanOrEqual(
        await ciphernodeBondToken.getPastTotalSupply(at),
      );
    });
  });

  describe("current voting power", function () {
    /// `getVotes` must read both halves at the same instant. Pairing a current wallet balance
    /// with a timepoint-behind bonded read would leave the bonded half stale after a claim in the
    /// same block, and the sum could exceed what the owner actually holds.
    it("reflects a claim in the same block", async function () {
      const { bondedVotes, bondOwnerAddress, bond, unbond, claim } =
        await loadFixture(setup);

      await bond(BOND);
      await unbond(BOND);
      await time.increase(SEVEN_DAYS + 1);
      await claim(BOND);

      // Read immediately, without advancing time.
      expect(await bondedVotes.getVotes(bondOwnerAddress)).to.equal(MINTED);
    });

    it("reflects a slash in the same block", async function () {
      const { bondedVotes, bondOwnerAddress, bond, slash } =
        await loadFixture(setup);

      await bond(BOND);
      const slashAmount = BOND / 4n;
      await slash(slashAmount);

      expect(await bondedVotes.getVotes(bondOwnerAddress)).to.equal(
        MINTED - slashAmount,
      );
    });

    it("agrees with the historical read once the timepoint settles", async function () {
      const { bondedVotes, bondOwnerAddress, bond } = await loadFixture(setup);

      await bond(BOND);
      const now = await bondedVotes.getVotes(bondOwnerAddress);

      await time.increase(1);
      expect(
        await bondedVotes.getPastVotes(
          bondOwnerAddress,
          (await time.latest()) - 1,
        ),
      ).to.equal(now);
    });
  });

  describe("history predating configuration", function () {
    /// The sync is a no-op while `bondedCheckpoints` is unset, so an owner that bonded before
    /// configuration has no history until its next mutation. `resyncBondedCheckpoint` repairs
    /// that without waiting for one.
    it("records an owner that bonded before the checkpoint contract existed", async function () {
      const [, operatorKey, bondOwner] = await ethers.getSigners();

      const sys = await deployInterfoldSystem({
        useMockCiphernodeRegistry: true,
        setupOperators: 0,
        wireSlashingManager: false,
        mintUsdcTo: [],
      });
      const { bondingRegistry, ciphernodeBondToken } = sys;

      const bondOwnerAddress = await bondOwner.getAddress();
      const operatorAddress = await operatorKey.getAddress();
      const registryAddress = await bondingRegistry.getAddress();

      await ciphernodeBondToken.mint(
        bondOwnerAddress,
        MINTED,
        ethers.encodeBytes32String("Test allocation"),
      );
      await bondingRegistry.connect(operatorKey).setBondOwner(bondOwnerAddress);

      // Bond first, with no checkpoint contract configured.
      await ciphernodeBondToken
        .connect(bondOwner)
        .approve(registryAddress, BOND);
      await bondingRegistry
        .connect(bondOwner)
        .bondCiphernodeFor(operatorAddress, BOND);

      const checkpoints = await ethers.deployContract("BondedCheckpoints", [
        registryAddress,
      ]);
      await bondingRegistry.setBondedCheckpoints(
        await checkpoints.getAddress(),
      );

      // Configuration alone backfills nothing.
      expect(await checkpoints.bonded(bondOwnerAddress)).to.equal(0n);

      // Permissionless: a third party can repair an owner's history.
      await bondingRegistry
        .connect(operatorKey)
        .resyncBondedCheckpoint(bondOwnerAddress);

      expect(await checkpoints.bonded(bondOwnerAddress)).to.equal(BOND);
      expect(await bondingRegistry.totalBonded(bondOwnerAddress)).to.equal(
        BOND,
      );
    });

    it("is idempotent", async function () {
      const { bondingRegistry, checkpoints, bondOwnerAddress, bond } =
        await loadFixture(setup);

      await bond(BOND);
      await bondingRegistry.resyncBondedCheckpoint(bondOwnerAddress);
      await bondingRegistry.resyncBondedCheckpoint(bondOwnerAddress);

      // It can only ever write the true current total, so repeating it changes nothing.
      expect(await checkpoints.bonded(bondOwnerAddress)).to.equal(BOND);
    });
  });

  /// Aragon's `TokenVotingSetup` and the CRISP fork of it decide what a voting token is by probing
  /// it, not by asking for an ERC-165 answer. These reproduce those exact probes, so the adapter
  /// cannot drift out of installability without a test failing.
  describe("Aragon plugin compatibility", function () {
    /// `TokenVotingSetup._isERC20` staticcalls `balanceOf(address)` and rejects the token unless it
    /// returns 32 bytes. Failing this reverts installation with `TokenNotERC20`.
    it("passes the ERC-20 probe the plugin setup gates installation on", async function () {
      const { bondedVotes, bondOwnerAddress } = await loadFixture(setup);

      const raw = await ethers.provider.call({
        to: await bondedVotes.getAddress(),
        data: bondedVotes.interface.encodeFunctionData("balanceOf", [
          bondOwnerAddress,
        ]),
      });

      expect(ethers.dataLength(raw)).to.equal(32);
    });

    /// `supportsIVotesInterface` staticcalls these three with a zero timepoint. ERC-165 is never
    /// consulted. If any of them reverts or returns short, the setup silently wraps the token in
    /// `GovernanceWrappedERC20`, which would drop the bonded half entirely.
    it("answers all three IVotes probes at timepoint zero", async function () {
      const { bondedVotes, bondOwnerAddress } = await loadFixture(setup);
      const to = await bondedVotes.getAddress();

      for (const data of [
        bondedVotes.interface.encodeFunctionData("getPastTotalSupply", [0]),
        bondedVotes.interface.encodeFunctionData("getVotes", [
          bondOwnerAddress,
        ]),
        bondedVotes.interface.encodeFunctionData("getPastVotes", [
          bondOwnerAddress,
          0,
        ]),
      ]) {
        expect(
          ethers.dataLength(await ethers.provider.call({ to, data })),
        ).to.equal(32);
      }
    });

    /// `TokenVoting._detectTokenClock` reads both and reverts `TokenClockMismatch` when they
    /// disagree. Agreeing on timestamp is what makes the plugin snapshot with `block.timestamp - 1`
    /// instead of `block.number - 1` — the difference between counting bonded weight and reading
    /// zero for everyone.
    it("reports a clock and a CLOCK_MODE that agree on timestamp", async function () {
      const { bondedVotes } = await loadFixture(setup);

      expect(await bondedVotes.CLOCK_MODE()).to.equal("mode=timestamp");
      expect(await bondedVotes.clock()).to.equal(await time.latest());
    });

    it("exposes the metadata the governance app renders amounts with", async function () {
      const { bondedVotes, ciphernodeBondToken } = await loadFixture(setup);

      expect(await bondedVotes.decimals()).to.equal(
        await ciphernodeBondToken.decimals(),
      );
      expect(await bondedVotes.name()).to.equal(
        await ciphernodeBondToken.name(),
      );
      expect(await bondedVotes.symbol()).to.equal(
        await ciphernodeBondToken.symbol(),
      );
      expect(await bondedVotes.totalSupply()).to.equal(
        await ciphernodeBondToken.totalSupply(),
      );
    });

    it("counts wallet and bonded FOLD in the balance, ignoring delegation", async function () {
      const { bondedVotes, ciphernodeBondToken, bondOwnerAddress, bond } =
        await loadFixture(setup);

      await bond(BOND);

      // Delegation moves votes, never the balance, so this stays the full attributable amount.
      expect(await bondedVotes.balanceOf(bondOwnerAddress)).to.equal(
        (await ciphernodeBondToken.balanceOf(bondOwnerAddress)) + BOND,
      );
    });

    it("keeps total supply a pass-through so bonded FOLD is never counted twice", async function () {
      const { bondedVotes, ciphernodeBondToken, bond } =
        await loadFixture(setup);

      const before = await ciphernodeBondToken.totalSupply();
      await bond(BOND);

      // Bonding moves FOLD to the registry; it is not burned, so supply is unchanged.
      expect(await bondedVotes.totalSupply()).to.equal(before);
    });

    /// The wrapper must never look spendable: it owns no position and could not honour a transfer.
    it("exposes no way to move tokens", async function () {
      const { bondedVotes } = await loadFixture(setup);

      const names = bondedVotes.interface.fragments
        .filter((f) => f.type === "function")
        .map((f) => (f as unknown as { name: string }).name);

      for (const absent of [
        "transfer",
        "transferFrom",
        "approve",
        "allowance",
      ]) {
        expect(names).to.not.include(absent);
      }
    });
  });

  /// Findings from the bonded-voting audit. Each of these failed before the fix that follows it.
  describe("audit regressions", function () {
    /// The clock check proves the history speaks the token's units, not that it is about the token.
    /// Without the registry binding, a history written by a registry custodying something else
    /// added unbacked weight: 500,000,000 votes against a 100,000 supply, undetectable downstream.
    it("refuses a history whose registry bonds a different token", async function () {
      const { ciphernodeBondToken } = await loadFixture(setup);
      const [signer] = await ethers.getSigners();

      // Registry is an EOA here — it custodies no FOLD and cannot answer for a ciphernode bond token.
      const foreign = await ethers.deployContract("BondedCheckpoints", [
        await signer.getAddress(),
      ]);

      await expect(
        ethers.deployContract("BondedVotes", [
          await ciphernodeBondToken.getAddress(),
          await ciphernodeBondToken.getAddress(),
          await foreign.getAddress(),
        ]),
      ).to.be.revert(ethers);
    });

    it("binds itself to the registry that writes the history", async function () {
      const { bondedVotes, registryAddress } = await loadFixture(setup);

      expect(await bondedVotes.registry()).to.equal(registryAddress);
    });

    /// The registry holds every operator's bond while this contract attributes it to the owner.
    /// Counting it at both addresses put the same FOLD in two places, so summed balances exceeded
    /// total supply — the denominator every holder-percentage view divides by.
    it("nets the registry down by what it only custodies", async function () {
      const {
        bondedVotes,
        ciphernodeBondToken,
        bondOwnerAddress,
        registryAddress,
        bond,
      } = await loadFixture(setup);

      await bond(BOND);

      // The registry's raw balance holds the bond; its attributable balance must not.
      expect(await ciphernodeBondToken.balanceOf(registryAddress)).to.equal(
        BOND,
      );
      expect(await bondedVotes.balanceOf(registryAddress)).to.equal(0);

      // The bond is attributed once, to the owner.
      expect(await bondedVotes.balanceOf(bondOwnerAddress)).to.equal(
        (await ciphernodeBondToken.balanceOf(bondOwnerAddress)) + BOND,
      );
    });

    it("keeps summed balances within total supply while bonded", async function () {
      const {
        bondedVotes,
        ciphernodeBondToken,
        bondOwnerAddress,
        otherHolderAddress,
        newOwnerAddress,
        registryAddress,
        bond,
      } = await loadFixture(setup);

      await bond(BOND);

      let summed = 0n;
      for (const who of [
        bondOwnerAddress,
        otherHolderAddress,
        newOwnerAddress,
        registryAddress,
      ]) {
        summed += await bondedVotes.balanceOf(who);
      }

      expect(summed).to.be.lessThanOrEqual(
        await ciphernodeBondToken.totalSupply(),
      );
    });

    it("leaves surplus sent to the registry visible", async function () {
      const {
        bondedVotes,
        ciphernodeBondToken,
        otherHolder,
        registryAddress,
        bond,
      } = await loadFixture(setup);

      await bond(BOND);
      const surplus = ethers.parseEther("7");
      await ciphernodeBondToken
        .connect(otherHolder)
        .transfer(registryAddress, surplus);

      // Only the custodied portion is netted out, so an unsolicited transfer still shows.
      expect(await bondedVotes.balanceOf(registryAddress)).to.equal(surplus);
    });

    /// `resyncBondedCheckpoint` is permissionless, so a no-op write that still consumed a slot let
    /// anyone grow any owner's history by one checkpoint per block for as long as they paid.
    it("does not record a checkpoint when the total is unchanged", async function () {
      const { bondingRegistry, checkpoints, bondOwnerAddress, bond } =
        await loadFixture(setup);

      await bond(BOND);
      await time.increase(60);

      await expect(
        bondingRegistry.resyncBondedCheckpoint(bondOwnerAddress),
      ).to.not.emit(checkpoints, "BondedCheckpointed");

      // Skipping is exact: the reads still answer with the value already recorded.
      expect(await checkpoints.bonded(bondOwnerAddress)).to.equal(BOND);
      expect(await bondingRegistry.totalBonded(bondOwnerAddress)).to.equal(
        BOND,
      );
    });

    it("still records a checkpoint when the total actually moves", async function () {
      const {
        bondingRegistry,
        checkpoints,
        ciphernodeBondToken,
        bondOwner,
        bondOwnerAddress,
        operatorAddress,
        registryAddress,
        bond,
      } = await loadFixture(setup);

      await bond(BOND);
      await time.increase(60);

      await ciphernodeBondToken
        .connect(bondOwner)
        .approve(registryAddress, BOND);
      await expect(
        bondingRegistry
          .connect(bondOwner)
          .bondCiphernodeFor(operatorAddress, BOND),
      ).to.emit(checkpoints, "BondedCheckpointed");

      expect(await checkpoints.bonded(bondOwnerAddress)).to.equal(BOND * 2n);
    });

    it("keeps history readable across a skipped write", async function () {
      const { bondingRegistry, checkpoints, bondOwnerAddress, bond } =
        await loadFixture(setup);

      await bond(BOND);
      await time.increase(60);
      const before = await time.latest();

      // A skipped write must not create a hole: the timepoint resolves to the previous entry.
      await bondingRegistry.resyncBondedCheckpoint(bondOwnerAddress);
      await time.increase(60);

      expect(
        await checkpoints.getPastBonded(bondOwnerAddress, before),
      ).to.equal(BOND);
      expect(
        await checkpoints.getPastBonded(
          bondOwnerAddress,
          (await time.latest()) - 1,
        ),
      ).to.equal(BOND);
    });
  });

  describe("wiring", function () {
    it("rejects a checkpoint contract bound to another registry", async function () {
      // Deliberately NOT the shared fixture: that one already configures a checkpoint contract,
      // so the one-shot guard would fire first and this would assert the repoint path instead.
      // Both revert with InvalidConfiguration, so the mismatch branch would go uncovered.
      const { bondingRegistry } = await deployInterfoldSystem({
        useMockCiphernodeRegistry: true,
        setupOperators: 0,
        wireSlashingManager: false,
        mintUsdcTo: [],
      });

      const foreign = await ethers.deployContract("BondedCheckpoints", [
        ethers.Wallet.createRandom().address,
      ]);

      // A mismatch would make every sync revert and brick bonding for good.
      await expect(
        bondingRegistry.setBondedCheckpoints(await foreign.getAddress()),
      ).to.be.revertedWithCustomError(bondingRegistry, "InvalidConfiguration");

      // Proves the revert above came from the registry cross-check and not the one-shot guard:
      // the slot is still unset, so a correctly bound contract is still accepted.
      const owned = await ethers.deployContract("BondedCheckpoints", [
        await bondingRegistry.getAddress(),
      ]);
      await expect(
        bondingRegistry.setBondedCheckpoints(await owned.getAddress()),
      )
        .to.emit(bondingRegistry, "BondedCheckpointsSet")
        .withArgs(await owned.getAddress());
    });

    it("refuses to be repointed once set", async function () {
      const { bondingRegistry, registryAddress } = await loadFixture(setup);

      const replacement = await ethers.deployContract("BondedCheckpoints", [
        registryAddress,
      ]);

      // Repointing would abandon the recorded history, silently changing every past answer.
      await expect(
        bondingRegistry.setBondedCheckpoints(await replacement.getAddress()),
      ).to.be.revertedWithCustomError(bondingRegistry, "InvalidConfiguration");
    });

    it("rejects an address that names this registry but cannot record history", async function () {
      // `registry()` is not unique to a checkpoint contract: InterfoldTicketToken answers it with
      // this same address, so an ordinary address mix-up passes that check. With one-shot
      // semantics the slot would then be spent on a contract that cannot record anything, and
      // every bond, slash, exit claim and owner transfer would revert with no way to correct it.
      const { bondingRegistry, ticketToken } = await deployInterfoldSystem({
        useMockCiphernodeRegistry: true,
        setupOperators: 0,
        wireSlashingManager: false,
        mintUsdcTo: [],
      });

      expect(await ticketToken.registry()).to.equal(
        await bondingRegistry.getAddress(),
      );
      await expect(
        bondingRegistry.setBondedCheckpoints(await ticketToken.getAddress()),
      ).to.be.revert(ethers);

      // The slot survived the rejection, so the mistake is correctable.
      expect(await bondingRegistry.bondedCheckpoints()).to.equal(
        ethers.ZeroAddress,
      );
      const owned = await ethers.deployContract("BondedCheckpoints", [
        await bondingRegistry.getAddress(),
      ]);
      await bondingRegistry.setBondedCheckpoints(await owned.getAddress());
      expect(await bondingRegistry.bondedCheckpoints()).to.equal(
        await owned.getAddress(),
      );
    });

    it("only lets the registry write history", async function () {
      const { checkpoints, bondOwnerAddress, otherHolder } =
        await loadFixture(setup);

      await expect(
        (checkpoints.connect(otherHolder) as typeof checkpoints).sync(
          bondOwnerAddress,
          BOND,
        ),
      ).to.be.revertedWithCustomError(checkpoints, "OnlyRegistry");
    });
  });

  /// The history counts ciphernode-bond-token units, but `BondedVotes` adds them to the voting power of
  /// one fixed token chosen at construction. A replacement ciphernode bond token would otherwise write
  /// into the same history and be counted as FOLD, so an operator could hold voting power the
  /// token's total supply does not back.
  describe("ciphernode-bond-token rotation", function () {
    async function newCiphernodeBondToken() {
      return (
        await ethers.getContractFactory("MockLockAwareCiphernodeBondToken")
      ).deploy(0);
    }

    async function rotate(bondingRegistry: any) {
      const replacement = await newCiphernodeBondToken();
      await setBondingAssetConfig(bondingRegistry, {
        ciphernodeBondToken: await replacement.getAddress(),
      });
      return replacement;
    }

    it("detaches the history the previous token's votes are read through", async function () {
      const { bondingRegistry, checkpoints } = await loadFixture(setup);

      const replacement = await newCiphernodeBondToken();

      // Rotation already requires every old bond to be drained, so nothing live is truncated.
      await expect(
        setBondingAssetConfig(bondingRegistry, {
          ciphernodeBondToken: await replacement.getAddress(),
        }),
      )
        .to.emit(bondingRegistry, "BondedCheckpointsDetached")
        .withArgs(await checkpoints.getAddress());

      expect(await bondingRegistry.bondedCheckpoints()).to.equal(
        ethers.ZeroAddress,
      );
    });

    it("keeps a replacement token's bonds out of the previous token's voting power", async function () {
      const {
        bondingRegistry,
        bondOwner,
        bondOwnerAddress,
        operatorAddress,
        registryAddress,
        settledVotes,
      } = await loadFixture(setup);

      const walletVotes = await settledVotes(bondOwnerAddress);
      const replacement = await rotate(bondingRegistry);

      await replacement.mint(bondOwnerAddress, BOND);
      await replacement.connect(bondOwner).getFunction("approve")(
        registryAddress,
        BOND,
      );
      await bondingRegistry
        .connect(bondOwner)
        .bondCiphernodeFor(operatorAddress, BOND);

      // Bonded in a different token, so it must not add to FOLD voting power. Before the
      // detachment this bond entered the FOLD history and pushed the owner's votes above what
      // FOLD's own supply backs.
      expect(await settledVotes(bondOwnerAddress)).to.equal(walletVotes);
    });

    it("leaves bonding working while no history is attached", async function () {
      const { bondingRegistry, bondOwner, operatorAddress, registryAddress } =
        await loadFixture(setup);

      const replacement = await rotate(bondingRegistry);
      await replacement.mint(await bondOwner.getAddress(), BOND);
      await replacement.connect(bondOwner).getFunction("approve")(
        registryAddress,
        BOND,
      );

      // The sync is a no-op while unconfigured, so detaching must not freeze bonding.
      await bondingRegistry
        .connect(bondOwner)
        .bondCiphernodeFor(operatorAddress, BOND);
      expect(
        await bondingRegistry.totalBonded(await bondOwner.getAddress()),
      ).to.equal(BOND);
    });

    it("lets governance attach a history for the replacement token", async function () {
      const { bondingRegistry, registryAddress } = await loadFixture(setup);

      await rotate(bondingRegistry);

      // The one-shot guard is per ciphernode bond token, not per registry lifetime: the previous contract
      // keeps answering for the timepoints it covers, and the new era gets its own history.
      const fresh = await ethers.deployContract("BondedCheckpoints", [
        registryAddress,
      ]);
      await expect(
        bondingRegistry.setBondedCheckpoints(await fresh.getAddress()),
      )
        .to.emit(bondingRegistry, "BondedCheckpointsSet")
        .withArgs(await fresh.getAddress());
    });

    it("leaves the history attached when the ciphernode bond token is unchanged", async function () {
      const { bondingRegistry, checkpoints } = await loadFixture(setup);

      // Re-stating the same assets is a routine reprice and must not cost the recorded history.
      await setBondingAssetConfig(bondingRegistry, {
        requiredCiphernodeBond: ethers.parseEther("2"),
      });

      expect(await bondingRegistry.bondedCheckpoints()).to.equal(
        await checkpoints.getAddress(),
      );
    });
  });
  /// Lock-to-vote. `votesSource` is an escrow adapter instead of the token, so idle wallet FOLD
  /// carries no weight and a holder must lock to participate — while an operator keeps its weight
  /// by bonding, without locking anything.
  ///
  /// The property that makes this sound is that the DENOMINATOR stays on FOLD. Locked and bonded
  /// FOLD were both transferred rather than burned, so both are still inside FOLD's total supply
  /// and summed votes can never exceed it. Reading the denominator off the escrow instead would
  /// omit the bonded half entirely and let participation exceed 100%.
  describe("escrow votes source", function () {
    const LOCKED = ethers.parseEther("4000");

    async function veSetup() {
      const base = await setup();
      const { ciphernodeBondToken, checkpoints } = base;

      const foldAddress = await ciphernodeBondToken.getAddress();
      const escrow = await ethers.deployContract("MockVotingEscrow", [
        foldAddress,
      ]);
      const adapter = await ethers.deployContract("MockEscrowVotesAdapter", [
        await escrow.getAddress(),
      ]);

      const veBondedVotes = await ethers.deployContract("BondedVotes", [
        foldAddress,
        await adapter.getAddress(),
        await checkpoints.getAddress(),
      ]);

      return { ...base, escrow, adapter, veBondedVotes, foldAddress };
    }

    it("counts locked FOLD and bonded FOLD, but not idle wallet FOLD", async function () {
      const { veBondedVotes, adapter, bond, bondOwnerAddress } =
        await loadFixture(veSetup);

      // The holder has a large wallet balance and has self-delegated on the token itself, which
      // under the original configuration would have been their entire voting power.
      await bond(BOND);
      await adapter.setVotes(bondOwnerAddress, LOCKED);

      await time.increase(1);
      const timepoint = (await time.latest()) - 1;

      expect(
        await veBondedVotes.getPastVotes(bondOwnerAddress, timepoint),
      ).to.equal(LOCKED + BOND);
      expect(await veBondedVotes.getVotes(bondOwnerAddress)).to.equal(
        LOCKED + BOND,
      );
    });

    it("gives a holder who locked nothing and bonded nothing no voting power", async function () {
      const { veBondedVotes, otherHolderAddress } = await loadFixture(veSetup);

      // Holds MINTED FOLD and has self-delegated on the token. Under lock-to-vote that is
      // deliberately worth nothing.
      await time.increase(1);
      const timepoint = (await time.latest()) - 1;

      expect(
        await veBondedVotes.getPastVotes(otherHolderAddress, timepoint),
      ).to.equal(0n);
    });

    it("does not let a later CCA claim change an earlier snapshot", async function () {
      const { veBondedVotes, ciphernodeBondToken, otherHolderAddress } =
        await loadFixture(veSetup);
      const [claimSource] = await ethers.getSigners();
      const claimSourceAddress = await claimSource.getAddress();
      const claim = ethers.parseEther("123");

      expect(await ciphernodeBondToken.CLAIM_SOURCE()).to.equal(
        claimSourceAddress,
      );

      await ciphernodeBondToken.mint(
        claimSourceAddress,
        claim,
        ethers.encodeBytes32String("CCA claim"),
      );

      await time.increase(1);
      const snapshot = (await time.latest()) - 1;

      expect(
        await veBondedVotes.getPastVotes(otherHolderAddress, snapshot),
      ).to.equal(0n);

      await ciphernodeBondToken
        .connect(claimSource)
        .transfer(otherHolderAddress, claim);

      expect(
        await ciphernodeBondToken.lockedBalanceOf(otherHolderAddress),
      ).to.equal(claim);
      expect(
        await veBondedVotes.getPastVotes(otherHolderAddress, snapshot),
      ).to.equal(0n);
      expect(await veBondedVotes.getVotes(otherHolderAddress)).to.equal(claim);
    });

    it("does not let a later linked CCA claim change an earlier snapshot", async function () {
      const { veBondedVotes, ciphernodeBondToken, otherHolderAddress } =
        await loadFixture(veSetup);
      const [claimSource] = await ethers.getSigners();
      const claim = ethers.parseEther("123");
      const policyId = ethers.encodeBytes32String("CCA_LINKED");

      await ciphernodeBondToken.createLockPolicy(policyId, {
        holdUntil: 0n,
        unlock: {
          anchor: 1,
          start: 0n,
          cliffDuration: 0n,
          vestDuration: 2n * 365n * 24n * 60n * 60n,
        },
      });
      await ciphernodeBondToken.mint(
        await claimSource.getAddress(),
        claim,
        ethers.encodeBytes32String("CCA claim"),
      );

      await time.increase(1);
      const snapshot = (await time.latest()) - 1;

      await ciphernodeBondToken
        .connect(claimSource)
        .transfer(otherHolderAddress, claim);
      await ciphernodeBondToken.linkClaim(otherHolderAddress, claim, policyId);

      expect(
        await ciphernodeBondToken.lockedBalanceOf(otherHolderAddress),
      ).to.equal(claim);
      expect(
        await veBondedVotes.getPastVotes(otherHolderAddress, snapshot),
      ).to.equal(0n);
      expect(await veBondedVotes.getVotes(otherHolderAddress)).to.equal(claim);
    });

    it("lets an operator vote by bonding alone, without locking", async function () {
      const { veBondedVotes, bond, bondOwnerAddress } =
        await loadFixture(veSetup);

      await bond(BOND);

      await time.increase(1);
      const timepoint = (await time.latest()) - 1;

      expect(
        await veBondedVotes.getPastVotes(bondOwnerAddress, timepoint),
      ).to.equal(BOND);
    });

    /// The whole reason the token reference is kept separate from the votes source.
    it("measures quorum against FOLD's supply, not the escrow's", async function () {
      const {
        veBondedVotes,
        adapter,
        ciphernodeBondToken,
        bond,
        bondOwnerAddress,
      } = await loadFixture(veSetup);

      await bond(BOND);
      await adapter.setVotes(bondOwnerAddress, LOCKED);

      await time.increase(1);
      const timepoint = (await time.latest()) - 1;

      // The adapter reports zero supply. Had the denominator been read from it, any turnout at
      // all would have cleared every quorum.
      expect(await adapter.getPastTotalSupply(timepoint)).to.equal(0n);

      const supply = await veBondedVotes.getPastTotalSupply(timepoint);
      expect(supply).to.equal(
        await ciphernodeBondToken.getPastTotalSupply(timepoint),
      );
      expect(supply).to.be.greaterThan(0n);

      // Soundness: what one account can vote with is inside the supply it is measured against.
      expect(
        await veBondedVotes.getPastVotes(bondOwnerAddress, timepoint),
      ).to.be.lessThanOrEqual(supply);
    });

    /// The escrow adapter has no `decimals`, `name`, `symbol` or `totalSupply`. Routing metadata
    /// through it would revert — and `decimals` reverting is the dangerous one, because CRISP's
    /// tally scaling catches the failure and silently falls back to a scale of 1.
    it("reads metadata from FOLD, which the escrow adapter cannot answer for", async function () {
      const { veBondedVotes, adapter, ciphernodeBondToken } =
        await loadFixture(veSetup);

      expect(await veBondedVotes.decimals()).to.equal(
        await ciphernodeBondToken.decimals(),
      );
      expect(await veBondedVotes.name()).to.equal(
        await ciphernodeBondToken.name(),
      );
      expect(await veBondedVotes.symbol()).to.equal(
        await ciphernodeBondToken.symbol(),
      );
      expect(await veBondedVotes.totalSupply()).to.equal(
        await ciphernodeBondToken.totalSupply(),
      );

      // Not merely different — unanswerable, which is why it must not be asked.
      const adapterAsToken = await ethers.getContractAt(
        "BondedVotes",
        await adapter.getAddress(),
      );
      await expect(adapterAsToken.decimals()).to.be.revert(ethers);
    });

    it("attributes locked FOLD to the locker in balanceOf", async function () {
      const {
        veBondedVotes,
        adapter,
        escrow,
        ciphernodeBondToken,
        bond,
        bondOwnerAddress,
      } = await loadFixture(veSetup);

      await bond(BOND);
      await escrow.setLocked(bondOwnerAddress, LOCKED);
      await adapter.setVotes(bondOwnerAddress, LOCKED);

      const wallet = await ciphernodeBondToken.balanceOf(bondOwnerAddress);

      // Wallet plus what the escrow and the registry each custody on the account's behalf.
      expect(await veBondedVotes.balanceOf(bondOwnerAddress)).to.equal(
        wallet + LOCKED + BOND,
      );
    });

    /// The mirror of the registry netting. The escrow custodies real FOLD and every unit of it is
    /// already attributed above to the account that locked it, so leaving it at the escrow's own
    /// address as well would place the same tokens twice and push summed balances past total
    /// supply — the denominator every holder-percentage view divides by.
    it("nets the escrow down to nothing in balanceOf", async function () {
      const { veBondedVotes, escrow, ciphernodeBondToken, otherHolderAddress } =
        await loadFixture(veSetup);

      const escrowAddress = await escrow.getAddress();
      const custodied = ethers.parseEther("9000");

      // Stands in for FOLD deposited by lockers: the escrow holds it, and it is attributed to the
      // lockers rather than to the escrow.
      await ciphernodeBondToken.mint(
        escrowAddress,
        custodied,
        ethers.encodeBytes32String("Escrow deposits"),
      );
      await escrow.setLocked(otherHolderAddress, custodied);

      expect(await ciphernodeBondToken.balanceOf(escrowAddress)).to.equal(
        custodied,
      );
      expect(await veBondedVotes.balanceOf(escrowAddress)).to.equal(0n);
      // Counted exactly once, at the locker.
      expect(await veBondedVotes.balanceOf(otherHolderAddress)).to.equal(
        (await ciphernodeBondToken.balanceOf(otherHolderAddress)) + custodied,
      );
    });

    it("routes delegation lookups to the votes source", async function () {
      const { veBondedVotes, adapter, bondOwnerAddress, otherHolderAddress } =
        await loadFixture(veSetup);

      await adapter.setDelegate(bondOwnerAddress, otherHolderAddress);

      expect(await veBondedVotes.delegates(bondOwnerAddress)).to.equal(
        otherHolderAddress,
      );
    });

    /// Same argument as `TokenMismatch`, applied to the other half of the numerator: an escrow
    /// over a different token would mint voting power FOLD's supply does not back, and the
    /// denominator would never reveal it.
    it("rejects an escrow that custodies a different token", async function () {
      const { checkpoints, foldAddress } = await loadFixture(veSetup);

      const foreignToken = await (
        await ethers.getContractFactory("MockLockAwareCiphernodeBondToken")
      ).deploy(0);
      const foreignEscrow = await ethers.deployContract("MockVotingEscrow", [
        await foreignToken.getAddress(),
      ]);
      const foreignAdapter = await ethers.deployContract(
        "MockEscrowVotesAdapter",
        [await foreignEscrow.getAddress()],
      );

      await expect(
        ethers.deployContract("BondedVotes", [
          foldAddress,
          await foreignAdapter.getAddress(),
          await checkpoints.getAddress(),
        ]),
      ).to.be.revert(ethers);
    });

    it("rejects a votes source whose clock disagrees with the token", async function () {
      const { checkpoints, adapter, foldAddress } = await loadFixture(veSetup);

      // A block-numbered escrow summed with a timestamp-keyed history answers for two unrelated
      // instants, and nothing downstream could detect it.
      await adapter.setClock(1);

      await expect(
        ethers.deployContract("BondedVotes", [
          foldAddress,
          await adapter.getAddress(),
          await checkpoints.getAddress(),
        ]),
      ).to.be.revert(ethers);
    });

    /// FOLD's own vesting locks, the current-only third source under an escrow votes source.
    ///
    /// Lock-encumbered FOLD sits in the holder's wallet and the token's transfer hook refuses to
    /// move it, so it can never reach the escrow. The historical vote path excludes this term
    /// because the token lock schedule is not checkpointed.
    describe("vesting-locked FOLD", function () {
      const ALLOCATION = ethers.parseEther("6000");

      /// Tge-anchored, and the fixture never fires TGE, so the allocation stays fully locked for
      /// every timestamp the tests read. What is being measured is the netting, not the curve.
      async function allocate(
        token: Awaited<ReturnType<typeof setup>>["ciphernodeBondToken"],
        recipient: string,
        amount: bigint,
        policyName = "VE_LOCK",
      ) {
        const policyId = ethers.encodeBytes32String(policyName);
        await token.createLockPolicy(policyId, {
          holdUntil: 0n,
          unlock: {
            anchor: 1,
            start: 0n,
            cliffDuration: 0n,
            vestDuration: 2n * 365n * 24n * 60n * 60n,
          },
        });
        await token.mintAllocations([
          {
            recipient,
            amount,
            policyId,
            label: ethers.encodeBytes32String("ve-test"),
          },
        ]);
        return policyId;
      }

      it("does not count token-level locks in historical voting power", async function () {
        const { veBondedVotes, ciphernodeBondToken, otherHolderAddress } =
          await loadFixture(veSetup);

        await allocate(ciphernodeBondToken, otherHolderAddress, ALLOCATION);

        await time.increase(1);
        const timepoint = (await time.latest()) - 1;

        expect(
          await ciphernodeBondToken.lockedBalanceOf(otherHolderAddress),
        ).to.equal(ALLOCATION);
        expect(
          await veBondedVotes.getPastVotes(otherHolderAddress, timepoint),
        ).to.equal(0n);
        expect(await veBondedVotes.getVotes(otherHolderAddress)).to.equal(
          ALLOCATION,
        );
      });

      it("keeps token-level locks in current voting power", async function () {
        const {
          veBondedVotes,
          ciphernodeBondToken,
          adapter,
          bond,
          bondOwnerAddress,
        } = await loadFixture(veSetup);

        await allocate(ciphernodeBondToken, bondOwnerAddress, ALLOCATION);
        await adapter.setVotes(bondOwnerAddress, LOCKED);
        await bond(BOND);

        await time.increase(1);
        const timepoint = (await time.latest()) - 1;

        // The bond is smaller than the lock, so it covers only part of the obligation: the rest
        // is FOLD the wallet is still holding and still cannot escrow.
        expect(
          await veBondedVotes.getPastVotes(bondOwnerAddress, timepoint),
        ).to.equal(LOCKED + BOND);
        expect(await veBondedVotes.getVotes(bondOwnerAddress)).to.equal(
          LOCKED + ALLOCATION,
        );
      });

      /// The one place a naive `locked + escrowed + bonded` sum goes wrong. A bond SATISFIES a
      /// lock — {InterfoldToken.transferableBalanceOf} nets the bond against the obligation — so
      /// bonded FOLD is reported by both `lockedBalanceAt` and the bonded history while existing
      /// exactly once. Summing both would let an operator vote twice with the same token.
      it("does not count FOLD twice when the bond covers the lock", async function () {
        const { veBondedVotes, ciphernodeBondToken, bond, bondOwnerAddress } =
          await loadFixture(veSetup);

        await allocate(ciphernodeBondToken, bondOwnerAddress, BOND);
        await bond(BOND);

        await time.increase(1);
        const timepoint = (await time.latest()) - 1;

        expect(
          await ciphernodeBondToken.lockedBalanceOf(bondOwnerAddress),
        ).to.equal(BOND);
        expect(
          await veBondedVotes.getPastVotes(bondOwnerAddress, timepoint),
        ).to.equal(BOND);
        expect(await veBondedVotes.getVotes(bondOwnerAddress)).to.equal(BOND);
      });

      it("does not count a token-level lock in historical voting power", async function () {
        const { veBondedVotes, ciphernodeBondToken, otherHolderAddress } =
          await loadFixture(veSetup);

        await allocate(ciphernodeBondToken, otherHolderAddress, ALLOCATION);

        await time.increase(1);
        const timepoint = (await time.latest()) - 1;

        expect(
          await ciphernodeBondToken.balanceOf(otherHolderAddress),
        ).to.be.greaterThan(ALLOCATION);
        expect(
          await veBondedVotes.getPastVotes(otherHolderAddress, timepoint),
        ).to.equal(0n);
        expect(await veBondedVotes.getVotes(otherHolderAddress)).to.equal(
          ALLOCATION,
        );
      });

      it("keeps a bond larger than the lock in historical voting power", async function () {
        const { veBondedVotes, ciphernodeBondToken, bond, bondOwnerAddress } =
          await loadFixture(veSetup);

        await allocate(ciphernodeBondToken, bondOwnerAddress, BOND / 4n);
        await bond(BOND);

        await time.increase(1);
        const timepoint = (await time.latest()) - 1;

        expect(
          await veBondedVotes.getPastVotes(bondOwnerAddress, timepoint),
        ).to.equal(BOND);
      });

      it("counts a bond larger than the lock exactly once for current voting power", async function () {
        const { veBondedVotes, ciphernodeBondToken, bond, bondOwnerAddress } =
          await loadFixture(veSetup);

        await allocate(ciphernodeBondToken, bondOwnerAddress, BOND / 4n);
        await bond(BOND);

        await time.increase(1);
        const timepoint = (await time.latest()) - 1;

        expect(
          await veBondedVotes.getPastVotes(bondOwnerAddress, timepoint),
        ).to.equal(BOND);
        expect(await veBondedVotes.getVotes(bondOwnerAddress)).to.equal(BOND);
      });

      /// Soundness: what one account votes with never exceeds the supply it is measured against,
      /// which is what any double count would break first.
      it("keeps a locked, escrowed and bonded holder inside total supply", async function () {
        const {
          veBondedVotes,
          ciphernodeBondToken,
          adapter,
          bond,
          bondOwnerAddress,
        } = await loadFixture(veSetup);

        await allocate(ciphernodeBondToken, bondOwnerAddress, ALLOCATION);
        await adapter.setVotes(bondOwnerAddress, LOCKED);
        await bond(BOND);

        await time.increase(1);
        const timepoint = (await time.latest()) - 1;

        expect(
          await veBondedVotes.getPastVotes(bondOwnerAddress, timepoint),
        ).to.be.lessThanOrEqual(
          await veBondedVotes.getPastTotalSupply(timepoint),
        );
      });

      /// Under an escrow votes source the lock schedule is the only way an encumbered holder can
      /// report current voting power, so a token that cannot answer for it must be rejected at
      /// construction. Tolerating the failure at read time would silently return zero for that
      /// current-vote path.
      it("refuses an escrow votes source over a token with no lock schedule", async function () {
        const { veBondedVotes, foldAddress } = await loadFixture(veSetup);

        // Carries the voting surface and a matching clock, but no `lockedBalanceAt`.
        const lockless = await ethers.deployContract("MockVotesToken");
        const locklessAddress = await lockless.getAddress();

        const escrowOver = async (tokenAddress: string) => {
          const escrow = await ethers.deployContract("MockVotingEscrow", [
            tokenAddress,
          ]);
          return ethers.deployContract("MockEscrowVotesAdapter", [
            await escrow.getAddress(),
          ]);
        };

        await expect(
          ethers.deployContract("BondedVotes", [
            locklessAddress,
            await (await escrowOver(locklessAddress)).getAddress(),
            await (
              await ethers.deployContract("MockBondedCheckpointsStub", [
                locklessAddress,
              ])
            ).getAddress(),
          ]),
        ).to.be.revertedWithCustomError(
          veBondedVotes,
          "LockedBalancesUnsupported",
        );

        // Control: the same wiring over FOLD, which does answer, constructs. Without this the
        // test would pass just as well if the stub were what rejected the deployment.
        await expect(
          ethers.deployContract("BondedVotes", [
            foldAddress,
            await (await escrowOver(foldAddress)).getAddress(),
            await (
              await ethers.deployContract("MockBondedCheckpointsStub", [
                foldAddress,
              ])
            ).getAddress(),
          ]),
        ).to.not.be.revert(ethers);
      });

      /// The token votes for itself here, so the lock schedule is never read and a token without
      /// one stays deployable. Probing unconditionally would break every such configuration for a
      /// surface it does not use.
      it("does not require a lock schedule when the token votes for itself", async function () {
        const lockless = await ethers.deployContract("MockVotesToken");
        const locklessAddress = await lockless.getAddress();

        await expect(
          ethers.deployContract("BondedVotes", [
            locklessAddress,
            locklessAddress,
            await (
              await ethers.deployContract("MockBondedCheckpointsStub", [
                locklessAddress,
              ])
            ).getAddress(),
          ]),
        ).to.not.be.revert(ethers);
      });

      /// Netting the bond off the lock is only sound while the token's own transfer rule holds:
      /// `balance >= locked - bonded`, checked on every transfer. SLASHING breaks it — it takes
      /// the bond without touching the lock — so an operator that had already moved locked FOLD
      /// out on the strength of that bond is left owing more than it holds. Uncapped, the locked
      /// term would vote with FOLD that is now in the slash recipient's hands and countable
      /// there too.
      it("stops counting locked FOLD a slash left unbacked", async function () {
        const { veBondedVotes, bondingRegistry, ciphernodeBondToken } =
          await loadFixture(veSetup);

        const [, , , , , locker, lockerOperator, sink] =
          await ethers.getSigners();
        const lockerAddress = await locker.getAddress();
        const lockerOperatorAddress = await lockerOperator.getAddress();
        const sinkAddress = await sink.getAddress();
        const registryAddress = await bondingRegistry.getAddress();

        // A wallet holding exactly one lock and an equal amount of free FOLD.
        await allocate(ciphernodeBondToken, lockerAddress, BOND, "SLASH_LOCK");
        await ciphernodeBondToken.mint(
          lockerAddress,
          BOND,
          ethers.encodeBytes32String("Free"),
        );

        // Bonding the free half satisfies the lock, which frees the locked half to move.
        await bondingRegistry
          .connect(lockerOperator)
          .setBondOwner(lockerAddress);
        await ciphernodeBondToken
          .connect(locker)
          .approve(registryAddress, BOND);
        await bondingRegistry
          .connect(locker)
          .bondCiphernodeFor(lockerOperatorAddress, BOND);

        await ciphernodeBondToken.setTransferWhitelisted(sinkAddress, true);
        await ciphernodeBondToken.connect(locker).transfer(sinkAddress, BOND);
        expect(await ciphernodeBondToken.balanceOf(lockerAddress)).to.equal(0n);

        // At this point the sum is honest: nothing in the wallet, the whole lock covered.
        await time.increase(1);
        expect(
          await veBondedVotes.getPastVotes(
            lockerAddress,
            (await time.latest()) - 1,
          ),
        ).to.equal(BOND);

        const managerAddress = await bondingRegistry.slashingManager();
        await networkHelpers.setBalance(managerAddress, ethers.parseEther("1"));
        await networkHelpers.impersonateAccount(managerAddress);
        await bondingRegistry
          .connect(await ethers.getSigner(managerAddress))
          .slashCiphernodeBond(
            lockerOperatorAddress,
            BOND,
            ethers.encodeBytes32String("TEST_SLASH"),
          );
        await networkHelpers.stopImpersonatingAccount(managerAddress);

        await time.increase(1);
        const timepoint = (await time.latest()) - 1;

        // The lock outlives the bond that covered it, so `locked - bonded` is the whole
        // allocation — but the wallet holds none of it, and the slashed FOLD votes elsewhere.
        expect(
          await ciphernodeBondToken.lockedBalanceOf(lockerAddress),
        ).to.equal(BOND);
        expect(
          await veBondedVotes.getPastVotes(lockerAddress, timepoint),
        ).to.equal(0n);
        expect(await veBondedVotes.getVotes(lockerAddress)).to.equal(0n);
      });

      /// The cap is a bound, not a source: it never lets an account vote with more than the
      /// unbonded part of its lock, and never reaches into FOLD the lock does not encumber.
      it("caps current voting power at the lock, not at the wallet balance", async function () {
        const { veBondedVotes, ciphernodeBondToken, otherHolderAddress } =
          await loadFixture(veSetup);

        // The holder's wallet is far larger than the lock; only the locked part may vote.
        await allocate(ciphernodeBondToken, otherHolderAddress, ALLOCATION);

        await time.increase(1);
        const timepoint = (await time.latest()) - 1;

        expect(
          await ciphernodeBondToken.balanceOf(otherHolderAddress),
        ).to.be.greaterThan(ALLOCATION);
        expect(
          await veBondedVotes.getPastVotes(otherHolderAddress, timepoint),
        ).to.equal(0n);
        expect(await veBondedVotes.getVotes(otherHolderAddress)).to.equal(
          ALLOCATION,
        );
      });

      /// When the token votes for itself, locked FOLD is wallet FOLD and the token's own
      /// checkpoints already carry it. Adding the lock schedule there would double every locked
      /// holder's weight.
      it("is ignored when the votes source is the token itself", async function () {
        const { bondedVotes, ciphernodeBondToken, otherHolderAddress } =
          await loadFixture(veSetup);

        await allocate(ciphernodeBondToken, otherHolderAddress, ALLOCATION);

        await time.increase(1);
        const timepoint = (await time.latest()) - 1;

        expect(
          await bondedVotes.getPastVotes(otherHolderAddress, timepoint),
        ).to.equal(
          await ciphernodeBondToken.getPastVotes(otherHolderAddress, timepoint),
        );
      });
    });

    it("records the escrow it resolved, and leaves it zero without one", async function () {
      const { veBondedVotes, bondedVotes, escrow } = await loadFixture(veSetup);

      expect(await veBondedVotes.escrow()).to.equal(await escrow.getAddress());
      // The original configuration resolves no escrow, so balanceOf never consults one.
      expect(await bondedVotes.escrow()).to.equal(ethers.ZeroAddress);
    });
  });
});
