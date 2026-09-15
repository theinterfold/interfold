// SPDX-License-Identifier: LGPL-3.0-only
//
// Per-E3 dust rotation in `_distributeRewards`.
//
// With integer-division splitting, each E3's per-node remainder
// (`cnAmount % committeeSize`) was historically stuffed into the last
// committee slot, biasing rewards toward whichever operator landed there.
// The fix rotates the dust slot deterministically by `e3Id % n`, so the
// bias averages out across requests with the same committee membership.
import { expect } from "chai";
import type { Signer } from "ethers";

import {
  ACTIVE_CRYPTO_CONFIG_ID,
  DATA as data,
  deployInterfoldSystem,
  encodeMockDkgProof,
  ethers,
  networkHelpers,
  PROOF as proof,
  publishAvailableCiphertextOutput,
  setPricingConfig,
} from "../fixtures";

const { loadFixture, time } = networkHelpers;

describe("Pricing — per-E3 dust rotation across consecutive E3s", function () {
  const inputWindowDuration = 300;
  const abiCoder = ethers.AbiCoder.defaultAbiCoder();

  const setupAndPublishCommittee = async (
    registry: any,
    e3Id: number | bigint,
    publicKey: string,
    operators: Signer[],
  ) => {
    await time.increase(1);
    for (const operator of operators) {
      await registry.connect(operator).submitTicket(e3Id, 1);
    }
    const deadline = await registry.getCommitteeDeadline(e3Id);
    await time.setNextBlockTimestamp(deadline + 1n);
    await registry.finalizeCommittee(e3Id);
    const pkCommitment = ethers.keccak256(publicKey);
    await registry.publishCommittee(
      e3Id,
      pkCommitment,
      encodeMockDkgProof(pkCommitment),
      "0x01",
    );
  };

  const setup = async () => {
    const sys = await deployInterfoldSystem({
      mintUsdcTo: [],
      committeeThresholds: [[0, [2, 3]]],
    });
    const {
      owner,
      operator1: operator1Maybe,
      operator2: operator2Maybe,
      operator3: operator3Maybe,
      interfold,
      bondingRegistry,
      ciphernodeRegistry: ciphernodeRegistryContract,
      usdcToken: feeToken,
      mocks: { e3Program, decryptionVerifier },
    } = sys;
    const operator1 = operator1Maybe!;
    const operator2 = operator2Maybe!;
    const operator3 = operator3Maybe!;
    const [, , , , , treasury] = await ethers.getSigners();
    const treasuryAddress = await treasury.getAddress();
    const ownerAddress = await owner.getAddress();
    const signers = await ethers.getSigners();
    const rewardOwners = [signers[7], signers[8], signers[9]];
    for (let i = 0; i < 3; i++) {
      const operator = [operator1, operator2, operator3][i];
      const operatorAddress = await operator.getAddress();
      const rewardOwnerAddress = await rewardOwners[i].getAddress();
      await bondingRegistry
        .connect(owner)
        .proposeBondOwner(operatorAddress, rewardOwnerAddress);
      await bondingRegistry
        .connect(rewardOwners[i])
        .acceptBondOwner(operatorAddress);
    }

    // Pricing — pick params that yield a per-node cnAmount remainder ≠ 0
    // for committeeSize=3 so the dust rotation is observable. The values
    // here were chosen empirically: stripping `protocolShareBps=0` and
    // setting `keyGenFixedPerNode=1` causes the fee to land on a value
    // whose `cnAmount % 3 != 0`.
    await setPricingConfig(interfold, {
      keyGenFixedPerNode: 1n,
      keyGenPerEncryptionProof: 0n,
      coordinationPerPair: 0n,
      availabilityPerNodePerSec: 0n,
      decryptionPerNode: 0n,
      publicationBase: 1n, // total base = 3*1 + 1 = 4 → 4 % 3 = 1
      verificationPerProof: 0n,
      protocolTreasury: treasuryAddress,
      marginBps: 0,
      protocolShareBps: 0,
      dkgUtilizationBps: 2500,
      computeUtilizationBps: 5000,
      decryptUtilizationBps: 2500,
      minCommitteeSize: 0,
      minThreshold: 0,
      randomnessFlatFee: 1n,
    });

    await feeToken.mint(ownerAddress, ethers.parseUnits("1000000", 6));

    const makeRequest = () => {
      const now0 = Math.floor(Date.now() / 1000);
      return {
        committeeSize: 0,
        inputWindow: [now0 + 10, now0 + inputWindowDuration] as [
          number,
          number,
        ],
        e3Program: e3Program.getAddress() as unknown as string,
        paramSet: 0,
        computeProviderParams: abiCoder.encode(
          ["address"],
          [decryptionVerifier.getAddress()],
        ),
        customParams: abiCoder.encode(
          ["address"],
          ["0x1234567890123456789012345678901234567890"],
        ),
      } as any;
    };

    const firstE3Id = await interfold.nexte3Id();
    const makeAndRun = async (e3Id: bigint) => {
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
        expectedFeeToken: await feeToken.getAddress(),
        expectedCryptoConfigId: ACTIVE_CRYPTO_CONFIG_ID,
        maxFee: ethers.MaxUint256,
      };
      await feeToken.approve(await interfold.getAddress(), ethers.MaxUint256);
      await interfold.request(req);
      // topNodes are sorted as operator3, operator1, operator2, so map that
      // order to the corresponding bond-owner reward recipients.
      const recipients = [
        await rewardOwners[2].getAddress(),
        await rewardOwners[0].getAddress(),
        await rewardOwners[1].getAddress(),
      ];
      await setupAndPublishCommittee(
        ciphernodeRegistryContract,
        e3Id,
        e3Id === firstE3Id ? "0x1234" : "0x5678",
        [operator1, operator2, operator3],
      );
      await time.increase(inputWindowDuration + 200);
      await publishAvailableCiphertextOutput(
        interfold,
        e3Id,
        data,
        ethers.keccak256(data),
        proof,
      );
      const e3Proof = ethers.concat([proof, ethers.toBeHex(e3Id, 32)]);
      await interfold.publishPlaintextOutput(e3Id, data, e3Proof);
      return recipients;
    };

    return {
      owner,
      operator1,
      operator2,
      operator3,
      interfold,
      ciphernodeRegistryContract,
      feeToken,
      makeRequest,
      makeAndRun,
      firstE3Id,
    };
  };

  it("rotates the per-E3 dust slot deterministically by e3Id", async function () {
    const ctx = await loadFixture(setup);
    const { interfold, makeAndRun, firstE3Id } = ctx;

    const nodes = await makeAndRun(firstE3Id);
    const pending0 = await Promise.all(
      nodes.map((n) => interfold.pendingReward(firstE3Id, n)),
    );

    const secondE3Id = firstE3Id + 1n;
    const nodes2 = await makeAndRun(secondE3Id);
    expect(nodes2).to.deep.equal(nodes);
    const pending1 = await Promise.all(
      nodes.map((n) => interfold.pendingReward(secondE3Id, n)),
    );

    // Sanity: cnAmount per E3 should not be divisible by 3 with the chosen
    // pricing — i.e. at least one node received strictly more than another.
    const max0 = pending0.reduce((a, b) => (a > b ? a : b));
    const min0 = pending0.reduce((a, b) => (a < b ? a : b));
    expect(max0, "test config must produce non-zero dust").to.be.gt(min0);

    const expectedDustSlot0 = Number(firstE3Id % 3n);
    const expectedDustSlot1 = Number(secondE3Id % 3n);
    const dustSlot0 = pending0.findIndex((p) => p === max0);
    const max1 = pending1.reduce((a, b) => (a > b ? a : b));
    const dustSlot1 = pending1.findIndex((p) => p === max1);

    expect(dustSlot0).to.equal(expectedDustSlot0);
    expect(dustSlot1).to.equal(expectedDustSlot1);

    // The shortfall (per-node payout) should be identical across both E3s
    // for the non-dust slots — the formula only changed who got the dust.
    const per0 = pending0[(expectedDustSlot0 + 1) % 3];
    const per1 = pending1[(expectedDustSlot1 + 1) % 3];
    expect(per0).to.equal(per1);
  });
});
