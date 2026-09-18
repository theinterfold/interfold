// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
import { expect } from "chai";

import { ethers, networkHelpers } from "../fixtures";

describe("ChainlinkVrfRandomnessProvider", function () {
  async function setup({
    nativePayment = false,
    fundedBalance = ethers.parseEther("100"),
    minimumBalance = 1n,
    baseFee = 0n,
  } = {}) {
    const [owner, protocolOwner, other] = await ethers.getSigners();
    const requester = await ethers.deployContract("MockCiphernodeRegistry");
    await requester.waitForDeployment();

    const coordinator = await ethers.deployContract(
      "ChainlinkVrfCoordinatorV2_5Mock",
      [baseFee, 0, ethers.parseEther("1")],
    );
    await coordinator.waitForDeployment();
    await coordinator.createSubscription();
    const [subscriptionId] = await coordinator.getActiveSubscriptionIds(0, 1);
    if (!subscriptionId) throw new Error("subscription missing");
    if (nativePayment) {
      await coordinator.fundSubscriptionWithNative(subscriptionId, {
        value: fundedBalance,
      });
    } else {
      await coordinator.fundSubscription(subscriptionId, fundedBalance);
    }

    const provider: any = await ethers.deployContract(
      "ChainlinkVrfRandomnessProvider",
      [
        await requester.getAddress(),
        await coordinator.getAddress(),
        subscriptionId,
        `0x${"11".repeat(32)}`,
        3,
        500_000,
        nativePayment,
        minimumBalance,
        await protocolOwner.getAddress(),
      ],
    );
    await provider.waitForDeployment();
    await coordinator.addConsumer(subscriptionId, await provider.getAddress());

    const requesterAddress = await requester.getAddress();
    await networkHelpers.impersonateAccount(requesterAddress);
    await networkHelpers.setBalance(requesterAddress, ethers.parseEther("1"));
    const requesterSigner = await ethers.getSigner(requesterAddress);

    return {
      coordinator,
      other,
      owner,
      protocolOwner,
      provider,
      requesterAddress,
      requesterSigner,
      subscriptionId,
    };
  }

  it("binds reverse-order responses to their request and E3", async function () {
    const { coordinator, provider, requesterSigner } = await setup();
    const firstE3Id = 42n;
    const secondE3Id = 73n;
    const firstWord = 123456789n;
    const secondWord = 987654321n;

    await expect(provider.connect(requesterSigner).requestRandomness(firstE3Id))
      .to.emit(provider, "RandomnessRequested")
      .withArgs(1, firstE3Id);
    await expect(
      provider.connect(requesterSigner).requestRandomness(secondE3Id),
    )
      .to.emit(provider, "RandomnessRequested")
      .withArgs(2, secondE3Id);

    const secondFulfillment = await coordinator.fulfillRandomWordsWithOverride(
      2,
      await provider.getAddress(),
      [secondWord],
    );
    const secondReceipt = await secondFulfillment.wait();
    if (!secondReceipt) throw new Error("second fulfillment receipt missing");
    const firstFulfillment = await coordinator.fulfillRandomWordsWithOverride(
      1,
      await provider.getAddress(),
      [firstWord],
    );
    const firstReceipt = await firstFulfillment.wait();
    if (!firstReceipt) throw new Error("first fulfillment receipt missing");

    expect(await provider.requestIdByE3Id(firstE3Id)).to.equal(1n);
    expect(await provider.requestIdByE3Id(secondE3Id)).to.equal(2n);
    expect(await provider.e3IdByRequestId(1)).to.equal(firstE3Id);
    expect(await provider.e3IdByRequestId(2)).to.equal(secondE3Id);

    for (const [requestId, word, receipt] of [
      [1n, firstWord, firstReceipt],
      [2n, secondWord, secondReceipt],
    ] as const) {
      const [fulfilled, storedWord, fulfilledAt, fulfilledBlock] =
        await provider.getRandomness(requestId);
      const block = await ethers.provider.getBlock(receipt.blockNumber);
      expect(fulfilled).to.equal(true);
      expect(storedWord).to.equal(word);
      expect(fulfilledAt).to.equal(BigInt(block!.timestamp));
      expect(fulfilledBlock).to.equal(BigInt(receipt.blockNumber));
    }
  });

  it("allows only the bound registry to request and never re-requests an E3", async function () {
    const { other, provider, requesterSigner } = await setup();

    await expect(provider.connect(other).requestRandomness(7))
      .to.be.revertedWithCustomError(provider, "OnlyRequester")
      .withArgs(await other.getAddress());
    await provider.connect(requesterSigner).requestRandomness(7);
    await expect(provider.connect(requesterSigner).requestRandomness(7))
      .to.be.revertedWithCustomError(provider, "RandomnessAlreadyRequested")
      .withArgs(7);
  });

  it("checks the LINK balance floor", async function () {
    const { coordinator, provider, requesterSigner, subscriptionId } =
      await setup({ fundedBalance: 4n, minimumBalance: 5n });

    await expect(provider.connect(requesterSigner).requestRandomness(7))
      .to.be.revertedWithCustomError(
        provider,
        "InsufficientSubscriptionBalance",
      )
      .withArgs(4, 5);

    await coordinator.fundSubscription(subscriptionId, 1n);
    await expect(provider.connect(requesterSigner).requestRandomness(7))
      .to.emit(provider, "RandomnessRequested")
      .withArgs(1, 7);
  });

  it("checks the native balance floor", async function () {
    const { coordinator, provider, requesterSigner, subscriptionId } =
      await setup({
        nativePayment: true,
        fundedBalance: 4n,
        minimumBalance: 5n,
      });

    await coordinator.fundSubscription(subscriptionId, 100n);
    await expect(provider.connect(requesterSigner).requestRandomness(7))
      .to.be.revertedWithCustomError(
        provider,
        "InsufficientSubscriptionBalance",
      )
      .withArgs(4, 5);

    await coordinator.fundSubscriptionWithNative(subscriptionId, {
      value: 1n,
    });
    await expect(provider.connect(requesterSigner).requestRandomness(7))
      .to.emit(provider, "RandomnessRequested")
      .withArgs(1, 7);
  });

  it("blocks requests after balance depletion", async function () {
    const { coordinator, provider, requesterSigner } = await setup({
      fundedBalance: 2n,
      minimumBalance: 2n,
      baseFee: 1n,
    });

    await provider.connect(requesterSigner).requestRandomness(7);
    await coordinator.fulfillRandomWordsWithOverride(
      1,
      await provider.getAddress(),
      [111],
    );

    await expect(provider.connect(requesterSigner).requestRandomness(8))
      .to.be.revertedWithCustomError(
        provider,
        "InsufficientSubscriptionBalance",
      )
      .withArgs(1, 2);
  });

  it("reserves the balance floor for each unfulfilled draw", async function () {
    // ZEN2-07(b): a burst of requests in one block must not all pass the same balance check.
    const { provider, requesterSigner } = await setup({
      fundedBalance: 10n,
      minimumBalance: 5n,
    });

    await provider.connect(requesterSigner).requestRandomness(1);
    expect(await provider.pendingRequestCount()).to.equal(1n);
    await provider.connect(requesterSigner).requestRandomness(2);
    expect(await provider.pendingRequestCount()).to.equal(2n);

    await expect(provider.connect(requesterSigner).requestRandomness(3))
      .to.be.revertedWithCustomError(
        provider,
        "InsufficientSubscriptionBalance",
      )
      .withArgs(10, 15);
  });

  it("frees the reservation when a draw responds", async function () {
    const { coordinator, provider, requesterSigner } = await setup({
      fundedBalance: 10n,
      minimumBalance: 5n,
    });

    await provider.connect(requesterSigner).requestRandomness(1);
    await provider.connect(requesterSigner).requestRandomness(2);
    await coordinator.fulfillRandomWordsWithOverride(
      1,
      await provider.getAddress(),
      [111],
    );
    expect(await provider.pendingRequestCount()).to.equal(1n);
    await expect(
      provider.connect(requesterSigner).requestRandomness(3),
    ).to.emit(provider, "RandomnessRequested");
  });

  it("ignores a response to a released request", async function () {
    const { coordinator, owner, provider, requesterSigner } = await setup({
      fundedBalance: 10n,
      minimumBalance: 5n,
    });

    await provider.connect(requesterSigner).requestRandomness(1);
    expect(await provider.pendingRequestCount()).to.equal(1n);

    await provider.connect(owner).releaseAbandonedRequest(1);
    expect(await provider.pendingRequestCount()).to.equal(0n);

    // The reservation is back, so the released draw must stay unusable. Accepting it would let
    // the provider hold more usable draws than the reservation covers.
    await expect(
      coordinator.fulfillRandomWordsWithOverride(
        1,
        await provider.getAddress(),
        [222],
      ),
    ).to.emit(provider, "RandomnessResponseIgnored");

    const [fulfilled, randomWord] = await provider.getRandomness(1);
    expect(fulfilled).to.equal(false);
    expect(randomWord).to.equal(0n);
    expect(await provider.pendingRequestCount()).to.equal(0n);
  });

  it("lets the owner release the reservation of an abandoned draw", async function () {
    const { owner, provider, requesterSigner, other } = await setup({
      fundedBalance: 10n,
      minimumBalance: 5n,
    });

    await provider.connect(requesterSigner).requestRandomness(1);
    await provider.connect(requesterSigner).requestRandomness(2);

    await expect(
      provider.connect(other).releaseAbandonedRequest(1),
    ).to.be.revert(ethers);
    await expect(provider.connect(owner).releaseAbandonedRequest(99))
      .to.be.revertedWithCustomError(provider, "UnknownRandomnessRequest")
      .withArgs(99);

    await expect(provider.connect(owner).releaseAbandonedRequest(1))
      .to.emit(provider, "RandomnessRequestReleased")
      .withArgs(1);
    expect(await provider.pendingRequestCount()).to.equal(1n);
    await expect(provider.connect(owner).releaseAbandonedRequest(1))
      .to.be.revertedWithCustomError(provider, "RandomnessRequestNotReleasable")
      .withArgs(1);
  });

  it("does not revert the coordinator callback for an unknown response", async function () {
    const { coordinator, provider } = await setup();
    const coordinatorAddress = await coordinator.getAddress();
    await networkHelpers.impersonateAccount(coordinatorAddress);
    await networkHelpers.setBalance(coordinatorAddress, ethers.parseEther("1"));
    const coordinatorSigner = await ethers.getSigner(coordinatorAddress);

    await expect(
      provider.connect(coordinatorSigner).rawFulfillRandomWords(999, [1]),
    )
      .to.emit(provider, "RandomnessResponseIgnored")
      .withArgs(999);
  });

  it("keeps the first valid response when the coordinator calls back twice", async function () {
    const { coordinator, provider, requesterSigner } = await setup();
    await provider.connect(requesterSigner).requestRandomness(7);
    await coordinator.fulfillRandomWordsWithOverride(
      1,
      await provider.getAddress(),
      [111],
    );

    const coordinatorAddress = await coordinator.getAddress();
    await networkHelpers.impersonateAccount(coordinatorAddress);
    await networkHelpers.setBalance(coordinatorAddress, ethers.parseEther("1"));
    const coordinatorSigner = await ethers.getSigner(coordinatorAddress);
    await expect(
      provider.connect(coordinatorSigner).rawFulfillRandomWords(1, [222]),
    )
      .to.emit(provider, "RandomnessResponseIgnored")
      .withArgs(1);

    const [fulfilled, randomWord] = await provider.getRandomness(1);
    expect(fulfilled).to.equal(true);
    expect(randomWord).to.equal(111);
  });

  it("hands coordinator migration control to the protocol owner", async function () {
    const { owner, protocolOwner, provider } = await setup();
    expect(await provider.owner()).to.equal(await owner.getAddress());
    await provider.connect(protocolOwner).acceptOwnership();
    expect(await provider.owner()).to.equal(await protocolOwner.getAddress());
  });
});
