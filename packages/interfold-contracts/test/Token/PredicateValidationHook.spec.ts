// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
import { expect } from "chai";

import {
  MockPredicateRegistry__factory as MockPredicateRegistryFactory,
  MockValidationHookCaller__factory as MockValidationHookCallerFactory,
  PredicateValidationHook__factory as PredicateValidationHookFactory,
} from "../../types";
import { ethers, networkHelpers } from "../fixtures";

const { loadFixture } = networkHelpers;
const POLICY_ID = "x-interfold-cca";
const ATTESTATION_TUPLE =
  "tuple(string uuid,uint256 expiration,address attester,bytes signature)";

function encodeAttestation(opts: {
  uuid?: string;
  expiration?: bigint;
  attester: string;
  signature?: string;
}) {
  return ethers.AbiCoder.defaultAbiCoder().encode(
    [ATTESTATION_TUPLE],
    [
      [
        opts.uuid ?? "attestation-1",
        opts.expiration ?? 4_102_444_800n,
        opts.attester,
        opts.signature ?? "0x1234",
      ],
    ],
  );
}

describe("PredicateValidationHook", function () {
  async function deploy() {
    const [deployer, safe, bidder, delegate, stranger, attester] =
      await ethers.getSigners();

    const registryFactory = new MockPredicateRegistryFactory(deployer);
    const registry = await registryFactory.deploy();
    await registry.waitForDeployment();

    const hookFactory = new PredicateValidationHookFactory(deployer);
    const hook = await hookFactory.deploy(
      await safe.getAddress(),
      await registry.getAddress(),
      POLICY_ID,
      true,
    );
    await hook.waitForDeployment();

    const callerFactory = new MockValidationHookCallerFactory(deployer);
    const auction = await callerFactory.deploy();
    await auction.waitForDeployment();

    return {
      deployer,
      safe,
      bidder,
      delegate,
      stranger,
      attester,
      registryFactory,
      registry,
      hookFactory,
      hook,
      auction,
    };
  }

  it("registers Predicate policy under the hook address", async function () {
    const { hook, registry, safe } = await loadFixture(deploy);
    const hookAddress = await hook.getAddress();

    expect(await hook.owner()).to.equal(await safe.getAddress());
    expect(await hook.getRegistry()).to.equal(await registry.getAddress());
    expect(await hook.getPolicyID()).to.equal(POLICY_ID);
    expect(await registry.getPolicyID(hookAddress)).to.equal(POLICY_ID);
  });

  it("requires the Safe owner to set a deployed auction contract", async function () {
    const { hook, safe, stranger, auction } = await loadFixture(deploy);

    await expect(hook.connect(stranger).setAuction(await auction.getAddress()))
      .to.be.revertedWithCustomError(hook, "OwnableUnauthorizedAccount")
      .withArgs(await stranger.getAddress());

    await expect(hook.connect(safe).setAuction(await stranger.getAddress()))
      .to.be.revertedWithCustomError(hook, "NoContractCode")
      .withArgs(await stranger.getAddress());

    await expect(hook.connect(safe).setAuction(await auction.getAddress()))
      .to.emit(hook, "AuctionSet")
      .withArgs(await auction.getAddress());
  });

  it("validates attestation hookData from the configured auction only", async function () {
    const { hook, registry, safe, bidder, attester, stranger, auction } =
      await loadFixture(deploy);
    await hook.connect(safe).setAuction(await auction.getAddress());

    const bidderAddress = await bidder.getAddress();
    const hookData = encodeAttestation({
      uuid: "cca-bid-1",
      attester: await attester.getAddress(),
    });

    await expect(
      hook.validate(1n, 2n, bidderAddress, bidderAddress, hookData),
    ).to.be.revertedWithCustomError(hook, "CallerMustBeAuction");

    await expect(
      auction.callValidate(
        await hook.getAddress(),
        1n,
        2n,
        bidderAddress,
        await stranger.getAddress(),
        hookData,
      ),
    ).to.be.revertedWithCustomError(hook, "SenderMustBeOwner");

    await expect(
      auction.callValidate(
        await hook.getAddress(),
        1n,
        2n,
        bidderAddress,
        bidderAddress,
        hookData,
      ),
    )
      .to.emit(hook, "AttestationValidated")
      .withArgs(bidderAddress, "cca-bid-1");

    const statement = await registry.lastStatement();
    expect(statement.uuid).to.equal("cca-bid-1");
    expect(statement.msgSender).to.equal(bidderAddress);
    expect(statement.target).to.equal(await hook.getAddress());
    expect(statement.msgValue).to.equal(0n);
    expect(statement.encodedSigAndArgs).to.equal("0x");
    expect(statement.policy).to.equal(POLICY_ID);
  });

  it("can allow delegated owners when explicitly configured", async function () {
    const { hook, registry, safe, bidder, delegate, attester, auction } =
      await loadFixture(deploy);
    await hook.connect(safe).setAuction(await auction.getAddress());
    await hook.connect(safe).setRequireSenderIsOwner(false);

    const delegateAddress = await delegate.getAddress();
    const hookData = encodeAttestation({
      uuid: "delegated-bid",
      attester: await attester.getAddress(),
    });

    await auction.callValidate(
      await hook.getAddress(),
      1n,
      2n,
      await bidder.getAddress(),
      delegateAddress,
      hookData,
    );

    const statement = await registry.lastStatement();
    expect(statement.uuid).to.equal("delegated-bid");
    expect(statement.msgSender).to.equal(delegateAddress);
  });

  it("reverts when Predicate rejects the attestation", async function () {
    const { hook, registry, safe, bidder, attester, auction } =
      await loadFixture(deploy);
    await hook.connect(safe).setAuction(await auction.getAddress());
    await registry.setShouldValidate(false);

    const bidderAddress = await bidder.getAddress();
    const hookData = encodeAttestation({
      attester: await attester.getAddress(),
    });

    await expect(
      auction.callValidate(
        await hook.getAddress(),
        1n,
        2n,
        bidderAddress,
        bidderAddress,
        hookData,
      ),
    ).to.be.revertedWithCustomError(hook, "InvalidAttestation");
  });

  it("rejects a non-contract Predicate registry", async function () {
    const { hookFactory, safe, stranger } = await loadFixture(deploy);
    await expect(
      hookFactory.deploy(
        await safe.getAddress(),
        await stranger.getAddress(),
        POLICY_ID,
        true,
      ),
    )
      .to.be.revertedWithCustomError(hookFactory, "NoContractCode")
      .withArgs(await stranger.getAddress());
  });
});
