// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
import { expect } from "chai";
import type { Signer } from "ethers";

import type { ProtocolDeployment } from "../../scripts/protocol/types";
import { getProxyAdmin } from "../../scripts/proxy";
import { deployUpgradeImplementation } from "../../scripts/upgrade/safeProxyUpgrade";
import { requireV19RegistryUpgrade } from "../../scripts/upgrade/v19Cutover";
import {
  COMMITTEE_SIZE_LARGE,
  buildRequestParams,
  deployInterfoldSystem,
  encodeMockDkgProof,
  ethers,
  makeRequest,
  networkHelpers,
  setupOperatorForSortition,
} from "../fixtures";

const { loadFixture, time } = networkHelpers;

const LARGE_H = 34;
const LARGE_N = 45;
const SUBMISSION_WINDOW = 60;

// The v0.19 cutover replaces the registry implementation. `DkgPublicationLib` decodes the whole `E3`
// struct from `controller.getE3`, so an implementation compiled before `Large` (committee size 3)
// rejects every Large E3 in `publishCommittee`. This runs the cutover's own implementation deploy and
// `ProxyAdmin.upgradeAndCall`, then a full Large committee of 45 operators through the upgraded proxy.
describe("Large committee publication through the upgraded registry", function () {
  async function setup() {
    const sys = await deployInterfoldSystem({
      submissionWindow: SUBMISSION_WINDOW,
      setupOperators: 0,
      committeeThresholds: [[COMMITTEE_SIZE_LARGE, [LARGE_H, LARGE_N]]],
    });
    const registry = sys.ciphernodeRegistry;
    const registryProxy = await registry.getAddress();

    // The hardhat network has fewer accounts than a Large committee, so impersonate the rest.
    const operators: Signer[] = [];
    for (let i = 0; i < LARGE_N; i++) {
      const address = ethers.getAddress(ethers.toBeHex(0x4c0000 + i, 20));
      await networkHelpers.impersonateAccount(address);
      await networkHelpers.setBalance(address, ethers.parseEther("10"));
      const operator = await ethers.getSigner(address);
      await setupOperatorForSortition(
        operator,
        operator,
        sys.bondingRegistry,
        sys.ciphernodeBondToken,
        sys.usdcToken,
        sys.ticketToken,
        registry,
        sys.nodeReleaseRegistry,
      );
      operators.push(operator);
    }
    await time.increase(1);

    // The cutover's own implementation deploy, then its ProxyAdmin transaction.
    const poseidon = await ethers.deployContract("PoseidonT3");
    const upgrade = await deployUpgradeImplementation(
      ethers,
      sys.owner,
      "ciphernodeRegistry",
      { poseidonT3: await poseidon.getAddress() } as ProtocolDeployment,
    );
    const proxyAdmin = await ethers.getContractAt(
      "ProxyAdmin",
      await getProxyAdmin(ethers.provider, registryProxy),
      sys.owner,
    );
    await (
      await proxyAdmin.upgradeAndCall(
        registryProxy,
        upgrade.implementation,
        "0x",
      )
    ).wait();
    await requireV19RegistryUpgrade(ethers, {
      registryProxy,
      registryImplementation: upgrade.implementation,
      dkgPublicationLibrary: upgrade.dkgPublicationLibrary!,
    });

    return { ...sys, registry, operators };
  }

  it("publishes a Large committee, so the registry decodes a size-3 E3", async function () {
    const { registry, interfold, usdcToken, mocks, operators } =
      await loadFixture(setup);

    const e3Id = await interfold.nexte3Id();
    const params = await buildRequestParams(
      mocks.e3Program,
      mocks.decryptionVerifier,
      {
        committeeSize: COMMITTEE_SIZE_LARGE,
        startOffset: 100,
        windowDuration: 3600,
      },
    );
    await makeRequest(interfold, usdcToken, params);
    await time.increase(1);
    expect((await interfold.getE3(e3Id)).committeeSize).to.equal(
      BigInt(COMMITTEE_SIZE_LARGE),
    );

    for (const operator of operators) {
      await registry.connect(operator).submitTicket(e3Id, 1);
    }
    const deadline = await registry.getCommitteeDeadline(e3Id);
    await time.setNextBlockTimestamp(deadline + 1n);
    await registry.finalizeCommittee(e3Id);
    expect(await registry.committeeThresholdMet(e3Id)).to.equal(true);

    const pkCommitment = ethers.id("large-committee-public-key");
    await registry.publishCommittee(
      e3Id,
      pkCommitment,
      encodeMockDkgProof(pkCommitment),
      "0x01",
    );
    expect(await registry.committeePublicKey(e3Id)).to.equal(pkCommitment);
    expect(await registry.getCommitteeNodes(e3Id)).to.have.length(LARGE_N);
  });
});
