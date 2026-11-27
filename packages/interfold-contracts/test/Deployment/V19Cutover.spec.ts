// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
import { expect } from "chai";
import { ethers as ethersLib } from "ethers";
import fs from "fs";
import os from "os";
import path from "path";

import { proxyAdminInterface } from "../../scripts/protocol/constants";
import type { ProtocolDeployment } from "../../scripts/protocol/types";
import { getProxyAdmin } from "../../scripts/proxy";
import { deployUpgradeImplementation } from "../../scripts/upgrade/safeProxyUpgrade";
import {
  BFV_SCHEME_ID,
  SIZES_ADDED_BY_RELEASE,
  buildV19CutoverTransactions,
  readCommitteeThreshold,
  readOpenVmIdentity,
  requireTimeoutConfig,
  requireV19RegistryUpgrade,
  resolveOpenVmCrisp,
} from "../../scripts/upgrade/v19Cutover";
import {
  Interfold__factory as InterfoldFactory,
  NodeReleaseRegistry__factory as NodeReleaseRegistryFactory,
} from "../../types";
import { ethers } from "../fixtures";

const interfoldInterface = InterfoldFactory.createInterface();
const releaseInterface = NodeReleaseRegistryFactory.createInterface();

function addr(n: number): string {
  return ethersLib.getAddress(ethersLib.toBeHex(n, 20));
}

function decisions() {
  return {
    interfold: addr(1),
    interfoldProxyAdmin: addr(2),
    interfoldImplementation: addr(3),
    registry: addr(10),
    registryProxyAdmin: addr(11),
    registryImplementation: addr(12),
    paramSets: [{ index: 3, encoded: "0x1234" }],
    committeeThresholds: [
      { size: 2n, quorum: 9n, total: 20n },
      { size: 3n, quorum: 34n, total: 45n },
    ],
    pkVerifier: addr(4),
    decryptionVerifier: addr(5),
    ciphertextVerifier: addr(6),
    registerProgram: addr(7),
    retirePrograms: [addr(8)],
    bindProgram: addr(7),
    nodeReleaseRegistry: addr(9),
    nodeRelease: { protocolVersion: 8, nodeGeneration: 2 },
  };
}

function names(txs: { to: string; data: string }[]): string[] {
  return txs.map((tx) => {
    for (const iface of [interfoldInterface, releaseInterface]) {
      const parsed = iface.parseTransaction({ data: tx.data });
      if (parsed) return parsed.name;
    }
    return tx.data.slice(0, 10);
  });
}

describe("v0.19 cutover", function () {
  it("orders the batch: upgrade first, register before bind, release policy last", function () {
    const txs = buildV19CutoverTransactions(decisions());
    const upgradeAndCall = ethersLib
      .id("upgradeAndCall(address,address,bytes)")
      .slice(0, 10);
    const bindInterfold = ethersLib.id("bindInterfold(address)").slice(0, 10);
    expect(names(txs)).to.deep.equal([
      upgradeAndCall,
      upgradeAndCall,
      "setParamSet",
      "setCommitteeThresholds",
      "setCommitteeThresholds",
      "setPkVerifier",
      "setDecryptionVerifier",
      "setCiphertextVerifier",
      "registerE3Program",
      "unregisterE3Program",
      bindInterfold,
      "setRequiredNodeRelease",
    ]);
    expect(txs[0].to).to.equal(addr(2));
    expect(txs[txs.length - 1].to).to.equal(addr(9));
    const pk = interfoldInterface.parseTransaction({ data: txs[5].data })!;
    expect(pk.args[0]).to.equal(BFV_SCHEME_ID);
    expect(pk.args[1]).to.equal(addr(4));
  });

  it("pauses requests as the first action with --pause-in-batch", function () {
    const txs = buildV19CutoverTransactions({
      ...decisions(),
      pauseRequests: true,
    });
    const pause = interfoldInterface.parseTransaction({ data: txs[0].data })!;
    expect(txs[0].to).to.equal(addr(1));
    expect(pause.name).to.equal("setRequestsPaused");
    expect(pause.args[0]).to.equal(true);
    expect(txs.slice(1)).to.deep.equal(
      buildV19CutoverTransactions(decisions()),
    );
  });

  it("checks the drain on chain when a paused batch keeps the release policy", function () {
    const txs = buildV19CutoverTransactions({
      ...decisions(),
      pauseRequests: true,
      nodeRelease: undefined,
    });
    expect(
      interfoldInterface.parseTransaction({ data: txs[0].data })!.name,
    ).to.equal("setRequestsPaused");
    expect(txs[1].to).to.equal(addr(9));
    expect(
      releaseInterface.parseTransaction({ data: txs[1].data })!.name,
    ).to.equal("assertUpgradeWindow");
    expect(
      buildV19CutoverTransactions({
        ...decisions(),
        nodeRelease: undefined,
      }).some((tx) => tx.to === addr(9)),
    ).to.equal(false);
  });

  it("upgrades the registry right after Interfold and before the Large threshold", function () {
    const txs = buildV19CutoverTransactions(decisions());
    // A registry that predates `Large` rejects a size-3 E3 in its `E3` decode, so it must be
    // replaced before governance can set the Large threshold.
    const [interfoldUpgrade, registryUpgrade] = txs.slice(0, 2).map((tx) => ({
      to: tx.to,
      args: proxyAdminInterface.decodeFunctionData("upgradeAndCall", tx.data),
    }));
    expect(interfoldUpgrade.to).to.equal(addr(2));
    expect([...interfoldUpgrade.args]).to.deep.equal([addr(1), addr(3), "0x"]);
    expect(registryUpgrade.to).to.equal(addr(11));
    expect([...registryUpgrade.args]).to.deep.equal([addr(10), addr(12), "0x"]);
    const large = txs.findIndex((tx) => {
      const parsed = interfoldInterface.parseTransaction({ data: tx.data });
      return parsed?.name === "setCommitteeThresholds" && parsed.args[0] === 3n;
    });
    expect(large).to.be.greaterThan(1);
  });

  it("leaves out the steps that the chain already satisfies", function () {
    const txs = buildV19CutoverTransactions({
      ...decisions(),
      paramSets: [],
      committeeThresholds: [],
      ciphertextVerifier: undefined,
      registerProgram: undefined,
      retirePrograms: [],
      bindProgram: undefined,
      nodeRelease: undefined,
    });
    expect(names(txs).slice(2)).to.deep.equal([
      "setPkVerifier",
      "setDecryptionVerifier",
    ]);
  });

  it("registers every parameter set that the chain lacks", function () {
    const paramSets = [
      { index: 4, encoded: "0x12" },
      { index: 3, encoded: "0x34" },
    ];
    const registered = buildV19CutoverTransactions({
      ...decisions(),
      paramSets,
    })
      .map((tx) => interfoldInterface.parseTransaction({ data: tx.data }))
      .filter((parsed) => parsed?.name === "setParamSet")
      .map((parsed) => ({
        index: Number(parsed!.args[0]),
        encoded: parsed!.args[1],
      }));
    expect(registered).to.deep.equal(paramSets);
  });

  it("rejects the old Sepolia DKG window against the shipped configuration", function () {
    const configured = JSON.parse(
      fs.readFileSync(
        new URL(
          "../../deploy/protocol/sepolia-protocol.config.json",
          import.meta.url,
        ),
        "utf8",
      ),
    ).interfold.timeoutConfig;
    // Live Sepolia before the cutover's `setTimeoutConfig`.
    const live = {
      dkgWindow: 1800n,
      computeWindow: 604800n,
      decryptionWindow: 21600n,
    };
    expect(() => requireTimeoutConfig(live, configured)).to.throw(
      /dkgWindow is 1800 s; the configuration sets 7200 s/,
    );
    expect(() =>
      requireTimeoutConfig({ ...live, dkgWindow: 7200n }, configured),
    ).not.to.throw();
  });

  it("reads a committee size that the replaced implementation lacks as unset", async function () {
    const reverting = (error: unknown) => async (): Promise<bigint> => {
      throw error;
    };
    // Live Sepolia answers `committeeThresholds(3, …)` with an empty revert.
    expect(
      await readCommitteeThreshold(
        reverting({ code: 3, data: "0x" }),
        3n,
        SIZES_ADDED_BY_RELEASE,
      ),
    ).to.equal(undefined);
    // A size the replaced implementation already has must answer; an empty revert there is an error.
    await expect(
      readCommitteeThreshold(
        reverting({ code: 3, data: "0x" }),
        0n,
        SIZES_ADDED_BY_RELEASE,
      ),
    ).to.be.rejected;
    // A transport failure is not a missing function.
    await expect(
      readCommitteeThreshold(
        reverting(new Error("RPC unavailable")),
        3n,
        SIZES_ADDED_BY_RELEASE,
      ),
    ).to.be.rejectedWith("RPC unavailable");
    const live = async (index: bigint) => (index === 0n ? 34n : 45n);
    expect(
      await readCommitteeThreshold(live, 3n, SIZES_ADDED_BY_RELEASE),
    ).to.deep.equal([34n, 45n]);
  });

  it("reads an OpenVM guest identity and refuses a malformed one", function () {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "v19-identity-"));
    const good = path.join(dir, "good.json");
    const identity = {
      appExeCommit: ethersLib.toBeHex(1n, 32),
      appVmCommit: ethersLib.toBeHex(2n, 32),
      halo2RuntimeCodeHash: ethersLib.keccak256("0x00"),
    };
    fs.writeFileSync(good, JSON.stringify(identity));
    expect(readOpenVmIdentity(good)).to.deep.equal(identity);

    const bad = path.join(dir, "bad.json");
    fs.writeFileSync(bad, JSON.stringify({ ...identity, appVmCommit: "0x02" }));
    expect(() => readOpenVmIdentity(bad)).to.throw("appVmCommit");
  });

  it("reads the OpenVM CRISP contracts and refuses a RISC Zero record", function () {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "v19-crisp-"));
    const record = path.join(dir, "deployed_contracts.json");
    fs.writeFileSync(
      record,
      JSON.stringify({
        mainnet: {
          CRISPProgram: { address: addr(10) },
          OpenVmBfvCiphertextVerifier: { address: addr(11) },
          AvailVectorXDataAvailabilityVerifier: { address: addr(12) },
        },
        sepolia: {
          CRISPProgram: { address: addr(13) },
          Risc0BfvCiphertextVerifier: { address: addr(14) },
          MockCrispDataAvailabilityVerifier: { address: addr(15) },
        },
      }),
    );
    expect(resolveOpenVmCrisp("mainnet", record)).to.deep.equal({
      crispProgram: addr(10),
      ciphertextVerifier: addr(11),
      dataAvailabilityVerifier: addr(12),
      availDataAvailability: true,
    });
    expect(() => resolveOpenVmCrisp("sepolia", record)).to.throw(
      "OpenVmBfvCiphertextVerifier",
    );
  });

  it("requires the CRISP deployment record to be named", function () {
    expect(() => resolveOpenVmCrisp("mainnet")).to.throw("--crisp-deployments");
  });

  it("fails validation while the registry implementation is stale", async function () {
    const [owner] = await ethers.getSigners();
    const poseidon = await ethers.deployContract("PoseidonT3");
    const deployment = {
      poseidonT3: await poseidon.getAddress(),
    } as ProtocolDeployment;
    // Each call deploys fresh libraries, so the two implementations differ in address and links.
    const stale = await deployUpgradeImplementation(
      ethers,
      owner,
      "ciphernodeRegistry",
      deployment,
    );
    const planned = await deployUpgradeImplementation(
      ethers,
      owner,
      "ciphernodeRegistry",
      deployment,
    );
    const proxy = await ethers.deployContract("TransparentUpgradeableProxy", [
      stale.implementation,
      owner.address,
      "0x",
    ]);
    const registryProxy = await proxy.getAddress();
    const plan = {
      registryProxy,
      registryImplementation: planned.implementation,
      dkgPublicationLibrary: planned.dkgPublicationLibrary!,
    };

    await expect(requireV19RegistryUpgrade(ethers, plan)).to.be.rejectedWith(
      "CiphernodeRegistry implementation mismatch",
    );

    const proxyAdmin = await ethers.getContractAt(
      "ProxyAdmin",
      await getProxyAdmin(ethers.provider, registryProxy),
      owner,
    );
    await (
      await proxyAdmin.upgradeAndCall(
        registryProxy,
        planned.implementation,
        "0x",
      )
    ).wait();
    await requireV19RegistryUpgrade(ethers, plan);

    // The planned library must be the one that the implementation links.
    await expect(
      requireV19RegistryUpgrade(ethers, {
        ...plan,
        dkgPublicationLibrary: stale.dkgPublicationLibrary!,
      }),
    ).to.be.rejectedWith("registry DkgPublicationLib link mismatch");
  });
});
