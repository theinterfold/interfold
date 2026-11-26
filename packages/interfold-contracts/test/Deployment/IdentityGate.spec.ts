// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
import { expect } from "chai";
import { ethers as ethersLib } from "ethers";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { proxyAdminInterface } from "../../scripts/protocol/constants";
import {
  deployOwnerIdentityRegistry,
  deployZKPassportIdentityVerifier,
} from "../../scripts/protocol/identityRegistry";
import type { ProtocolConfigFile } from "../../scripts/protocol/types";
import {
  EXECUTION_MARGIN,
  MAX_BATCH_OPERATORS,
  REFRESH_BATCH,
  buildIdentityGateTransactions,
  buildRevokeTransactions,
  changedIdentifierSettings,
  enforceDeadline,
  identityGateSettings,
  identityNamespace,
  identityPolicyOf,
  lateRegistrations,
  sameVerifierSettings,
  unrefreshedOperators,
} from "../../scripts/upgrade/identityGate";
import { readProofBundle } from "../../scripts/upgrade/identityProofFork";
import {
  BondingRegistry__factory as BondingRegistryFactory,
  OwnerIdentityRegistry__factory as OwnerIdentityRegistryFactory,
} from "../../types";
import {
  CAPACITY_WINDOW,
  PLANNED_IDENTITY,
  PROOF_BUNDLE_KIND,
  capacityWindowEnd,
  zkPassportVersion,
} from "../../zkpassport";
import { deployInterfoldSystem, ethers, networkHelpers } from "../fixtures";

const bondingInterface = BondingRegistryFactory.createInterface();
const registryInterface = OwnerIdentityRegistryFactory.createInterface();

function addr(n: number): string {
  return ethersLib.getAddress(ethersLib.toBeHex(n, 20));
}

function decode(tx: { to: string; data: string }) {
  for (const iface of [
    bondingInterface,
    proxyAdminInterface,
    registryInterface,
  ]) {
    const parsed = iface.parseTransaction({ data: tx.data });
    if (parsed) return { to: tx.to, name: parsed.name, args: parsed.args };
  }
  throw new Error(`unknown call ${tx.data.slice(0, 10)}`);
}

const operators = Array.from({ length: REFRESH_BATCH * 2 + 3 }, (_, i) =>
  addr(1_000 + i),
);

function config(identity: Record<string, unknown>): ProtocolConfigFile {
  return {
    name: "test-protocol",
    identity: {
      zkPassportRootVerifier: "0x1D000001000EFD9a6371f4d90bB8920D5431c0D8",
      zkPassportVersion: zkPassportVersion(0, 20, 0),
      domain: "dashboard.theinterfold.com",
      scope: "interfold-bond-owner",
      nullifierType: 0,
      oprfKeyHash: ethersLib.ZeroHash,
      faceMatchRequired: true,
      proofValidity: "604800",
      maxValidity: "31536000",
      ...identity,
    },
  } as unknown as ProtocolConfigFile;
}

describe("identity gate rollout", function () {
  it("upgrades, publishes the registry, then refreshes every operator", function () {
    const txs = buildIdentityGateTransactions({
      bondingRegistry: addr(1),
      upgrade: { proxyAdmin: addr(2), implementation: addr(3) },
      identityRegistry: addr(4),
      required: false,
      operators,
    }).map(decode);

    expect(txs.map((tx) => tx.name)).to.deep.equal([
      "upgradeAndCall",
      "setIdentityPolicy",
      "refreshOperatorStatuses",
      "refreshOperatorStatuses",
      "refreshOperatorStatuses",
    ]);
    expect(txs[0].to).to.equal(addr(2));
    expect([...txs[0].args]).to.deep.equal([addr(1), addr(3), "0x"]);
    expect(txs[1].to).to.equal(addr(1));
    expect([...txs[1].args]).to.deep.equal([addr(4), false]);
    // The refreshes cover every operator once, in order, in batches.
    const refreshed = txs.slice(2).flatMap((tx) => [...tx.args[0]]);
    expect(refreshed).to.deep.equal(operators);
    expect(txs[2].args[0]).to.have.length(REFRESH_BATCH);
  });

  it("switches the requirement without an upgrade", function () {
    for (const required of [true, false]) {
      const txs = buildIdentityGateTransactions({
        bondingRegistry: addr(1),
        identityRegistry: addr(4),
        required,
        operators: operators.slice(0, 2),
      }).map(decode);
      expect(txs.map((tx) => tx.name)).to.deep.equal([
        "setIdentityPolicy",
        "refreshOperatorStatuses",
      ]);
      expect([...txs[0].args]).to.deep.equal([addr(4), required]);
    }
  });

  it("revokes, then refreshes every operator in one batch", function () {
    const identityId = ethersLib.id("document");
    const txs = buildRevokeTransactions({
      bondingRegistry: addr(1),
      identityRegistry: addr(4),
      identityId,
      operators,
    }).map(decode);
    expect(txs[0].to).to.equal(addr(4));
    expect(txs[0].name).to.equal("revoke");
    expect([...txs[0].args]).to.deep.equal([identityId]);
    expect(txs.slice(1).map((tx) => tx.name)).to.deep.equal([
      "refreshOperatorStatuses",
      "refreshOperatorStatuses",
      "refreshOperatorStatuses",
    ]);
    expect(txs.slice(1).flatMap((tx) => [...tx.args[0]])).to.deep.equal(
      operators,
    );
    const many = Array.from({ length: MAX_BATCH_OPERATORS + 1 }, (_, i) =>
      addr(5_000 + i),
    );
    expect(() =>
      buildRevokeTransactions({
        bondingRegistry: addr(1),
        identityRegistry: addr(4),
        identityId,
        operators: many,
      }),
    ).to.throw(/refresh in stages/);
  });

  it("rotates a verifier only when its identifiers stay the same", function () {
    const current = identityGateSettings(config({}));
    const nextVersion = {
      ...current,
      zkPassportVersion: zkPassportVersion(0, 21, 0),
    };
    expect(changedIdentifierSettings(current, nextVersion)).to.deep.equal([]);
    expect(sameVerifierSettings(current, nextVersion)).to.equal(false);
    expect(
      sameVerifierSettings(current, {
        ...current,
        oprfKeyHash: current.oprfKeyHash.toUpperCase().replace("0X", "0x"),
      }),
    ).to.equal(true);
    expect(
      changedIdentifierSettings(current, {
        ...current,
        domain: "other.example",
        scope: "other-scope",
        nullifierType: 1,
        oprfKeyHash: ethersLib.id("key"),
      }),
    ).to.deep.equal(["domain", "scope", "identifier type", "OPRF key hash"]);
  });

  it("deploys mainnet with the settings that the verification page proves", function () {
    const mainnet = JSON.parse(
      fs.readFileSync(
        new URL(
          "../../deploy/protocol/mainnet-protocol.config.json",
          import.meta.url,
        ),
        "utf8",
      ),
    ) as ProtocolConfigFile;
    const settings = identityGateSettings(mainnet);
    expect({
      rootVerifier: settings.zkPassportRootVerifier,
      domain: settings.domain,
      scope: settings.scope,
      nullifierType: settings.nullifierType,
      faceMatchRequired: settings.faceMatchRequired,
      proofValidity: BigInt(settings.proofValidity),
      maxValidity: BigInt(settings.maxValidity),
    }).to.deep.equal(PLANNED_IDENTITY);
  });

  it("refuses verifier settings that the constructor or the plan would get wrong", function () {
    expect(identityGateSettings(config({})).domain).to.equal(
      "dashboard.theinterfold.com",
    );
    expect(() =>
      identityGateSettings({ name: "x" } as ProtocolConfigFile),
    ).to.throw(/no "identity" section/);
    expect(() =>
      identityGateSettings(config({ zkPassportVersion: ethersLib.ZeroHash })),
    ).to.throw(/zkPassportVersion is unset/);
    expect(() =>
      identityGateSettings(
        config({ zkPassportVersion: zkPassportVersion(0, 24, 0) }),
      ),
    ).to.throw(/does not know the public-input layout/);
    expect(() => identityGateSettings(config({ nullifierType: 1 }))).to.throw(
      /OPRF key hash/,
    );
    expect(() =>
      identityGateSettings(
        config({ oprfKeyHash: ethersLib.zeroPadValue("0x01", 32) }),
      ),
    ).to.throw(/OPRF key hash/);
    expect(() => identityGateSettings(config({ nullifierType: 2 }))).to.throw(
      /nullifierType/,
    );
    expect(() => identityGateSettings(config({ scope: "" }))).to.throw(
      /domain and identity.scope/,
    );
    expect(() => identityGateSettings(config({ maxValidity: "0" }))).to.throw(
      /maxValidity/,
    );
    expect(() =>
      identityGateSettings(config({ zkPassportRootVerifier: "0x1234" })),
    ).to.throw();
    // ethers would encode a missing or string flag silently.
    expect(() =>
      identityGateSettings(config({ faceMatchRequired: undefined })),
    ).to.throw(/faceMatchRequired/);
    expect(() =>
      identityGateSettings(config({ faceMatchRequired: "false" })),
    ).to.throw(/faceMatchRequired/);
    expect(() => identityGateSettings(config({ domain: 7 }))).to.throw(
      /domain and identity.scope/,
    );
    expect(() =>
      identityGateSettings(config({ maxValidity: (2n ** 48n).toString() })),
    ).to.throw(/uint48/);
  });

  it("reads only the identity panel's proof download", function () {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "identity-proof-"));
    const good = path.join(dir, "proof.json");
    const bad = path.join(dir, "other.json");
    fs.writeFileSync(
      good,
      JSON.stringify({
        kind: PROOF_BUNDLE_KIND,
        scope: "interfold-bond-owner",
      }),
    );
    fs.writeFileSync(bad, JSON.stringify({ kind: "other" }));
    expect(readProofBundle(good).scope).to.equal("interfold-bond-owner");
    expect(() => readProofBundle(bad)).to.throw(/not a proof download/);
  });

  it("refuses a batch that one transaction cannot refresh", function () {
    const many = Array.from({ length: MAX_BATCH_OPERATORS + 1 }, (_, i) =>
      addr(5_000 + i),
    );
    expect(() =>
      buildIdentityGateTransactions({
        bondingRegistry: addr(1),
        identityRegistry: addr(4),
        required: true,
        operators: many,
      }),
    ).to.throw(/refresh in stages/);
  });

  it("derives the identifier namespace as the verifier does", async function () {
    const helper = await ethers.deployContract("MockZKPassportHelper");
    const rootVerifier = await ethers.deployContract(
      "MockZKPassportRootVerifier",
      [await helper.getAddress(), ethersLib.ZeroHash],
    );
    // Mixed case: the verifier hashes the domain and scope exactly as given.
    const settings = identityGateSettings(
      config({
        domain: "Dashboard.TheInterfold.com",
        scope: "Interfold-Bond-Owner",
      }),
    );
    const verifier = await ethers.getContractAt(
      "ZKPassportIdentityVerifier",
      await deployZKPassportIdentityVerifier(ethers, {
        ...settings,
        zkPassportRootVerifier: await rootVerifier.getAddress(),
      }),
    );
    expect(await verifier.IDENTITY_NAMESPACE()).to.equal(
      identityNamespace(settings.domain, settings.scope),
    );
  });

  it("counts enforce owners to the window of the latest execution", function () {
    const start = CAPACITY_WINDOW * 680n;
    // Early in a window, a week later is still the same window.
    expect(enforceDeadline(start)).to.equal(capacityWindowEnd(start));
    // A week before the window ends, execution can fall in the next window.
    const late = start + CAPACITY_WINDOW - EXECUTION_MARGIN;
    expect(enforceDeadline(late)).to.equal(
      capacityWindowEnd(start + CAPACITY_WINDOW),
    );
    const day = new Date(Number(start + 86_400n) * 1000)
      .toISOString()
      .slice(0, 10);
    expect(enforceDeadline(start, day)).to.equal(capacityWindowEnd(start));
    expect(() => enforceDeadline(start + 2n * 86_400n, day)).to.throw(
      /in the past/,
    );
    expect(() => enforceDeadline(start, "next week")).to.throw(
      /must be a date/,
    );
  });

  it("finds registered operators that a batch did not refresh", function () {
    // Checksummed and lowercase forms name the same operator.
    expect(
      unrefreshedOperators(
        [addr(0xabc1), addr(0xabc2), addr(0xabc3)],
        [addr(0xabc1).toLowerCase(), addr(0xabc3)],
      ),
    ).to.deep.equal([addr(0xabc2)]);
    expect(unrefreshedOperators([addr(0xabc1)], [])).to.deep.equal([
      addr(0xabc1),
    ]);
  });

  it("reads the current identity policy from BondingRegistry storage", async function () {
    const ctx = await deployInterfoldSystem({});
    const bonding = await ctx.bondingRegistry.getAddress();
    expect(await identityPolicyOf(ethers.provider, bonding)).to.equal(null);
    const { proxy: registry } = await deployOwnerIdentityRegistry(
      ethers,
      await ctx.owner.getAddress(),
      ethersLib.ZeroAddress,
    );
    await ctx.bondingRegistry.setIdentityPolicy(registry, false);
    const at = BigInt(await networkHelpers.time.latest());
    expect(await identityPolicyOf(ethers.provider, bonding)).to.deep.equal({
      registry,
      required: false,
      timepoint: at,
    });
    await ctx.bondingRegistry.setIdentityPolicy(registry, true);
    expect(
      (await identityPolicyOf(ethers.provider, bonding))?.required,
    ).to.equal(true);
    // Clearing the registry turns the gate off.
    await ctx.bondingRegistry.setIdentityPolicy(ethersLib.ZeroAddress, false);
    expect(await identityPolicyOf(ethers.provider, bonding)).to.equal(null);
  });

  it("reads late registrations from the connected chain only", async function () {
    const topic = ethersLib.id(
      "CiphernodeAdded(address,uint256,uint256,uint256)",
    );
    const added = (operator: string, blockNumber: number) => ({
      blockNumber,
      topics: [topic, ethersLib.zeroPadValue(operator, 32)],
    });
    // The connected chain: on a fork, these include blocks that no public log RPC has.
    const logs = [
      added(addr(0xabc1), 10),
      added(addr(0xabc2), 12),
      added(addr(0xabc3), 13),
      added(addr(0xabc5), 20),
      added(addr(0xabc4), 30),
    ];
    const filters: unknown[] = [];
    const provider = {
      getLogs: async (filter: {
        address: string;
        topics: string[];
        fromBlock: number;
        toBlock: number;
      }) => {
        filters.push({ address: filter.address, topics: filter.topics });
        return logs.filter(
          (log) =>
            log.blockNumber >= filter.fromBlock &&
            log.blockNumber <= filter.toBlock,
        );
      },
    } as unknown as ethersLib.Provider;
    const registered = new Set([
      addr(0xabc1),
      addr(0xabc2),
      addr(0xabc4),
      addr(0xabc5),
    ]);
    // 0xabc1 is in the batch, 0xabc3 left again, 0xabc5 is in the policy block, and 0xabc4 came
    // after the policy change.
    expect(
      await lateRegistrations(
        provider,
        addr(9),
        async (operator) => registered.has(operator),
        10,
        20,
        [addr(0xabc1)],
      ),
    ).to.deep.equal([addr(0xabc2), addr(0xabc5)]);
    expect(filters).to.deep.equal([{ address: addr(9), topics: [topic] }]);
  });
});
