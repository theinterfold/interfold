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
import type { ProtocolConfigFile } from "../../scripts/protocol/types";
import {
  CAPACITY_WINDOW,
  MAX_BATCH_OPERATORS,
  REFRESH_BATCH,
  buildIdentityGateTransactions,
  capacityWindowEnd,
  identityGateSettings,
  identityNamespace,
} from "../../scripts/upgrade/identityGate";
import {
  type ProofBundle,
  expectedIdentityId,
  readProofBundle,
} from "../../scripts/upgrade/identityProofFork";
import { BondingRegistry__factory as BondingRegistryFactory } from "../../types";

const bondingInterface = BondingRegistryFactory.createInterface();

function addr(n: number): string {
  return ethersLib.getAddress(ethersLib.toBeHex(n, 20));
}

function decode(tx: { to: string; data: string }) {
  for (const iface of [bondingInterface, proxyAdminInterface]) {
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
      zkPassportVersion: ethersLib.zeroPadValue("0x14", 32),
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

  it("derives the identifier of a downloaded proof as the verifier does", function () {
    const domain = "dashboard.theinterfold.com";
    const scope = "interfold-bond-owner";
    const nullifier = ethersLib.id("document scoped nullifier");
    const coder = ethersLib.AbiCoder.defaultAbiCoder();
    const namespace = ethersLib.keccak256(
      coder.encode(
        ["string", "string", "string"],
        ["interfold.identity.zkpassport.v1", domain, scope],
      ),
    );
    const bundle = {
      kind: "interfold.identity.zkpassport-proof",
      domain,
      scope,
      params: {
        proofVerificationData: {
          // The pinned version ends with [nullifier type, scoped nullifier, OPRF key hash].
          publicInputs: [
            ethersLib.ZeroHash,
            ethersLib.ZeroHash,
            nullifier,
            ethersLib.ZeroHash,
          ],
        },
      },
    } as unknown as ProofBundle;
    expect(expectedIdentityId(bundle)).to.equal(
      ethersLib.keccak256(
        coder.encode(["bytes32", "bytes32"], [namespace, nullifier]),
      ),
    );

    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "identity-proof-"));
    const good = path.join(dir, "proof.json");
    const bad = path.join(dir, "other.json");
    fs.writeFileSync(good, JSON.stringify(bundle));
    fs.writeFileSync(bad, JSON.stringify({ kind: "other" }));
    expect(readProofBundle(good).scope).to.equal(scope);
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

  it("matches the contract's capacity window and identifier namespace", function () {
    const start = CAPACITY_WINDOW * 680n;
    expect(capacityWindowEnd(start)).to.equal(start + CAPACITY_WINDOW - 1n);
    expect(capacityWindowEnd(start + CAPACITY_WINDOW)).to.equal(
      start + 2n * CAPACITY_WINDOW - 1n,
    );
    const coder = ethersLib.AbiCoder.defaultAbiCoder();
    const domain = "dashboard.theinterfold.com";
    expect(identityNamespace(domain, "interfold-bond-owner")).to.equal(
      ethersLib.keccak256(
        coder.encode(
          ["string", "string", "string"],
          ["interfold.identity.zkpassport.v1", domain, "interfold-bond-owner"],
        ),
      ),
    );
    // A scope that differs only in case is another namespace.
    expect(identityNamespace(domain, "Interfold-bond-owner")).to.not.equal(
      identityNamespace(domain, "interfold-bond-owner"),
    );
  });
});
