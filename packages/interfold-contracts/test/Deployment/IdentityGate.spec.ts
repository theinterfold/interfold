// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
import { expect } from "chai";
import { ethers as ethersLib } from "ethers";

import { proxyAdminInterface } from "../../scripts/protocol/constants";
import type { ProtocolConfigFile } from "../../scripts/protocol/types";
import {
  REFRESH_BATCH,
  buildIdentityGateTransactions,
  identityGateSettings,
} from "../../scripts/upgrade/identityGate";
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
  });
});
