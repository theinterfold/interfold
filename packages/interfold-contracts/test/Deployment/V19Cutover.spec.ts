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

import {
  BFV_SCHEME_ID,
  buildV19CutoverTransactions,
  readOpenVmIdentity,
  resolveOpenVmCrisp,
} from "../../scripts/upgrade/v19Cutover";
import {
  Interfold__factory as InterfoldFactory,
  NodeReleaseRegistry__factory as NodeReleaseRegistryFactory,
} from "../../types";

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
    paramSet: { index: 2, encoded: "0x1234" },
    committeeThresholds: [{ size: 2n, quorum: 9n, total: 20n }],
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
      "setParamSet",
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
    const pk = interfoldInterface.parseTransaction({ data: txs[3].data })!;
    expect(pk.args[0]).to.equal(BFV_SCHEME_ID);
    expect(pk.args[1]).to.equal(addr(4));
  });

  it("leaves out the steps that the chain already satisfies", function () {
    const txs = buildV19CutoverTransactions({
      ...decisions(),
      paramSet: undefined,
      committeeThresholds: [],
      ciphertextVerifier: undefined,
      registerProgram: undefined,
      retirePrograms: [],
      bindProgram: undefined,
      nodeRelease: undefined,
    });
    expect(names(txs).slice(1)).to.deep.equal([
      "setPkVerifier",
      "setDecryptionVerifier",
    ]);
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
});
