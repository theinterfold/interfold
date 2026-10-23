// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
import { expect } from "chai";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { selectCanonicalVerifierFqn } from "../../scripts/deployAndSave/verifiers";

describe("verifier artifact selection", function () {
  const contractName = "DkgAggregatorVerifier";
  const source = `contracts/verifiers/bfv/honk/${contractName}.sol:${contractName}`;

  it("selects the canonical verifier when preset artifacts have the same name", function () {
    expect(
      selectCanonicalVerifierFqn(
        [
          `project/${source}`,
          `project/contracts/verifiers/bfv/honk/insecure-64/minimum/${contractName}.sol:${contractName}`,
          `project/contracts/verifiers/bfv/honk/secure-8192/small/${contractName}.sol:${contractName}`,
        ],
        contractName,
      ),
    ).to.equal(source);
  });

  it("normalizes the canonical verifier from the package artifact namespace", function () {
    expect(
      selectCanonicalVerifierFqn(
        [
          `npm/@interfold/contracts@1.2.3/${source}`,
          `npm/@interfold/contracts@1.2.3/contracts/verifiers/bfv/honk/secure-8192/minimum/${contractName}.sol:${contractName}`,
        ],
        contractName,
      ),
    ).to.equal(`@interfold/contracts/${source}`);
  });

  it("rejects an artifact set without the canonical verifier", function () {
    expect(() =>
      selectCanonicalVerifierFqn(
        [
          `project/contracts/verifiers/bfv/honk/insecure-64/minimum/${contractName}.sol:${contractName}`,
        ],
        contractName,
      ),
    ).to.throw(
      `Expected one canonical artifact for ${contractName} in contracts/verifiers/bfv/honk, found 0.`,
    );
  });

  it("resolves named identities from the matching package/archive pair and raw hashes", function () {
    const temp = fs.mkdtempSync(
      path.join(tmpdir(), "interfold-named-identities-"),
    );
    try {
      const packageRoot = fileURLToPath(new URL("../../", import.meta.url));
      const installed = path.join(temp, "package");
      fs.mkdirSync(path.join(installed, "dist/scripts"), { recursive: true });
      fs.mkdirSync(path.join(installed, "node_modules"));
      fs.writeFileSync(
        path.join(installed, "package.json"),
        JSON.stringify({ name: "@interfold/contracts", type: "module" }),
      );
      fs.symlinkSync(
        path.join(packageRoot, "node_modules/ethers"),
        path.join(installed, "node_modules/ethers"),
        "dir",
      );
      for (const file of ["scripts/utils.js", "bfv.js"]) {
        fs.copyFileSync(
          path.join(packageRoot, "dist", file),
          path.join(installed, "dist", file),
        );
      }
      const directory = path.join(temp, "circuits");
      const pairDirectory = path.join(directory, "insecure-64/minimum");
      const hash = path.join(
        pairDirectory,
        "default/threshold/user_data_encryption/user_data_encryption.vk_hash",
      );
      fs.mkdirSync(path.dirname(hash), { recursive: true });
      const value = `0x${"00".repeat(31)}01`;
      fs.writeFileSync(hash, Buffer.from(value.slice(2), "hex"));
      const key = "bb-vk-hash/default/threshold/user_data_encryption";
      const pair = {
        preset: "insecure-64",
        committee: "minimum",
        identities: { [key]: value },
      };
      const stamp = path.join(pairDirectory, ".build-stamp.json");
      fs.writeFileSync(
        stamp,
        JSON.stringify({
          preset: pair.preset,
          committee: pair.committee,
          sourceHash: "fixture-source",
        }),
      );
      const publish = (data: unknown) => {
        fs.writeFileSync(
          path.join(installed, "dist/circuit-identities.json"),
          JSON.stringify({ formatVersion: 1, pairs: [data] }),
        );
        fs.writeFileSync(
          path.join(pairDirectory, "identities.json"),
          JSON.stringify(data),
        );
      };
      const check = (circuit = "threshold/user_data_encryption") =>
        execFileSync(
          process.execPath,
          [
            "--input-type=module",
            "-e",
            `import { readBfvCircuitIdentity } from ${JSON.stringify(pathToFileURL(path.join(installed, "dist/scripts/utils.js")).href)}; console.log(readBfvCircuitIdentity(${JSON.stringify(circuit)}, "default", "bb-vk-hash"));`,
          ],
          {
            cwd: temp,
            env: { ...process.env, INTERFOLD_CIRCUITS_DIR: directory },
            stdio: "pipe",
            encoding: "utf8",
          },
        ).trim();

      publish(pair);
      expect(check()).to.equal(value);
      fs.rmSync(path.join(installed, "dist/circuit-identities.json"));
      expect(() => check()).to.throw(/Missing circuit identity manifest/);
      publish(pair);
      fs.writeFileSync(hash, Buffer.alloc(32));
      expect(() => check()).to.throw(/VK hash differs/);
      fs.writeFileSync(hash, Buffer.from(value.slice(2), "hex"));
      fs.writeFileSync(
        path.join(pairDirectory, "identities.json"),
        JSON.stringify({ ...pair, identities: {} }),
      );
      expect(() => check()).to.throw(/slice differs/);
      publish({ ...pair, identities: {} });
      expect(() => check()).to.throw(/Missing named circuit identity/);
      publish(pair);
      expect(() => check("../escape")).to.throw(
        /Invalid circuit identity name/,
      );
      fs.writeFileSync(
        stamp,
        JSON.stringify({
          preset: pair.preset,
          committee: "small",
          sourceHash: "fixture-source",
        }),
      );
      expect(() => check()).to.throw(/pair stamp differs/);
    } finally {
      fs.rmSync(temp, { recursive: true, force: true });
    }
  });
});
