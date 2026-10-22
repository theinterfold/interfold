// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
import { expect } from "chai";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
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

  it("resolves named package identities only with their matching artifacts and archive slice", function () {
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
      fs.copyFileSync(
        path.join(packageRoot, "dist/scripts/utils.js"),
        path.join(installed, "dist/scripts/utils.js"),
      );
      fs.copyFileSync(
        path.join(packageRoot, "dist/bfv.js"),
        path.join(installed, "dist/bfv.js"),
      );
      const directory = path.join(temp, "circuits");
      const relative = "insecure-64/minimum/recursive/threshold/a/a";
      const compiled = path.join(directory, `${relative}.json`);
      fs.mkdirSync(path.dirname(compiled), { recursive: true });
      fs.writeFileSync(compiled, "compiled fixture");
      fs.writeFileSync(path.join(directory, `${relative}.vk`), "key fixture");
      const value = `0x${"00".repeat(31)}01`;
      fs.writeFileSync(
        path.join(directory, `${relative}.vk_hash`),
        Buffer.from(value.slice(2), "hex"),
      );
      const key = {
        preset: "insecure-64",
        committee: "minimum",
        circuit: "threshold/a",
        proofVariant: "recursive",
        hashKind: "bb-vk-hash",
      };
      const digest = (filename: string) =>
        createHash("sha256").update(fs.readFileSync(filename)).digest("hex");
      const entry = {
        key,
        value,
        compiledArtifact: {
          path: `${relative}.json`,
          sha256: digest(compiled),
        },
        verificationKey: {
          path: `${relative}.vk`,
          sha256: digest(path.join(directory, `${relative}.vk`)),
        },
        dependencies: [],
      };
      const pair = {
        preset: "insecure-64",
        committee: "minimum",
        sourceHash: "fixture-source",
        entries: [entry],
      };
      const pairDirectory = path.join(directory, "insecure-64/minimum");
      fs.writeFileSync(
        path.join(pairDirectory, ".build-stamp.json"),
        JSON.stringify({
          preset: pair.preset,
          committee: pair.committee,
          sourceHash: pair.sourceHash,
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
      publish(pair);
      const check = (circuit = "threshold/a", kind = "bb-vk-hash") =>
        execFileSync(
          process.execPath,
          [
            "--input-type=module",
            "-e",
            `import { readBfvCircuitIdentity } from ${JSON.stringify(pathToFileURL(path.join(installed, "dist/scripts/utils.js")).href)}; console.log(readBfvCircuitIdentity(${JSON.stringify(circuit)}, ${JSON.stringify(kind === "recursive-tree-commitment" ? "default" : "recursive")}, ${JSON.stringify(kind)}));`,
          ],
          {
            cwd: temp,
            env: { ...process.env, INTERFOLD_CIRCUITS_DIR: directory },
            stdio: "pipe",
            encoding: "utf8",
          },
        ).trim();
      expect(check()).to.equal(value);
      fs.rmSync(path.join(installed, "dist/circuit-identities.json"));
      expect(() => check()).to.throw(/Missing circuit identity manifest/);
      publish(pair);
      fs.writeFileSync(compiled, "different compiled circuit");
      expect(() => check()).to.throw(/digest differs/);
      fs.writeFileSync(compiled, "compiled fixture");
      fs.writeFileSync(
        path.join(directory, `${relative}.vk_hash`),
        Buffer.alloc(32),
      );
      expect(() => check()).to.throw(/VK hash differs/);
      fs.writeFileSync(
        path.join(directory, `${relative}.vk_hash`),
        Buffer.from(value.slice(2), "hex"),
      );
      fs.writeFileSync(
        path.join(pairDirectory, "identities.json"),
        JSON.stringify({ ...pair, sourceHash: "wrong" }),
      );
      expect(() => check()).to.throw(/slice differs/);
      publish({ ...pair, entries: [entry, entry] });
      expect(() => check()).to.throw(/duplicate circuit identity/);
      publish({
        ...pair,
        entries: [{ ...entry, key: { ...key, proofVariant: "evm" } }],
      });
      expect(() => check()).to.throw(/Missing or duplicate circuit identity/);
      publish({
        ...pair,
        entries: [
          {
            ...entry,
            compiledArtifact: {
              ...entry.compiledArtifact,
              path: "../escape.json",
            },
          },
        ],
      });
      expect(() => check()).to.throw(/Invalid circuit identity artifact path/);
      const treeKey = {
        ...key,
        circuit: "recursive_aggregation/test_tree",
        proofVariant: "default",
        hashKind: "recursive-tree-commitment",
      };
      publish({
        ...pair,
        entries: [
          {
            key: treeKey,
            value,
            compiledArtifact: null,
            verificationKey: null,
            dependencies: [treeKey],
          },
        ],
      });
      expect(() => check(treeKey.circuit, treeKey.hashKind)).to.throw(
        /Cyclic circuit identity/,
      );
    } finally {
      fs.rmSync(temp, { recursive: true, force: true });
    }
  });
});
