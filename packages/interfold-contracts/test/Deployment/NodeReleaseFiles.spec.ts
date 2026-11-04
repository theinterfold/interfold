// SPDX-License-Identifier: LGPL-3.0-only
import { expect } from "chai";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { readRepoNodeRelease } from "../../scripts/protocol/nodeRelease";

describe("Node release files", function () {
  let root: string;
  let manifest: string;

  beforeEach(function () {
    root = fs.mkdtempSync(path.join(os.tmpdir(), "interfold-node-release-"));
    manifest = path.join(
      root,
      "crates/ciphernode/config/protocol-release.toml",
    );
    fs.mkdirSync(path.dirname(manifest), { recursive: true });
    fs.writeFileSync(manifest, "protocol_version = 17\nnode_generation = 23\n");
    fs.writeFileSync(
      path.join(root, "package.json"),
      JSON.stringify({ version: "1.2.3-rc.4" }),
    );
    fs.writeFileSync(
      path.join(root, "Cargo.toml"),
      '[workspace.package]\nversion = "1.2.3-rc.4"\n',
    );
  });

  afterEach(function () {
    fs.rmSync(root, { recursive: true, force: true });
  });

  it("loads exact release identity and counters from ciphernode configuration", function () {
    expect(readRepoNodeRelease(root)).to.deep.equal({
      version: "1.2.3-rc.4",
      protocolVersion: 17,
      nodeGeneration: 23,
      releaseId:
        "0x4a1b485c6b603ac011dbeb51ae27c1d179a00d87a9b78f2cf19c11dfc1e8fec6",
    });
  });

  it("refuses mismatched Rust and package versions", function () {
    fs.writeFileSync(
      path.join(root, "Cargo.toml"),
      '[workspace.package]\nversion = "1.2.3-rc.5"\n',
    );
    expect(() => readRepoNodeRelease(root)).to.throw(
      "Release version mismatch",
    );
  });

  for (const field of ["protocol_version", "node_generation"] as const) {
    it(`refuses invalid ${field} counters`, function () {
      for (const value of ["0", "-1", "1.5", "4294967296", "invalid"]) {
        fs.writeFileSync(
          manifest,
          `protocol_version = ${field === "protocol_version" ? value : "17"}\n` +
            `node_generation = ${field === "node_generation" ? value : "23"}\n`,
        );
        expect(() => readRepoNodeRelease(root)).to.throw(
          `${field} must be a positive uint32 value`,
        );
      }
    });
  }
});
