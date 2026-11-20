// SPDX-License-Identifier: LGPL-3.0-only
import { expect } from "chai";
import { rejects } from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { runProofCommand } from "./fixtures/proofCommand";

(process.platform === "win32" ? describe.skip : describe)(
  "proof command deadline",
  function () {
    it("stops the worker before returning a timeout", async function () {
      this.timeout(10_000);
      const cwd = mkdtempSync(join(tmpdir(), "proof-deadline-"));
      try {
        const result = runProofCommand(
          performance.now() + 1_000,
          "/bin/sh",
          ["-c", "sleep 20 & echo $! > worker; wait"],
          { cwd },
        );
        await rejects(result, /Proof deadline expired/);
        const pid = readFileSync(join(cwd, "worker"), "utf8").trim();
        const status = spawnSync("ps", ["-p", pid, "-o", "stat="], {
          encoding: "utf8",
        });
        expect(status.error).to.equal(undefined);
        expect(status.status === 1 || /^Z/.test(status.stdout.trim())).to.equal(
          true,
        );
      } finally {
        rmSync(cwd, { recursive: true, force: true });
      }
    });

    it("preserves a nonzero exit before the deadline", async function () {
      await rejects(
        runProofCommand(
          performance.now() + 5_000,
          "/bin/sh",
          ["-c", "exit 23"],
          {},
        ),
        /exited with 23/,
      );
    });
  },
);
