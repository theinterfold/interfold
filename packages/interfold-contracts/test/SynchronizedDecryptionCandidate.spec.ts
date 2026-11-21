// SPDX-License-Identifier: LGPL-3.0-only
import { expect } from "chai";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";

import { ethers } from "./fixtures/connection";
import { decryptionCandidate } from "./fixtures/synchronizedCandidate";
import {
  compileSynchronized,
  deployCompiled,
} from "./fixtures/synchronizedSolidity";

const fixture = process.env.E3_SYNC_CANDIDATE_FIXTURE;
(fixture ? describe : describe.skip)(
  "Synchronized decryption candidate",
  function () {
    it("verifies the manifest-pinned fields in the generated EVM verifier", async () => {
      const candidate = join(fixture!, "candidate");
      const profile = process.env.E3_SYNC_CANDIDATE_PROFILE;
      if (profile !== "sync-secure-8192" && profile !== "sync-insecure-64")
        throw new Error("Select the expected candidate profile");
      const manifest = decryptionCandidate(candidate, profile);
      const [c6, c7, outer] = manifest.circuits;
      const source = "SynchronizedHonk.sol";
      const solidity = readFileSync(
        join(candidate, outer.path, source),
        "utf8",
      );
      expect(createHash("sha256").update(solidity).digest("hex")).to.equal(
        outer.soliditySha256,
      );
      const verifier = await deployCompiled(
        compileSynchronized({ [source]: { content: solidity } }),
        (await ethers.getSigners())[0]!,
      )(source, "DecryptionAggregatorVerifier");
      const proof = readFileSync(join(fixture!, "proof"));
      const fields = readFileSync(join(fixture!, "public_inputs"))
        .toString("hex")
        .match(/.{64}/g)!
        .map((x) => "0x" + x);
      expect(fields).to.have.length(76);
      expect(fields.slice(0, 2)).to.deep.equal([c6.vkHash, c7.vkHash]);
      const verify = () =>
        verifier.getFunction("verify").staticCall(proof, fields);
      expect(await verify()).to.equal(true);
      fields[75] = ethers.toBeHex(BigInt(fields[75]!) ^ 1n, 32);
      await expect(verify()).to.be.revert(ethers);
    });
  },
);
