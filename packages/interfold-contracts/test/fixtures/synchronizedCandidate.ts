// SPDX-License-Identifier: LGPL-3.0-only
import { expect } from "chai";
import { readFileSync } from "node:fs";
import { join, resolve } from "node:path";

type Profile = "sync-insecure-64" | "sync-secure-8192";

/** Source snapshots include more than the compiled statement. A changed VK/role requires
 * a deliberate new candidate; a changed source hash is never copied into an old manifest. */
export function decryptionCandidate(directory: string, profile: Profile) {
  const read = (file: string) => JSON.parse(readFileSync(file, "utf8"));
  const manifest = read(join(directory, "manifest.json"));
  const recorded = read(
    resolve("../../circuits/qualification", profile, "minimum/manifest.json"),
  );
  expect(manifest.profile).to.equal(profile);
  for (const key of [
    "scope",
    "formatVersion",
    "admissionEnabled",
    "committee",
    "cryptoConfigId",
    "bb",
    "nargo",
  ]) {
    expect(manifest[key], key).to.equal(recorded[key]);
  }
  expect(manifest.circuits).to.have.length(3);
  manifest.circuits.forEach((c: Record<string, unknown>, i: number) => {
    for (const key of [
      "role",
      "path",
      "target",
      "vkHash",
      "vkSha256",
      "soliditySha256",
    ]) {
      expect(c[key], `${profile} ${c.role} ${key}`).to.equal(
        recorded.circuits[i][key],
      );
    }
  });
  return manifest;
}
