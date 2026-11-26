// SPDX-License-Identifier: LGPL-3.0-only
import { network } from "hardhat";
import { readFileSync, writeFileSync } from "node:fs";

import { BFV_PROFILES, type BfvProfile } from "../bfv";
import {
  compileSynchronized,
  deployCompiled,
} from "../test/fixtures/synchronizedSolidity";

const { ethers } = await network.connect();
const read = (key: string) => readFileSync(process.env[key]!, "utf8");
const {
  benchmark_config: cfg,
  authority,
  folded_artifacts,
} = JSON.parse(read("BENCHMARK_FOLDED_JSON"));
const profile = BFV_PROFILES[cfg.mode as BfvProfile];
if (profile.protocol !== "synchronized" || cfg.committee !== "minimum")
  throw new Error("Expected a synchronized Minimum measurement");
const config = profile.configurations.find(
  (entry) => entry.committee === "minimum",
)!;
const [signer] = await ethers.getSigners();
const source = "SynchronizedHonk.sol";
const honk = await deployCompiled(
  compileSynchronized({ [source]: { content: read("BENCHMARK_SYNC_HONK") } }),
  signer!,
)(source, "DecryptionAggregatorVerifier");
const id = 1n;
const committee = ethers.id("standalone benchmark committee");
const registry = await ethers.deployContract("BenchmarkSynchronizedAuthority", [
  id,
  committee,
  {
    version: 1,
    verifier: signer!.address,
    cryptoConfigId: config.cryptoConfigId,
    setupBinding: authority.setup,
    dealerBatch: ethers.ZeroHash,
    pkCommitment: ethers.ZeroHash,
    partyIds: authority.owners,
    thresholdPkCommits: authority.owners.map(() => ethers.ZeroHash),
    skAggCommits: authority.sk,
    keyBundleCommits: authority.bundles,
  },
]);
const verifier = await ethers.deployContract("SynchronizedDecryptionVerifier", [
  await honk.getAddress(),
  await registry.getAddress(),
  config.cryptoConfigId,
]);
const { proof_hex, public_inputs_hex } = folded_artifacts.decryption_aggregator;
const fields = public_inputs_hex
  .slice(2)
  .match(/.{64}/g)
  .map((s: string) => `0x${s}`);
const call = [
  id,
  authority.domain,
  ethers.keccak256(Uint8Array.from(authority.plaintext)),
  committee,
  authority.ciphertext,
  ethers.AbiCoder.defaultAbiCoder().encode(
    ["bytes", "bytes32[]"],
    [proof_hex, fields],
  ),
] as const;
if (!(await verifier.verify.staticCall(...call)))
  throw new Error("Candidate verifier rejected the proof");
const gas = await verifier.verify.estimateGas(...call);
writeFileSync(
  process.env.BENCHMARK_GAS_OUTPUT!,
  JSON.stringify({ profile: cfg.mode, verify_gas: { dec: Number(gas) } }),
);
