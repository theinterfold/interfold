// SPDX-License-Identifier: LGPL-3.0-only
import { writeFileSync } from "node:fs";

import { BFV_ENCRYPTION_SCHEME_ID } from "../bfv";
import {
  BFV_PARAMS_SECURE,
  deployInterfoldSystem,
  ethers,
} from "../test/fixtures";
import { deployBfvVerifierRoutes } from "./protocol/deployContracts";
import { currentNodeRelease } from "./protocol/nodeRelease";
import {
  INSECURE_MINIMUM_BFV_CONFIG,
  SECURE_MINIMUM_BFV_CONFIG,
} from "./utils";

const profile = process.env.E3_BENCHMARK_PROFILE;
if (
  new URL(process.env.E3_BENCHMARK_RPC!).hostname !== "127.0.0.1" ||
  (await ethers.provider.getNetwork()).chainId !== 31337n ||
  !String(await ethers.provider.send("web3_clientVersion", []))
    .toLowerCase()
    .includes("anvil")
)
  throw new Error("SS benchmark requires its private Anvil instance");
if (profile !== "ss-insecure-64" && profile !== "ss-secure-8192")
  throw new Error(`Unsupported SS Minimum profile: ${profile}`);
const config =
  profile === "ss-insecure-64"
    ? INSECURE_MINIMUM_BFV_CONFIG
    : SECURE_MINIMUM_BFV_CONFIG;
const system = await deployInterfoldSystem({
  deploymentId: "ss-minimum",
  committeeThresholds: [[0, [config.h, config.n]]],
  wireMockDkgFoldAttestationVerifier: false,
});
const { interfold, ciphernodeRegistry, mocks } = system;
const release = currentNodeRelease();
await (await interfold.setRequestsPaused(true)).wait();
await (
  await system.nodeReleaseRegistry.setRequiredNodeRelease(
    release.protocolVersion,
    release.nodeGeneration,
  )
).wait();
const registry = await ciphernodeRegistry.getAddress();
const { pkVerifier, decryptionVerifier } = await deployBfvVerifierRoutes(
  ethers,
  registry,
  config,
  [config],
);
const fold = await ethers.deployContract("DkgFoldAttestationVerifier");
await (
  await ciphernodeRegistry.setInitialDkgFoldAttestationVerifier(
    await fold.getAddress(),
  )
).wait();
if (profile === "ss-secure-8192")
  await (
    await interfold.setParamSet(config.paramSet, BFV_PARAMS_SECURE)
  ).wait();
await (
  await interfold.setPkVerifier(BFV_ENCRYPTION_SCHEME_ID, pkVerifier)
).wait();
await (
  await interfold.setDecryptionVerifier(
    BFV_ENCRYPTION_SCHEME_ID,
    decryptionVerifier,
  )
).wait();
await (await mocks.randomnessProvider!.setAutoFulfill(false)).wait();
await (await interfold.setRequestsPaused(false)).wait();

writeFileSync(
  process.env.E3_BENCHMARK_DEPLOYMENTS!,
  JSON.stringify({
    benchmark: {
      Interfold: { address: await interfold.getAddress() },
      CiphernodeRegistryOwnable: { address: registry },
      BondingRegistry: { address: await system.bondingRegistry.getAddress() },
      SlashingManager: { address: await system.slashingManager.getAddress() },
      DkgFoldAttestationVerifier: { address: await fold.getAddress() },
      BfvPkVerifier: { address: pkVerifier },
      BfvDecryptionVerifier: { address: decryptionVerifier },
      MockDecryptionVerifier: {
        address: await mocks.decryptionVerifier.getAddress(),
      },
      MockUSDC: { address: await system.usdcToken.getAddress() },
      MockE3Program: { address: await mocks.e3Program.getAddress() },
      MockRandomnessProvider: {
        address: await mocks.randomnessProvider!.getAddress(),
      },
    },
  }),
  { flag: "wx" },
);
