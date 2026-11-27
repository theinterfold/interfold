// SPDX-License-Identifier: LGPL-3.0-only
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import { BFV_ENCRYPTION_SCHEME_ID } from "../bfv";
import {
  BFV_PARAMS_SECURE,
  deployInterfoldSystem,
  ethers,
} from "../test/fixtures";
import {
  compileSynchronized,
  deployCompiled,
} from "../test/fixtures/synchronizedSolidity";
import { getProxyAdmin } from "./proxy";

const output = process.env.E3_BENCHMARK_DEPLOYMENTS!;
const directory = process.env.E3_BENCHMARK_PAIR!;
if (
  new URL(process.env.E3_BENCHMARK_RPC!).hostname !== "127.0.0.1" ||
  (await ethers.provider.getNetwork()).chainId !== 31337n ||
  !((await ethers.provider.send("web3_clientVersion", [])) as string)
    .toLowerCase()
    .includes("anvil")
)
  throw new Error(
    "Candidate deployment requires the benchmark's private Anvil instance",
  );

// The runner has staged and checked both complete graphs before starting this chain.
const manifest = (name: string) =>
  JSON.parse(readFileSync(join(directory, name), "utf8"));
const dkg = manifest("dkg-publication.json");
const dec = manifest("manifest.json");
if (dkg.cryptoConfigId !== dec.cryptoConfigId)
  throw new Error("Mismatched candidate graphs");
const system = await deployInterfoldSystem({
  deploymentId: "sync-minimum",
  committeeThresholds: [[0, [2, 3]]],
});
const { interfold, ciphernodeRegistry, owner, mocks } = system;
const address = await interfold.getAddress();
const registry = await ciphernodeRegistry.getAddress();
const benchmarkLifecycle = await ethers.deployContract(
  "SynchronizedBenchmarkLifecycle",
  {
    libraries: { InterfoldLifecycle: system.interfoldLifecycle },
  },
);
const implementation = await ethers.deployContract("Interfold", {
  libraries: {
    InterfoldLifecycle: await benchmarkLifecycle.getAddress(),
    InterfoldPricing: system.interfoldPricing,
  },
});
const admin = await ethers.getContractAt(
  "ProxyAdmin",
  await getProxyAdmin(ethers.provider, address),
  owner,
);
await (
  await admin.upgradeAndCall(address, await implementation.getAddress(), "0x")
).wait();
const deployHonk = async (path: string, name: string) => {
  const source = "SynchronizedHonk.sol";
  const compiled = compileSynchronized({
    [source]: { content: readFileSync(join(directory, path, source), "utf8") },
  });
  return (await deployCompiled(compiled, owner)(source, name)).getAddress();
};
const pk = await ethers.deployContract("SynchronizedDkgPublicationVerifier", [
  await deployHonk(dkg.circuits.at(-1).path, "DkgAggregatorVerifier"),
  address,
  dec.cryptoConfigId,
  dkg.setupTreeHash,
  dkg.c5KeyHash,
  3,
  2,
]);
const verifier = await ethers.deployContract("SynchronizedDecryptionVerifier", [
  await deployHonk(dec.circuits.at(-1).path, "DecryptionAggregatorVerifier"),
  registry,
  dec.cryptoConfigId,
]);
if (dec.profile === "sync-secure-8192")
  await (await interfold.setParamSet(3, BFV_PARAMS_SECURE)).wait();
await (
  await interfold.setPkVerifier(BFV_ENCRYPTION_SCHEME_ID, await pk.getAddress())
).wait();
await (
  await interfold.setDecryptionVerifier(
    BFV_ENCRYPTION_SCHEME_ID,
    await verifier.getAddress(),
  )
).wait();
await (await mocks.randomnessProvider!.setAutoFulfill(false)).wait();
writeFileSync(
  output,
  JSON.stringify({
    benchmark: {
      Interfold: { address },
      CiphernodeRegistryOwnable: { address: registry },
      MockUSDC: { address: await system.usdcToken.getAddress() },
      MockE3Program: { address: await mocks.e3Program.getAddress() },
      MockRandomnessProvider: {
        address: await mocks.randomnessProvider!.getAddress(),
      },
      MockDecryptionVerifier: {
        address: await mocks.decryptionVerifier.getAddress(),
      },
      SynchronizedDecryptionVerifier: { address: await verifier.getAddress() },
      SynchronizedDkgPublicationVerifier: { address: await pk.getAddress() },
    },
  }),
  { flag: "wx" },
);
