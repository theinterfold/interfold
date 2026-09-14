// SPDX-License-Identifier: LGPL-3.0-only
import hre from "hardhat";

import {
  activeBfvConfigForChain,
  bfvConfigsForChain,
  getBfvPkSubCircuitVkHashPaths,
  readVkRecursiveHash,
} from "../utils";
import { bfvHonkSource } from "./deployContracts";

async function main() {
  const interfoldAddress = process.env.INTERFOLD_ADDRESS;
  if (!interfoldAddress) throw new Error("Set INTERFOLD_ADDRESS");

  const { ethers } = await hre.network.connect();
  const chainId = Number((await ethers.provider.getNetwork()).chainId);
  if (chainId !== 11155111) throw new Error("This upgrade is for Sepolia only");

  const [signer] = await ethers.getSigners();
  const interfold = await ethers.getContractAt(
    "Interfold",
    interfoldAddress,
    signer,
  );
  if (
    (await interfold.owner()).toLowerCase() !== signer.address.toLowerCase()
  ) {
    throw new Error("The signer is not the Interfold owner");
  }
  if ((await interfold.activeE3Count()) !== 0n) {
    throw new Error("Wait for active E3s before replacing the DKG verifier");
  }

  const scheme = ethers.id("fhe.rs:BFV");
  const oldRouterAddress = await interfold.pkVerifiers(scheme);
  const oldRouter = await ethers.getContractAt(
    "BfvPkVerifierRouter",
    oldRouterAddress,
    signer,
  );
  const defaultH = await oldRouter.h();
  if (defaultH !== BigInt(activeBfvConfigForChain(chainId).h)) {
    throw new Error("The current router has the wrong default H");
  }

  const configs = bfvConfigsForChain(chainId);
  const count = Number(await oldRouter.routeCount());
  if (count !== configs.length)
    throw new Error("Unexpected verifier route count");

  const routes = await Promise.all(
    Array.from({ length: count }, async (_, index) => {
      const [verifier, length, nodesFoldHash, c5Hash] =
        await oldRouter.routeAt(index);
      return { verifier, length, nodesFoldHash, c5Hash };
    }),
  );

  const replacements = configs.map((config) => {
    const paths = getBfvPkSubCircuitVkHashPaths(config);
    const nodesFoldHash = readVkRecursiveHash(paths.nodesFold, config);
    const c5Hash = readVkRecursiveHash(paths.c5, config);
    const matches = routes.flatMap((route, index) =>
      route.length === BigInt(3 * config.h + 6) &&
      route.nodesFoldHash.toLowerCase() === nodesFoldHash.toLowerCase() &&
      route.c5Hash.toLowerCase() === c5Hash.toLowerCase()
        ? [index]
        : [],
    );
    if (matches.length !== 1) {
      throw new Error(
        `Expected one existing route for ${config.preset}/${config.committee}`,
      );
    }
    return { config, index: matches[0], nodesFoldHash, c5Hash };
  });

  if (new Set(replacements.map(({ index }) => index)).size !== count) {
    throw new Error("Two configurations resolved to the same route");
  }

  console.log(
    JSON.stringify({
      chainId,
      interfold: interfoldAddress,
      owner: signer.address,
      oldRouter: oldRouterAddress,
      activeE3Count: 0,
      replacements: replacements.map(({ config, index }) => ({
        index,
        preset: config.preset,
        committee: config.committee,
      })),
    }),
  );
  if (process.env.EXECUTE_DKG_PK_UPGRADE !== "true") return;

  const nextRoutes = routes.map(({ verifier }) => verifier);
  for (const { config, index, nodesFoldHash, c5Hash } of replacements) {
    const source = bfvHonkSource(config, "DkgAggregatorVerifier");
    const transcript = await (
      await ethers.getContractFactory(`${source}:ZKTranscriptLib`)
    ).deploy();
    await transcript.waitForDeployment();
    const relations = await (
      await ethers.getContractFactory(`${source}:RelationsLib`)
    ).deploy();
    await relations.waitForDeployment();
    const honk = await (
      await ethers.getContractFactory(`${source}:DkgAggregatorVerifier`, {
        libraries: {
          [`project/${source}:ZKTranscriptLib`]: await transcript.getAddress(),
          [`project/${source}:RelationsLib`]: await relations.getAddress(),
        },
      })
    ).deploy();
    await honk.waitForDeployment();
    const wrapper = await (
      await ethers.getContractFactory("BfvPkVerifier")
    ).deploy(await honk.getAddress(), nodesFoldHash, c5Hash, config.h);
    await wrapper.waitForDeployment();
    nextRoutes[index] = await wrapper.getAddress();
    console.log(
      `${config.preset}/${config.committee}: ${routes[index].verifier} -> ${nextRoutes[index]}`,
    );
  }

  const nextRouter = await (
    await ethers.getContractFactory("BfvPkVerifierRouter")
  ).deploy(nextRoutes, defaultH);
  await nextRouter.waitForDeployment();
  const nextRouterAddress = await nextRouter.getAddress();
  for (let index = 0; index < nextRoutes.length; index++) {
    const [verifier] = await nextRouter.routeAt(index);
    if (verifier.toLowerCase() !== nextRoutes[index].toLowerCase()) {
      throw new Error(`New router mismatch at route ${index}`);
    }
  }
  if ((await interfold.activeE3Count()) !== 0n) {
    throw new Error(
      "An E3 started during deployment; the new router was not activated",
    );
  }
  await (await interfold.setPkVerifier(scheme, nextRouterAddress)).wait();
  if (
    (await interfold.pkVerifiers(scheme)).toLowerCase() !==
    nextRouterAddress.toLowerCase()
  ) {
    throw new Error("Interfold did not retain the new router");
  }
  console.log(
    `BFV PK verifier router: ${oldRouterAddress} -> ${nextRouterAddress}`,
  );
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
