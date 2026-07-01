// SPDX-License-Identifier: LGPL-3.0-only
import path from "path";

import { bidClaim } from "./bidClaim";
import { arg, connect, hasFlag, networkName } from "./cli";
import { CCA_FACTORY_ADDRESS } from "./constants";
import {
  deployMockBondingRegistryProxy,
  deployMockCcaFactory,
  deploySaleDeployer,
} from "./deployContracts";
import {
  deploymentPath,
  planPath,
  saleDir,
  writeJson,
} from "./files";
import { deployFromPlan } from "./deploy";
import {
  buildSalePlan,
  printPlan,
  writeSaleUiManifest,
} from "./plan";
import { makeTemplateConfig } from "./template";
import { address } from "./values";
import { validateDeployment } from "./validate";

export async function actionFullTest(): Promise<void> {
  const { ethers } = await connect();
  const network = await ethers.provider.getNetwork();
  if (
    network.chainId === 1n &&
    process.env.ALLOW_MAINNET_FULL_TEST !== "true"
  ) {
    throw new Error("Refusing to run mock full-test on mainnet");
  }
  const [operator] = await ethers.getSigners();
  const operatorAddress = await operator.getAddress();

  const safeInput = arg("safe") ?? process.env.SAFE_ADDRESS;
  const safe = safeInput ? address(safeInput, "safe") : operatorAddress;
  const registry = await deployMockBondingRegistryProxy(ethers, safe);
  const useMockCca = hasFlag("mock-cca") || network.chainId === 31337n;
  const ccaFactory = useMockCca
    ? await deployMockCcaFactory(ethers)
    : CCA_FACTORY_ADDRESS;
  const saleDeployer = await deploySaleDeployer(ethers, safe);
  const latest = await ethers.provider.getBlock("latest");
  if (!latest) throw new Error("Could not read latest block");

  const name = arg("name") ?? `${networkName()}-sale-dry-run-${Date.now()}`;
  const config = makeTemplateConfig({
    name,
    chainId: Number(network.chainId),
    safe,
    saleDeployer,
    bondingRegistry: registry.proxy,
    ccaFactory,
    currentBlock: BigInt(latest.number),
    currentTimestamp: BigInt(latest.timestamp),
  });
  const configFile = path.join(saleDir, `${name}.config.json`);
  writeJson(configFile, config);

  const plan = await buildSalePlan(ethers, config);
  const planFile = planPath(config);
  writeJson(planFile, plan);
  printPlan(plan, planFile);

  const deployment = await deployFromPlan(ethers, config, plan);
  if (useMockCca) deployment.mockCcaFactory = ccaFactory;
  deployment.bondingRegistryProxyAdmin = registry.proxyAdmin;
  writeJson(deploymentPath(config), deployment);
  writeSaleUiManifest(config, plan, deployment);

  if (safe === operatorAddress) {
    const fold = await ethers.getContractAt("InterfoldToken", deployment.fold);
    await (await fold.acceptOwnership()).wait();
    console.log(`Accepted FOLD ownership: ${deployment.fold}`);
  } else {
    console.log(
      `FOLD ownership is pending Safe acceptance. Run acceptOwnership from ${safe}.`,
    );
  }

  await validateDeployment(
    ethers,
    config,
    deployment,
    plan,
    safe !== operatorAddress,
  );
  await bidClaim(ethers, config, deployment);

  console.log(`
Full Sepolia/local rehearsal complete
  config:     ${configFile}
  plan:       ${planFile}
  deployment: ${deploymentPath(config)}
  FOLD:       ${deployment.fold}
  auction:    ${deployment.auction}
`);
}

