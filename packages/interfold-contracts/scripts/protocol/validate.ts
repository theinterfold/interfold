// SPDX-License-Identifier: LGPL-3.0-only
import { ethers as ethersLib } from "ethers";

import { connect } from "./cli";
import { deploymentPath, readJson } from "./files";
import type { ProtocolDeployment } from "./types";
import { loadConfig, requireContract } from "./values";

export async function actionValidate(): Promise<void> {
  const { ethers } = await connect();
  const config = loadConfig();
  const deployment = readJson<ProtocolDeployment>(deploymentPath(config));
  const network = await ethers.provider.getNetwork();
  if (Number(network.chainId) !== deployment.chainId) {
    throw new Error("Connected to the wrong network for this deployment file");
  }

  const ticket = await ethers.getContractAt(
    "InterfoldTicketToken",
    deployment.ticketToken,
  );
  const registry = await ethers.getContractAt(
    "CiphernodeRegistryOwnable",
    deployment.ciphernodeRegistry,
  );
  const interfold = await ethers.getContractAt(
    "Interfold",
    deployment.interfold,
  );
  const refund = await ethers.getContractAt(
    "E3RefundManager",
    deployment.e3RefundManager,
  );
  const bonding = await ethers.getContractAt(
    "BondingRegistry",
    deployment.bondingRegistryProxy,
  );
  const slashing = await ethers.getContractAt(
    "SlashingManager",
    deployment.slashingManager,
  );

  for (const [label, address] of [
    ["interfoldLifecycle", deployment.interfoldLifecycle],
    ["interfoldPricing", deployment.interfoldPricing],
  ] as const) {
    if ((await ethers.provider.getCode(address)) === "0x") {
      throw new Error(`${label}: no contract at ${address}`);
    }
    console.log(`  ok ${label}`);
  }

  const checks: Array<[string, Promise<unknown>, unknown]> = [
    ["ticket.owner", ticket.owner(), config.safe],
    ["ticket.registry", ticket.registry(), deployment.bondingRegistryProxy],
    ["registry.owner", registry.owner(), config.safe],
    ["registry.interfold", registry.interfold(), deployment.interfold],
    [
      "registry.bondingRegistry",
      registry.bondingRegistry(),
      deployment.bondingRegistryProxy,
    ],
    [
      "registry.slashingManager",
      registry.slashingManager(),
      deployment.slashingManager,
    ],
    ["interfold.owner", interfold.owner(), config.safe],
    [
      "interfold.bondingRegistry",
      interfold.bondingRegistry(),
      deployment.bondingRegistryProxy,
    ],
    [
      "interfold.ciphernodeRegistry",
      interfold.ciphernodeRegistry(),
      deployment.ciphernodeRegistry,
    ],
    [
      "interfold.e3RefundManager",
      interfold.e3RefundManager(),
      deployment.e3RefundManager,
    ],
    [
      "interfold.slashingManager",
      interfold.slashingManager(),
      deployment.slashingManager,
    ],
    ["refund.owner", refund.owner(), config.safe],
    ["bonding.owner", bonding.owner(), config.safe],
    ["bonding.ticketToken", bonding.ticketToken(), deployment.ticketToken],
    ["bonding.licenseToken", bonding.licenseToken(), config.fold],
    ["bonding.registry", bonding.registry(), deployment.ciphernodeRegistry],
    [
      "bonding.slashingManager",
      bonding.slashingManager(),
      deployment.slashingManager,
    ],
    ["slashing.interfold", slashing.interfold(), deployment.interfold],
    [
      "slashing.bondingRegistry",
      slashing.bondingRegistry(),
      deployment.bondingRegistryProxy,
    ],
    [
      "slashing.ciphernodeRegistry",
      slashing.ciphernodeRegistry(),
      deployment.ciphernodeRegistry,
    ],
    [
      "slashing.e3RefundManager",
      slashing.e3RefundManager(),
      deployment.e3RefundManager,
    ],
  ];

  for (const [label, actualPromise, expected] of checks) {
    const actual = await actualPromise;
    if (String(actual).toLowerCase() !== String(expected).toLowerCase()) {
      throw new Error(`${label}: expected ${expected}, got ${actual}`);
    }
    console.log(`  ok ${label}`);
  }

  for (const program of config.e3Programs) {
    await requireContract(ethers.provider, program, "e3Programs[0]");
    if (!(await interfold.e3Programs(program))) {
      throw new Error(`E3 Program is not registered: ${program}`);
    }
    console.log(`  ok interfold.e3Programs(${program})`);
  }

  const defaultAdmin = ethersLib.ZeroHash;
  if (!(await slashing.hasRole(defaultAdmin, config.safe))) {
    throw new Error("Safe does not have SlashingManager DEFAULT_ADMIN_ROLE");
  }
  console.log("Protocol validation complete");
}
