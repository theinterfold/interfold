// SPDX-License-Identifier: LGPL-3.0-only
import type { HardhatEthers } from "@nomicfoundation/hardhat-ethers/types";

import { syncBondedVotesRecord } from "../deploymentRecords";
import { readDeploymentArgs } from "../utils";
import { connect, networkName } from "./cli";
import { deploymentPath, readJson, writeJson } from "./files";
import type { ProtocolConfigFile, ProtocolDeployment } from "./types";
import {
  checkExcludedAccounts,
  deployedAddress,
  loadConfig,
  requireContract,
} from "./values";

/**
 * Deploy `BondedVotes` and hand back the address governance points at.
 *
 * Split from `--action deploy` because it cannot run there. The constructor asks the registry which
 * token it bonds and refuses to build unless that matches the token it will read votes from, and
 * the registry is only initialized by the governance batch that `--action deploy` writes. Running this
 * before that batch executes fails loudly rather than producing an adapter bound to nothing.
 *
 * A recorded adapter is reused only when it excludes exactly `bondedVotesExcludedAccounts`. An
 * adapter from before the exclusion list, or one with a different list, is refused, not reused.
 * Replacing it moves the address that governance and CRISP rounds read, so the operator clears the
 * record on purpose.
 *
 * The new adapter is recorded in `deployed_contracts.json` with its constructor arguments and
 * deploy block, as `--action deploy` records the rest of the protocol.
 *
 * Nothing here needs a Safe transaction: `BondedVotes` has no owner and no privileged functions.
 */
export async function actionActivateVoting(): Promise<void> {
  const { ethers } = await connect();
  const config = loadConfig();
  const deployment = readJson<ProtocolDeployment>(deploymentPath(config));

  const network = await ethers.provider.getNetwork();
  if (Number(network.chainId) !== deployment.chainId) {
    throw new Error("Connected to the wrong network for this deployment file");
  }

  await requireContract(
    ethers.provider,
    deployment.bondedCheckpoints,
    "bondedCheckpoints",
  );

  const registry = await ethers.getContractAt(
    "BondingRegistry",
    deployment.bondingRegistryProxy,
  );

  // Fail here, with a readable message, rather than inside the constructor.
  const ciphernodeBondToken: string = await registry.getCiphernodeBondToken();
  if (ciphernodeBondToken.toLowerCase() !== config.fold.toLowerCase()) {
    throw new Error(
      `BondingRegistry bonds ${ciphernodeBondToken}, not FOLD (${config.fold}). ` +
        "Execute the governance batch from --action deploy first.",
    );
  }

  const attached: string = await registry.bondedCheckpoints();
  if (attached.toLowerCase() !== deployment.bondedCheckpoints.toLowerCase()) {
    throw new Error(
      `BondingRegistry has ${attached} attached, not the deployed ` +
        `${deployment.bondedCheckpoints}. Execute the governance batch first.`,
    );
  }

  const excludedAccounts = config.bondedVotesExcludedAccounts ?? [];

  if (deployment.bondedVotes) {
    await requireContract(
      ethers.provider,
      deployment.bondedVotes,
      "bondedVotes",
    );
    // An older adapter is refused even with nothing configured, so that the record names current
    // code.
    const outdated = await checkExcludedAccounts(
      ethers.provider,
      deployment.bondedVotes,
      excludedAccounts,
      deploymentPath(config),
    );
    if (outdated) throw new Error(outdated);
    // A run that failed after saving the address left the record unwritten
    await recordBondedVotes(ethers, config, deployment);
    console.log(`BondedVotes already deployed at ${deployment.bondedVotes}`);
    return;
  }

  // Defaults to FOLD itself, which counts wallet-held votes. Setting `escrowVotesAdapter` makes
  // locking a precondition for voting; the constructor checks the escrow custodies this same FOLD.
  const votesSource = config.escrowVotesAdapter ?? config.fold;

  const factory = await ethers.getContractFactory("BondedVotes");
  const bondedVotes = await factory.deploy(
    config.fold,
    votesSource,
    deployment.bondedCheckpoints,
    excludedAccounts,
  );
  const deploymentTx = bondedVotes.deploymentTransaction();
  await bondedVotes.waitForDeployment();
  // Saved before any other network call: a retry then finds the mined adapter and records it
  // instead of deploying a second one
  deployment.bondedVotes = await deployedAddress(bondedVotes);
  deployment.bondedVotesDeploymentTx = deploymentTx?.hash;
  writeJson(deploymentPath(config), deployment);
  await recordBondedVotes(ethers, config, deployment);

  console.log(`
Bonded voting activated
  BondedCheckpoints: ${deployment.bondedCheckpoints}
  BondedVotes:       ${deployment.bondedVotes}
  Votes source:      ${votesSource}${
    config.escrowVotesAdapter ? " (locked FOLD only)" : " (wallet-held FOLD)"
  }
  Excluded:          ${excludedAccounts.length ? excludedAccounts.join(", ") : "(none)"}

Point the governance plugin at BondedVotes as its voting token.
`);
}

/**
 * Records `BondedVotes` unless the record already names it. The record is written from the config,
 * so the adapter is checked to have been built with those arguments: an adapter recorded on a
 * retry may predate a config change. The deploy block is read from the deployment transaction
 * saved with the address, so a retry records the same adapter. A file from before the transaction
 * was saved records it without a block.
 */
async function recordBondedVotes(
  ethers: HardhatEthers,
  config: ProtocolConfigFile,
  deployment: ProtocolDeployment,
): Promise<void> {
  const bondedVotes = deployment.bondedVotes;
  if (!bondedVotes) throw new Error("BondedVotes is not deployed");
  const chain = networkName();
  const recorded = readDeploymentArgs("BondedVotes", chain)?.address;
  if (recorded?.toLowerCase() === bondedVotes.toLowerCase()) return;

  const adapter = await ethers.getContractAt("BondedVotes", bondedVotes);
  const expected = {
    token: config.fold,
    votesSource: config.escrowVotesAdapter ?? config.fold,
    checkpoints: deployment.bondedCheckpoints,
  };
  const actual = {
    token: await adapter.token(),
    votesSource: await adapter.votesSource(),
    checkpoints: await adapter.checkpoints(),
  };
  for (const key of Object.keys(expected) as (keyof typeof expected)[]) {
    if (actual[key].toLowerCase() !== expected[key].toLowerCase()) {
      throw new Error(
        `BondedVotes at ${bondedVotes} was built with ${key} ${actual[key]}, but the config ` +
          `gives ${expected[key]}. Restore the config it was deployed with, or remove ` +
          `bondedVotes from ${deploymentPath(config)} to deploy a new adapter.`,
      );
    }
  }

  const hash = deployment.bondedVotesDeploymentTx;
  let blockNumber: number | undefined;
  if (hash) {
    const receipt = await ethers.provider.getTransactionReceipt(hash);
    if (!receipt) {
      throw new Error(`No receipt for the BondedVotes deployment ${hash}`);
    }
    if (receipt.contractAddress?.toLowerCase() !== bondedVotes.toLowerCase()) {
      throw new Error(
        `Transaction ${hash} deployed ${receipt.contractAddress ?? "no contract"}, not ` +
          `BondedVotes at ${bondedVotes}. Remove bondedVotesDeploymentTx from ` +
          `${deploymentPath(config)} to record it without a block.`,
      );
    }
    blockNumber = receipt.blockNumber;
  }
  syncBondedVotesRecord(
    config,
    { bondedVotes, bondedCheckpoints: deployment.bondedCheckpoints },
    { chain, blockNumber },
  );
}
