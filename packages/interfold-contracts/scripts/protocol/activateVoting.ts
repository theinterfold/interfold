// SPDX-License-Identifier: LGPL-3.0-only
import { connect } from "./cli";
import { deploymentPath, readJson, writeJson } from "./files";
import type { ProtocolDeployment } from "./types";
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
  await bondedVotes.waitForDeployment();
  deployment.bondedVotes = await deployedAddress(bondedVotes);
  writeJson(deploymentPath(config), deployment);

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
