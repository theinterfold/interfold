// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
import type { HardhatRuntimeEnvironment } from "hardhat/types/hre";

import {
  BondedVotes,
  BondedVotes__factory as BondedVotesFactory,
} from "../../types";
import { readExcludedAccounts, sameAccounts } from "../protocol/values";
import {
  getDeploymentChain,
  readDeploymentArgs,
  storeDeploymentArgs,
} from "../utils";

/**
 * The arguments for the deployAndSaveBondedVotes function
 */
export interface BondedVotesArgs {
  /** FOLD. Supplies the metadata, the total supply and the quorum denominator. */
  token: string;
  /**
   * Where per-account voting power is read. Pass `token` to count wallet-held FOLD, or an escrow
   * IVotes adapter to count only locked FOLD. Defaults to `token`, preserving the original
   * behaviour for callers that predate the lock-to-vote model.
   */
  votesSource?: string;
  /** The bonded-history contract to read alongside the votes source. */
  checkpoints: string;
  /** Accounts that have no voting power in the adapter. Defaults to none. */
  excludedAccounts?: string[];
  hre: HardhatRuntimeEnvironment;
}

/**
 * Deploys the BondedVotes contract and saves the deployment arguments.
 *
 * This is the address governance points at, so it has to be resolvable from the deployment
 * inventory. The constructor reverts unless the token and the history agree on their ERC-6372
 * clock, which makes a mismatched pair fail here rather than silently answer for two unrelated
 * points in time.
 * @param param0 - The deployment arguments
 * @returns The deployed BondedVotes contract
 */
export const deployAndSaveBondedVotes = async ({
  token,
  votesSource,
  checkpoints,
  excludedAccounts = [],
  hre,
}: BondedVotesArgs): Promise<{ bondedVotes: BondedVotes }> => {
  const resolvedVotesSource = votesSource ?? token;
  const { ethers } = await hre.network.connect();
  const [signer] = await ethers.getSigners();
  const chain = getDeploymentChain(hre);

  const preDeployedArgs = readDeploymentArgs("BondedVotes", chain);
  // All references and the excluded accounts are immutable, so a record for different arguments
  // cannot be reused. A record from before the exclusion list can have the same three references,
  // so the code is read too.
  const recorded =
    preDeployedArgs?.address &&
    preDeployedArgs?.constructorArgs?.token === token &&
    preDeployedArgs?.constructorArgs?.votesSource === resolvedVotesSource &&
    preDeployedArgs?.constructorArgs?.checkpoints === checkpoints
      ? await readExcludedAccounts(ethers.provider, preDeployedArgs.address)
      : undefined;
  if (
    preDeployedArgs?.address &&
    recorded &&
    sameAccounts(recorded, excludedAccounts)
  ) {
    return {
      bondedVotes: BondedVotesFactory.connect(preDeployedArgs.address, signer),
    };
  }

  const factory = await ethers.getContractFactory("BondedVotes");
  const bondedVotes = await factory.deploy(
    token,
    resolvedVotesSource,
    checkpoints,
    excludedAccounts,
  );
  await bondedVotes.waitForDeployment();

  const address = await bondedVotes.getAddress();
  storeDeploymentArgs(
    {
      constructorArgs: {
        token,
        votesSource: resolvedVotesSource,
        checkpoints,
        excludedAccounts,
      },
      blockNumber: await ethers.provider.getBlockNumber(),
      address,
    },
    "BondedVotes",
    chain,
  );

  return { bondedVotes: BondedVotesFactory.connect(address, signer) };
};
