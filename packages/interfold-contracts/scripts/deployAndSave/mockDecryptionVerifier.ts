// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
import type { HardhatRuntimeEnvironment } from "hardhat/types/hre";

import {
  MockDecryptionVerifier,
  MockDecryptionVerifier__factory as MockDecryptionVerifierFactory,
} from "../../types";
import { storeDeploymentArgs } from "../utils";

export const deployAndSaveMockDecryptionVerifier = async (
  hre: HardhatRuntimeEnvironment,
): Promise<{
  decryptionVerifier: MockDecryptionVerifier;
}> => {
  const { ethers } = await hre.network.connect();
  const [signer] = await ethers.getSigners();
  const chain = hre.globalOptions.network;

  const decryptionVerifierFactory = await ethers.getContractFactory(
    "MockDecryptionVerifier",
  );
  const decryptionVerifier = await decryptionVerifierFactory.deploy();

  await decryptionVerifier.waitForDeployment();
  const decryptionVerifierAddress = await decryptionVerifier.getAddress();

  const blockNumber = await ethers.provider.getBlockNumber();

  storeDeploymentArgs(
    {
      blockNumber,
      address: decryptionVerifierAddress,
    },
    "MockDecryptionVerifier",
    chain,
  );

  const decryptionVerifierContract = MockDecryptionVerifierFactory.connect(
    decryptionVerifierAddress,
    signer,
  );

  return { decryptionVerifier: decryptionVerifierContract };
};
