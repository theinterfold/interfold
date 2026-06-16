// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
import type { HardhatRuntimeEnvironment } from "hardhat/types/hre";
import poseidon from "poseidon-solidity";

import { getDeploymentChain, storeDeploymentArgs } from "../utils";

interface PoseidonT3ProxyDeployArgs {
  hre: HardhatRuntimeEnvironment;
}

/**
 * Deploy and save PoseidonT3 contract behind a proxy
 * @param param0
 */
export const deployAndSavePoseidonT3 = async ({
  hre,
}: PoseidonT3ProxyDeployArgs): Promise<string> => {
  const { ethers } = await hre.network.connect();
  const chain = getDeploymentChain(hre);

  // First check if the proxy exists
  if ((await ethers.provider.getCode(poseidon.proxy.address)) === "0x") {
    // probably on the hardhat network
    // fund the keyless account
    const [sender] = await ethers.getSigners();
    let tx = await sender.sendTransaction({
      to: poseidon.proxy.from,
      value: poseidon.proxy.gas,
    });
    await tx.wait();

    // then send the presigned transaction deploying the proxy
    tx = await ethers.provider.broadcastTransaction(poseidon.proxy.tx);
    await tx.wait();
    console.log(`Proxy deployed to: ${poseidon.proxy.address}`);
  }

  // Then deploy the hasher, if needed
  if ((await ethers.provider.getCode(poseidon.PoseidonT3.address)) === "0x") {
    const [sender] = await ethers.getSigners();
    let tx = await sender.sendTransaction({
      to: poseidon.proxy.address,
      data: poseidon.PoseidonT3.data,
    });
    await tx.wait();

    console.log(`PoseidonT3 deployed to: ${poseidon.PoseidonT3.address}`);
  }

  const blockNumber = await ethers.provider.getBlockNumber();

  storeDeploymentArgs(
    {
      blockNumber,
      address: poseidon.PoseidonT3.address,
    },
    "PoseidonT3",
    chain,
  );

  return poseidon.PoseidonT3.address;
};
