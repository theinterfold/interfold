// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
import hre from "hardhat";

import {
  BondingRegistry__factory as BondingRegistryFactory,
  Faucet__factory as FaucetFactory,
  Interfold__factory as InterfoldFactory,
  InterfoldToken__factory as InterfoldTokenFactory,
} from "../types";
import {
  getDeploymentChain,
  readDeploymentArgs,
  storeDeploymentArgs,
} from "./utils";

/**
 * Standalone script to (re)deploy ONLY the testnet Faucet and fund it.
 *
 * Force-deploys a fresh Faucet (the deployAndSave guard is idempotent on the
 * constructor args, so it would otherwise return the existing address),
 * overwrites the `Faucet` entry in deployed_contracts.json, whitelists it in
 * FOLD and funds it with FOLD and the live fee token.
 *
 * The token addresses come from the live Interfold and BondingRegistry
 * contracts. Deployment records can still contain tokens from an older stack.
 * FOLD funding uses admin minting, which closes when FOLD enters the Live phase.
 *
 * Usage: hardhat run scripts/deployFaucet.ts --network sepolia
 */
// Stock the faucet for this many self-serve claims; supply is derived from the
// contract's per-claim amounts below so it stays correct if those change.
const FAUCET_TARGET_MINTS = 1000n;

const main = async () => {
  const { ethers } = await hre.network.connect();
  const [signer] = await ethers.getSigners();
  const chain = getDeploymentChain(hre);

  if (chain !== "sepolia") {
    throw new Error(
      `Refusing to deploy faucet on non-sepolia chain "${chain}".`,
    );
  }

  const interfoldAddress = readDeploymentArgs("Interfold", chain)?.address;
  if (!interfoldAddress) {
    throw new Error(
      "Interfold not found in deployed_contracts.json. Run the full deploy first.",
    );
  }

  const interfold = InterfoldFactory.connect(interfoldAddress, signer);
  const feeTokenAddress = await interfold.feeToken();
  const bondingRegistryAddress = await interfold.bondingRegistry();
  const bondingRegistry = BondingRegistryFactory.connect(
    bondingRegistryAddress,
    signer,
  );
  const foldAddress = await bondingRegistry.getCiphernodeBondToken();
  if (
    (await ethers.provider.getCode(foldAddress)) === "0x" ||
    (await ethers.provider.getCode(feeTokenAddress)) === "0x"
  ) {
    throw new Error("The live protocol references a token without code.");
  }

  const fold = InterfoldTokenFactory.connect(foldAddress, signer);
  const feeToken = new ethers.Contract(
    feeTokenAddress,
    [
      "function decimals() view returns (uint8)",
      "function balanceOf(address) view returns (uint256)",
      "function mint(address,uint256)",
    ],
    signer,
  );

  // Phase 3 == Live. Admin minting is available before TGE.
  const phase = await fold.phase();
  if (phase === 3n) {
    throw new Error(
      "FOLD is Live and admin minting is closed; fund the faucet with a transfer instead.",
    );
  }

  console.log("Live FOLD:", foldAddress);
  console.log("Live fee token:", feeTokenAddress);

  console.log("Deploying Faucet...");
  const faucet = await new FaucetFactory(signer).deploy(
    foldAddress,
    feeTokenAddress,
  );
  await faucet.waitForDeployment();
  const faucetAddress = await faucet.getAddress();
  const blockNumber = await ethers.provider.getBlockNumber();
  console.log("Faucet deployed to:", faucetAddress);

  // Derive supply from the contract's per-claim amounts so it covers the
  // target number of mints regardless of how the amounts are configured.
  const foldSupply = (await faucet.AMOUNT_FOLD()) * FAUCET_TARGET_MINTS;
  const feeSupply = (await faucet.AMOUNT_FEE_TOKEN()) * FAUCET_TARGET_MINTS;

  console.log("Whitelisting Faucet in FOLD...");
  await (await fold.setTransferWhitelisted(faucetAddress, true)).wait();

  console.log("Minting FOLD to Faucet...");
  await (
    await fold.mint(
      faucetAddress,
      foldSupply,
      ethers.encodeBytes32String("faucet"),
    )
  ).wait();

  console.log("Minting fee tokens to Faucet...");
  await (await feeToken.mint(faucetAddress, feeSupply)).wait();

  if (
    (await fold.balanceOf(faucetAddress)) < foldSupply ||
    (await feeToken.balanceOf(faucetAddress)) < feeSupply
  ) {
    throw new Error("Faucet funding did not reach the expected balances.");
  }

  storeDeploymentArgs(
    {
      constructorArgs: { fold: foldAddress, feeToken: feeTokenAddress },
      blockNumber,
      address: faucetAddress,
    },
    "Faucet",
    chain,
  );

  console.log(`
    ============================================
    Faucet redeployed and funded!
    ============================================
    Faucet:  ${faucetAddress}
    Block:   ${blockNumber}
    FOLD:    ${ethers.formatEther(foldSupply)}
    Fee token: ${ethers.formatUnits(feeSupply, await feeToken.decimals())}
    ============================================
  `);
};

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
