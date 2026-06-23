// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
import hre from "hardhat";

import {
  Faucet__factory as FaucetFactory,
  InterfoldToken__factory as InterfoldTokenFactory,
  MockUSDC__factory as MockUSDCFactory,
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
 * FOLD and funds it with FOLD + mock USDC.
 *
 * FOLD funding uses `mint()`, which is only valid while FOLD is in the Virtual
 * phase (before CCA_START). The deployer holds no FOLD of its own, so there is
 * no alternative funding path — the script aborts if the window has passed.
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

  const foldAddress = readDeploymentArgs("InterfoldToken", chain)?.address;
  const feeTokenAddress = readDeploymentArgs("MockUSDC", chain)?.address;
  if (!foldAddress || !feeTokenAddress) {
    throw new Error(
      "InterfoldToken (FOLD) and/or MockUSDC not found in deployed_contracts.json. " +
        "Run the full deploy first.",
    );
  }

  const fold = InterfoldTokenFactory.connect(foldAddress, signer);
  const feeToken = MockUSDCFactory.connect(feeTokenAddress, signer);

  // Phase 0 == Virtual. mint() reverts (MintingClosed) once CCA_START passes.
  const phase = await fold.phase();
  if (phase !== 0n) {
    throw new Error(
      `FOLD is no longer in the Virtual phase (phase=${phase}); mint() is closed, ` +
        "so the faucet cannot be funded with FOLD. Re-run the full deploy to reset the CCA window.",
    );
  }

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
  const usdcSupply = (await faucet.AMOUNT_FEE_TOKEN()) * FAUCET_TARGET_MINTS;

  storeDeploymentArgs(
    {
      constructorArgs: { fold: foldAddress, feeToken: feeTokenAddress },
      blockNumber,
      address: faucetAddress,
    },
    "Faucet",
    chain,
  );

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

  console.log("Minting mock USDC to Faucet...");
  await (await feeToken.mint(faucetAddress, usdcSupply)).wait();

  console.log(`
    ============================================
    Faucet redeployed and funded!
    ============================================
    Faucet:  ${faucetAddress}
    Block:   ${blockNumber}
    FOLD:    ${ethers.formatEther(foldSupply)}
    USDC:    ${ethers.formatUnits(usdcSupply, 6)}
    ============================================
  `);
};

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
