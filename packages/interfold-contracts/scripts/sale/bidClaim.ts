// SPDX-License-Identifier: LGPL-3.0-only
import { ethers as ethersLib } from "ethers";
import fs from "fs";

import { arg, connect, hasFlag } from "./cli";
import { CCA_AUCTION_ABI, ZERO } from "./constants";
import {
  deploymentPath,
  planPath,
  readJson,
  writeJson,
} from "./files";
import { writeSaleUiManifest } from "./plan";
import type { DeploymentFile, HardhatEthers, SaleConfigFile, SalePlan } from "./types";
import { loadConfig, resolveCurrency } from "./values";

async function waitForBlock(
  provider: ethersLib.Provider,
  target: bigint,
): Promise<void> {
  let current = BigInt(await provider.getBlockNumber());
  const network = await provider.getNetwork();
  if (network.chainId === 31337n) {
    while (current < target) {
      await (provider as ethersLib.JsonRpcApiProvider).send("evm_mine", []);
      current = BigInt(await provider.getBlockNumber());
    }
    return;
  }
  while (current < target) {
    console.log(`  waiting for block ${target} (current ${current})`);
    await new Promise((resolve) => setTimeout(resolve, 6000));
    try {
      current = BigInt(await provider.getBlockNumber());
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      console.log(`  provider retry after block read failure: ${message}`);
    }
  }
}

export async function actionBidClaim(): Promise<void> {
  const { ethers } = await connect();
  const config = loadConfig();
  const deployment = readJson<DeploymentFile>(deploymentPath(config));
  await bidClaim(ethers, config, deployment);
}

export async function bidClaim(
  ethers: HardhatEthers,
  config: SaleConfigFile,
  deployment: DeploymentFile,
): Promise<void> {
  const signers = await ethers.getSigners();
  const buyer = signers[1] ?? signers[0];
  const buyerAddress = await buyer.getAddress();

  const auction = new ethersLib.Contract(
    deployment.auction,
    CCA_AUCTION_ABI,
    buyer,
  );
  const fold = await ethers.getContractAt("InterfoldToken", deployment.fold);
  const startBlock = BigInt(await auction.startBlock());
  const endBlock = BigInt(await auction.endBlock());
  const claimBlock = BigInt(await auction.claimBlock());
  const isMockCca =
    hasFlag("mock-cca") || deployment.mockCcaFactory !== undefined;
  const resumeBidId = arg("bid-id") ?? deployment.testBidId;

  const bidValue = ethersLib.parseEther(arg("bid-eth") ?? "0.001");
  let bidId = resumeBidId === undefined ? undefined : BigInt(resumeBidId);
  if (bidId !== undefined) {
    console.log(`Resuming existing bid ${bidId}`);
  } else {
    await waitForBlock(ethers.provider, startBlock);
    try {
      const floorPrice = BigInt(config.auction.floorPrice);
      const tickSpacing = BigInt(config.auction.tickSpacing);
      const maxPrice = BigInt(
        arg("max-price") ?? String(floorPrice + tickSpacing),
      );
      const hookData = arg("hook-data") ?? "0x";
      const bidTx = await auction["submitBid(uint256,uint128,address,bytes)"](
        maxPrice,
        bidValue,
        buyerAddress,
        hookData,
        {
          value:
            resolveCurrency(config.auction.currency) === ZERO ? bidValue : 0n,
        },
      );
      const receipt = await bidTx.wait();
      const event = receipt.logs
        .map((log: { topics: ReadonlyArray<string>; data: string }) => {
          try {
            return auction.interface.parseLog(log);
          } catch {
            return null;
          }
        })
        .find(
          (parsed: { name: string } | null) => parsed?.name === "BidSubmitted",
        );
      bidId = BigInt(event?.args?.id ?? 0);
      deployment.testBidId = bidId.toString();
      writeJson(deploymentPath(config), deployment);
      console.log(`Buyer bid submitted: ${bidTx.hash} (bid ${bidId})`);
    } catch (error) {
      if (!isMockCca) throw error;
      const bidTx = await auction.bid({ value: bidValue });
      await bidTx.wait();
      console.log(`Mock buyer bid submitted: ${bidTx.hash}`);
    }
  }

  await waitForBlock(ethers.provider, endBlock + 1n);
  if (bidId !== undefined) {
    if (!isMockCca) {
      try {
        const checkpointTx = await auction.checkpoint();
        await checkpointTx.wait();
        console.log(`Auction checkpoint submitted: ${checkpointTx.hash}`);
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        console.log(`Auction checkpoint skipped: ${message}`);
      }
    }
    try {
      const exitTx = await auction.exitBid(bidId);
      await exitTx.wait();
      console.log(`Buyer bid exited: ${exitTx.hash}`);
    } catch (error) {
      if (isMockCca) throw error;
      const bid = await auction.bids(bidId);
      const partialExitTx = await auction.exitPartiallyFilledBid(
        bidId,
        bid.startBlock,
        0,
      );
      await partialExitTx.wait();
      console.log(`Buyer partially filled bid exited: ${partialExitTx.hash}`);
    }
  }
  await waitForBlock(ethers.provider, claimBlock);
  const claimTx =
    bidId !== undefined
      ? await auction.claimTokens(bidId)
      : await auction.claim();
  await claimTx.wait();
  console.log(`Buyer claim submitted: ${claimTx.hash}`);

  const balance = await fold.balanceOf(buyerAddress);
  const lockCount = await fold.lockCount(buyerAddress);
  if (balance === 0n) throw new Error("Buyer did not receive FOLD");
  if (lockCount === 0n) {
    throw new Error("Buyer claim did not create a FOLD lock");
  }
  await expectTransferRestricted(fold.connect(buyer), deployment.safe);
  console.log(
    `Buyer ${buyerAddress} claimed ${balance} FOLD wei with ${lockCount} lock entry`,
  );
  if (bidId !== undefined) {
    deployment.testBidId = bidId.toString();
    writeJson(deploymentPath(config), deployment);
    if (fs.existsSync(planPath(config))) {
      writeSaleUiManifest(
        config,
        readJson<SalePlan>(planPath(config)),
        deployment,
      );
    }
  }
}

async function expectTransferRestricted(fold: any, to: string): Promise<void> {
  try {
    await fold.transfer.staticCall(to, 1n);
  } catch {
    return;
  }
  throw new Error("Expected claimed FOLD to be transfer-restricted before TGE");
}

