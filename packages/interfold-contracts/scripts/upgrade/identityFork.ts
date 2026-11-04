// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
//
// Anvil fork helpers for the identity rollout rehearsal and the batch check. Nothing here signs for
// a real network: every transaction goes to a local fork from an impersonated account.
import { ethers } from "ethers";
import { spawn } from "node:child_process";
import fs from "node:fs";

import type { ProtocolConfigFile } from "../protocol/types";
import { identityBatchPaths } from "./identityGate";

/** Starts `anvil` forking `forkUrl` on `port`, and resolves once it answers. */
export async function startFork(options: {
  forkUrl: string;
  port: number;
  forkBlock?: string;
}): Promise<{ provider: ethers.JsonRpcProvider; stop: () => void }> {
  const args = [
    "--fork-url",
    options.forkUrl,
    "--port",
    String(options.port),
    "--silent",
  ];
  if (options.forkBlock) args.push("--fork-block-number", options.forkBlock);
  const anvil = spawn("anvil", args, { stdio: "inherit" });
  const provider = new ethers.JsonRpcProvider(
    `http://127.0.0.1:${options.port}`,
  );
  for (let attempt = 0; attempt < 60; attempt += 1) {
    try {
      await provider.getBlockNumber();
      return { provider, stop: () => anvil.kill("SIGTERM") };
    } catch {
      await new Promise((resolve) => setTimeout(resolve, 1000));
    }
  }
  anvil.kill("SIGTERM");
  throw new Error("anvil did not start");
}

/** Impersonates `account`, gives it ether, sends `data` to `to`, and returns the mined receipt. */
export async function sendAs(
  provider: ethers.JsonRpcProvider,
  account: string,
  to: string,
  data: string,
  value = "0x0",
): Promise<ethers.TransactionReceipt> {
  await provider.send("anvil_impersonateAccount", [account]);
  await provider.send("anvil_setBalance", [account, "0x56BC75E2D63100000"]);
  const block = await provider.getBlock("latest");
  const hash = await provider.send("eth_sendTransaction", [
    { from: account, to, data, value, gas: ethers.toBeHex(block!.gasLimit) },
  ]);
  const receipt = await provider.waitForTransaction(hash);
  await provider.send("anvil_stopImpersonatingAccount", [account]);
  if (!receipt || receipt.status !== 1) {
    throw new Error(`Transaction to ${to} from ${account} reverted (${hash})`);
  }
  return receipt;
}

/**
 * Sends a written identity batch the way governance does: with Aragon governance, the proposer Safe
 * calls the Admin plugin, which runs every action in one transaction; otherwise the protocol owner
 * sends each call. Then mines a later block, because capacity reads one second before the head.
 * Returns the gas of each transaction.
 */
export async function executeIdentityBatch(
  provider: ethers.JsonRpcProvider,
  config: ProtocolConfigFile,
  stage: string,
): Promise<bigint[]> {
  const files = identityBatchPaths(config, stage);
  const [sender, file] = config.governance
    ? [config.governance.proposerSafe, files.safeBuilder]
    : [config.protocolOwner, files.raw];
  const batch = JSON.parse(fs.readFileSync(file, "utf8")) as {
    transactions: { to: string; data: string; value?: string }[];
  };
  const gas: bigint[] = [];
  for (const tx of batch.transactions) {
    const receipt = await sendAs(
      provider,
      sender,
      tx.to,
      tx.data,
      ethers.toBeHex(BigInt(tx.value ?? 0)),
    );
    gas.push(receipt.gasUsed);
  }
  await provider.send("evm_increaseTime", [2]);
  await provider.send("evm_mine", []);
  return gas;
}

/** Counted owner capacity one second before the head, as a request reads it. */
export async function ownerCapacity(
  provider: ethers.JsonRpcProvider,
  bondingRegistry: string,
): Promise<bigint> {
  const contract = new ethers.Contract(
    bondingRegistry,
    ["function committeeOwnerCapacity(uint256) view returns (uint256)"],
    provider,
  );
  // Read the head without the provider's block cache, and the capacity at that very block.
  const head = Number(await provider.send("eth_blockNumber", []));
  const block = await provider.getBlock(head);
  return contract.committeeOwnerCapacity(block!.timestamp - 1, {
    blockTag: head,
  });
}
