// SPDX-License-Identifier: LGPL-3.0-only
//
// Runs the v0.19 cutover end to end on a local anvil fork of mainnet:
//
//   1. fork mainnet and move the clock past every report window;
//   2. release the committees of ended E3s (anyone can);
//   3. deploy an OpenVM CRISP with a stub Halo2 verifier (wiring only; it proves nothing);
//   4. prepare the cutover with `v19Cutover.ts`, execute its batch as the protocol owner and
//      validate it twice, so validation is shown to repeat;
//   5. let every operator that served on a committee acknowledge the release, comparing the gas
//      that a node estimates at the latest block with the gas the acknowledgment uses;
//   6. refresh the other registered operators, prepare the resume batch, execute it and validate
//      once more with requests open.
//
// Usage (from packages/interfold-contracts):
//   FORK_URL=<mainnet RPC> LOG_RPC_URL=<RPCs> tsx scripts/upgrade/simulateV19Cutover.ts [--legacy]
//
// FORK_BLOCK pins the fork block. LOG_RPC_URL (comma-separated mainnet RPCs that serve eth_getLogs
// history) lists the registered operators for the refresh. `--legacy` also runs the v0.18
// `secureCrisp.ts` against the fork first and reports how it fails. Nothing here signs for
// mainnet: every transaction goes to the local fork, as an anvil test key or an impersonated
// account.
import { spawn, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { ethers } from "ethers";

const PORT = Number(process.env.ANVIL_PORT ?? 18545);
const RPC = `http://127.0.0.1:${PORT}`;
// anvil's first test account; funded on every fork.
const TEST_KEY =
  "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

const packageDir = path.resolve(path.dirname(new URL(import.meta.url).pathname), "..", "..");
const repoRoot = path.resolve(packageDir, "..", "..");
const crispDir = path.join(repoRoot, "examples", "CRISP", "packages", "crisp-contracts");
const protocolDir = path.join(packageDir, "deploy", "protocol");

function log(message: string) {
  console.log(`\n=== ${message}`);
}

function readJson(file: string) {
  return JSON.parse(fs.readFileSync(file, "utf8"));
}

async function rpc(provider: ethers.JsonRpcProvider, method: string, params: unknown[] = []) {
  return provider.send(method, params);
}

/** Run a child command with the fork as `mainnet`; throws on failure unless `allowFailure`. */
function run(
  cwd: string,
  command: string,
  args: string[],
  env: Record<string, string>,
  allowFailure = false,
): { status: number; output: string } {
  console.log(`$ (${path.relative(repoRoot, cwd) || "."}) ${command} ${args.join(" ")}`);
  const result = spawnSync(command, args, {
    cwd,
    env: { ...process.env, RPC_URL: RPC, PRIVATE_KEY: TEST_KEY, ...env },
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
  });
  const output = `${result.stdout ?? ""}${result.stderr ?? ""}`;
  process.stdout.write(output);
  if (result.status !== 0 && !allowFailure) {
    throw new Error(`${command} ${args.join(" ")} failed with status ${result.status}`);
  }
  return { status: result.status ?? 1, output };
}

async function startFork(): Promise<() => void> {
  const forkUrl = process.env.FORK_URL;
  if (!forkUrl) throw new Error("Set FORK_URL to a mainnet RPC");
  const args = ["--fork-url", forkUrl, "--port", String(PORT), "--silent"];
  if (process.env.FORK_BLOCK) args.push("--fork-block-number", process.env.FORK_BLOCK);
  const anvil = spawn("anvil", args, { stdio: "inherit" });
  const provider = new ethers.JsonRpcProvider(RPC);
  for (let attempt = 0; attempt < 60; attempt += 1) {
    try {
      await provider.getBlockNumber();
      return () => anvil.kill("SIGTERM");
    } catch {
      await new Promise((resolve) => setTimeout(resolve, 1000));
    }
  }
  anvil.kill("SIGTERM");
  throw new Error("anvil did not start");
}

/**
 * Impersonate `account`, give it ether, send `data` to `to` and wait for success. The gas limit is
 * fixed: anvil's own estimate for an impersonated send came out below the gas the acknowledgement
 * used on a fork, while `eth_estimateGas` for the same call did not.
 */
async function sendAs(
  provider: ethers.JsonRpcProvider,
  account: string,
  to: string,
  data: string,
  value = "0x0",
) {
  await rpc(provider, "anvil_impersonateAccount", [account]);
  await rpc(provider, "anvil_setBalance", [account, "0x56BC75E2D63100000"]);
  const gas = ethers.toBeHex(10_000_000);
  const hash = await rpc(provider, "eth_sendTransaction", [{ from: account, to, data, value, gas }]);
  const receipt = await provider.waitForTransaction(hash);
  if (!receipt || receipt.status !== 1) {
    throw new Error(`Transaction to ${to} from ${account} reverted (${hash})`);
  }
  await rpc(provider, "anvil_stopImpersonatingAccount", [account]);
  return receipt;
}

async function main() {
  const legacy = process.argv.includes("--legacy");
  const logRpc = process.env.LOG_RPC_URL;
  if (!logRpc) throw new Error("Set LOG_RPC_URL to mainnet RPCs that serve eth_getLogs history");
  const config = readJson(path.join(protocolDir, "mainnet-protocol.config.json"));
  const deployment = readJson(path.join(protocolDir, "mainnet-protocol.deployment.json"));

  // The tools run against copies, so the fork never writes the real mainnet plan or record.
  const work = fs.mkdtempSync(path.join(os.tmpdir(), "v19-cutover-"));
  const forkConfig = path.join(work, "mainnet-fork.config.json");
  const forkDeployment = path.join(work, "mainnet-fork.deployment.json");
  fs.writeFileSync(forkConfig, JSON.stringify({ ...config, name: "mainnet-fork" }, null, 2));
  fs.writeFileSync(forkDeployment, JSON.stringify({ ...deployment, name: "mainnet-fork" }, null, 2));
  const crispRecord = path.join(crispDir, "deployed_contracts.json");
  const crispRecordBackup = fs.readFileSync(crispRecord);

  const stopFork = await startFork();
  try {
    const provider = new ethers.JsonRpcProvider(RPC);
    const operator = new ethers.Wallet(TEST_KEY, provider);
    const forkBlock = await provider.getBlockNumber();
    log(`forked mainnet at block ${forkBlock}; work dir ${work}`);

    const interfold = new ethers.Contract(
      deployment.interfold,
      [
        "function requestsPaused() view returns (bool)",
        "function activeE3Count() view returns (uint256)",
        "function nexte3Id() view returns (uint256)",
      ],
      provider,
    );
    const registryAbi = [
      "function unreleasedCommitteeCount() view returns (uint256)",
      "function releaseCommittee(uint256 e3Id)",
      "function getCommitteeNodes(uint256 e3Id) view returns (address[])",
    ];
    const registry = new ethers.Contract(deployment.ciphernodeRegistry, registryAbi, operator);

    log("1. move the clock past every report window");
    const latest = await provider.getBlock("latest");
    const target = Number(process.env.ADVANCE_TO ?? latest!.timestamp + 3 * 86_400);
    await rpc(provider, "evm_setNextBlockTimestamp", [target]);
    await rpc(provider, "evm_mine");
    console.log(`block time is now ${new Date(target * 1000).toISOString()}`);

    log("2. release the committees of ended E3s");
    // E3 IDs are the Interfold address in the top bits and a counter below them.
    const firstE3 = BigInt(deployment.interfold) << 96n;
    const e3Ids: bigint[] = [];
    for (let id = firstE3; id < (await interfold.nexte3Id()); id += 1n) e3Ids.push(id);
    for (const e3Id of e3Ids) {
      try {
        await registry.releaseCommittee.staticCall(e3Id);
      } catch {
        continue;
      }
      console.log(`releaseCommittee(${e3Id})`);
      await (await registry.releaseCommittee(e3Id)).wait();
    }
    const unreleased = await registry.unreleasedCommitteeCount();
    const activeE3s = await interfold.activeE3Count();
    console.log(`unreleased committees ${unreleased}, active E3s ${activeE3s}, paused ${await interfold.requestsPaused()}`);
    if (unreleased !== 0n || activeE3s !== 0n) throw new Error("The fork is not drained");

    log("3. deploy an OpenVM CRISP with a stub Halo2 verifier");
    // Creation code that returns the one-byte runtime 0x00 (STOP): every verify call succeeds.
    const stub = await operator.sendTransaction({ data: "0x6001600c60003960016000f300" });
    const stubAddress = (await stub.wait())!.contractAddress!;
    const identity = {
      appExeCommit: ethers.toBeHex(1n, 32),
      appVmCommit: ethers.toBeHex(2n, 32),
      halo2RuntimeCodeHash: ethers.keccak256(await provider.getCode(stubAddress)),
    };
    const identityFile = path.join(work, "openvm-identity.json");
    fs.writeFileSync(identityFile, JSON.stringify(identity, null, 2));
    run(crispDir, "pnpm", ["hardhat", "run", "deploy/deploy.ts", "--network", "mainnet"], {
      CRISP_INITIAL_OWNER: config.protocolOwner,
      DEFER_PROTOCOL_WIRING: "true",
      ALLOW_MAINNET_DEFERRED_WIRING: "true",
      INPUT_AVAILABILITY_SIGNER: operator.address,
      OPENVM_APP_EXE_COMMIT: identity.appExeCommit,
      OPENVM_APP_VM_COMMIT: identity.appVmCommit,
      OPENVM_HALO2_VERIFIER: stubAddress,
      OPENVM_HALO2_RUNTIME_CODE_HASH: identity.halo2RuntimeCodeHash,
    });

    const toolArgs = [
      "--network", "mainnet",
      "--config", forkConfig,
      "--deployment", forkDeployment,
      "--crisp-deployments", crispRecord,
    ];
    if (legacy) {
      log("legacy: run the v0.18 secure-CRISP builder against the fork");
      const result = run(
        packageDir,
        "pnpm",
        ["exec", "tsx", "scripts/upgrade/secureCrisp.ts", ...toolArgs, "--input-availability-signer", operator.address],
        {},
        true,
      );
      console.log(`legacy builder exit status ${result.status}`);
    }

    log("4. prepare the v0.19 cutover");
    run(packageDir, "pnpm", [
      "exec", "tsx", "scripts/upgrade/v19Cutover.ts", "prepare", ...toolArgs,
      "--openvm-identity", identityFile,
      "--input-availability-signer", operator.address,
    ], {});
    const batch = readJson(path.join(protocolDir, "mainnet-fork.v19-cutover.safe.json"));
    log(`execute ${batch.transactions.length} governance transactions as ${config.protocolOwner}`);
    for (const tx of batch.transactions) {
      await sendAs(provider, config.protocolOwner, tx.to, tx.data, ethers.toBeHex(BigInt(tx.value ?? 0)));
    }

    log("validate twice (read-only), then with --write-records, then once more");
    run(packageDir, "pnpm", ["exec", "tsx", "scripts/upgrade/v19Cutover.ts", "validate", ...toolArgs], {});
    run(packageDir, "pnpm", ["exec", "tsx", "scripts/upgrade/v19Cutover.ts", "validate", ...toolArgs], {});
    run(packageDir, "pnpm", ["exec", "tsx", "scripts/upgrade/v19Cutover.ts", "validate", ...toolArgs, "--write-records"], {});
    run(packageDir, "pnpm", ["exec", "tsx", "scripts/upgrade/v19Cutover.ts", "validate", ...toolArgs], {});

    log("5. every operator that served on a committee acknowledges the release");
    const plan = readJson(path.join(protocolDir, "mainnet-fork.v19-cutover.json"));
    const operatorSet = new Set<string>();
    for (const e3Id of e3Ids) {
      let nodes: string[];
      try {
        nodes = await registry.getCommitteeNodes(e3Id);
      } catch {
        continue; // the E3 failed before its committee published a key
      }
      for (const node of nodes) operatorSet.add(ethers.getAddress(node));
    }
    const operators = [...operatorSet];
    const releases = new ethers.Interface([
      "function acknowledgeNodeRelease(bytes32 releaseId, uint32 protocolVersion, uint32 nodeGeneration)",
    ]);
    const acknowledgment = releases.encodeFunctionData("acknowledgeNodeRelease", [
      plan.nodeRelease.releaseId,
      plan.nodeRelease.protocolVersion,
      plan.nodeRelease.nodeGeneration,
    ]);
    let acknowledged = 0;
    let underestimated = 0;
    for (const node of operators) {
      // A node estimates at the latest block, as geth's eth_estimateGas does, and its
      // transaction lands in a later block.
      const estimate = BigInt(
        await rpc(provider, "eth_estimateGas", [
          { from: node, to: plan.nodeReleaseRegistry, data: acknowledgment },
          "latest",
        ]),
      );
      try {
        const receipt = await sendAs(provider, node, plan.nodeReleaseRegistry, acknowledgment);
        acknowledged += 1;
        if (receipt.gasUsed > estimate) {
          underestimated += 1;
          console.log(`  ${node}: estimate ${estimate}, used ${receipt.gasUsed}`);
        }
      } catch (error) {
        console.log(`  ${node} cannot acknowledge: ${(error as Error).message}`);
      }
    }
    console.log(`${acknowledged} of ${operators.length} operators acknowledged`);
    console.log(`${underestimated} acknowledgments used more gas than the latest-block estimate`);

    log("6. refresh the other registered operators, then resume");
    run(packageDir, "pnpm", ["exec", "tsx", "scripts/upgrade/v19Cutover.ts", "refresh", ...toolArgs, "--log-rpc", logRpc], {});
    // Capacity counts from the block after the last refresh.
    const head = await provider.getBlock("latest");
    await rpc(provider, "evm_setNextBlockTimestamp", [head!.timestamp + 12]);
    await rpc(provider, "evm_mine");
    run(packageDir, "pnpm", ["exec", "tsx", "scripts/upgrade/v19Cutover.ts", "resume", ...toolArgs, "--ciphernodes-restarted"], {});
    const resume = readJson(path.join(protocolDir, "mainnet-fork.v19-resume.safe.json"));
    for (const tx of resume.transactions) {
      await sendAs(provider, config.protocolOwner, tx.to, tx.data);
    }
    console.log(`requests paused after resume: ${await interfold.requestsPaused()}`);
    run(packageDir, "pnpm", ["exec", "tsx", "scripts/upgrade/v19Cutover.ts", "validate", ...toolArgs], {});
    log("simulation complete");
  } finally {
    stopFork();
    fs.writeFileSync(crispRecord, crispRecordBackup);
    // Copy, not rename: the work dir can be on another filesystem.
    for (const file of fs.readdirSync(protocolDir)) {
      if (!file.startsWith("mainnet-fork.")) continue;
      fs.copyFileSync(path.join(protocolDir, file), path.join(work, file));
      fs.unlinkSync(path.join(protocolDir, file));
    }
    console.log(`fork outputs moved to ${work}`);
  }
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
