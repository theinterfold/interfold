// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
//
// Runs the identity gate rollout end to end on a local anvil fork of mainnet:
//
//   1. prepare the gate with `identityGate.ts` against copies of the mainnet config and deployment,
//      execute its batch as the protocol owner, and validate it with the policy off;
//   2. with --proof, register the proof's bond owner against ZKPassport's mainnet verifier;
//   3. check that `enforce` refuses while too few owners are verified, then force it, execute it,
//      and read the owner capacity that the required policy leaves;
//   4. relax the policy (the rollback), execute it, and validate again.
//
// Usage (from packages/interfold-contracts):
//   FORK_URL=<mainnet RPC> LOG_RPC_URL=<RPCs> tsx scripts/upgrade/simulateIdentityGate.ts \
//     [--proof <the identity panel's download>]
//
// LOG_RPC_URL (comma-separated mainnet RPCs that serve eth_getLogs history) lists the registered
// operators. With --proof, the verifier takes the proof's settings; without it, the example
// settings with ZKPassport 0.21.1. FORK_BLOCK pins the fork block. Nothing here signs for mainnet:
// every transaction goes to the local fork, as an anvil test key or an impersonated account.
import { ethers } from "ethers";
import { spawn, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { readProofBundle } from "./identityProofFork";

const PORT = Number(process.env.ANVIL_PORT ?? 18545);
const RPC = `http://127.0.0.1:${PORT}`;
// anvil's first test account; funded on every fork.
const TEST_KEY =
  "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
// ZKPassport 0.21.1: two bytes each for major, minor, and patch.
const DEFAULT_VERSION = ethers.zeroPadBytes("0x000000150001", 32);

const packageDir = path.resolve(
  path.dirname(new URL(import.meta.url).pathname),
  "..",
  "..",
);
const protocolDir = path.join(packageDir, "deploy", "protocol");

function log(message: string) {
  console.log(`\n=== ${message}`);
}

function readJson(file: string) {
  return JSON.parse(fs.readFileSync(file, "utf8"));
}

/** Run `identityGate.ts` against the fork as `mainnet`; returns the exit status and the output. */
function gate(action: string, args: string[]): { ok: boolean; out: string } {
  console.log(`$ identityGate.ts ${action} ${args.join(" ")}`);
  const result = spawnSync(
    "pnpm",
    ["exec", "tsx", "scripts/upgrade/identityGate.ts", action, ...args],
    {
      cwd: packageDir,
      env: {
        ...process.env,
        RPC_URL: RPC,
        PRIVATE_KEY: TEST_KEY,
        SKIP_SOURCE_VERIFICATION: "1",
      },
      encoding: "utf8",
      maxBuffer: 64 * 1024 * 1024,
    },
  );
  const out = `${result.stdout ?? ""}${result.stderr ?? ""}`;
  process.stdout.write(out);
  return { ok: result.status === 0, out };
}

function mustPass(action: string, args: string[]) {
  if (!gate(action, args).ok)
    throw new Error(`identityGate.ts ${action} failed`);
}

/** The step must fail, and its output must match `expected`. */
function mustRefuse(action: string, args: string[], expected: RegExp) {
  const { ok, out } = gate(action, args);
  if (ok || !expected.test(out)) {
    throw new Error(
      `identityGate.ts ${action} should have refused (${expected})`,
    );
  }
  console.log(`refused as expected (${expected})`);
}

async function startFork(): Promise<() => void> {
  const forkUrl = process.env.FORK_URL;
  if (!forkUrl) throw new Error("Set FORK_URL to a mainnet RPC");
  const args = ["--fork-url", forkUrl, "--port", String(PORT), "--silent"];
  if (process.env.FORK_BLOCK)
    args.push("--fork-block-number", process.env.FORK_BLOCK);
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

/** Impersonate `account`, give it ether, send `data` to `to`, and return the mined receipt. */
async function sendAs(
  provider: ethers.JsonRpcProvider,
  account: string,
  to: string,
  data: string,
  value = "0x0",
) {
  await provider.send("anvil_impersonateAccount", [account]);
  await provider.send("anvil_setBalance", [account, "0x56BC75E2D63100000"]);
  const hash = await provider.send("eth_sendTransaction", [
    { from: account, to, data, value, gas: ethers.toBeHex(25_000_000) },
  ]);
  const receipt = await provider.waitForTransaction(hash);
  await provider.send("anvil_stopImpersonatingAccount", [account]);
  if (!receipt || receipt.status !== 1) {
    throw new Error(`Transaction to ${to} from ${account} reverted (${hash})`);
  }
  return receipt;
}

/** Execute a written governance batch as the protocol owner; returns the gas of each call. */
async function execute(
  provider: ethers.JsonRpcProvider,
  owner: string,
  stage: string,
): Promise<bigint[]> {
  const batch = readJson(
    path.join(protocolDir, `mainnet-fork.identity-${stage}.safe.json`),
  );
  log(
    `execute the ${stage} batch: ${batch.transactions.length} calls as ${owner}`,
  );
  const gas: bigint[] = [];
  for (const tx of batch.transactions) {
    const receipt = await sendAs(
      provider,
      owner,
      tx.to,
      tx.data,
      ethers.toBeHex(BigInt(tx.value ?? 0)),
    );
    gas.push(receipt.gasUsed);
  }
  console.log(`gas per call: ${gas.join(", ")}`);
  // Capacity reads one second before the head, as a request does, so mine a later block: the
  // operators that the last call refreshed count only from there.
  await provider.send("evm_increaseTime", [2]);
  await provider.send("evm_mine", []);
  return gas;
}

async function capacity(provider: ethers.JsonRpcProvider, bonding: string) {
  const contract = new ethers.Contract(
    bonding,
    ["function committeeOwnerCapacity(uint256) view returns (uint256)"],
    provider,
  );
  const block = await provider.getBlock("latest");
  return contract.committeeOwnerCapacity(block!.timestamp - 1);
}

async function main() {
  const logRpc = process.env.LOG_RPC_URL;
  if (!logRpc)
    throw new Error(
      "Set LOG_RPC_URL to mainnet RPCs that serve eth_getLogs history",
    );
  const proofArg = process.argv.indexOf("--proof");
  const bundle =
    proofArg > 0
      ? readProofBundle(path.resolve(process.argv[proofArg + 1]))
      : null;
  const config = readJson(
    path.join(protocolDir, "mainnet-protocol.config.json"),
  );
  const deployment = readJson(
    path.join(protocolDir, "mainnet-protocol.deployment.json"),
  );
  const example = readJson(
    path.join(protocolDir, "example.protocol.config.json"),
  );
  const identity = bundle
    ? {
        ...example.identity,
        zkPassportVersion: bundle.version,
        domain: bundle.domain,
        scope: bundle.scope,
        nullifierType: bundle.nullifierType,
        oprfKeyHash: bundle.oprfKeyHash,
        faceMatchRequired: bundle.faceMatch,
      }
    : { ...example.identity, zkPassportVersion: DEFAULT_VERSION };
  // The tools run against copies, so the fork never writes the real mainnet plan or record.
  const work = fs.mkdtempSync(path.join(os.tmpdir(), "identity-gate-"));
  const forkConfig = path.join(work, "mainnet-fork.config.json");
  const forkDeployment = path.join(work, "mainnet-fork.deployment.json");
  fs.writeFileSync(
    forkConfig,
    JSON.stringify({ ...config, name: "mainnet-fork", identity }, null, 2),
  );
  fs.writeFileSync(
    forkDeployment,
    JSON.stringify({ ...deployment, name: "mainnet-fork" }, null, 2),
  );
  const protocolRecord = path.join(packageDir, "deployed_contracts.json");
  const protocolRecordBackup = fs.readFileSync(protocolRecord);
  const args = [
    "--network",
    "mainnet",
    "--config",
    forkConfig,
    "--deployment",
    forkDeployment,
    "--log-rpc",
    logRpc,
  ];
  const stopFork = await startFork();
  try {
    const provider = new ethers.JsonRpcProvider(RPC);
    log(
      `forked mainnet at block ${await provider.getBlockNumber()}; work dir ${work}`,
    );
    const owner: string = config.protocolOwner;
    const bonding: string = deployment.bondingRegistryProxy;

    log("1. prepare, execute, and validate with the policy off");
    mustPass("prepare", args);
    const gas = await execute(provider, owner, "prepare");
    mustPass("validate", [...args, "--required", "false"]);
    const plan = readJson(
      path.join(protocolDir, "mainnet-fork.identity-gate.json"),
    );
    console.log(`owner capacity: ${await capacity(provider, bonding)}`);

    if (bundle) {
      log(`2. register the proof's owner ${bundle.owner}`);
      const registry = new ethers.Interface([
        "function register(bytes evidence)",
        "function identityOf(address owner) view returns (bytes32 identityId, uint48 expiresAt)",
      ]);
      const receipt = await sendAs(
        provider,
        bundle.owner,
        plan.identityRegistry,
        registry.encodeFunctionData("register", [bundle.evidence]),
      );
      const [identityId, expiresAt] = registry.decodeFunctionResult(
        "identityOf",
        await provider.call({
          to: plan.identityRegistry,
          data: registry.encodeFunctionData("identityOf", [bundle.owner]),
        }),
      );
      console.log(
        `registered: identity ${identityId}, expires ${new Date(Number(expiresAt) * 1000).toISOString()}, gas ${receipt.gasUsed}`,
      );
    } else {
      log("2. no --proof: no owner registers");
    }

    log("3. enforce: refused with too few verified owners, then forced");
    mustRefuse("enforce", args, /owners have a credential/);
    mustPass("enforce", [...args, "--force"]);
    gas.push(...(await execute(provider, owner, "enforce")));
    console.log(
      `owner capacity under the required policy: ${await capacity(provider, bonding)}`,
    );
    mustRefuse(
      "validate",
      [...args, "--required", "true"],
      /bond owners are counted/,
    );

    log("4. relax (the rollback), execute, and validate");
    mustPass("relax", args);
    gas.push(...(await execute(provider, owner, "relax")));
    mustPass("validate", [...args, "--required", "false"]);
    console.log(
      `owner capacity after the rollback: ${await capacity(provider, bonding)}`,
    );

    const block = await provider.getBlock("latest");
    log(
      `simulation complete: largest call ${gas.reduce((a, b) => (a > b ? a : b), 0n)} gas (block gas limit ${block!.gasLimit})`,
    );
  } finally {
    stopFork();
    fs.writeFileSync(protocolRecord, protocolRecordBackup);
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
