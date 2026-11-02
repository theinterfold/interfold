// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
//
// Runs the identity gate rollout end to end on a local anvil fork of mainnet. Every batch executes
// as governance sends it: with Aragon, the proposer Safe calls the Admin plugin in one transaction.
//
//   1. prepare the gate with `identityGate.ts` against copies of the mainnet config and deployment,
//      execute its batch, and validate it with the policy off;
//   2. with --proof, register the proof's bond owner against ZKPassport's mainnet verifier;
//   3. check that `enforce` refuses while too few owners are verified, that the batch check refuses
//      its payload, then force it, execute it, and read the owner capacity that it leaves;
//   4. check that `rotate-verifier` refuses an unchanged config and a changed identifier setting,
//      then rotate to a verifier with another proof validity; credentials stay;
//   5. with --proof, revoke the proof's identifier (refused without --force: too few owners stay);
//   6. relax the policy (the rollback): the batch check passes it; execute it and validate again.
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
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import type { ProtocolConfigFile } from "../protocol/types";
import {
  executeIdentityBatch,
  ownerCapacity,
  sendAs,
  startFork,
} from "./identityFork";
import {
  expectedExpiresAt,
  expectedIdentityId,
  readProofBundle,
} from "./identityProofFork";

const PORT = Number(process.env.ANVIL_PORT ?? 18545);
const RPC = `http://127.0.0.1:${PORT}`;
// anvil's first test account; funded on every fork.
const TEST_KEY =
  "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
// ZKPassport 0.21.1: two bytes each for major, minor, and patch.
const DEFAULT_VERSION = ethers.zeroPadBytes("0x000000150001", 32);
const GATE = "scripts/upgrade/identityGate.ts";
const CHECK = "scripts/upgrade/identityBatchCheck.ts";

const packageDir = path.resolve(
  path.dirname(new URL(import.meta.url).pathname),
  "..",
  "..",
);
const protocolDir = path.join(packageDir, "deploy", "protocol");
const registryInterface = new ethers.Interface([
  "function register(bytes evidence)",
  "function identityOf(address owner) view returns (bytes32 identityId, uint48 expiresAt)",
]);

function log(message: string) {
  console.log(`\n=== ${message}`);
}

function readJson(file: string) {
  return JSON.parse(fs.readFileSync(file, "utf8"));
}

/** Runs a rollout script against the fork; returns the exit status and the output. */
function run(
  script: string,
  args: string[],
  env: Record<string, string> = {},
): { ok: boolean; out: string } {
  console.log(`$ ${path.basename(script)} ${args.join(" ")}`);
  const result = spawnSync("pnpm", ["exec", "tsx", script, ...args], {
    cwd: packageDir,
    env: {
      ...process.env,
      RPC_URL: RPC,
      PRIVATE_KEY: TEST_KEY,
      SKIP_SOURCE_VERIFICATION: "1",
      ...env,
    },
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
  });
  const out = `${result.stdout ?? ""}${result.stderr ?? ""}`;
  process.stdout.write(out);
  return { ok: result.status === 0, out };
}

function mustPass(
  script: string,
  args: string[],
  env?: Record<string, string>,
) {
  if (!run(script, args, env).ok) {
    throw new Error(`${path.basename(script)} ${args[0]} failed`);
  }
}

/** The step must fail, and its output must match `expected`. */
function mustRefuse(
  script: string,
  args: string[],
  expected: RegExp,
  env?: Record<string, string>,
) {
  const { ok, out } = run(script, args, env);
  if (ok || !expected.test(out)) {
    throw new Error(
      `${path.basename(script)} ${args[0]} should have refused (${expected})`,
    );
  }
  console.log(`refused as expected (${expected})`);
}

async function identityOf(
  provider: ethers.JsonRpcProvider,
  registry: string,
  owner: string,
): Promise<[string, bigint]> {
  const [identityId, expiresAt] = registryInterface.decodeFunctionResult(
    "identityOf",
    await provider.call({
      to: registry,
      data: registryInterface.encodeFunctionData("identityOf", [owner]),
    }),
  );
  return [identityId, BigInt(expiresAt)];
}

/** Writes a copy of the fork config with other identity settings; returns its path. */
function configWith(
  work: string,
  name: string,
  config: ProtocolConfigFile,
  identity: Record<string, unknown>,
): string {
  const file = path.join(work, name);
  fs.writeFileSync(
    file,
    JSON.stringify(
      { ...config, identity: { ...config.identity, ...identity } },
      null,
      2,
    ),
  );
  return file;
}

async function main() {
  const forkUrl = process.env.FORK_URL;
  if (!forkUrl) throw new Error("Set FORK_URL to a mainnet RPC");
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
  const forkConfigJson: ProtocolConfigFile = {
    ...config,
    name: "mainnet-fork",
    identity,
  };
  const forkConfig = configWith(
    work,
    "mainnet-fork.config.json",
    forkConfigJson,
    {},
  );
  const forkDeployment = path.join(work, "mainnet-fork.deployment.json");
  fs.writeFileSync(
    forkDeployment,
    JSON.stringify({ ...deployment, name: "mainnet-fork" }, null, 2),
  );
  // A rotation keeps the identifier settings; this one shortens the proof validity.
  const rotatedConfigJson: ProtocolConfigFile = {
    ...forkConfigJson,
    identity: { ...forkConfigJson.identity!, proofValidity: "259200" },
  };
  const rotatedConfig = configWith(
    work,
    "mainnet-fork.rotated.config.json",
    forkConfigJson,
    { proofValidity: "259200" },
  );
  const otherDomainConfig = configWith(
    work,
    "mainnet-fork.other-domain.config.json",
    forkConfigJson,
    { domain: "other.example" },
  );
  const protocolRecord = path.join(packageDir, "deployed_contracts.json");
  const protocolRecordBackup = fs.readFileSync(protocolRecord);
  const argsFor = (configFile: string) => [
    "--network",
    "mainnet",
    "--config",
    configFile,
    "--deployment",
    forkDeployment,
    "--log-rpc",
    logRpc,
  ];
  const args = argsFor(forkConfig);
  const rotatedArgs = argsFor(rotatedConfig);
  // The batch check forks this fork, so it replays the exact payload against the rehearsal state.
  const checkEnv = { FORK_URL: RPC, ANVIL_PORT: String(PORT + 1) };
  const fork = await startFork({
    forkUrl,
    port: PORT,
    forkBlock: process.env.FORK_BLOCK,
  });
  try {
    const provider = fork.provider;
    log(
      `forked mainnet at block ${await provider.getBlockNumber()}; work dir ${work}`,
    );
    const bonding: string = deployment.bondingRegistryProxy;
    const capacity = () => ownerCapacity(provider, bonding);

    log("1. prepare, execute, and validate with the policy off");
    mustPass(GATE, ["prepare", ...args]);
    const gas = await executeIdentityBatch(provider, forkConfigJson, "prepare");
    mustPass(GATE, ["validate", ...args, "--required", "false"]);
    const plan = readJson(
      path.join(protocolDir, "mainnet-fork.identity-gate.json"),
    );
    console.log(`owner capacity: ${await capacity()}`);

    let identityId: string | undefined;
    if (bundle) {
      log(`2. register the proof's owner ${bundle.owner}`);
      const receipt = await sendAs(
        provider,
        bundle.owner,
        plan.identityRegistry,
        registryInterface.encodeFunctionData("register", [bundle.evidence]),
      );
      const [registered, expiresAt] = await identityOf(
        provider,
        plan.identityRegistry,
        bundle.owner,
      );
      if (registered !== expectedIdentityId(bundle)) {
        throw new Error(
          `Registered identifier ${registered} differs from the proof's ${expectedIdentityId(bundle)}`,
        );
      }
      const expectedExpiry = expectedExpiresAt(
        bundle,
        BigInt(identity.maxValidity),
      );
      if (expiresAt !== expectedExpiry) {
        throw new Error(
          `Registered expiry ${expiresAt} differs from the proof's ${expectedExpiry}`,
        );
      }
      identityId = registered;
      console.log(
        `registered: identity ${registered}, expires ${new Date(Number(expiresAt) * 1000).toISOString()}, gas ${receipt.gasUsed}`,
      );
    } else {
      log("2. no --proof: no owner registers");
    }

    log("3. enforce: refused with too few verified owners, then forced");
    mustRefuse(GATE, ["enforce", ...args], /owners have a credential/);
    mustPass(GATE, ["enforce", ...args, "--force"]);
    mustRefuse(
      CHECK,
      ["--stage", "enforce", "--network", "mainnet", "--config", forkConfig],
      /owner capacity is/,
      checkEnv,
    );
    gas.push(
      ...(await executeIdentityBatch(provider, forkConfigJson, "enforce")),
    );
    console.log(
      `owner capacity under the required policy: ${await capacity()}`,
    );
    mustRefuse(
      GATE,
      ["validate", ...args, "--required", "true"],
      /bond owners are counted/,
    );

    log("4. rotate the verifier: identifier settings stay, credentials stay");
    mustRefuse(GATE, ["rotate-verifier", ...args], /nothing to rotate/);
    mustRefuse(
      GATE,
      ["rotate-verifier", ...argsFor(otherDomainConfig)],
      /derive every identifier/,
    );
    mustPass(GATE, ["rotate-verifier", ...rotatedArgs]);
    gas.push(
      ...(await executeIdentityBatch(
        provider,
        rotatedConfigJson,
        "rotate-verifier",
      )),
    );
    // The verifier reads back; only the low capacity of the forced policy still refuses.
    mustRefuse(
      GATE,
      ["validate", ...rotatedArgs, "--required", "true"],
      /bond owners are counted/,
    );
    if (bundle && identityId) {
      const [kept] = await identityOf(
        provider,
        plan.identityRegistry,
        bundle.owner,
      );
      if (kept !== identityId) {
        throw new Error("The rotation changed the registered identifier");
      }
      console.log("the proof's credential stays through the rotation");
    }

    if (bundle && identityId) {
      log(
        "5. revoke the proof's identifier: refused with too few owners left, then forced",
      );
      mustRefuse(
        GATE,
        ["revoke", ...rotatedArgs, "--identity", identityId],
        /After the revocation/,
      );
      mustPass(GATE, [
        "revoke",
        ...rotatedArgs,
        "--identity",
        identityId,
        "--force",
      ]);
      gas.push(
        ...(await executeIdentityBatch(provider, rotatedConfigJson, "revoke")),
      );
      const [cleared, expiry] = await identityOf(
        provider,
        plan.identityRegistry,
        bundle.owner,
      );
      if (cleared !== ethers.ZeroHash || expiry !== 0n) {
        throw new Error("The revoked credential is still set");
      }
      console.log(`owner capacity after the revocation: ${await capacity()}`);
    } else {
      log("5. no --proof: nothing to revoke");
    }

    log(
      "6. relax (the rollback): check the exact payload, execute, and validate",
    );
    mustPass(GATE, ["relax", ...rotatedArgs]);
    mustPass(
      CHECK,
      ["--stage", "relax", "--network", "mainnet", "--config", rotatedConfig],
      checkEnv,
    );
    gas.push(
      ...(await executeIdentityBatch(provider, rotatedConfigJson, "relax")),
    );
    mustPass(GATE, ["validate", ...rotatedArgs, "--required", "false"]);
    console.log(`owner capacity after the rollback: ${await capacity()}`);

    const block = await provider.getBlock("latest");
    log(
      `simulation complete: largest batch ${gas.reduce((a, b) => (a > b ? a : b), 0n)} gas (block gas limit ${block!.gasLimit})`,
    );
  } finally {
    fork.stop();
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
