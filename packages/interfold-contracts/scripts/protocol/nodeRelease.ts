// SPDX-License-Identifier: LGPL-3.0-only
import { ethers } from "ethers";
import fs from "node:fs";
import path from "node:path";

import { getRepoRoot } from "../utils";
import { safeTx } from "./safe";
import type {
  ProtocolContracts,
  ProtocolInterfaces,
  SafeTransaction,
} from "./types";

const RELEASE_DOMAIN = "interfold.node.release:v1:";

export interface CurrentNodeRelease {
  version: string;
  protocolVersion: number;
  nodeGeneration: number;
  releaseId: string;
}

/**
 * Returns whether governance must raise the on-chain release policy.
 *
 * A matching policy is already valid and must not be submitted again because
 * `NodeReleaseRegistry` rejects no-op updates. A release that is older in either dimension is not
 * safe to activate.
 */
export function requiresNodeReleasePolicyUpdate(
  release: Pick<CurrentNodeRelease, "protocolVersion" | "nodeGeneration">,
  requiredProtocolVersion: bigint,
  requiredNodeGeneration: bigint,
): boolean {
  const protocolVersion = BigInt(release.protocolVersion);
  const nodeGeneration = BigInt(release.nodeGeneration);
  if (
    protocolVersion < requiredProtocolVersion ||
    nodeGeneration < requiredNodeGeneration
  ) {
    throw new Error(
      `Node release cannot move backwards from protocol ${requiredProtocolVersion}, generation ${requiredNodeGeneration} to protocol ${protocolVersion}, generation ${nodeGeneration}`,
    );
  }
  return (
    protocolVersion !== requiredProtocolVersion ||
    nodeGeneration !== requiredNodeGeneration
  );
}

export function requiredCircuitsVersion(): string {
  const root = getRepoRoot();
  const versions = JSON.parse(
    fs.readFileSync(path.join(root, "crates/zk-prover/versions.json"), "utf8"),
  ) as { required_circuits_version?: string };
  if (!versions.required_circuits_version) {
    throw new Error("Required circuit version is missing");
  }
  return versions.required_circuits_version;
}

function unsignedInteger(source: string, name: string): number {
  const match = source.match(new RegExp(`^${name}\\s*=\\s*(\\d+)\\s*$`, "m"));
  const value = Number(match?.[1]);
  if (!Number.isSafeInteger(value) || value <= 0 || value > 0xffff_ffff) {
    throw new Error(`${name} must be a positive uint32 value`);
  }
  return value;
}

export function currentNodeRelease(): CurrentNodeRelease {
  const root = getRepoRoot();
  const source = fs.readFileSync(
    path.join(root, "crates/config/protocol-release.toml"),
    "utf8",
  );
  const rootPackage = JSON.parse(
    fs.readFileSync(path.join(root, "package.json"), "utf8"),
  ) as { version?: string };
  if (!rootPackage.version) throw new Error("Root package version is missing");
  const cargoSource = fs.readFileSync(path.join(root, "Cargo.toml"), "utf8");
  const workspacePackage = cargoSource.match(
    /\[workspace\.package\]([\s\S]*?)(?=\n\[|$)/,
  )?.[1];
  const rustVersion = workspacePackage?.match(
    /^version\s*=\s*"([^"]+)"\s*$/m,
  )?.[1];
  if (rustVersion !== rootPackage.version) {
    throw new Error(
      `Release version mismatch: package.json has ${rootPackage.version}, Cargo.toml has ${rustVersion ?? "no workspace version"}`,
    );
  }
  return {
    version: rootPackage.version,
    protocolVersion: unsignedInteger(source, "protocol_version"),
    nodeGeneration: unsignedInteger(source, "node_generation"),
    releaseId: ethers.id(`${RELEASE_DOMAIN}${rootPackage.version}`),
  };
}

export function appendNodeReleaseTransactions(
  txs: SafeTransaction[],
  contracts: ProtocolContracts,
  interfaces: ProtocolInterfaces,
): CurrentNodeRelease {
  const release = currentNodeRelease();
  txs.push(
    safeTx(
      contracts.interfold,
      interfaces.interfold.encodeFunctionData("setNodeReleaseRegistry", [
        contracts.nodeReleaseRegistry,
      ]),
    ),
    safeTx(
      contracts.nodeReleaseRegistry,
      interfaces.nodeRelease.encodeFunctionData("setRequiredNodeRelease", [
        release.protocolVersion,
        release.nodeGeneration,
      ]),
    ),
  );
  return release;
}

export async function deployNodeReleaseRegistry(
  ethersRuntime: any,
  owner: string,
  bondingRegistry: string,
  ciphernodeRegistry: string,
): Promise<{ address: string; interface: any }> {
  const factory = await ethersRuntime.getContractFactory("NodeReleaseRegistry");
  const contract = await factory.deploy(
    owner,
    bondingRegistry,
    ciphernodeRegistry,
  );
  await contract.waitForDeployment();
  return { address: await contract.getAddress(), interface: factory.interface };
}
