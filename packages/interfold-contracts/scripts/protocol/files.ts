// SPDX-License-Identifier: LGPL-3.0-only
import fs from "fs";
import path from "path";

import { arg, networkName } from "./cli";
import type { ProtocolConfigFile } from "./types";

export function findRepoRoot(): string {
  let dir = process.cwd();
  while (true) {
    if (
      fs.existsSync(path.join(dir, "AGENTS.md")) &&
      fs.existsSync(path.join(dir, "packages", "interfold-contracts"))
    ) {
      return dir;
    }
    const parent = path.dirname(dir);
    if (parent === dir) return process.cwd();
    dir = parent;
  }
}

export const repoRoot = findRepoRoot();
export const protocolDir = path.join(
  repoRoot,
  "packages",
  "interfold-contracts",
  "deploy",
  "protocol",
);

export function resolvePath(input: string): string {
  if (path.isAbsolute(input)) return input;
  const cwdPath = path.resolve(input);
  if (fs.existsSync(cwdPath)) return cwdPath;
  return path.join(repoRoot, input);
}

export function defaultConfigPath(): string {
  return path.join(protocolDir, `${networkName()}-protocol.config.json`);
}

export function configPath(required = true): string {
  const file = arg("config")
    ? resolvePath(arg("config")!)
    : defaultConfigPath();
  if (required && !fs.existsSync(file)) {
    throw new Error(
      `Protocol config not found: ${file}. Pass --config or create it from packages/interfold-contracts/deploy/protocol/example.protocol.config.json.`,
    );
  }
  return file;
}

export function deploymentPath(config: ProtocolConfigFile): string {
  return arg("deployment")
    ? resolvePath(arg("deployment")!)
    : path.join(protocolDir, `${config.name}.deployment.json`);
}

export function safeBatchPath(config: ProtocolConfigFile): string {
  return arg("safe-batch")
    ? resolvePath(arg("safe-batch")!)
    : path.join(protocolDir, `${config.name}.safe-transactions.json`);
}

export function safeProposalPath(config: ProtocolConfigFile): string {
  return arg("safe-proposal")
    ? resolvePath(arg("safe-proposal")!)
    : path.join(protocolDir, `${config.name}.safe-proposal.json`);
}

export function readJson<T>(file: string): T {
  return JSON.parse(fs.readFileSync(file, "utf8")) as T;
}

export function writeJson(file: string, value: unknown): void {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(
    file,
    `${JSON.stringify(
      value,
      (_key, v) => (typeof v === "bigint" ? v.toString() : v),
      2,
    )}\n`,
    "utf8",
  );
}
