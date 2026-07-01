// SPDX-License-Identifier: LGPL-3.0-only
import fs from "fs";
import path from "path";

import { arg, networkName } from "./cli";
import type { SaleConfigFile } from "./types";

function findRepoRoot(): string {
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
export const saleDir = path.join(
  repoRoot,
  "packages",
  "interfold-contracts",
  "deploy",
  "sale",
);

export function resolvePath(input: string): string {
  if (path.isAbsolute(input)) return input;

  const packagePrefix = "packages/interfold-contracts/";
  if (input.startsWith(packagePrefix)) {
    return path.join(repoRoot, input);
  }

  const salePrefix = "deploy/sale/";
  if (input.startsWith(salePrefix)) {
    return path.join(saleDir, input.slice(salePrefix.length));
  }

  const cwdPath = path.resolve(input);
  if (fs.existsSync(cwdPath)) return cwdPath;
  return path.join(repoRoot, input);
}

export function defaultConfigPath(): string {
  return path.join(saleDir, `${networkName()}-sale.config.json`);
}

export function configPath(required = true): string {
  const cliConfig = arg("config");
  const file = cliConfig ? resolvePath(cliConfig) : defaultConfigPath();
  if (required && !fs.existsSync(file)) {
    throw new Error(
      `Sale config not found: ${file}. Run --action prepare or pass --config.`,
    );
  }
  return file;
}

export function nextAvailablePath(file: string): string {
  if (!fs.existsSync(file)) return file;

  const dir = path.dirname(file);
  const basename = path.basename(file);
  const knownSuffixes = [
    ".config.json",
    ".plan.json",
    ".deployment.json",
    ".infra.json",
    ".safe-proposal.json",
    ".safe-transactions.json",
    ".json",
  ];
  const suffix =
    knownSuffixes.find((candidate) => basename.endsWith(candidate)) ??
    path.extname(basename);
  const stem = suffix ? basename.slice(0, -suffix.length) : basename;

  for (let index = 2; ; index++) {
    const candidate = path.join(dir, `${stem}-${index}${suffix}`);
    if (!fs.existsSync(candidate)) return candidate;
  }
}

export function saleNameFromConfigPath(file: string): string {
  const basename = path.basename(file);
  return basename.endsWith(".config.json")
    ? basename.slice(0, -".config.json".length)
    : basename.replace(/\.json$/u, "");
}

export function planPath(config: SaleConfigFile): string {
  const cliPlan = arg("plan");
  return cliPlan
    ? resolvePath(cliPlan)
    : path.join(saleDir, `${config.name}.plan.json`);
}

export function deploymentPath(config: SaleConfigFile): string {
  const cliDeployment = arg("deployment");
  return cliDeployment
    ? resolvePath(cliDeployment)
    : path.join(saleDir, `${config.name}.deployment.json`);
}

export function safeProposalPath(config: SaleConfigFile): string {
  return arg("safe-proposal")
    ? resolvePath(arg("safe-proposal")!)
    : path.join(saleDir, `${config.name}.safe-proposal.json`);
}

export function safeTransactionsPath(config: SaleConfigFile): string {
  return arg("safe-transactions")
    ? resolvePath(arg("safe-transactions")!)
    : path.join(saleDir, `${config.name}.safe-transactions.json`);
}

export function saleUiDir(): string {
  return path.join(repoRoot, "packages", "interfold-sale", "public", "sale");
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
