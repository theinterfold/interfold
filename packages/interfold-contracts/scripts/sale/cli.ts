// SPDX-License-Identifier: LGPL-3.0-only
import hre from "hardhat";

const scriptArgs = process.argv.slice(2);

export function arg(name: string): string | undefined {
  const flag = `--${name}`;
  const withEquals = `${flag}=`;
  for (let i = 0; i < scriptArgs.length; i++) {
    const value = scriptArgs[i];
    if (value === flag) return scriptArgs[i + 1];
    if (value.startsWith(withEquals)) return value.slice(withEquals.length);
  }
  return undefined;
}

export function hasFlag(name: string): boolean {
  return scriptArgs.includes(`--${name}`);
}

export function networkName(): string {
  return (
    arg("network") ??
    (hre.network as unknown as { name?: string }).name ??
    (hre.globalOptions as unknown as { network?: string }).network ??
    process.env.HARDHAT_NETWORK ??
    "network"
  );
}

export async function connect() {
  const requested =
    arg("network") ??
    (hre.globalOptions as unknown as { network?: string }).network ??
    process.env.HARDHAT_NETWORK;
  return requested ? hre.network.connect(requested) : hre.network.connect();
}

