// SPDX-License-Identifier: LGPL-3.0-only
import { expect } from "chai";
import { type BaseContract, ContractFactory, type Signer } from "ethers";
import { execFileSync } from "node:child_process";

/** Compile fresh synchronized Honk sources with the contract package's release settings. */
export function compileSynchronized(
  sources: Record<string, { content: string }>,
) {
  expect(execFileSync("solc", ["--version"], { encoding: "utf8" })).to.match(
    /Version: 0\.8\.28\+/,
  );
  const output = JSON.parse(
    execFileSync("solc", ["--standard-json"], {
      input: JSON.stringify({
        language: "Solidity",
        sources,
        settings: {
          optimizer: { enabled: true, runs: 1 },
          evmVersion: "paris",
          debug: { revertStrings: "strip" },
          metadata: { bytecodeHash: "none" },
          outputSelection: {
            "*": { "*": ["abi", "evm.bytecode", "evm.deployedBytecode"] },
          },
        },
      }),
      maxBuffer: 64 * 1024 * 1024,
      encoding: "utf8",
    }),
  );
  expect(
    (output.errors ?? []).filter(
      (e: { severity: string }) => e.severity === "error",
    ),
  ).to.deep.equal([]);
  return output.contracts;
}

export function deployCompiled(
  contracts: ReturnType<typeof compileSynchronized>,
  signer: Signer,
) {
  const deployed = new Map<string, string>();
  async function deploy(
    file: string,
    name: string,
    args: unknown[] = [],
  ): Promise<BaseContract> {
    const artifact = contracts[file][name];
    let bytecode = artifact.evm.bytecode.object;
    for (const [libFile, libraries] of Object.entries(
      artifact.evm.bytecode.linkReferences,
    )) {
      for (const [library, locations] of Object.entries(
        libraries as Record<string, { start: number; length: number }[]>,
      )) {
        const id = `${libFile}:${library}`;
        if (!deployed.has(id))
          deployed.set(id, await (await deploy(libFile, library)).getAddress());
        for (const { start, length } of locations) {
          expect(length).to.equal(20);
          bytecode =
            bytecode.slice(0, 2 * start) +
            deployed.get(id)!.slice(2) +
            bytecode.slice(2 * (start + length));
        }
      }
    }
    expect(artifact.evm.deployedBytecode.object.length / 2).to.be.at.most(
      24_576,
    );
    const instance = await new ContractFactory(
      artifact.abi,
      `0x${bytecode}`,
      signer,
    ).deploy(...args);
    await instance.waitForDeployment();
    return instance;
  }
  return deploy;
}
