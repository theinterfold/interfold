// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
import type { HardhatEthers } from "@nomicfoundation/hardhat-ethers/types";
import { createHash } from "node:crypto";
import { readFileSync, statSync } from "node:fs";

/** Deploy a receipt binding from explicit application commitments and a checked Halo2 verifier. */
export async function deployOpenVmReceiptVerifier(
  ethers: HardhatEthers,
  environment: Record<string, string | undefined> = process.env,
) {
  const required = (name: string): string => {
    const value = environment[name];
    if (!value)
      throw new Error(`Set ${name}; OpenVM has no default compute verifier`);
    return value;
  };
  const appExeCommit = required("OPENVM_APP_EXE_COMMIT");
  const appVmCommit = required("OPENVM_APP_VM_COMMIT");
  const scalarModulus =
    21888242871839275222246405745257275088548364400416034343698204186575808495617n;
  for (const value of [appExeCommit, appVmCommit]) {
    if (
      !/^0x[0-9a-fA-F]{64}$/.test(value) ||
      BigInt(value) === 0n ||
      BigInt(value) >= scalarModulus
    ) {
      throw new Error(
        "OpenVM application commitments must be nonzero canonical 32-byte scalars",
      );
    }
  }
  const artifactPath = environment.OPENVM_VERIFIER_ARTIFACT;
  if (artifactPath && environment.OPENVM_HALO2_VERIFIER) {
    throw new Error(
      "Configure an OpenVM verifier artifact or an existing verifier address, not both",
    );
  }
  let halo2Verifier: string;
  if (artifactPath) {
    const checksum = required("OPENVM_VERIFIER_SHA256");
    if (!/^[0-9a-f]{64}$/.test(checksum))
      throw new Error(
        "The OpenVM artifact checksum must be a lowercase SHA-256 digest",
      );
    if (statSync(artifactPath).size > 256 * 1024)
      throw new Error("The OpenVM verifier artifact exceeds the byte limit");
    const bytes = readFileSync(artifactPath);
    if (createHash("sha256").update(bytes).digest("hex") !== checksum)
      throw new Error("The OpenVM verifier artifact checksum differs");
    const artifact = JSON.parse(bytes.toString("utf8"));
    if (
      typeof artifact.bytecode !== "string" ||
      !/^(?:0x)?(?:[0-9a-fA-F]{2})+$/.test(artifact.bytecode)
    ) {
      throw new Error(
        "The OpenVM verifier artifact must contain hexadecimal creation bytecode",
      );
    }
    const [owner] = await ethers.getSigners();
    const halo2 = await new ethers.ContractFactory(
      ["function verify(bytes,bytes,bytes32,bytes32) view"],
      `0x${artifact.bytecode.replace(/^0x/, "")}`,
      owner,
    ).deploy();
    await halo2.waitForDeployment();
    halo2Verifier = await halo2.getAddress();
  } else {
    halo2Verifier = ethers.getAddress(required("OPENVM_HALO2_VERIFIER"));
    const code = await ethers.provider.getCode(halo2Verifier);
    if (
      code === "0x" ||
      ethers.keccak256(code).toLowerCase() !==
        required("OPENVM_HALO2_RUNTIME_CODE_HASH").toLowerCase()
    ) {
      throw new Error(
        "The OpenVM verifier runtime code differs from the configured hash",
      );
    }
  }
  const code = await ethers.provider.getCode(halo2Verifier);
  if (code === "0x")
    throw new Error("The OpenVM Halo2 verifier has no deployed code");
  const receipt = await ethers.deployContract("OpenVmReceiptVerifier", [
    halo2Verifier,
    appExeCommit,
    appVmCommit,
  ]);
  await receipt.waitForDeployment();
  return {
    receipt,
    halo2Verifier,
    halo2RuntimeCodeHash: ethers.keccak256(code),
    appExeCommit,
    appVmCommit,
  };
}
