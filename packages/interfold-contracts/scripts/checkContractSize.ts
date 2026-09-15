// SPDX-License-Identifier: LGPL-3.0-only
import hre from "hardhat";

const EIP170_LIMIT_BYTES = 24_576;
const REQUIRED_HEADROOM_BYTES = 256;
const MAX_RUNTIME_BYTES = EIP170_LIMIT_BYTES - REQUIRED_HEADROOM_BYTES;

const RELEASE_CONTRACTS = [
  "Interfold",
  "BondingRegistry",
  "CiphernodeRegistryOwnable",
  "contracts/verifiers/bfv/honk/DkgAggregatorVerifier.sol:DkgAggregatorVerifier",
  "contracts/verifiers/bfv/honk/DecryptionAggregatorVerifier.sol:DecryptionAggregatorVerifier",
  "contracts/verifiers/bfv/honk/secure-16384/minimum/DkgAggregatorV2Verifier.sol:DkgAggregatorV2Verifier",
] as const;

let failed = false;
for (const contractName of RELEASE_CONTRACTS) {
  const artifact = await hre.artifacts.readArtifact(contractName);
  const runtimeBytes = (artifact.deployedBytecode.length - 2) / 2;
  const headroom = EIP170_LIMIT_BYTES - runtimeBytes;

  console.log(
    `${contractName}: ${runtimeBytes} runtime bytes (${headroom} bytes EIP-170 headroom)`,
  );

  if (runtimeBytes > MAX_RUNTIME_BYTES) {
    failed = true;
    console.error(
      `${contractName} exceeds the ${MAX_RUNTIME_BYTES}-byte release budget ` +
        `(EIP-170 minus ${REQUIRED_HEADROOM_BYTES} bytes).`,
    );
  }
}

if (failed) process.exitCode = 1;
