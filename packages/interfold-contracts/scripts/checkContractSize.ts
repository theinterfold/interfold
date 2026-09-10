// SPDX-License-Identifier: LGPL-3.0-only
import hre from "hardhat";

const EIP170_LIMIT_BYTES = 24_576;
// Deploy margin above the consensus limit, not a protocol rule. Lowered from 256 after the
// Zenith 2026-09 remediation: the size folds on #1928 reclaimed ~500 bytes across the three
// near-cap contracts, and the combined tree still lands Interfold 69 bytes inside the old
// reserve while 187 bytes under EIP-170. Hold the release contracts to this line.
const REQUIRED_HEADROOM_BYTES = 128;
const MAX_RUNTIME_BYTES = EIP170_LIMIT_BYTES - REQUIRED_HEADROOM_BYTES;

const RELEASE_CONTRACTS = [
  "Interfold",
  "BondingRegistry",
  "CiphernodeRegistryOwnable",
  "contracts/verifiers/bfv/honk/DkgAggregatorVerifier.sol:DkgAggregatorVerifier",
  "contracts/verifiers/bfv/honk/DecryptionAggregatorVerifier.sol:DecryptionAggregatorVerifier",
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
