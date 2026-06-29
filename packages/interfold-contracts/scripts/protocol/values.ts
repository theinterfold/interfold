// SPDX-License-Identifier: LGPL-3.0-only
import { ethers as ethersLib } from "ethers";

import { arg } from "./cli";
import { ZERO, abi } from "./constants";
import { configPath, readJson } from "./files";
import type { PricingConfig, ProtocolConfigFile, TimeoutConfig } from "./types";

export function address(value: string, label: string): string {
  try {
    return ethersLib.getAddress(value);
  } catch {
    throw new Error(`${label} is not a valid address: ${value}`);
  }
}

export function optionalAddress(
  value: string | undefined,
  label: string,
): string | undefined {
  if (!value || value === ZERO) return undefined;
  return address(value, label);
}

export async function requireContract(
  provider: ethersLib.Provider,
  target: string,
  label: string,
): Promise<void> {
  const code = await provider.getCode(target);
  if (code === "0x") throw new Error(`${label} has no code: ${target}`);
}

export async function deployedAddress(contract: {
  target?: unknown;
  getAddress?: () => Promise<string>;
}): Promise<string> {
  if (typeof contract.target === "string")
    return address(contract.target, "contract");
  if (contract.getAddress)
    return address(await contract.getAddress(), "contract");
  throw new Error("Could not determine deployed contract address");
}

export function encodeBfvParams(params: {
  degree: bigint;
  plaintextModulus: bigint;
  moduli: readonly bigint[];
  error1Variance: string;
}): string {
  return abi.encode(
    [
      "tuple(uint256 degree,uint256 plaintext_modulus,uint256[] moduli,string error1_variance)",
    ],
    [
      [
        params.degree,
        params.plaintextModulus,
        [...params.moduli],
        params.error1Variance,
      ],
    ],
  );
}

export function timeoutConfig(config: TimeoutConfig) {
  return {
    dkgWindow: BigInt(config.dkgWindow),
    computeWindow: BigInt(config.computeWindow),
    decryptionWindow: BigInt(config.decryptionWindow),
  };
}

export function pricingConfig(config: PricingConfig) {
  return {
    keyGenFixedPerNode: BigInt(config.keyGenFixedPerNode),
    keyGenPerEncryptionProof: BigInt(config.keyGenPerEncryptionProof),
    coordinationPerPair: BigInt(config.coordinationPerPair),
    availabilityPerNodePerSec: BigInt(config.availabilityPerNodePerSec),
    decryptionPerNode: BigInt(config.decryptionPerNode),
    publicationBase: BigInt(config.publicationBase),
    verificationPerProof: BigInt(config.verificationPerProof),
    protocolTreasury: address(
      config.protocolTreasury,
      "interfold.pricing.protocolTreasury",
    ),
    marginBps: BigInt(config.marginBps),
    protocolShareBps: BigInt(config.protocolShareBps),
    dkgUtilizationBps: BigInt(config.dkgUtilizationBps),
    computeUtilizationBps: BigInt(config.computeUtilizationBps),
    decryptUtilizationBps: BigInt(config.decryptUtilizationBps),
    minCommitteeSize: BigInt(config.minCommitteeSize),
    minThreshold: BigInt(config.minThreshold),
  };
}

export function loadConfig(file = configPath()): ProtocolConfigFile {
  const config = readJson<ProtocolConfigFile>(file);
  const safeOverride = arg("safe") ?? process.env.SAFE_ADDRESS;
  if (safeOverride && config.safe === ZERO) config.safe = safeOverride;
  validateConfig(config);
  return config;
}

function validateConfig(config: ProtocolConfigFile): void {
  if (!config.name) throw new Error("Config name is required");
  config.safe = address(config.safe, "safe");
  config.fold = address(config.fold, "fold");
  config.bondingRegistryProxy = address(
    config.bondingRegistryProxy,
    "bondingRegistryProxy",
  );
  config.bondingRegistryProxyAdmin = address(
    config.bondingRegistryProxyAdmin,
    "bondingRegistryProxyAdmin",
  );
  config.feeToken = address(config.feeToken, "feeToken");
  config.protocolTreasury = address(
    config.protocolTreasury,
    "protocolTreasury",
  );
  config.slashedFundsTreasury = address(
    config.slashedFundsTreasury,
    "slashedFundsTreasury",
  );
  if (config.slasher !== ZERO)
    config.slasher = address(config.slasher, "slasher");
  config.interfold.pricing.protocolTreasury = address(
    config.interfold.pricing.protocolTreasury,
    "interfold.pricing.protocolTreasury",
  );
  for (const program of config.e3Programs ?? []) address(program, "e3Program");
  optionalAddress(config.verifiers?.decryptionVerifier, "decryptionVerifier");
  optionalAddress(config.verifiers?.pkVerifier, "pkVerifier");
  optionalAddress(
    config.verifiers?.dkgFoldAttestationVerifier,
    "dkgFoldAttestationVerifier",
  );
}
