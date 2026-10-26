// SPDX-License-Identifier: LGPL-3.0-only
import config from "./crypto-config.json";

if (config.formatVersion !== 1) {
  throw new Error(
    `Unsupported crypto configuration format: ${config.formatVersion}`,
  );
}

export const BFV_ENCRYPTION_SCHEME = config.bfv.encryptionScheme;
export const BFV_ENCRYPTION_SCHEME_ID = config.bfv
  .encryptionSchemeId as `0x${string}`;
export const INTERFOLD_BFV_VERSION = config.bfv.circuitVersion;

function parameters(value: (typeof config.bfv.presets)[number]["threshold"]) {
  // Keep the four-field ABI tuple shape and order; the metadata's name is not an ABI field.
  return {
    degree: BigInt(value.degree),
    plaintextModulus: BigInt(value.plaintextModulus),
    moduli: value.moduli.map(BigInt),
    error1Variance: value.error1Variance,
  } as const;
}

export const BFV_PRESETS = Object.fromEntries(
  config.bfv.presets.map(
    (preset) =>
      [
        preset.preset,
        {
          paramSet: preset.paramSet,
          paramSetHash: preset.parameterHash as `0x${string}`,
          configId: preset.cryptoConfigId as `0x${string}`,
          threshold: parameters(preset.threshold),
          dkg: parameters(preset.dkg),
          search: preset.search,
        },
      ] as const,
  ),
);

export const CIRCUIT_DIMENSIONS = config.zk;
export const COMMITTEES = Object.fromEntries(
  config.committees.map((committee) => [committee.name, committee]),
);
export const SUPPORTED_BFV_BUILD_PAIRS = config.buildPairs;

export function bfvPresetForParamSet(paramSet: number) {
  return Object.values(BFV_PRESETS).find(
    (preset) => preset.paramSet === paramSet,
  );
}
