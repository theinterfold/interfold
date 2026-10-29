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

function preset(name: string) {
  const preset = config.bfv.presets.find((entry) => entry.preset === name);
  if (!preset) throw new Error(`Missing BFV preset: ${name}`);
  return {
    paramSet: preset.paramSet,
    paramSetHash: preset.parameterHash as `0x${string}`,
    configId: preset.cryptoConfigId as `0x${string}`,
    threshold: parameters(preset.threshold),
    dkg: parameters(preset.dkg),
    search: preset.search,
  };
}

export const BFV_PRESETS = {
  "insecure-64": preset("insecure-64"),
  "secure-8192": preset("secure-8192"),
};

const { decryptionAggregator, ...dimensions } = config.zk;
export const CIRCUIT_DIMENSIONS = dimensions;
export const DECRYPTION_AGGREGATOR_LAYOUT = decryptionAggregator;
function inputIndex(name: string) {
  const index = decryptionAggregator.publicInputs.findIndex(
    (field) => field.name === name,
  );
  if (index === -1) throw new Error(`Missing decryption public input: ${name}`);
  return index;
}

export const DECRYPTION_INPUT_INDICES = {
  c6_fold_key_hash: inputIndex("c6_fold_key_hash"),
  c7_key_hash: inputIndex("c7_key_hash"),
  committee_hash_hi: inputIndex("committee_hash_hi"),
  committee_hash_lo: inputIndex("committee_hash_lo"),
  domain_hi: inputIndex("domain_hi"),
  domain_lo: inputIndex("domain_lo"),
  ciphertext_commitment: inputIndex("ciphertext_commitment"),
};

export function decryptionAggregatorLayout(threshold: number) {
  const shareCount = threshold + 1;
  const partyIdOffset =
    decryptionAggregator.publicInputs.length +
    decryptionAggregator.returnPrefix.length;
  const skOffset = partyIdOffset + shareCount;
  const esmOffset = skOffset + shareCount;
  const messageOffset =
    partyIdOffset + decryptionAggregator.columns.length * shareCount;
  return {
    shareCount,
    partyIdOffset,
    skOffset,
    esmOffset,
    messageOffset,
    publicInputsLength: messageOffset + CIRCUIT_DIMENSIONS.messageCoeffsCount,
  };
}
function committee(name: string) {
  const committee = config.committees.find((entry) => entry.name === name);
  if (!committee) throw new Error(`Missing committee: ${name}`);
  return committee;
}

export const COMMITTEES = {
  minimum: committee("minimum"),
  micro: committee("micro"),
  small: committee("small"),
};
export const SUPPORTED_BFV_BUILD_PAIRS = config.buildPairs;

export function bfvPresetForParamSet(paramSet: number) {
  return Object.values(BFV_PRESETS).find(
    (preset) => preset.paramSet === paramSet,
  );
}
