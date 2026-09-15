// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
import {
  ContractTransactionReceipt,
  ContractTransactionResponse,
  getBytes,
  hexlify,
  zeroPadValue,
} from "ethers";
import fs from "fs";
import type { HardhatRuntimeEnvironment } from "hardhat/types/hre";
import { fileURLToPath } from "node:url";
import path from "path";

/**
 * Reconstruct `keccak256(abi.encodePacked(topNodes))` from aggregator public-input
 * limbs. Each limb is a bytes32 with 128 bits right-aligned (`CommitteeHashLib`).
 */
export function committeeHashFromLimbs(hi: string, lo: string): string {
  const hiBytes = getBytes(zeroPadValue(hi, 32));
  const loBytes = getBytes(zeroPadValue(lo, 32));
  const hash = new Uint8Array(32);
  hash.set(hiBytes.subarray(16, 32), 0);
  hash.set(loBytes.subarray(16, 32), 16);
  return hexlify(hash);
}

export const deploymentsFile = path.join("deployed_contracts.json");

/** Hardhat network names used for local development. */
export const LOCAL_DEPLOYMENT_NETWORKS = [
  "localhost",
  "hardhat",
  "anvil",
  "ganache",
] as const;

/**
 * Legacy deployment bucket keys written when scripts used `provider.getNetwork().name`
 * (ethers reports "default" / "undefined" on local chains). Cleared with local deploys.
 */
export const LEGACY_LOCAL_DEPLOYMENT_ALIASES = [
  "default",
  "undefined",
] as const;

/**
 * Chain key for `deployed_contracts.json`. Use Hardhat's network name, not the provider's
 * `network.name` (which is often `"default"` on localhost and does not match clean/deploy).
 */
export const getDeploymentChain = (hre: HardhatRuntimeEnvironment): string =>
  hre.globalOptions.network ?? "localhost";

export const isLocalDeploymentChain = (chain: string): boolean =>
  (LOCAL_DEPLOYMENT_NETWORKS as readonly string[]).includes(chain) ||
  (LEGACY_LOCAL_DEPLOYMENT_ALIASES as readonly string[]).includes(chain);

/** Monorepo root (`interfold/`). Works from `scripts/` and compiled `dist/scripts/`. */
function resolveRepoRoot(): string {
  let dir = path.dirname(fileURLToPath(import.meta.url));
  const root = path.parse(dir).root;
  while (dir !== root) {
    const pkgPath = path.join(dir, "package.json");
    if (fs.existsSync(pkgPath)) {
      try {
        const pkg = JSON.parse(fs.readFileSync(pkgPath, "utf8")) as {
          name?: string;
        };
        if (pkg.name === "@interfold/main") {
          return dir;
        }
      } catch {
        // keep walking
      }
    }
    dir = path.dirname(dir);
  }
  throw new Error(
    "Could not find interfold repo root (expected package.json name @interfold/main)",
  );
}

let _repoRoot: string | undefined;

/** Lazy version of REPO_ROOT — only resolves when called, safe for import-time. */
export function getRepoRoot(): string {
  if (!_repoRoot) _repoRoot = resolveRepoRoot();
  return _repoRoot;
}

/**
 * <generated-committee-doc>
 * Active insecure / minimum committee layout for BFV aggregator verifiers.
 * Must match `lib::configs::default::{H, T}` in compiled circuits.
 * Minimum committee: N=3, T=1, H=2.
 * </generated-committee-doc>
 */
export const BFV_DKG_H = 2;
export const BFV_THRESHOLD_T = 1;
export const ACTIVE_BFV_PARAM_SET = 0;
export const ACTIVE_BFV_COMMITTEE_SIZE = 0;
export const ACTIVE_BFV_COMMITTEE_N = 3;

export type BfvArtifactPreset = "insecure" | "secure-8192" | "secure-16384";
export type BfvCommittee = "minimum" | "micro" | "small";

export interface ActiveBfvConfig {
  preset: BfvArtifactPreset;
  committee: BfvCommittee;
  paramSet: number;
  paramSetHash: string;
  configId: string;
  committeeSize: number;
  h: number;
  t: number;
  n: number;
}

const INSECURE_PARAM_SET_HASH =
  "0x18c6d8650486b997d48aa2d285fae878fb267b268332d056a3e8527d50e87b4f";
const INSECURE_CONFIG_ID =
  "0x19921c8c12f93c3013be57d0859f4ddcdb4464ac856a0c62be1ad617fbbd2e7d";
const SECURE_PARAM_SET_HASH =
  "0x80775a19b6126a12943f9c1c53f92299f0c92ece819b625026ab1406bbbe0721";
const SECURE_CONFIG_ID =
  "0xac5490c59e158cbb104642bba0ab7b3fd11ca49dd4bb05ce7bec8089ce3c8c31";
const SECURE_16384_PARAM_SET_HASH =
  "0x8afd5dddf1bc0cfb00c70e9a7d0a0fb11bd0617df27574fa7d2ccf9ae3a6bdb8";
const SECURE_16384_CONFIG_ID =
  "0xde3c303973a0bf2b841cd0e7266ae68a7e48f8b271ffd629b245485e52dc8cd8";

function bfvConfig(
  preset: BfvArtifactPreset,
  committee: BfvCommittee,
  params: Pick<ActiveBfvConfig, "committeeSize" | "h" | "t" | "n">,
): ActiveBfvConfig {
  const paramSet = preset === "insecure" ? 0 : preset === "secure-8192" ? 1 : 2;
  const paramSetHash =
    paramSet === 0
      ? INSECURE_PARAM_SET_HASH
      : paramSet === 1
        ? SECURE_PARAM_SET_HASH
        : SECURE_16384_PARAM_SET_HASH;
  const configId =
    paramSet === 0
      ? INSECURE_CONFIG_ID
      : paramSet === 1
        ? SECURE_CONFIG_ID
        : SECURE_16384_CONFIG_ID;
  return {
    preset,
    committee,
    paramSet,
    paramSetHash,
    configId,
    ...params,
  };
}

export const INSECURE_MINIMUM_BFV_CONFIG: ActiveBfvConfig = bfvConfig(
  "insecure",
  "minimum",
  { committeeSize: 0, h: 2, t: 1, n: 3 },
);

export const INSECURE_MICRO_BFV_CONFIG: ActiveBfvConfig = bfvConfig(
  "insecure",
  "micro",
  { committeeSize: 1, h: 5, t: 4, n: 9 },
);

export const INSECURE_SMALL_BFV_CONFIG: ActiveBfvConfig = bfvConfig(
  "insecure",
  "small",
  { committeeSize: 2, h: 10, t: 9, n: 19 },
);

export const SECURE_MINIMUM_BFV_CONFIG: ActiveBfvConfig = bfvConfig(
  "secure-8192",
  "minimum",
  { committeeSize: 0, h: 2, t: 1, n: 3 },
);

export const SECURE_MICRO_BFV_CONFIG: ActiveBfvConfig = bfvConfig(
  "secure-8192",
  "micro",
  { committeeSize: 1, h: 5, t: 4, n: 9 },
);

export const SECURE_SMALL_BFV_CONFIG: ActiveBfvConfig = bfvConfig(
  "secure-8192",
  "small",
  { committeeSize: 2, h: 10, t: 9, n: 19 },
);

export const SECURE_16384_MINIMUM_BFV_CONFIG: ActiveBfvConfig = bfvConfig(
  "secure-16384",
  "minimum",
  { committeeSize: 0, h: 2, t: 1, n: 3 },
);

export const PRODUCTION_BFV_CONFIG: ActiveBfvConfig = SECURE_SMALL_BFV_CONFIG;

export const TESTNET_BFV_CONFIG: ActiveBfvConfig = INSECURE_MINIMUM_BFV_CONFIG;

export const MAINNET_BFV_CONFIGS: readonly ActiveBfvConfig[] = [
  SECURE_SMALL_BFV_CONFIG,
  SECURE_MICRO_BFV_CONFIG,
  SECURE_MINIMUM_BFV_CONFIG,
] as const;

export const TESTNET_BFV_CONFIGS: readonly ActiveBfvConfig[] = [
  INSECURE_MINIMUM_BFV_CONFIG,
  INSECURE_MICRO_BFV_CONFIG,
  INSECURE_SMALL_BFV_CONFIG,
  SECURE_MINIMUM_BFV_CONFIG,
  SECURE_MICRO_BFV_CONFIG,
  SECURE_SMALL_BFV_CONFIG,
  SECURE_16384_MINIMUM_BFV_CONFIG,
] as const;

export function isTestnetOrLocalChainId(chainId: number): boolean {
  return chainId === 11155111 || chainId === 31337 || chainId === 1337;
}

export function activeBfvConfigForChain(chainId: number): ActiveBfvConfig {
  return isTestnetOrLocalChainId(chainId)
    ? TESTNET_BFV_CONFIG
    : PRODUCTION_BFV_CONFIG;
}

export function bfvConfigsForChain(
  chainId: number,
): readonly ActiveBfvConfig[] {
  return isTestnetOrLocalChainId(chainId)
    ? TESTNET_BFV_CONFIGS
    : MAINNET_BFV_CONFIGS;
}

export function bfvParamSetConfigsForChain(chainId: number): ActiveBfvConfig[] {
  const seen = new Set<number>();
  const configs: ActiveBfvConfig[] = [];
  for (const config of bfvConfigsForChain(chainId)) {
    if (seen.has(config.paramSet)) continue;
    seen.add(config.paramSet);
    configs.push(config);
  }
  return configs;
}

/** `dkg_aggregator` EVM public-input count for honest-set size `h`. */
export function bfvPkExpectedPublicInputsLen(h: number): number {
  // dkg_aggregator public inputs: nodes_fold + c5 key hashes (2), party_ids (h),
  // committee hash limbs (2), vk_binding (16), returned key hash (1),
  // C2A/C2B chunk hashes (2), sk/esm agg commits (2h), aggregated pk commit (1).
  // The generated Honk VK includes eight pairing-point slots outside the public-input array.
  return 3 * h + 24;
}

/** `publicInputs` indices for `committee_hash_hi` / `committee_hash_lo` (matches `BfvPkVerifier`). */
export function bfvDkgCommitteeHashIndices(h: number): {
  hi: number;
  lo: number;
} {
  return { hi: 2 + h, lo: 3 + h };
}

/** `decryption_aggregator` EVM public-input count for BFV threshold `t`. */
export function bfvDecExpectedPublicInputsLen(threshold: number): number {
  return 111 + 3 * threshold;
}

/** `publicInputs` indices for decryption-aggregator committee hash limbs. */
export function bfvDecCommitteeHashIndices(): { hi: number; lo: number } {
  return { hi: 2, lo: 3 };
}

/**
 * `publicInputs` start indices for the `party_ids`/`expected_sk`/`expected_esm`
 * columns (each `threshold + 1` wide), matching `BfvDecryptionVerifier`'s
 * `partyIdColOffset`/`skColOffset`/`esmColOffset`.
 */
export function bfvDecPartyColOffsets(threshold: number): {
  partyId: number;
  sk: number;
  esm: number;
} {
  const partyId = 8; // 7 domain/VK/committee/commitment inputs + DEC_RETURN_PREFIX_LEN
  const sk = partyId + (threshold + 1);
  const esm = sk + (threshold + 1);
  return { partyId, sk, esm };
}

/** `publicInputs` indices for decryption-aggregator E3 domain limbs. */
export function bfvDecDomainIndices(): { hi: number; lo: number } {
  return { hi: 4, lo: 5 };
}

/** `publicInputs` index for the final circuit-compatible ciphertext commitment. */
export function bfvDecCiphertextCommitmentIndex(): number {
  return 6;
}

function distCircuitRoot(config: ActiveBfvConfig): string {
  return path.join(
    getRepoRoot(),
    "dist/circuits",
    config.preset,
    config.committee,
  );
}

function localCircuitArtifactPath(
  group: string,
  circuit: string,
  fileName: string,
): string {
  const root = getRepoRoot();
  const circuitPath = path.join(
    root,
    "circuits/bin",
    group,
    circuit,
    "target",
    fileName,
  );
  return fs.existsSync(circuitPath)
    ? circuitPath
    : path.join(root, "circuits/bin", group, "target", fileName);
}

function localRecursiveVkHashPath(group: string, circuit: string): string {
  return localCircuitArtifactPath(
    group,
    circuit,
    `${circuit}.vk_recursive_hash`,
  );
}

/** Recursive VK hashes for `BfvPkVerifier` sub-circuits. */
export function getBfvPkSubCircuitVkHashPaths(config?: ActiveBfvConfig) {
  if (config) {
    const root = distCircuitRoot(config);
    return {
      nodesFold: path.join(
        root,
        "default/recursive_aggregation/nodes_fold/nodes_fold.vk_hash",
      ),
      c5: path.join(
        root,
        "default/threshold/pk_aggregation/pk_aggregation.vk_hash",
      ),
      skC2Chunk: path.join(
        root,
        "recursive/dkg/sk_share_computation_chunk/sk_share_computation_chunk.vk_hash",
      ),
      esmC2Chunk: path.join(
        root,
        "recursive/dkg/esm_share_computation_chunk/esm_share_computation_chunk.vk_hash",
      ),
    } as const;
  }

  return {
    nodesFold: localRecursiveVkHashPath("recursive_aggregation", "nodes_fold"),
    c5: localRecursiveVkHashPath("threshold", "pk_aggregation"),
    skC2Chunk: localRecursiveVkHashPath("dkg", "sk_share_computation_chunk"),
    esmC2Chunk: localRecursiveVkHashPath("dkg", "esm_share_computation_chunk"),
  } as const;
}

/** Recursive VK hashes used to build the DKG pipeline binding manifest. */
export function getBfvPkVkBindingHashPaths(config?: ActiveBfvConfig) {
  const root = config ? distCircuitRoot(config) : getRepoRoot();
  const recursive = config ? "recursive" : "target";
  const defaultVariant = config ? "default" : "target";
  const local = (group: string, circuit: string) =>
    localRecursiveVkHashPath(group, circuit);
  return [
    config
      ? path.join(
          root,
          "default/recursive_aggregation/node_fold/node_fold.vk_hash",
        )
      : local("recursive_aggregation", "node_fold"),
    config
      ? path.join(root, `${recursive}/dkg/pk/pk.vk_hash`)
      : local("dkg", "pk"),
    config
      ? path.join(
          root,
          `${recursive}/threshold/pk_generation/pk_generation.vk_hash`,
        )
      : local("threshold", "pk_generation"),
    config
      ? path.join(
          root,
          `${defaultVariant}/recursive_aggregation/c2ab_chunk_fold/c2ab_chunk_fold.vk_hash`,
        )
      : local("recursive_aggregation", "c2ab_chunk_fold"),
    config
      ? path.join(
          root,
          `${defaultVariant}/recursive_aggregation/c3ab_fold/c3ab_fold.vk_hash`,
        )
      : local("recursive_aggregation", "c3ab_fold"),
    config
      ? path.join(
          root,
          `${defaultVariant}/recursive_aggregation/c4ab_fold/c4ab_fold.vk_hash`,
        )
      : local("recursive_aggregation", "c4ab_fold"),
    config
      ? path.join(
          root,
          `${defaultVariant}/recursive_aggregation/sk_c2_chunk_finalize/sk_c2_chunk_finalize.vk_hash`,
        )
      : local("recursive_aggregation", "sk_c2_chunk_finalize"),
    config
      ? path.join(
          root,
          `${defaultVariant}/recursive_aggregation/esm_c2_chunk_finalize/esm_c2_chunk_finalize.vk_hash`,
        )
      : local("recursive_aggregation", "esm_c2_chunk_finalize"),
    config
      ? path.join(
          root,
          `${defaultVariant}/recursive_aggregation/c2_chunk_batch/c2_chunk_batch.vk_hash`,
        )
      : local("recursive_aggregation", "c2_chunk_batch"),
    config
      ? path.join(
          root,
          `${recursive}/dkg/sk_share_computation_chunk/sk_share_computation_chunk.vk_hash`,
        )
      : local("dkg", "sk_share_computation_chunk"),
    config
      ? path.join(
          root,
          `${recursive}/dkg/esm_share_computation_chunk/esm_share_computation_chunk.vk_hash`,
        )
      : local("dkg", "esm_share_computation_chunk"),
    config
      ? path.join(
          root,
          `${defaultVariant}/recursive_aggregation/c3_fold/c3_fold.vk_hash`,
        )
      : local("recursive_aggregation", "c3_fold"),
    config
      ? path.join(
          root,
          `${recursive}/dkg/share_encryption/share_encryption.vk_hash`,
        )
      : local("dkg", "share_encryption"),
    config
      ? path.join(
          root,
          `${recursive}/dkg/share_decryption/share_decryption.vk_hash`,
        )
      : local("dkg", "share_decryption"),
    config
      ? path.join(
          root,
          `${defaultVariant}/recursive_aggregation/c3_fold_kernel/c3_fold_kernel.vk_hash`,
        )
      : local("recursive_aggregation", "c3_fold_kernel"),
    config
      ? path.join(
          root,
          `${defaultVariant}/recursive_aggregation/nodes_fold_kernel/nodes_fold_kernel.vk_hash`,
        )
      : local("recursive_aggregation", "nodes_fold_kernel"),
  ] as const;
}

/** Recursive VK hashes used by the secure-16384 V2 DKG aggregation wrapper. */
export function getBfvV2SubCircuitVkHashPaths(config?: ActiveBfvConfig) {
  const root = config ? distCircuitRoot(config) : getRepoRoot();
  return {
    nodesFold: config
      ? path.join(
          root,
          "default/recursive_aggregation/nodes_fold_v2/nodes_fold_v2.vk_hash",
        )
      : localRecursiveVkHashPath("recursive_aggregation", "nodes_fold_v2"),
  } as const;
}

/** V2 recursive VK binding manifest in the order consumed by `dkg_aggregator_v2`. */
export function getBfvV2VkBindingHashPaths(config?: ActiveBfvConfig) {
  const root = config ? distCircuitRoot(config) : getRepoRoot();
  const defaultVariant = config ? "default" : "target";
  const recursive = config ? "recursive" : "target";
  const pathFor = (variant: string, group: string, circuit: string) =>
    config
      ? path.join(root, `${variant}/${group}/${circuit}/${circuit}.vk_hash`)
      : localRecursiveVkHashPath(group, circuit);

  return [
    pathFor(defaultVariant, "recursive_aggregation", "node_fold_v2"),
    pathFor(defaultVariant, "recursive_aggregation", "nodes_fold_v2"),
    pathFor(defaultVariant, "recursive_aggregation", "nodes_fold_v2_kernel"),
    pathFor(defaultVariant, "recursive_aggregation", "lbfv_generation_fold"),
    pathFor(
      defaultVariant,
      "recursive_aggregation",
      "lbfv_generation_fold_kernel",
    ),
    pathFor(recursive, "threshold", "lbfv_pk_generation"),
    pathFor(recursive, "threshold", "rlk_generation"),
    pathFor(recursive, "threshold", "rlk_generation_limb"),
    pathFor(defaultVariant, "recursive_aggregation", "lbfv_aggregation_fold"),
    pathFor(
      defaultVariant,
      "recursive_aggregation",
      "lbfv_aggregation_fold_kernel",
    ),
    pathFor(recursive, "threshold", "lbfv_pk_aggregation"),
    pathFor(recursive, "threshold", "rlk_aggregation"),
  ] as const;
}

/** Recursive VK hashes for `BfvDecryptionVerifier` sub-circuits. */
export function getBfvDecryptionSubCircuitVkHashPaths(
  config?: ActiveBfvConfig,
) {
  if (config) {
    const root = distCircuitRoot(config);
    return {
      c6Fold: path.join(
        root,
        "default/recursive_aggregation/c6_fold/c6_fold.vk_hash",
      ),
      c7: path.join(
        root,
        "default/threshold/decrypted_shares_aggregation/decrypted_shares_aggregation.vk_hash",
      ),
    } as const;
  }

  return {
    c6Fold: localRecursiveVkHashPath("recursive_aggregation", "c6_fold"),
    c7: localRecursiveVkHashPath("threshold", "decrypted_shares_aggregation"),
  } as const;
}

/**
 * Reads a 32-byte recursive VK hash emitted by the circuit build (`*.vk_recursive_hash`).
 * Co-redeploy `BfvPkVerifier` / `BfvDecryptionVerifier` when the corresponding sub-circuit VK changes.
 */
export function readVkRecursiveHash(
  filePath: string,
  config?: ActiveBfvConfig,
): string {
  if (!fs.existsSync(filePath)) {
    const buildHint = config
      ? `pnpm build:circuits --preset ${config.preset} --committee ${config.committee}`
      : "pnpm build:circuits";
    throw new Error(
      `Missing circuit VK hash file: ${filePath}. From repo root run: ${buildHint}`,
    );
  }

  const raw = fs.readFileSync(filePath);
  if (raw.length !== 32) {
    throw new Error(
      `Invalid VK hash length in ${filePath}: expected 32 bytes, got ${raw.length}`,
    );
  }

  return `0x${raw.toString("hex")}`;
}

/** On-chain `BfvPkVerifier` sub-circuit VK immutables (for deploy-time staleness checks). */
export interface BfvPkVerifierVkReader {
  expectedNodesFoldKeyHash(): Promise<string>;
  expectedC5KeyHash(): Promise<string>;
  expectedSkC2ChunkKeyHash(): Promise<string>;
  expectedESmC2ChunkKeyHash(): Promise<string>;
  expectedVkBinding(index: bigint): Promise<string>;
}

/** On-chain `BfvPkVerifierV2` sub-circuit VK immutables (for deploy-time staleness checks). */
export interface BfvPkVerifierV2VkReader {
  expectedNodesFoldKeyHash(): Promise<string>;
  expectedC5KeyHash(): Promise<string>;
  expectedSkC2ChunkKeyHash(): Promise<string>;
  expectedESmC2ChunkKeyHash(): Promise<string>;
  expectedLegacyVkBinding(index: bigint): Promise<string>;
  expectedV2VkBinding(index: bigint): Promise<string>;
}

/** On-chain `BfvDecryptionVerifier` sub-circuit VK immutables (for deploy-time staleness checks). */
export interface BfvDecryptionVerifierVkReader {
  expectedC6FoldKeyHash(): Promise<string>;
  expectedC7KeyHash(): Promise<string>;
}

/**
 * Ensures deployed `BfvPkVerifier` immutables match current `*.vk_recursive_hash` artifacts.
 * Call when reusing an address from `deployed_contracts.json` after `pnpm compile:circuits`.
 */
export async function assertBfvPkVerifierSubCircuitVkHashes(
  verifier: BfvPkVerifierVkReader,
  address: string,
  config?: ActiveBfvConfig,
): Promise<void> {
  const expectedNodesFold = readVkRecursiveHash(
    getBfvPkSubCircuitVkHashPaths(config).nodesFold,
    config,
  );
  const expectedC5 = readVkRecursiveHash(
    getBfvPkSubCircuitVkHashPaths(config).c5,
    config,
  );
  const expectedSkC2Chunk = readVkRecursiveHash(
    getBfvPkSubCircuitVkHashPaths(config).skC2Chunk,
    config,
  );
  const expectedESmC2Chunk = readVkRecursiveHash(
    getBfvPkSubCircuitVkHashPaths(config).esmC2Chunk,
    config,
  );
  const expectedVkBinding = getBfvPkVkBindingHashPaths(config).map((filePath) =>
    readVkRecursiveHash(filePath, config),
  );
  const [onChainNodesFold, onChainC5, onChainSkC2Chunk, onChainESmC2Chunk] =
    await Promise.all([
      verifier.expectedNodesFoldKeyHash(),
      verifier.expectedC5KeyHash(),
      verifier.expectedSkC2ChunkKeyHash(),
      verifier.expectedESmC2ChunkKeyHash(),
    ]);
  const onChainVkBinding = await Promise.all(
    expectedVkBinding.map((_, index) =>
      verifier.expectedVkBinding(BigInt(index)),
    ),
  );

  if (
    onChainNodesFold === expectedNodesFold &&
    onChainC5 === expectedC5 &&
    onChainSkC2Chunk === expectedSkC2Chunk &&
    onChainESmC2Chunk === expectedESmC2Chunk &&
    onChainVkBinding.every((value, index) => value === expectedVkBinding[index])
  ) {
    return;
  }

  throw new Error(
    `BfvPkVerifier at ${address} has stale sub-circuit VK immutables. ` +
      `On-chain nodes_fold=${onChainNodesFold} expected=${expectedNodesFold}; ` +
      `on-chain c5=${onChainC5} expected=${expectedC5}; ` +
      `on-chain sk_c2_chunk=${onChainSkC2Chunk} expected=${expectedSkC2Chunk}; ` +
      `on-chain esm_c2_chunk=${onChainESmC2Chunk} expected=${expectedESmC2Chunk}; ` +
      `recursive VK binding mismatch at one or more indices. ` +
      `Redeploy after pnpm compile:circuits or remove the stale entry from deployed_contracts.json.`,
  );
}

/**
 * Ensures deployed `BfvPkVerifierV2` immutables match current legacy and V2 recursive VK hashes.
 */
export async function assertBfvPkVerifierV2VkHashes(
  verifier: BfvPkVerifierV2VkReader,
  address: string,
  config?: ActiveBfvConfig,
): Promise<void> {
  const expectedNodesFold = readVkRecursiveHash(
    getBfvV2SubCircuitVkHashPaths(config).nodesFold,
    config,
  );
  const pkPaths = getBfvPkSubCircuitVkHashPaths(config);
  const expectedC5 = readVkRecursiveHash(pkPaths.c5, config);
  const expectedSkC2Chunk = readVkRecursiveHash(pkPaths.skC2Chunk, config);
  const expectedESmC2Chunk = readVkRecursiveHash(pkPaths.esmC2Chunk, config);
  const expectedLegacyVkBinding = getBfvPkVkBindingHashPaths(config).map(
    (filePath) => readVkRecursiveHash(filePath, config),
  );
  const expectedV2VkBinding = getBfvV2VkBindingHashPaths(config).map(
    (filePath) => readVkRecursiveHash(filePath, config),
  );

  const [onChainNodesFold, onChainC5, onChainSkC2Chunk, onChainESmC2Chunk] =
    await Promise.all([
      verifier.expectedNodesFoldKeyHash(),
      verifier.expectedC5KeyHash(),
      verifier.expectedSkC2ChunkKeyHash(),
      verifier.expectedESmC2ChunkKeyHash(),
    ]);
  const [onChainLegacyVkBinding, onChainV2VkBinding] = await Promise.all([
    Promise.all(
      expectedLegacyVkBinding.map((_, index) =>
        verifier.expectedLegacyVkBinding(BigInt(index)),
      ),
    ),
    Promise.all(
      expectedV2VkBinding.map((_, index) =>
        verifier.expectedV2VkBinding(BigInt(index)),
      ),
    ),
  ]);

  if (
    onChainNodesFold === expectedNodesFold &&
    onChainC5 === expectedC5 &&
    onChainSkC2Chunk === expectedSkC2Chunk &&
    onChainESmC2Chunk === expectedESmC2Chunk &&
    onChainLegacyVkBinding.every(
      (value, index) => value === expectedLegacyVkBinding[index],
    ) &&
    onChainV2VkBinding.every(
      (value, index) => value === expectedV2VkBinding[index],
    )
  ) {
    return;
  }

  throw new Error(
    `BfvPkVerifierV2 at ${address} has stale sub-circuit VK immutables. ` +
      `On-chain nodes_fold=${onChainNodesFold} expected=${expectedNodesFold}; ` +
      `on-chain c5=${onChainC5} expected=${expectedC5}; ` +
      `on-chain sk_c2_chunk=${onChainSkC2Chunk} expected=${expectedSkC2Chunk}; ` +
      `on-chain esm_c2_chunk=${onChainESmC2Chunk} expected=${expectedESmC2Chunk}; ` +
      `legacy or V2 recursive VK binding mismatch at one or more indices. ` +
      `Redeploy after pnpm compile:circuits or remove the stale entry from deployed_contracts.json.`,
  );
}

/**
 * Ensures deployed `BfvDecryptionVerifier` immutables match current `*.vk_recursive_hash` artifacts.
 */
export async function assertBfvDecryptionVerifierSubCircuitVkHashes(
  verifier: BfvDecryptionVerifierVkReader,
  address: string,
  config?: ActiveBfvConfig,
): Promise<void> {
  const expectedC6Fold = readVkRecursiveHash(
    getBfvDecryptionSubCircuitVkHashPaths(config).c6Fold,
    config,
  );
  const expectedC7 = readVkRecursiveHash(
    getBfvDecryptionSubCircuitVkHashPaths(config).c7,
    config,
  );
  const [onChainC6Fold, onChainC7] = await Promise.all([
    verifier.expectedC6FoldKeyHash(),
    verifier.expectedC7KeyHash(),
  ]);

  if (onChainC6Fold === expectedC6Fold && onChainC7 === expectedC7) {
    return;
  }

  throw new Error(
    `BfvDecryptionVerifier at ${address} has stale sub-circuit VK immutables. ` +
      `On-chain c6_fold=${onChainC6Fold} expected=${expectedC6Fold}; ` +
      `on-chain c7=${onChainC7} expected=${expectedC7}. ` +
      `Redeploy after pnpm compile:circuits or remove the stale entry from deployed_contracts.json.`,
  );
}

// Type for deployment arguments
export interface DeploymentArgs {
  address: string;
  bytecodeHash?: string;
  constructorArgs?: Record<string, unknown>;
  libraries?: Record<string, string>;
  proxyRecords?: Record<string, unknown>;
  blockNumber?: number | null;
  skipVerification?: boolean;
  verificationNote?: string;
}

// Type for chain-specific deployments
export interface ChainDeployments {
  [contractName: string]: DeploymentArgs;
}

// Type for the deployments object organized by chain
export interface Deployments {
  [chainName: string]: ChainDeployments;
}

/**
 * Defines the Interfold.config.yaml structure
 */
export interface InterfoldConfig {
  chains: Array<{
    name: string;
    rpc_url: string;
    contracts: {
      e3_program?: { address: string; deploy_block: number };
      interfold?: { address: string; deploy_block: number };
      ciphernode_registry?: { address: string; deploy_block: number };
      bonding_registry?: { address: string; deploy_block: number };
      slashing_manager?: { address: string; deploy_block: number };
      fee_token?: { address: string; deploy_block: number };
    };
  }>;
  // we don't care about the below fields
  program: unknown;
  nodes: unknown;
}

/**
 * Store the deployment arguments for a given contract and chain
 * @param args - The deployment arguments to store
 * @param contractName - The name of the contract to store the deployments for
 * @param chain - The chain to store the deployments for
 */
export const storeDeploymentArgs = (
  args: DeploymentArgs,
  contractName: string,
  chain: string,
): void => {
  let deployments: Deployments = {};

  // Read existing deployments if file exists
  if (fs.existsSync(deploymentsFile)) {
    try {
      deployments = JSON.parse(
        fs.readFileSync(deploymentsFile, "utf8"),
      ) as Deployments;
    } catch {
      console.warn("Failed to parse existing deployments file, starting fresh");
      deployments = {};
    }
  } else {
    // create a new file
    deployments = {};
    fs.writeFileSync(deploymentsFile, JSON.stringify(deployments, null, 2));
  }

  // Initialize chain if it doesn't exist
  if (!deployments[chain]) {
    deployments[chain] = {};
  }

  // Add or update the contract deployment for the specific chain
  deployments[chain][contractName] = args;

  fs.writeFileSync(deploymentsFile, JSON.stringify(deployments, null, 2));
};

/**
 * Read the deployment arguments for a given contract and chain
 * @param contractName - The name of the contract to read the deployments from
 * @param chain - The chain to read the deployments from
 * @returns The deployment arguments for the given contract and chain
 */
export const readDeploymentArgs = (
  contractName: string,
  chain: string,
): DeploymentArgs | undefined => {
  if (!fs.existsSync(deploymentsFile)) {
    // create a new file
    fs.writeFileSync(deploymentsFile, JSON.stringify({}, null, 2));
    return undefined;
  }

  const deployments = JSON.parse(
    fs.readFileSync(deploymentsFile, "utf8"),
  ) as Deployments;
  return deployments[chain]?.[contractName];
};

/**
 * Read all the deployments from the deployments file
 * @returns All the deployments from the deployments file
 */
export const readAllDeployments = (): Deployments => {
  if (!fs.existsSync(deploymentsFile)) {
    return {};
  }

  try {
    return JSON.parse(fs.readFileSync(deploymentsFile, "utf8")) as Deployments;
  } catch {
    console.warn("Failed to parse deployments file");
    return {};
  }
};

/**
 * Clean the deployments for a given network
 * @param network - The network for which to clean the deployments
 */
export const cleanDeployments = (network: string): void => {
  if (!fs.existsSync(deploymentsFile)) {
    return;
  }

  const deployments = readAllDeployments();
  if (deployments[network]) {
    delete deployments[network];
  }
  fs.writeFileSync(deploymentsFile, JSON.stringify(deployments, null, 2));
};

/**
 * Remove deployment records for a local Hardhat network and legacy provider-name buckets.
 */
export const cleanLocalDeployments = (network: string): void => {
  const isLocalNetwork =
    (LOCAL_DEPLOYMENT_NETWORKS as readonly string[]).includes(network) ||
    (LEGACY_LOCAL_DEPLOYMENT_ALIASES as readonly string[]).includes(network);

  const targets = new Set<string>([network]);
  if (isLocalNetwork) {
    for (const name of LOCAL_DEPLOYMENT_NETWORKS) {
      targets.add(name);
    }
    for (const alias of LEGACY_LOCAL_DEPLOYMENT_ALIASES) {
      targets.add(alias);
    }
  }

  if (!fs.existsSync(deploymentsFile)) {
    return;
  }

  const deployments = readAllDeployments();
  let changed = false;
  for (const key of targets) {
    if (deployments[key]) {
      delete deployments[key];
      changed = true;
    }
  }
  if (changed) {
    fs.writeFileSync(deploymentsFile, JSON.stringify(deployments, null, 2));
  }
};

/**
 * Check if two arrays are equal by checking the values inside
 * @param arr1 - The first array
 * @param arr2 - The second array to check
 * @returns Whether the two arrays are equal
 */
export function areArraysEqual<T>(arr1: T[], arr2: T[]): boolean {
  if (arr1.length !== arr2.length) {
    return false;
  }

  for (let i = 0; i < arr1.length; i++) {
    if (arr1[i] !== arr2[i]) {
      return false;
    }
  }

  return true;
}

/**
 * The function to update the interfold.config.yaml file with the deployed contract addresses.
 * Uses line-by-line text manipulation to preserve comments, blank lines, and quote style.
 * @param chainToConfig - The chain name to update in the config
 * @param pathToConfigFile - The path to the interfold.config.yaml file
 * @param contractMapping - A mapping of contract names to config keys
 */
export const updateE3Config = (
  chainToConfig: string,
  pathToConfigFile: string,
  contractMapping: Record<string, string>,
  rpcUrl?: string,
): void => {
  const content = fs.readFileSync(pathToConfigFile, "utf8");
  const lines = content.split("\n");

  // Collect deployment data keyed by config key
  const updates = new Map<string, { address: string; deployBlock: number }>();
  for (const [contractName, configKey] of Object.entries(contractMapping)) {
    const deployment = readDeploymentArgs(contractName, chainToConfig);
    if (deployment) {
      updates.set(configKey, {
        address: deployment.address,
        deployBlock: deployment.blockNumber ?? 1,
      });
    }
  }

  if (updates.size === 0) {
    console.log("No deployments found to update.");
    return;
  }

  console.log(`\nUpdating contracts for chain: ${chainToConfig}`);

  // State machine to walk through the YAML lines
  let inTargetChain = false;
  let foundTargetChain = false;
  let inContracts = false;
  let currentContractKey: string | null = null;
  let chainBaseIndent = -1;
  let contractsKeyIndent = -1;
  let contractEntryIndent = -1;
  const foundKeys = new Set<string>();
  let lastContractsLine = -1;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trim();

    if (trimmed === "" || trimmed.startsWith("#")) {
      if (inContracts) lastContractsLine = i;
      continue;
    }

    const indent = line.length - line.trimStart().length;

    // Detect chain name entry: `  - name: "chainName"`
    const nameMatch = trimmed.match(/^-\s+name:\s*["']?(.+?)["']?\s*$/);
    if (nameMatch) {
      if (inTargetChain) {
        // We've passed the target chain
        break;
      }

      if (nameMatch[1] === chainToConfig) {
        inTargetChain = true;
        foundTargetChain = true;
        chainBaseIndent = indent;
      }
      continue;
    }

    // If we hit a top-level key while in the target chain, we've left it
    if (
      inTargetChain &&
      indent <= chainBaseIndent &&
      !trimmed.startsWith("-")
    ) {
      break;
    }

    if (!inTargetChain) continue;

    // Detect `contracts:` section
    if (trimmed === "contracts:") {
      inContracts = true;
      contractsKeyIndent = indent;
      lastContractsLine = i;
      continue;
    }

    if (!inContracts) continue;

    // Check if we've left the contracts section
    if (indent <= contractsKeyIndent) {
      break;
    }

    lastContractsLine = i;

    // Detect contract key line (e.g., `      interfold:`)
    const keyMatch = trimmed.match(/^(\w+):$/);
    if (
      keyMatch &&
      (contractEntryIndent === -1 || indent === contractEntryIndent)
    ) {
      currentContractKey = keyMatch[1];
      if (contractEntryIndent === -1) contractEntryIndent = indent;
      continue;
    }

    if (!currentContractKey) continue;

    // We're inside a contract entry — update address/deploy_block if this contract needs updating
    const update = updates.get(currentContractKey);
    if (!update) continue;

    if (trimmed.startsWith("address:")) {
      foundKeys.add(currentContractKey);
      const ws = line.match(/^(\s*)/)?.[1] ?? "";
      const comment = trimmed.match(
        /^address:\s*["']?[^#"']*["']?\s*(#.*)$/,
      )?.[1];
      lines[i] =
        `${ws}address: "${update.address}"${comment ? " " + comment : ""}`;
      console.log(
        `✓ Updated ${currentContractKey}: ${update.address} (block ${update.deployBlock})`,
      );
    }

    if (trimmed.startsWith("deploy_block:")) {
      const ws = line.match(/^(\s*)/)?.[1] ?? "";
      const comment = trimmed.match(/^deploy_block:\s*\S+\s*(#.*)$/)?.[1];
      lines[i] =
        `${ws}deploy_block: ${update.deployBlock}${comment ? " " + comment : ""}`;
    }
  }

  if (!foundTargetChain) {
    // Chain not found — append a new chain block at the end of the chains section
    console.log(
      `Chain "${chainToConfig}" not found in config. Creating new entry...`,
    );
    if (!rpcUrl) {
      console.warn(
        "Warning: No RPC URL provided. You'll need to update it manually in the config.",
      );
    }

    const chainsIdx = lines.findIndex((l) => l.trim() === "chains:");
    let insertIdx = lines.length;
    if (chainsIdx !== -1) {
      for (let i = chainsIdx + 1; i < lines.length; i++) {
        const t = lines[i].trim();
        if (t === "" || t.startsWith("#")) continue;
        if (lines[i].length - lines[i].trimStart().length === 0) {
          insertIdx = i;
          break;
        }
      }
    }

    const newLines = [
      `  - name: "${chainToConfig}"`,
      `    rpc_url: "${rpcUrl || "ws://localhost:8545"}"`,
      `    contracts:`,
    ];
    for (const [configKey, update] of updates) {
      newLines.push(`      ${configKey}:`);
      newLines.push(`        address: "${update.address}"`);
      newLines.push(`        deploy_block: ${update.deployBlock}`);
      console.log(
        `✓ Added ${configKey}: ${update.address} (block ${update.deployBlock})`,
      );
    }
    lines.splice(insertIdx, 0, ...newLines);
  } else {
    // Insert any contracts that weren't found in the existing config
    const missingKeys = [...updates.keys()].filter((k) => !foundKeys.has(k));
    if (missingKeys.length > 0 && lastContractsLine !== -1) {
      const keyIndent =
        contractEntryIndent !== -1
          ? contractEntryIndent
          : contractsKeyIndent + 2;
      const valIndent = keyIndent + 2;

      const newLines: string[] = [];
      for (const configKey of missingKeys) {
        const update = updates.get(configKey)!;
        newLines.push(`${" ".repeat(keyIndent)}${configKey}:`);
        newLines.push(`${" ".repeat(valIndent)}address: "${update.address}"`);
        newLines.push(
          `${" ".repeat(valIndent)}deploy_block: ${update.deployBlock}`,
        );
        console.log(
          `✓ Added ${configKey}: ${update.address} (block ${update.deployBlock})`,
        );
      }

      lines.splice(lastContractsLine + 1, 0, ...newLines);
    }
  }

  fs.writeFileSync(pathToConfigFile, lines.join("\n"), "utf8");
  console.log("\n✓ interfold.config.yaml updated successfully!");
};

/**
 * Awaits a contract call being *mined*, not merely sent.
 *
 * `await contract.setX(...)` resolves when the transaction is dispatched — the receipt only exists
 * after `.wait()`. On an auto-mining local node the difference is invisible, which is why the bug
 * survives; against a real network a run of back-to-back writes silently loses whichever ones do
 * not land, and the script reports success regardless.
 */
export const send = async (
  call: Promise<ContractTransactionResponse>,
  label?: string,
): Promise<ContractTransactionReceipt> => {
  const what = label ?? "transaction";
  let tx: ContractTransactionResponse;
  try {
    tx = await call;
  } catch (error) {
    throw new Error(`${what} failed to send`, { cause: error });
  }
  let receipt: ContractTransactionReceipt | null;
  try {
    receipt = await tx.wait();
  } catch (error) {
    throw new Error(`${what} failed while mining: ${tx.hash}`, {
      cause: error,
    });
  }
  if (!receipt) throw new Error(`${what} ${tx.hash}: no receipt`);
  if (receipt.status !== 1) throw new Error(`${what} reverted: ${tx.hash}`);
  return receipt;
};
