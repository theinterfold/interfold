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
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";
import { isDeepStrictEqual } from "node:util";
import path from "path";

import {
  BFV_PRESETS,
  COMMITTEES,
  DECRYPTION_INPUT_INDICES,
  decryptionAggregatorLayout,
} from "../bfv.js";

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

/**
 * Monorepo root (`interfold/`), or `undefined` when this package is installed outside it. Works
 * from `scripts/` and compiled `dist/scripts/`.
 */
export function findMonorepoRoot(): string | undefined {
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
  return undefined;
}

let _repoRoot: string | undefined;

/** Monorepo root, resolved on first call. Throws when this package is installed outside it. */
export function getRepoRoot(): string {
  _repoRoot ??= findMonorepoRoot();
  if (!_repoRoot) {
    throw new Error(
      "Could not find interfold repo root (expected package.json name @interfold/main)",
    );
  }
  return _repoRoot;
}

// The circuit builder switches these names; all numerical values come from the shared binding.
export const ACTIVE_BFV_PRESET: BfvArtifactPreset = "insecure-64";
export const ACTIVE_BFV_COMMITTEE: BfvCommittee = "minimum";

export type BfvArtifactPreset = "insecure-64" | "secure-8192";
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

function bfvConfig(
  preset: BfvArtifactPreset,
  committee: BfvCommittee,
): ActiveBfvConfig {
  const parameters = BFV_PRESETS[preset];
  const members = COMMITTEES[committee];
  return {
    preset,
    committee,
    paramSet: parameters.paramSet,
    paramSetHash: parameters.paramSetHash,
    configId: parameters.configId,
    committeeSize: members.committeeSize,
    h: members.h,
    t: members.t,
    n: members.n,
  };
}

export const INSECURE_MINIMUM_BFV_CONFIG: ActiveBfvConfig = bfvConfig(
  "insecure-64",
  "minimum",
);

export const INSECURE_MICRO_BFV_CONFIG: ActiveBfvConfig = bfvConfig(
  "insecure-64",
  "micro",
);

export const INSECURE_SMALL_BFV_CONFIG: ActiveBfvConfig = bfvConfig(
  "insecure-64",
  "small",
);

export const SECURE_MINIMUM_BFV_CONFIG: ActiveBfvConfig = bfvConfig(
  "secure-8192",
  "minimum",
);

export const SECURE_MICRO_BFV_CONFIG: ActiveBfvConfig = bfvConfig(
  "secure-8192",
  "micro",
);

export const SECURE_SMALL_BFV_CONFIG: ActiveBfvConfig = bfvConfig(
  "secure-8192",
  "small",
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
] as const;

/** Local artifact selection, independent of the production/testnet admission defaults. */
const ACTIVE_BFV_CONFIG = TESTNET_BFV_CONFIGS.find(
  (config) =>
    config.preset === ACTIVE_BFV_PRESET &&
    config.committee === ACTIVE_BFV_COMMITTEE,
)!;

export const BFV_DKG_H = ACTIVE_BFV_CONFIG.h;
export const BFV_THRESHOLD_T = ACTIVE_BFV_CONFIG.t;
export const ACTIVE_BFV_PARAM_SET = ACTIVE_BFV_CONFIG.paramSet;
export const ACTIVE_BFV_COMMITTEE_SIZE = ACTIVE_BFV_CONFIG.committeeSize;
export const ACTIVE_BFV_COMMITTEE_N = ACTIVE_BFV_CONFIG.n;

/**
 * Names a circuit directory in the release-archive layout (`<preset>/<committee>/default/...`):
 * the `circuits/` directory of `circuits-<version>.tar.gz`, or the directory that
 * `interfold noir setup` installs, from the release of this package. Only a package installed
 * outside the monorepo reads it; the monorepo reads its own release-verified circuit build.
 */
const CIRCUITS_DIR_ENV = "INTERFOLD_CIRCUITS_DIR";

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

/**
 * The `[H, N]` committee thresholds of every committee size that the chain's BFV routes use, in
 * route order. `Interfold.setCommitteeThresholds` takes one pair per size, so the presets must agree
 * on each size.
 */
export function committeeThresholdsForChain(
  chainId: number,
): Pick<ActiveBfvConfig, "committeeSize" | "h" | "n">[] {
  const thresholds = new Map<
    number,
    Pick<ActiveBfvConfig, "committeeSize" | "h" | "n">
  >();
  for (const { committeeSize, h, n } of bfvConfigsForChain(chainId)) {
    const existing = thresholds.get(committeeSize);
    if (existing && (existing.h !== h || existing.n !== n)) {
      throw new Error(
        `BFV presets disagree on committee size ${committeeSize}`,
      );
    }
    thresholds.set(committeeSize, { committeeSize, h, n });
  }
  return [...thresholds.values()];
}

/** `dkg_aggregator` EVM public-input count for honest-set size `h`. */
export function bfvPkExpectedPublicInputsLen(h: number): number {
  return 3 * h + 6;
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
  return decryptionAggregatorLayout(threshold).publicInputsLength;
}

/** `publicInputs` indices for decryption-aggregator committee hash limbs. */
export function bfvDecCommitteeHashIndices(): { hi: number; lo: number } {
  return {
    hi: DECRYPTION_INPUT_INDICES.committee_hash_hi,
    lo: DECRYPTION_INPUT_INDICES.committee_hash_lo,
  };
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
  const layout = decryptionAggregatorLayout(threshold);
  return {
    partyId: layout.partyIdOffset,
    sk: layout.skOffset,
    esm: layout.esmOffset,
  };
}

/** `publicInputs` indices for decryption-aggregator E3 domain limbs. */
export function bfvDecDomainIndices(): { hi: number; lo: number } {
  return {
    hi: DECRYPTION_INPUT_INDICES.domain_hi,
    lo: DECRYPTION_INPUT_INDICES.domain_lo,
  };
}

/** `publicInputs` index for the final circuit-compatible ciphertext commitment. */
export function bfvDecCiphertextCommitmentIndex(): number {
  return DECRYPTION_INPUT_INDICES.ciphertext_commitment;
}

/**
 * Release-layout directory of a preset/committee pair, or `undefined` for the monorepo circuit
 * build under `circuits/bin`. In the monorepo, a selected `config` reads `dist/circuits`. Outside
 * it, `INTERFOLD_CIRCUITS_DIR` is required, and a missing `config` selects the active pair.
 */
function releaseCircuitRoot(config?: ActiveBfvConfig): string | undefined {
  const root = findMonorepoRoot();
  if (root) {
    return config
      ? path.join(root, "dist/circuits", config.preset, config.committee)
      : undefined;
  }
  const dir = process.env[CIRCUITS_DIR_ENV];
  if (!dir) {
    throw new Error(
      `Outside the Interfold monorepo, set ${CIRCUITS_DIR_ENV} to a release circuit directory to read BFV VK hashes`,
    );
  }
  const { preset, committee } = config ?? ACTIVE_BFV_CONFIG;
  return path.join(dir, preset, committee);
}

/** Complete nodes-fold VK-tree anchor and C5 recursive VK hash. */
export function getBfvPkSubCircuitVkHashPaths(config?: ActiveBfvConfig) {
  const releaseRoot = releaseCircuitRoot(config);
  if (releaseRoot) {
    return {
      nodesFold: path.join(
        releaseRoot,
        "default/recursive_aggregation/nodes_fold/nodes_fold.vk_tree_hash",
      ),
      c5: path.join(
        releaseRoot,
        "default/threshold/pk_aggregation/pk_aggregation.vk_hash",
      ),
    } as const;
  }

  const root = getRepoRoot();
  return {
    nodesFold: path.join(
      root,
      "circuits/bin/recursive_aggregation/nodes_fold/target/nodes_fold.vk_tree_hash",
    ),
    c5: path.join(
      root,
      "circuits/bin/threshold/target/pk_aggregation.vk_recursive_hash",
    ),
  } as const;
}

/** Complete C6-fold VK-tree anchor and C7 recursive VK hash. */
export function getBfvDecryptionSubCircuitVkHashPaths(
  config?: ActiveBfvConfig,
) {
  const releaseRoot = releaseCircuitRoot(config);
  if (releaseRoot) {
    return {
      c6Fold: path.join(
        releaseRoot,
        "default/recursive_aggregation/c6_fold/c6_fold.vk_tree_hash",
      ),
      c7: path.join(
        releaseRoot,
        "default/threshold/decrypted_shares_aggregation/decrypted_shares_aggregation.vk_hash",
      ),
    } as const;
  }

  const root = getRepoRoot();
  return {
    c6Fold: path.join(
      root,
      "circuits/bin/recursive_aggregation/c6_fold/target/c6_fold.vk_tree_hash",
    ),
    c7: path.join(
      root,
      "circuits/bin/threshold/target/decrypted_shares_aggregation.vk_recursive_hash",
    ),
  } as const;
}

/**
 * Read a 32-byte recursive VK hash or complete VK-tree anchor from the circuit build.
 * Replace the corresponding BFV wrapper when any anchored descendant VK changes.
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

interface CircuitIdentityKey {
  preset: string;
  committee: string;
  circuit: string;
  proofVariant: "default" | "recursive" | "evm";
  hashKind: "bb-vk-hash" | "solidity-vk-hash" | "recursive-tree-commitment";
}

interface CircuitIdentityEntry {
  key: CircuitIdentityKey;
  value: string;
  compiledArtifact: { path: string; sha256: string } | null;
  verificationKey: { path: string; sha256: string } | null;
  dependencies: CircuitIdentityKey[];
}

interface CircuitIdentityPair {
  preset: string;
  committee: string;
  sourceHash: string;
  entries: CircuitIdentityEntry[];
}

function readIdentityValues(
  requested: Pick<
    CircuitIdentityKey,
    "circuit" | "proofVariant" | "hashKind"
  >[],
  selected: ActiveBfvConfig = ACTIVE_BFV_CONFIG,
): string[] {
  const repo = findMonorepoRoot();
  const artifacts = repo
    ? path.join(repo, "dist/circuits")
    : process.env[CIRCUITS_DIR_ENV];
  if (!artifacts)
    throw new Error(`Set ${CIRCUITS_DIR_ENV} to the release circuit directory`);
  const packaged = path.resolve(
    path.dirname(fileURLToPath(import.meta.url)),
    "../circuit-identities.json",
  );
  const manifestPath = repo
    ? path.join(repo, "circuits/identities.json")
    : packaged;
  if (!fs.existsSync(manifestPath))
    throw new Error(
      `Missing circuit identity manifest: ${manifestPath}; prepare and qualify the complete circuit matrix`,
    );
  const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8")) as {
    formatVersion: number;
    pairs: CircuitIdentityPair[];
  };
  if (manifest.formatVersion !== 1 || !Array.isArray(manifest.pairs))
    throw new Error("Unsupported circuit identity manifest");
  const pairs = manifest.pairs.filter(
    (pair) =>
      pair.preset === selected.preset && pair.committee === selected.committee,
  );
  if (pairs.length !== 1)
    throw new Error(
      `Expected one circuit identity pair for ${selected.preset}/${selected.committee}`,
    );
  const pair = pairs[0];
  const pairDirectory = path.join(
    artifacts,
    selected.preset,
    selected.committee,
  );
  const slice = JSON.parse(
    fs.readFileSync(path.join(pairDirectory, "identities.json"), "utf8"),
  );
  if (!isDeepStrictEqual(slice, pair))
    throw new Error(
      "Circuit archive identity slice differs from the package manifest",
    );
  const stamp = JSON.parse(
    fs.readFileSync(path.join(pairDirectory, ".build-stamp.json"), "utf8"),
  );
  if (
    stamp.preset !== selected.preset ||
    stamp.committee !== selected.committee ||
    stamp.sourceHash !== pair.sourceHash
  )
    throw new Error(
      "Circuit identity source stamp differs from the package manifest",
    );
  const verified = new Set<string>();
  const visiting = new Set<string>();
  const identity = (key: CircuitIdentityKey) =>
    JSON.stringify([
      key.preset,
      key.committee,
      key.circuit,
      key.proofVariant,
      key.hashKind,
    ]);
  const lookup = (key: CircuitIdentityKey): CircuitIdentityEntry => {
    if (key.preset !== selected.preset || key.committee !== selected.committee)
      throw new Error("Cross-pair circuit identity dependency");
    const matches = pair.entries.filter(
      (entry) => identity(entry.key) === identity(key),
    );
    if (matches.length !== 1)
      throw new Error(`Missing or duplicate circuit identity ${identity(key)}`);
    return matches[0];
  };
  const root = fs.realpathSync(artifacts);
  const digest = (artifact: { path: string; sha256: string }) => {
    if (
      path.isAbsolute(artifact.path) ||
      artifact.path.includes("\\") ||
      artifact.path
        .split("/")
        .some((part) => !part || part === "." || part === "..") ||
      !artifact.path.startsWith(`${selected.preset}/${selected.committee}/`)
    )
      throw new Error("Invalid circuit identity artifact path");
    const filename = fs.realpathSync(path.join(root, artifact.path));
    if (!filename.startsWith(`${root}${path.sep}`))
      throw new Error("Circuit identity artifact escapes its directory");
    if (
      createHash("sha256").update(fs.readFileSync(filename)).digest("hex") !==
      artifact.sha256
    )
      throw new Error(
        `Circuit identity artifact digest differs: ${artifact.path}`,
      );
  };
  const verify = (key: CircuitIdentityKey) => {
    const id = identity(key);
    if (verified.has(id)) return;
    if (visiting.has(id)) throw new Error("Cyclic circuit identity dependency");
    visiting.add(id);
    const entry = lookup(key);
    if (!/^0x[0-9a-f]{64}$/.test(entry.value))
      throw new Error("Invalid circuit identity value");
    if (entry.compiledArtifact) digest(entry.compiledArtifact);
    if (entry.verificationKey) {
      digest(entry.verificationKey);
      if (
        key.hashKind === "bb-vk-hash" &&
        readVkRecursiveHash(
          path.join(root, `${entry.verificationKey.path}_hash`),
          selected,
        ) !== entry.value
      )
        throw new Error("Circuit VK hash differs from the named identity");
    } else if (key.hashKind !== "recursive-tree-commitment")
      throw new Error("Circuit key identity has no key material");
    for (const child of entry.dependencies) verify(child);
    if (
      key.hashKind === "recursive-tree-commitment" &&
      [
        "recursive_aggregation/nodes_fold",
        "recursive_aggregation/c6_fold",
      ].includes(key.circuit)
    ) {
      const name = key.circuit.split("/").pop()!;
      if (
        readVkRecursiveHash(
          path.join(
            pairDirectory,
            "default",
            key.circuit,
            `${name}.vk_tree_hash`,
          ),
          selected,
        ) !== entry.value
      )
        throw new Error("Circuit tree anchor differs from the named identity");
    }
    visiting.delete(id);
    verified.add(id);
  };
  return requested.map((request) => {
    const key = {
      preset: selected.preset,
      committee: selected.committee,
      ...request,
    };
    verify(key);
    return lookup(key).value;
  });
}

export function readBfvCircuitIdentity(
  circuit: string,
  proofVariant: CircuitIdentityKey["proofVariant"],
  hashKind: CircuitIdentityKey["hashKind"],
  config?: ActiveBfvConfig,
): string {
  return readIdentityValues([{ circuit, proofVariant, hashKind }], config)[0];
}

export function getBfvCircuitIdentities(config?: ActiveBfvConfig) {
  const [nodesFold, c5, c6Fold, c7] = readIdentityValues(
    [
      {
        circuit: "recursive_aggregation/nodes_fold",
        proofVariant: "default",
        hashKind: "recursive-tree-commitment",
      },
      {
        circuit: "threshold/pk_aggregation",
        proofVariant: "default",
        hashKind: "bb-vk-hash",
      },
      {
        circuit: "recursive_aggregation/c6_fold",
        proofVariant: "default",
        hashKind: "recursive-tree-commitment",
      },
      {
        circuit: "threshold/decrypted_shares_aggregation",
        proofVariant: "default",
        hashKind: "bb-vk-hash",
      },
    ],
    config,
  );
  return { nodesFold, c5, c6Fold, c7 };
}

/** On-chain `BfvPkVerifier` sub-circuit VK immutables (for deploy-time staleness checks). */
export interface BfvPkVerifierVkReader {
  expectedNodesFoldKeyHash(): Promise<string>;
  expectedC5KeyHash(): Promise<string>;
}

/** On-chain `BfvDecryptionVerifier` sub-circuit VK immutables (for deploy-time staleness checks). */
export interface BfvDecryptionVerifierVkReader {
  expectedC6FoldKeyHash(): Promise<string>;
  expectedC7KeyHash(): Promise<string>;
}

/**
 * Check the deployed DKG tree and C5 pins against the selected artifact pair.
 * Call when reusing an address from `deployed_contracts.json` after `pnpm compile:circuits`.
 */
export async function assertBfvPkVerifierSubCircuitVkHashes(
  verifier: BfvPkVerifierVkReader,
  address: string,
  config?: ActiveBfvConfig,
): Promise<void> {
  const { nodesFold: expectedNodesFold, c5: expectedC5 } =
    getBfvCircuitIdentities(config);
  const [onChainNodesFold, onChainC5] = await Promise.all([
    verifier.expectedNodesFoldKeyHash(),
    verifier.expectedC5KeyHash(),
  ]);

  if (onChainNodesFold === expectedNodesFold && onChainC5 === expectedC5) {
    return;
  }

  throw new Error(
    `BfvPkVerifier at ${address} has stale sub-circuit VK immutables. ` +
      `On-chain nodes_fold=${onChainNodesFold} expected=${expectedNodesFold}; ` +
      `on-chain c5=${onChainC5} expected=${expectedC5}. ` +
      `Redeploy after pnpm compile:circuits or remove the stale entry from deployed_contracts.json.`,
  );
}

/**
 * Check the deployed C6 tree and C7 pins against the selected artifact pair.
 */
export async function assertBfvDecryptionVerifierSubCircuitVkHashes(
  verifier: BfvDecryptionVerifierVkReader,
  address: string,
  config?: ActiveBfvConfig,
): Promise<void> {
  const { c6Fold: expectedC6Fold, c7: expectedC7 } =
    getBfvCircuitIdentities(config);
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
