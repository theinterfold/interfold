// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
import { network } from "hardhat";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

import {
  type ActiveBfvConfig,
  type BfvCommittee,
  TESTNET_BFV_CONFIGS,
  bfvDecCiphertextCommitmentIndex,
  bfvDecCommitteeHashIndices,
  bfvDecDomainIndices,
  bfvDecPartyColOffsets,
  bfvDkgCommitteeHashIndices,
  committeeHashFromLimbs,
  getBfvDecryptionSubCircuitVkHashPaths,
  getBfvPkSubCircuitVkHashPaths,
  getRepoRoot,
  readVkRecursiveHash,
} from "./utils";

const CANONICAL_BFV_PRESET = "insecure-512";
const CANONICAL_BFV_COMMITTEE: BfvCommittee = "minimum";
const COMMITTED_HONK_DIR = path.join(
  getRepoRoot(),
  "packages/interfold-contracts/contracts/verifiers/bfv/honk",
);

function presetFromFoldedArtifact(artifact: unknown): string | undefined {
  if (!artifact || typeof artifact !== "object") {
    return undefined;
  }
  const doc = artifact as Record<string, unknown>;
  const pick = (value: unknown): string | undefined => {
    if (typeof value !== "string") return undefined;
    const trimmed = value.trim();
    return trimmed.length > 0 ? trimmed : undefined;
  };

  const direct = pick(doc.preset) ?? pick(doc.bfv_preset_subdir);
  if (direct) return direct;

  const benchmarkConfig = doc.benchmark_config;
  if (benchmarkConfig && typeof benchmarkConfig === "object") {
    const cfg = benchmarkConfig as Record<string, unknown>;
    const fromConfig = pick(cfg.bfv_preset_subdir) ?? pick(cfg.preset);
    if (fromConfig) return fromConfig;
  }

  return undefined;
}

/** Prefer preset embedded in replayed folded/summary JSON, then env / active preset. */
function readBenchmarkPreset(foldedArtifact?: unknown): string {
  const fromArtifact = presetFromFoldedArtifact(foldedArtifact);
  if (fromArtifact) return fromArtifact;

  const fromEnv = process.env.BENCHMARK_PRESET?.trim();
  if (fromEnv) return fromEnv;
  const activePath = path.join(
    getRepoRoot(),
    "circuits/bin/.active-preset.json",
  );
  if (!fs.existsSync(activePath)) {
    return CANONICAL_BFV_PRESET;
  }
  try {
    const active = JSON.parse(fs.readFileSync(activePath, "utf8")) as {
      preset?: string;
    };
    return active.preset ?? CANONICAL_BFV_PRESET;
  } catch {
    return CANONICAL_BFV_PRESET;
  }
}

function committeeFromFoldedArtifact(
  artifact: unknown,
): BfvCommittee | undefined {
  if (!artifact || typeof artifact !== "object") return undefined;

  const doc = artifact as Record<string, unknown>;
  const benchmarkConfig =
    doc.benchmark_config && typeof doc.benchmark_config === "object"
      ? (doc.benchmark_config as Record<string, unknown>)
      : undefined;
  const named = doc.committee ?? benchmarkConfig?.committee;
  if (typeof named === "string" && named.trim().length > 0) {
    const committee = named.trim();
    const match = TESTNET_BFV_CONFIGS.find(
      (config) => config.committee === committee,
    );
    if (!match) {
      throw new Error(`Unknown benchmark committee: ${committee}`);
    }
    return match.committee;
  }

  const h = benchmarkConfig?.committee_h;
  const n = benchmarkConfig?.committee_n;
  const t = benchmarkConfig?.committee_t;
  if ([h, n, t].every((value) => typeof value === "number")) {
    const match = TESTNET_BFV_CONFIGS.find(
      (config) => config.h === h && config.n === n && config.t === t,
    );
    if (!match) {
      throw new Error(
        `Benchmark committee parameters do not match a supported committee: H=${h}, N=${n}, T=${t}`,
      );
    }
    return match.committee;
  }

  return undefined;
}

/** Prefer committee metadata in folded JSON, then the environment or active build. */
function readBenchmarkCommittee(foldedArtifact?: unknown): BfvCommittee {
  const fromArtifact = committeeFromFoldedArtifact(foldedArtifact);
  if (fromArtifact) return fromArtifact;

  const fromEnv = process.env.BENCHMARK_COMMITTEE?.trim();
  if (fromEnv) {
    const match = TESTNET_BFV_CONFIGS.find(
      (config) => config.committee === fromEnv,
    );
    if (!match) throw new Error(`Unknown BENCHMARK_COMMITTEE: ${fromEnv}`);
    return match.committee;
  }

  const activePath = path.join(
    getRepoRoot(),
    "circuits/bin/.active-preset.json",
  );
  if (fs.existsSync(activePath)) {
    try {
      const active = JSON.parse(fs.readFileSync(activePath, "utf8")) as {
        committee?: string;
      };
      if (active.committee) {
        const match = TESTNET_BFV_CONFIGS.find(
          (config) => config.committee === active.committee,
        );
        if (!match) {
          throw new Error(`Unknown active committee: ${active.committee}`);
        }
        return match.committee;
      }
    } catch (error) {
      if (error instanceof SyntaxError) return CANONICAL_BFV_COMMITTEE;
      throw error;
    }
  }
  return CANONICAL_BFV_COMMITTEE;
}

function resolveBenchmarkConfig(foldedArtifact?: unknown): ActiveBfvConfig {
  const preset = readBenchmarkPreset(foldedArtifact);
  const committee = readBenchmarkCommittee(foldedArtifact);
  const config = TESTNET_BFV_CONFIGS.find(
    (candidate) =>
      candidate.preset === preset && candidate.committee === committee,
  );
  if (!config) {
    throw new Error(
      `Unsupported benchmark configuration: ${preset}/${committee}`,
    );
  }
  return config;
}

/**
 * Resolve the verifier directory for one preset and committee pair.
 * Generate an isolated copy only when the committed pair is unavailable.
 */
function ensureHonkVerifierContractDir(config: ActiveBfvConfig): string {
  const isCanonical =
    config.preset === CANONICAL_BFV_PRESET &&
    config.committee === CANONICAL_BFV_COMMITTEE;
  const committedDir = isCanonical
    ? COMMITTED_HONK_DIR
    : path.join(COMMITTED_HONK_DIR, config.preset, config.committee);
  const verifierNames = [
    "DkgAggregatorVerifier.sol",
    "DecryptionAggregatorVerifier.sol",
  ];
  if (
    verifierNames.every((name) => fs.existsSync(path.join(committedDir, name)))
  ) {
    return committedDir;
  }

  const benchDir = path.join(
    COMMITTED_HONK_DIR,
    ".benchmark",
    config.preset,
    config.committee,
  );
  fs.mkdirSync(benchDir, { recursive: true });
  console.log(
    `[benchmarkGasFromRaw] Generating ${config.preset}/${config.committee} Honk verifiers into ${benchDir}...`,
  );
  execFileSync(
    "pnpm",
    [
      "generate:verifiers",
      "--circuits",
      "dkg_aggregator,decryption_aggregator",
      "--no-compile",
      "--write",
      "--preset",
      config.preset,
      "--committee",
      config.committee,
      "--output-dir",
      benchDir,
    ],
    { cwd: getRepoRoot(), stdio: "inherit" },
  );
  // Hardhat does not pick up freshly written .sol under honk/.benchmark/ until compile.
  execFileSync("pnpm", ["hardhat", "compile"], {
    cwd: path.join(getRepoRoot(), "packages/interfold-contracts"),
    stdio: "inherit",
  });
  return benchDir;
}

/** Hardhat `project/` source path for a generated Honk verifier file. */
function honkContractSource(honkDir: string, name: string): string {
  const rel = path.relative(
    path.join(getRepoRoot(), "packages/interfold-contracts"),
    path.join(honkDir, `${name}.sol`),
  );
  return rel.split(path.sep).join("/");
}

async function deployHonkAggregator(
  ethersLib: Awaited<ReturnType<typeof network.connect>>["ethers"],
  honkDir: string,
  contractName: "DkgAggregatorVerifier" | "DecryptionAggregatorVerifier",
): Promise<string> {
  const solSource = honkContractSource(honkDir, contractName);
  const libraryPrefix = `project/${solSource}:`;
  const zkTranscriptLibFactory = await ethersLib.getContractFactory(
    `${solSource}:ZKTranscriptLib`,
  );
  const zkTranscriptLib = await zkTranscriptLibFactory.deploy();
  await zkTranscriptLib.waitForDeployment();
  const zkTranscriptLibAddress = await zkTranscriptLib.getAddress();
  const relationsLibFactory = await ethersLib.getContractFactory(
    `${solSource}:RelationsLib`,
  );
  const relationsLib = await relationsLibFactory.deploy();
  await relationsLib.waitForDeployment();
  const relationsLibAddress = await relationsLib.getAddress();

  const aggFactory = await ethersLib.getContractFactory(
    `${solSource}:${contractName}`,
    {
      libraries: {
        [`${libraryPrefix}ZKTranscriptLib`]: zkTranscriptLibAddress,
        [`${libraryPrefix}RelationsLib`]: relationsLibAddress,
      },
    },
  );
  const agg = await aggFactory.deploy();
  await agg.waitForDeployment();
  return agg.getAddress();
}

function findRawJson(rawDir: string, fragment: string): any {
  const entries = fs.readdirSync(rawDir).filter((f) => f.endsWith(".json"));
  for (const f of entries) {
    if (!f.includes(fragment)) continue;
    const full = path.join(rawDir, f);
    return JSON.parse(fs.readFileSync(full, "utf8"));
  }
  throw new Error(`Missing raw benchmark JSON for fragment: ${fragment}`);
}

const MIN_VK_HASH_PUBLIC_INPUTS = 2;
const DEC_COMMITTEE_HASH_IDX = bfvDecCommitteeHashIndices();
const DEC_DOMAIN_IDX = bfvDecDomainIndices();

function requirePublicInputLen(
  label: string,
  publicInputs: string[],
  minLen: number,
): void {
  if (publicInputs.length < minLen) {
    throw new Error(
      `${label}: public_inputs length ${publicInputs.length} < ${minLen} (truncated or stale artifact?)`,
    );
  }
}

function hexToBytes32Array(hex: string): string[] {
  const clean = hex.startsWith("0x") ? hex.slice(2) : hex;
  if (clean.length === 0) return [];
  if (clean.length % 64 !== 0) {
    throw new Error(
      `public_inputs_hex length is not 32-byte aligned: ${clean.length}`,
    );
  }
  const out: string[] = [];
  for (let i = 0; i < clean.length; i += 64) {
    out.push(`0x${clean.slice(i, i + 64)}`);
  }
  return out;
}

function plaintextHashFromPublicInputs(
  publicInputs: string[],
  ethersLib: any,
): string {
  const messageCoeffsCount = 100;
  if (publicInputs.length < messageCoeffsCount) {
    throw new Error(`Not enough public inputs: ${publicInputs.length}`);
  }
  const offset = publicInputs.length - messageCoeffsCount;
  const plaintext = new Uint8Array(messageCoeffsCount * 8);
  for (let i = 0; i < messageCoeffsCount; i++) {
    const coeff = BigInt(publicInputs[offset + i]);
    for (let j = 0; j < 8; j++) {
      plaintext[i * 8 + j] = Number((coeff >> BigInt(j * 8)) & 0xffn);
    }
  }
  return ethersLib.keccak256(plaintext);
}

async function main() {
  const rawDir = process.env.BENCHMARK_RAW_DIR;
  const outputPath = process.env.BENCHMARK_GAS_OUTPUT;
  const foldedPath = process.env.BENCHMARK_FOLDED_JSON;
  if (!rawDir || !outputPath) {
    throw new Error("BENCHMARK_RAW_DIR and BENCHMARK_GAS_OUTPUT are required");
  }

  const { ethers } = await network.connect();
  const [benchmarkSigner] = await ethers.getSigners();
  // The DKG verifier still receives the committee context directly. The
  // decryption verifier receives the E3 ID for DKG-anchor lookup plus the
  // domain limbs carried by the folded proof.
  const benchmarkE3Id = 1n;
  const benchmarkCommitteeRoot = BigInt(
    ethers.id("benchmark-gas-committee-root"),
  );
  const benchmarkSortedNodes = [benchmarkSigner.address];

  let dkgProofHex: string | undefined;
  let dkgPublicHex: string | undefined;
  let decProofHex: string | undefined;
  let decPublicHex: string | undefined;
  let foldedDoc: unknown;

  if (foldedPath && fs.existsSync(foldedPath)) {
    const raw = fs.readFileSync(foldedPath, "utf8").trim();
    if (!raw) {
      console.warn(
        `[benchmarkGasFromRaw] ${foldedPath} is empty — integration test likely failed before exporting folded proofs`,
      );
    } else {
      foldedDoc = JSON.parse(raw);
      const artifacts =
        (foldedDoc as { folded_artifacts?: unknown }).folded_artifacts ??
        foldedDoc;
      const proofBundle = artifacts as {
        dkg_aggregator?: { proof_hex?: string; public_inputs_hex?: string };
        decryption_aggregator?: {
          proof_hex?: string;
          public_inputs_hex?: string;
        };
      };
      dkgProofHex = proofBundle?.dkg_aggregator?.proof_hex;
      dkgPublicHex = proofBundle?.dkg_aggregator?.public_inputs_hex;
      decProofHex = proofBundle?.decryption_aggregator?.proof_hex;
      decPublicHex = proofBundle?.decryption_aggregator?.public_inputs_hex;
    }
  } else {
    const dkgRaw = findRawJson(rawDir, "threshold_pk_aggregation");
    const decRaw = findRawJson(
      rawDir,
      "threshold_decrypted_shares_aggregation",
    );
    dkgProofHex = dkgRaw?.proof_generation?.proof_hex;
    dkgPublicHex = dkgRaw?.verification?.public_inputs_hex;
    decProofHex = decRaw?.proof_generation?.proof_hex;
    decPublicHex = decRaw?.verification?.public_inputs_hex;
  }

  if (!dkgProofHex || !dkgPublicHex || !decProofHex || !decPublicHex) {
    const missing = [
      !dkgProofHex && "dkg proof",
      !dkgPublicHex && "dkg public inputs",
      !decProofHex && "decryption proof",
      !decPublicHex && "decryption public inputs",
    ]
      .filter(Boolean)
      .join(", ");
    throw new Error(
      `[benchmarkGasFromRaw] Missing benchmark proofs (${missing}); run test_trbfv_actor successfully first. outputPath=${outputPath}`,
    );
  }

  const dkgPublicInputs = hexToBytes32Array(dkgPublicHex);
  const decPublicInputs = hexToBytes32Array(decPublicHex);
  requirePublicInputLen(
    "dkg_aggregator",
    dkgPublicInputs,
    MIN_VK_HASH_PUBLIC_INPUTS,
  );
  requirePublicInputLen(
    "decryption_aggregator",
    decPublicInputs,
    MIN_VK_HASH_PUBLIC_INPUTS,
  );

  const benchmarkConfig = resolveBenchmarkConfig(foldedDoc);
  const expectedNodesFoldKeyHash = readVkRecursiveHash(
    getBfvPkSubCircuitVkHashPaths(benchmarkConfig).nodesFold,
    benchmarkConfig,
  );
  const expectedC5KeyHash = readVkRecursiveHash(
    getBfvPkSubCircuitVkHashPaths(benchmarkConfig).c5,
    benchmarkConfig,
  );
  const expectedC6FoldKeyHash = readVkRecursiveHash(
    getBfvDecryptionSubCircuitVkHashPaths(benchmarkConfig).c6Fold,
    benchmarkConfig,
  );
  const expectedC7KeyHash = readVkRecursiveHash(
    getBfvDecryptionSubCircuitVkHashPaths(benchmarkConfig).c7,
    benchmarkConfig,
  );

  if (
    dkgPublicInputs[0] !== expectedNodesFoldKeyHash ||
    dkgPublicInputs[1] !== expectedC5KeyHash
  ) {
    throw new Error(
      "DKG aggregator proof publicInputs[0..1] do not match nodes_fold / pk_aggregation .vk_recursive_hash artifacts",
    );
  }
  if (
    decPublicInputs[0] !== expectedC6FoldKeyHash ||
    decPublicInputs[1] !== expectedC7KeyHash
  ) {
    throw new Error(
      "Decryption aggregator proof publicInputs[0..1] do not match c6_fold / decrypted_shares_aggregation .vk_recursive_hash artifacts",
    );
  }

  const abiCoder = ethers.AbiCoder.defaultAbiCoder();

  const honkDir = ensureHonkVerifierContractDir(benchmarkConfig);
  if (
    benchmarkConfig.preset !== CANONICAL_BFV_PRESET ||
    benchmarkConfig.committee !== CANONICAL_BFV_COMMITTEE
  ) {
    console.log(
      `[benchmarkGasFromRaw] Using ${benchmarkConfig.preset}/${benchmarkConfig.committee} Honk verifiers for this benchmark.`,
    );
  }

  const dkgAggAddress = await deployHonkAggregator(
    ethers,
    honkDir,
    "DkgAggregatorVerifier",
  );
  const decAggAddress = await deployHonkAggregator(
    ethers,
    honkDir,
    "DecryptionAggregatorVerifier",
  );

  const bfvPk = await (
    await ethers.getContractFactory("BfvPkVerifier")
  ).deploy(
    dkgAggAddress,
    expectedNodesFoldKeyHash,
    expectedC5KeyHash,
    benchmarkConfig.h,
  );
  await bfvPk.waitForDeployment();

  const dkgEncodedProof = abiCoder.encode(
    ["bytes", "bytes32[]"],
    [dkgProofHex, dkgPublicInputs],
  );
  requirePublicInputLen(
    "dkg_aggregator committee_hash",
    dkgPublicInputs,
    bfvDkgCommitteeHashIndices(benchmarkConfig.h).lo + 1,
  );
  const pkCommitment = dkgPublicInputs[dkgPublicInputs.length - 1];
  const dkgCommitteeHashIndices = bfvDkgCommitteeHashIndices(benchmarkConfig.h);
  const dkgCommitteeHash = committeeHashFromLimbs(
    dkgPublicInputs[dkgCommitteeHashIndices.hi],
    dkgPublicInputs[dkgCommitteeHashIndices.lo],
  );
  const dkgOk = await bfvPk.verify.staticCall(
    benchmarkE3Id,
    benchmarkCommitteeRoot,
    benchmarkSortedNodes,
    pkCommitment,
    dkgCommitteeHash,
    dkgEncodedProof,
  );
  if (!dkgOk) {
    throw new Error(
      "BfvPkVerifier.verify returned false for folded DKG proof (Honk VK / proof mismatch?)",
    );
  }
  const dkgGas = await bfvPk.verify.estimateGas(
    benchmarkE3Id,
    benchmarkCommitteeRoot,
    benchmarkSortedNodes,
    pkCommitment,
    dkgCommitteeHash,
    dkgEncodedProof,
  );

  const registry = await (
    await ethers.getContractFactory("MockCiphernodeRegistry")
  ).deploy();
  await registry.waitForDeployment();

  const bfvDec = await (
    await ethers.getContractFactory("BfvDecryptionVerifier")
  ).deploy(
    decAggAddress,
    await registry.getAddress(),
    expectedC6FoldKeyHash,
    expectedC7KeyHash,
    benchmarkConfig.t,
  );
  await bfvDec.waitForDeployment();

  const partyOffsets = bfvDecPartyColOffsets(benchmarkConfig.t);
  const registryPartyIds: bigint[] = [];
  const skCommits: string[] = [];
  const esmCommits: string[] = [];
  for (let i = 0; i < benchmarkConfig.t + 1; i++) {
    registryPartyIds.push(
      BigInt(decPublicInputs[partyOffsets.partyId + i]) - 1n,
    );
    skCommits.push(decPublicInputs[partyOffsets.sk + i]);
    esmCommits.push(decPublicInputs[partyOffsets.esm + i]);
  }
  await registry.setDkgAnchors(
    benchmarkE3Id,
    registryPartyIds,
    skCommits,
    esmCommits,
  );

  const decEncodedProof = abiCoder.encode(
    ["bytes", "bytes32[]"],
    [decProofHex, decPublicInputs],
  );
  const plaintextHash = plaintextHashFromPublicInputs(decPublicInputs, ethers);
  requirePublicInputLen(
    "decryption_aggregator committee_hash",
    decPublicInputs,
    DEC_COMMITTEE_HASH_IDX.lo + 1,
  );
  const decCommitteeHash = committeeHashFromLimbs(
    decPublicInputs[DEC_COMMITTEE_HASH_IDX.hi],
    decPublicInputs[DEC_COMMITTEE_HASH_IDX.lo],
  );
  const decDomain = committeeHashFromLimbs(
    decPublicInputs[DEC_DOMAIN_IDX.hi],
    decPublicInputs[DEC_DOMAIN_IDX.lo],
  );
  const decCiphertextCommitment =
    decPublicInputs[bfvDecCiphertextCommitmentIndex()];
  const decOk = await bfvDec.verify.staticCall(
    benchmarkE3Id,
    decDomain,
    plaintextHash,
    decCommitteeHash,
    decCiphertextCommitment,
    decEncodedProof,
  );
  if (!decOk) {
    throw new Error(
      "BfvDecryptionVerifier.verify returned false for folded decryption proof (Honk VK / proof mismatch?)",
    );
  }
  const decGas = await bfvDec.verify.estimateGas(
    benchmarkE3Id,
    decDomain,
    plaintextHash,
    decCommitteeHash,
    decCiphertextCommitment,
    decEncodedProof,
  );

  const output = {
    verify_gas: {
      dkg: Number(dkgGas),
      dec: Number(decGas),
    },
    source: "benchmark_raw_artifacts",
    bfv_preset: benchmarkConfig.preset,
    bfv_committee: benchmarkConfig.committee,
  };
  fs.writeFileSync(outputPath, JSON.stringify(output, null, 2));
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
