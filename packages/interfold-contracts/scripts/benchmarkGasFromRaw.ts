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
  BFV_DECRYPTION_SUB_CIRCUIT_VK_HASH_PATHS,
  BFV_DKG_H,
  BFV_PK_SUB_CIRCUIT_VK_HASH_PATHS,
  BFV_THRESHOLD_T,
  REPO_ROOT,
  bfvDecCommitteeHashIndices,
  bfvDkgCommitteeHashIndices,
  committeeHashFromLimbs,
  readVkRecursiveHash,
} from "./utils";

const CANONICAL_BFV_PRESET = "insecure-512";
const COMMITTED_HONK_DIR = path.join(
  REPO_ROOT,
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
  const activePath = path.join(REPO_ROOT, "circuits/bin/.active-preset.json");
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

/**
 * Committed Honk `.sol` files embed the insecure-512 aggregator VK. Secure benchmark
 * proofs need verifiers generated from the active circuits/bin preset.
 */
function ensureHonkVerifierContractDir(preset: string): string {
  if (preset === CANONICAL_BFV_PRESET) {
    return COMMITTED_HONK_DIR;
  }
  const benchDir = path.join(COMMITTED_HONK_DIR, ".benchmark", preset);
  fs.mkdirSync(benchDir, { recursive: true });
  console.log(
    `[benchmarkGasFromRaw] Generating ${preset} Honk verifiers into ${benchDir}...`,
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
      preset,
      "--output-dir",
      benchDir,
    ],
    { cwd: REPO_ROOT, stdio: "inherit" },
  );
  // Hardhat does not pick up freshly written .sol under honk/.benchmark/ until compile.
  execFileSync("pnpm", ["hardhat", "compile"], {
    cwd: path.join(REPO_ROOT, "packages/interfold-contracts"),
    stdio: "inherit",
  });
  return benchDir;
}

/** Hardhat `project/` source path for a generated Honk verifier file. */
function honkContractSource(honkDir: string, name: string): string {
  const rel = path.relative(
    path.join(REPO_ROOT, "packages/interfold-contracts"),
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
  const libKey = `project/${solSource}:ZKTranscriptLib`;
  const libFactory = await ethersLib.getContractFactory(
    `${solSource}:ZKTranscriptLib`,
  );
  const lib = await libFactory.deploy();
  await lib.waitForDeployment();
  const libAddress = await lib.getAddress();

  const aggFactory = await ethersLib.getContractFactory(
    `${solSource}:${contractName}`,
    {
      libraries: {
        [libKey]: libAddress,
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
const DKG_COMMITTEE_HASH_IDX = bfvDkgCommitteeHashIndices(BFV_DKG_H);
const DEC_COMMITTEE_HASH_IDX = bfvDecCommitteeHashIndices();

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
  // e3Id / committeeRoot / sortedNodes are forward-compat params; wrappers do not
  // bind them yet (see BfvPkVerifier / BfvDecryptionVerifier). Any fixed values
  // yield representative verify gas for the Honk + wrapper path.
  const benchmarkE3Id = 1n;
  const benchmarkCommitteeRoot = BigInt(
    ethers.id("benchmark-gas-committee-root"),
  );
  const benchmarkSortedNodes = [benchmarkSigner.address];
  const benchmarkCiphertextHash = ethers.ZeroHash;
  const benchmarkCommitteePublicKey = ethers.ZeroHash;

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

  const expectedNodesFoldKeyHash = readVkRecursiveHash(
    BFV_PK_SUB_CIRCUIT_VK_HASH_PATHS.nodesFold,
  );
  const expectedC5KeyHash = readVkRecursiveHash(
    BFV_PK_SUB_CIRCUIT_VK_HASH_PATHS.c5,
  );
  const expectedC6FoldKeyHash = readVkRecursiveHash(
    BFV_DECRYPTION_SUB_CIRCUIT_VK_HASH_PATHS.c6Fold,
  );
  const expectedC7KeyHash = readVkRecursiveHash(
    BFV_DECRYPTION_SUB_CIRCUIT_VK_HASH_PATHS.c7,
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

  const benchmarkPreset = readBenchmarkPreset(foldedDoc);
  const honkDir = ensureHonkVerifierContractDir(benchmarkPreset);
  if (benchmarkPreset !== CANONICAL_BFV_PRESET) {
    console.log(
      `[benchmarkGasFromRaw] Using preset ${benchmarkPreset} Honk verifiers (not committed insecure-512 .sol).`,
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
    BFV_DKG_H,
  );
  await bfvPk.waitForDeployment();

  const dkgEncodedProof = abiCoder.encode(
    ["bytes", "bytes32[]"],
    [dkgProofHex, dkgPublicInputs],
  );
  requirePublicInputLen(
    "dkg_aggregator committee_hash",
    dkgPublicInputs,
    DKG_COMMITTEE_HASH_IDX.lo + 1,
  );
  const pkCommitment = dkgPublicInputs[dkgPublicInputs.length - 1];
  const dkgCommitteeHash = committeeHashFromLimbs(
    dkgPublicInputs[DKG_COMMITTEE_HASH_IDX.hi],
    dkgPublicInputs[DKG_COMMITTEE_HASH_IDX.lo],
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

  const bfvDec = await (
    await ethers.getContractFactory("BfvDecryptionVerifier")
  ).deploy(
    decAggAddress,
    expectedC6FoldKeyHash,
    expectedC7KeyHash,
    BFV_THRESHOLD_T,
  );
  await bfvDec.waitForDeployment();

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
  const decOk = await bfvDec.verify.staticCall(
    benchmarkE3Id,
    benchmarkCommitteeRoot,
    benchmarkSortedNodes,
    benchmarkCiphertextHash,
    benchmarkCommitteePublicKey,
    plaintextHash,
    decCommitteeHash,
    decEncodedProof,
  );
  if (!decOk) {
    throw new Error(
      "BfvDecryptionVerifier.verify returned false for folded decryption proof (Honk VK / proof mismatch?)",
    );
  }
  const decGas = await bfvDec.verify.estimateGas(
    benchmarkE3Id,
    benchmarkCommitteeRoot,
    benchmarkSortedNodes,
    benchmarkCiphertextHash,
    benchmarkCommitteePublicKey,
    plaintextHash,
    decCommitteeHash,
    decEncodedProof,
  );

  const output = {
    verify_gas: {
      dkg: Number(dkgGas),
      dec: Number(decGas),
    },
    source: "benchmark_raw_artifacts",
    bfv_preset: benchmarkPreset,
  };
  fs.writeFileSync(outputPath, JSON.stringify(output, null, 2));
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
