// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
import { expect } from "chai";
import { network } from "hardhat";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import MockCiphernodeRegistryModule from "../ignition/modules/mockCiphernodeRegistry";
import {
  BFV_DKG_H,
  BFV_THRESHOLD_T,
  assertBfvDecryptionVerifierSubCircuitVkHashes,
  assertBfvPkVerifierSubCircuitVkHashes,
  bfvDecCiphertextCommitmentIndex,
  bfvDecCommitteeHashIndices,
  bfvDecDomainIndices,
  bfvDecExpectedPublicInputsLen,
  bfvDecPartyColOffsets,
  bfvDkgCommitteeHashIndices,
  bfvPkExpectedPublicInputsLen,
  committeeHashFromLimbs,
  getBfvDecryptionSubCircuitVkHashPaths,
  getBfvPkSubCircuitVkHashPaths,
  readVkRecursiveHash,
} from "../scripts/utils";
import type {
  BfvDecryptionVerifier,
  BfvPkVerifier,
  MockCiphernodeRegistry,
} from "../types";

const { ethers, ignition, networkHelpers } = await network.connect();
const { loadFixture } = networkHelpers;

const testDir = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.join(testDir, "../../..");
const COMMITTED_FOLDED_ARTIFACTS_FIXTURE = path.join(
  testDir,
  "fixtures/bfv_vk_binding/folded_artifacts.json",
);
const INSECURE_INTEGRATION_SUMMARY = path.join(
  repoRoot,
  "circuits/benchmarks/results_insecure_minimum/integration_summary.json",
);

type FoldedArtifacts = {
  dkg_aggregator: { proof_hex: string; public_inputs_hex: string };
  decryption_aggregator: { proof_hex: string; public_inputs_hex: string };
};

const isValidFoldedArtifacts = (value: unknown): value is FoldedArtifacts => {
  if (value === null || typeof value !== "object") {
    return false;
  }
  const folded = value as FoldedArtifacts;
  return (
    typeof folded.dkg_aggregator?.proof_hex === "string" &&
    typeof folded.dkg_aggregator?.public_inputs_hex === "string" &&
    typeof folded.decryption_aggregator?.proof_hex === "string" &&
    typeof folded.decryption_aggregator?.public_inputs_hex === "string"
  );
};

const readFoldedArtifactsFromFile = (
  filePath: string,
): FoldedArtifacts | null => {
  if (!fs.existsSync(filePath)) {
    return null;
  }
  const parsed: unknown = JSON.parse(fs.readFileSync(filePath, "utf8"));
  if (filePath.endsWith("integration_summary.json")) {
    const summary = parsed as { folded_artifacts?: unknown };
    return isValidFoldedArtifacts(summary.folded_artifacts)
      ? summary.folded_artifacts
      : null;
  }
  return isValidFoldedArtifacts(parsed) ? parsed : null;
};

/** Prefer env override, then fresh insecure benchmark output, then committed fixture. */
const resolveFoldedArtifacts = (): FoldedArtifacts | null => {
  const envPath = process.env.BFV_VK_BINDING_FOLDED_ARTIFACTS;
  if (envPath) {
    return readFoldedArtifactsFromFile(envPath);
  }
  const fromBenchmark = readFoldedArtifactsFromFile(
    INSECURE_INTEGRATION_SUMMARY,
  );
  if (fromBenchmark !== null) {
    return fromBenchmark;
  }
  return readFoldedArtifactsFromFile(COMMITTED_FOLDED_ARTIFACTS_FIXTURE);
};

const loadFoldedArtifacts = (): FoldedArtifacts | null =>
  resolveFoldedArtifacts();

const hasCompiledVkArtifacts = (): boolean =>
  Object.values(getBfvPkSubCircuitVkHashPaths()).every((p) =>
    fs.existsSync(p),
  ) &&
  Object.values(getBfvDecryptionSubCircuitVkHashPaths()).every((p) =>
    fs.existsSync(p),
  );

const describeDeployTimeVkChecks = hasCompiledVkArtifacts()
  ? describe
  : describe.skip;

function hexToBytes32Array(hex: string): string[] {
  const clean = hex.startsWith("0x") ? hex.slice(2) : hex;
  const out: string[] = [];
  for (let i = 0; i < clean.length; i += 64) {
    out.push(`0x${clean.slice(i, i + 64)}`);
  }
  return out;
}

const DKG_COMMITTEE_HASH_IDX = bfvDkgCommitteeHashIndices(BFV_DKG_H);
const DKG_EXPECTED_PUBLIC_INPUT_LEN = bfvPkExpectedPublicInputsLen(BFV_DKG_H);
const DEC_COMMITTEE_HASH_IDX = bfvDecCommitteeHashIndices();
const DEC_DOMAIN_IDX = bfvDecDomainIndices();
const DEC_EXPECTED_PUBLIC_INPUT_LEN =
  bfvDecExpectedPublicInputsLen(BFV_THRESHOLD_T);

/** Headroom for Honk `verify` staticCalls (much higher under `--coverage`). */
const HONK_VERIFY_GAS_LIMIT = 1_000_000_000n;

const isCoverageRun = process.argv.includes("--coverage");

function plaintextHashFromPublicInputs(publicInputs: string[]): string {
  const messageCoeffsCount = 100;
  const offset = publicInputs.length - messageCoeffsCount;
  const plaintext = new Uint8Array(messageCoeffsCount * 8);
  for (let i = 0; i < messageCoeffsCount; i++) {
    const coeff = BigInt(publicInputs[offset + i]);
    for (let j = 0; j < 8; j++) {
      plaintext[i * 8 + j] = Number((coeff >> BigInt(j * 8)) & 0xffn);
    }
  }
  return ethers.keccak256(plaintext);
}

describe("BfvVkBindingIntegration", function () {
  const deployHonkAndBfv = async () => {
    const { mockCiphernodeRegistry } = await ignition.deploy(
      MockCiphernodeRegistryModule,
    );
    const registryAddr = await mockCiphernodeRegistry.getAddress();

    const libFactory = await ethers.getContractFactory(
      "contracts/verifiers/bfv/honk/DkgAggregatorVerifier.sol:ZKTranscriptLib",
    );
    const zkTranscriptLib = await libFactory.deploy();
    await zkTranscriptLib.waitForDeployment();
    const zkTranscriptLibAddress = await zkTranscriptLib.getAddress();

    const dkgRelationsLibFactory = await ethers.getContractFactory(
      "contracts/verifiers/bfv/honk/DkgAggregatorVerifier.sol:RelationsLib",
    );
    const dkgRelationsLib = await dkgRelationsLibFactory.deploy();
    await dkgRelationsLib.waitForDeployment();
    const dkgRelationsLibAddress = await dkgRelationsLib.getAddress();

    const decRelationsLibFactory = await ethers.getContractFactory(
      "contracts/verifiers/bfv/honk/DecryptionAggregatorVerifier.sol:RelationsLib",
    );
    const decRelationsLib = await decRelationsLibFactory.deploy();
    await decRelationsLib.waitForDeployment();
    const decRelationsLibAddress = await decRelationsLib.getAddress();

    const dkgAggFactory = await ethers.getContractFactory(
      "contracts/verifiers/bfv/honk/DkgAggregatorVerifier.sol:DkgAggregatorVerifier",
      {
        libraries: {
          "project/contracts/verifiers/bfv/honk/DkgAggregatorVerifier.sol:ZKTranscriptLib":
            zkTranscriptLibAddress,
          "project/contracts/verifiers/bfv/honk/DkgAggregatorVerifier.sol:RelationsLib":
            dkgRelationsLibAddress,
        },
      },
    );
    const dkgAgg = await dkgAggFactory.deploy();
    await dkgAgg.waitForDeployment();

    const decAggFactory = await ethers.getContractFactory(
      "contracts/verifiers/bfv/honk/DecryptionAggregatorVerifier.sol:DecryptionAggregatorVerifier",
      {
        libraries: {
          "project/contracts/verifiers/bfv/honk/DecryptionAggregatorVerifier.sol:ZKTranscriptLib":
            zkTranscriptLibAddress,
          "project/contracts/verifiers/bfv/honk/DecryptionAggregatorVerifier.sol:RelationsLib":
            decRelationsLibAddress,
        },
      },
    );
    const decAgg = await decAggFactory.deploy();
    await decAgg.waitForDeployment();

    const expectedNodesFoldKeyHash = readVkRecursiveHash(
      getBfvPkSubCircuitVkHashPaths().nodesFold,
    );
    const expectedC5KeyHash = readVkRecursiveHash(
      getBfvPkSubCircuitVkHashPaths().c5,
    );
    const expectedSkC2ChunkKeyHash = readVkRecursiveHash(
      getBfvPkSubCircuitVkHashPaths().skC2Chunk,
    );
    const expectedESmC2ChunkKeyHash = readVkRecursiveHash(
      getBfvPkSubCircuitVkHashPaths().esmC2Chunk,
    );
    const expectedC6FoldKeyHash = readVkRecursiveHash(
      getBfvDecryptionSubCircuitVkHashPaths().c6Fold,
    );
    const expectedC7KeyHash = readVkRecursiveHash(
      getBfvDecryptionSubCircuitVkHashPaths().c7,
    );

    const bfvPk = await (
      await ethers.getContractFactory("BfvPkVerifier")
    ).deploy(
      await dkgAgg.getAddress(),
      expectedNodesFoldKeyHash,
      expectedC5KeyHash,
      expectedSkC2ChunkKeyHash,
      expectedESmC2ChunkKeyHash,
      BFV_DKG_H,
    );
    await bfvPk.waitForDeployment();

    const bfvDec = await (
      await ethers.getContractFactory("BfvDecryptionVerifier")
    ).deploy(
      await decAgg.getAddress(),
      registryAddr,
      expectedC6FoldKeyHash,
      expectedC7KeyHash,
      BFV_THRESHOLD_T,
    );
    await bfvDec.waitForDeployment();

    return {
      bfvPk: bfvPk as unknown as BfvPkVerifier,
      bfvDec: bfvDec as unknown as BfvDecryptionVerifier,
      mockCiphernodeRegistry:
        mockCiphernodeRegistry as unknown as MockCiphernodeRegistry,
    };
  };

  describeDeployTimeVkChecks("deploy-time VK staleness checks", function () {
    it("rejects BfvPkVerifier with stale immutables", async function () {
      const { bfvPk } = await loadFixture(deployHonkAndBfv);
      const address = await bfvPk.getAddress();
      const stale = await (
        await ethers.getContractFactory("BfvPkVerifier")
      ).deploy(
        await bfvPk.circuitVerifier(),
        ethers.id("stale-nodes-fold"),
        ethers.id("stale-c5"),
        readVkRecursiveHash(getBfvPkSubCircuitVkHashPaths().skC2Chunk),
        readVkRecursiveHash(getBfvPkSubCircuitVkHashPaths().esmC2Chunk),
        BFV_DKG_H,
      );
      await stale.waitForDeployment();

      await expect(
        assertBfvPkVerifierSubCircuitVkHashes(
          stale as unknown as BfvPkVerifier,
          await stale.getAddress(),
        ),
      ).to.be.rejectedWith(/stale sub-circuit VK immutables/);

      await expect(assertBfvPkVerifierSubCircuitVkHashes(bfvPk, address)).to.not
        .be.rejected;
    });

    it("rejects BfvDecryptionVerifier with stale immutables", async function () {
      const { bfvDec } = await loadFixture(deployHonkAndBfv);
      const address = await bfvDec.getAddress();
      const stale = await (
        await ethers.getContractFactory("BfvDecryptionVerifier")
      ).deploy(
        await bfvDec.circuitVerifier(),
        await bfvDec.ciphernodeRegistry(),
        ethers.id("stale-c6"),
        ethers.id("stale-c7"),
        BFV_THRESHOLD_T,
      );
      await stale.waitForDeployment();

      await expect(
        assertBfvDecryptionVerifierSubCircuitVkHashes(
          stale as unknown as BfvDecryptionVerifier,
          await stale.getAddress(),
        ),
      ).to.be.rejectedWith(/stale sub-circuit VK immutables/);

      await expect(
        assertBfvDecryptionVerifierSubCircuitVkHashes(bfvDec, address),
      ).to.not.be.rejected;
    });
  });

  const runFoldedProofIntegration =
    loadFoldedArtifacts() !== null && hasCompiledVkArtifacts();

  (runFoldedProofIntegration ? it : it.skip)(
    "folded aggregator proofs: artifact VK hashes match publicInputs[0..1] and verify passes",
    async function () {
      this.timeout(120_000);

      const folded = loadFoldedArtifacts();
      if (folded === null) {
        this.skip();
      }

      const dkgPublicInputs = hexToBytes32Array(
        folded.dkg_aggregator.public_inputs_hex,
      );
      const decPublicInputs = hexToBytes32Array(
        folded.decryption_aggregator.public_inputs_hex,
      );
      if (
        dkgPublicInputs.length !== DKG_EXPECTED_PUBLIC_INPUT_LEN ||
        decPublicInputs.length !== DEC_EXPECTED_PUBLIC_INPUT_LEN
      ) {
        console.warn(
          "Skipping folded proof verify: folded artifact public-input layout is stale. " +
            "Re-run insecure benchmarks (syncs test/fixtures/bfv_vk_binding/folded_artifacts.json) " +
            "or set BFV_VK_BINDING_FOLDED_ARTIFACTS.",
        );
        this.skip();
      }

      const expectedNodesFoldKeyHash = readVkRecursiveHash(
        getBfvPkSubCircuitVkHashPaths().nodesFold,
      );
      const expectedC5KeyHash = readVkRecursiveHash(
        getBfvPkSubCircuitVkHashPaths().c5,
      );
      const expectedSkC2ChunkKeyHash = readVkRecursiveHash(
        getBfvPkSubCircuitVkHashPaths().skC2Chunk,
      );
      const expectedESmC2ChunkKeyHash = readVkRecursiveHash(
        getBfvPkSubCircuitVkHashPaths().esmC2Chunk,
      );
      const expectedC6FoldKeyHash = readVkRecursiveHash(
        getBfvDecryptionSubCircuitVkHashPaths().c6Fold,
      );
      const expectedC7KeyHash = readVkRecursiveHash(
        getBfvDecryptionSubCircuitVkHashPaths().c7,
      );

      expect(dkgPublicInputs[0]).to.equal(expectedNodesFoldKeyHash);
      expect(dkgPublicInputs[1]).to.equal(expectedC5KeyHash);
      expect(dkgPublicInputs[5 + BFV_DKG_H]).to.equal(expectedSkC2ChunkKeyHash);
      expect(dkgPublicInputs[6 + BFV_DKG_H]).to.equal(
        expectedESmC2ChunkKeyHash,
      );
      expect(decPublicInputs[0]).to.equal(expectedC6FoldKeyHash);
      expect(decPublicInputs[1]).to.equal(expectedC7KeyHash);

      const dkgCommitteeHash = committeeHashFromLimbs(
        dkgPublicInputs[DKG_COMMITTEE_HASH_IDX.hi],
        dkgPublicInputs[DKG_COMMITTEE_HASH_IDX.lo],
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

      if (isCoverageRun) {
        // Instrumented Honk verifiers can exceed any practical eth_call budget;
        // VK hash binding is asserted above — skip the expensive on-chain verify.
        return;
      }

      await networkHelpers.setBlockGasLimit(HONK_VERIFY_GAS_LIMIT);

      const { bfvPk, bfvDec, mockCiphernodeRegistry } =
        await deployHonkAndBfv();
      const [testSigner] = await ethers.getSigners();
      const testE3Id = 1n;
      const testRoot = BigInt(ethers.id("test-root"));
      const abiCoder = ethers.AbiCoder.defaultAbiCoder();
      const verifyOverrides = { gasLimit: HONK_VERIFY_GAS_LIMIT };

      // Derive DKG anchors straight from the real folded proof's own public inputs
      // (circuit-side party_ids are 1-indexed; registry-side are 0-indexed) so the
      // new cross-phase sk/esm binding check passes for this genuine proof.
      const {
        partyId: partyIdOffset,
        sk: skOffset,
        esm: esmOffset,
      } = bfvDecPartyColOffsets(BFV_THRESHOLD_T);
      const registryPartyIds: bigint[] = [];
      const skCommits: string[] = [];
      const esmCommits: string[] = [];
      for (let i = 0; i < BFV_THRESHOLD_T + 1; i++) {
        registryPartyIds.push(BigInt(decPublicInputs[partyIdOffset + i]) - 1n);
        skCommits.push(decPublicInputs[skOffset + i]);
        esmCommits.push(decPublicInputs[esmOffset + i]);
      }
      await mockCiphernodeRegistry.setDkgAnchors(
        testE3Id,
        registryPartyIds,
        skCommits,
        esmCommits,
      );

      const dkgEncoded = abiCoder.encode(
        ["bytes", "bytes32[]"],
        [folded.dkg_aggregator.proof_hex, dkgPublicInputs],
      );
      const pkCommitment = dkgPublicInputs[dkgPublicInputs.length - 1];
      expect(
        await bfvPk.verify.staticCall(
          testE3Id,
          testRoot,
          [testSigner.address],
          pkCommitment,
          dkgCommitteeHash,
          dkgEncoded,
          verifyOverrides,
        ),
      ).to.equal(true);

      const decEncoded = abiCoder.encode(
        ["bytes", "bytes32[]"],
        [folded.decryption_aggregator.proof_hex, decPublicInputs],
      );
      const plaintextHash = plaintextHashFromPublicInputs(decPublicInputs);
      expect(
        await bfvDec.verify.staticCall(
          testE3Id,
          decDomain,
          plaintextHash,
          decCommitteeHash,
          decCiphertextCommitment,
          decEncoded,
          verifyOverrides,
        ),
      ).to.equal(true);

      await expect(
        bfvDec.verify.staticCall(
          testE3Id,
          ethers.id("different-e3-domain"),
          plaintextHash,
          decCommitteeHash,
          decCiphertextCommitment,
          decEncoded,
          verifyOverrides,
        ),
      ).to.be.revertedWithCustomError(bfvDec, "DomainBindingMismatch");
    },
  );

  (runFoldedProofIntegration ? it : it.skip)(
    "rejects verify when expectedNodesFoldKeyHash is wrong by one byte",
    async function () {
      this.timeout(120_000);

      const folded = loadFoldedArtifacts();
      if (folded === null) {
        this.skip();
      }
      const [testSigner] = await ethers.getSigners();

      const dkgPublicInputs = hexToBytes32Array(
        folded.dkg_aggregator.public_inputs_hex,
      );
      if (dkgPublicInputs.length !== bfvPkExpectedPublicInputsLen(BFV_DKG_H)) {
        this.skip();
      }
      const expectedC5KeyHash = readVkRecursiveHash(
        getBfvPkSubCircuitVkHashPaths().c5,
      );

      const libFactory = await ethers.getContractFactory(
        "contracts/verifiers/bfv/honk/DkgAggregatorVerifier.sol:ZKTranscriptLib",
      );
      const zkTranscriptLib = await libFactory.deploy();
      await zkTranscriptLib.waitForDeployment();
      const relationsLibFactory = await ethers.getContractFactory(
        "contracts/verifiers/bfv/honk/DkgAggregatorVerifier.sol:RelationsLib",
      );
      const relationsLib = await relationsLibFactory.deploy();
      await relationsLib.waitForDeployment();

      const dkgAgg = await (
        await ethers.getContractFactory(
          "contracts/verifiers/bfv/honk/DkgAggregatorVerifier.sol:DkgAggregatorVerifier",
          {
            libraries: {
              "project/contracts/verifiers/bfv/honk/DkgAggregatorVerifier.sol:ZKTranscriptLib":
                await zkTranscriptLib.getAddress(),
              "project/contracts/verifiers/bfv/honk/DkgAggregatorVerifier.sol:RelationsLib":
                await relationsLib.getAddress(),
            },
          },
        )
      ).deploy();
      await dkgAgg.waitForDeployment();

      const nodesFoldBuf = Buffer.from(dkgPublicInputs[0].slice(2), "hex");
      nodesFoldBuf[0] ^= 0xff;
      const wrongNodesFold = `0x${nodesFoldBuf.toString("hex")}`;

      const bfvPk = await (
        await ethers.getContractFactory("BfvPkVerifier")
      ).deploy(
        await dkgAgg.getAddress(),
        wrongNodesFold,
        expectedC5KeyHash,
        readVkRecursiveHash(getBfvPkSubCircuitVkHashPaths().skC2Chunk),
        readVkRecursiveHash(getBfvPkSubCircuitVkHashPaths().esmC2Chunk),
        BFV_DKG_H,
      );
      await bfvPk.waitForDeployment();

      const abiCoder = ethers.AbiCoder.defaultAbiCoder();
      const dkgEncoded = abiCoder.encode(
        ["bytes", "bytes32[]"],
        [folded.dkg_aggregator.proof_hex, dkgPublicInputs],
      );
      const pkCommitment = dkgPublicInputs[dkgPublicInputs.length - 1];
      const dkgCommitteeHash = committeeHashFromLimbs(
        dkgPublicInputs[DKG_COMMITTEE_HASH_IDX.hi],
        dkgPublicInputs[DKG_COMMITTEE_HASH_IDX.lo],
      );

      await expect(
        bfvPk.verify.staticCall(
          1n,
          BigInt(ethers.id("test-root")),
          [testSigner.address],
          pkCommitment,
          dkgCommitteeHash,
          dkgEncoded,
        ),
      ).to.be.revertedWithCustomError(bfvPk, "VkHashMismatch");
    },
  );
});
