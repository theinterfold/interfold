// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
import { expect } from "chai";
import { network } from "hardhat";

import MockCiphernodeRegistryModule from "../ignition/modules/mockCiphernodeRegistry";
import MockCircuitVerifierModule from "../ignition/modules/mockSlashingVerifier";
import {
  BFV_THRESHOLD_T,
  bfvDecExpectedPublicInputsLen,
  bfvDecPartyColOffsets,
} from "../scripts/utils";
import {
  BfvDecryptionVerifier__factory as BfvDecryptionVerifierFactory,
  MockCiphernodeRegistry__factory as MockCiphernodeRegistryFactory,
  MockCircuitVerifier__factory as MockCircuitVerifierFactory,
} from "../types";

const { ethers, ignition, networkHelpers } = await network.connect();
const { loadFixture } = networkHelpers;
const [testSigner] = await ethers.getSigners();

/** Must match `BfvDecryptionVerifier.MESSAGE_COEFFS_COUNT` / circuit `MAX_MSG_NON_ZERO_COEFFS`. */
const MESSAGE_COEFFS_COUNT = 100;
const BN254_SCALAR_MODULUS =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

function fieldHash(label: string): string {
  return ethers.toBeHex(BigInt(ethers.id(label)) % BN254_SCALAR_MODULUS, 32);
}

const EXPECTED_C6_FOLD_KEY_HASH = fieldHash("c6_fold");
const EXPECTED_C7_KEY_HASH = fieldHash("c7");
const DECRYPTION_DOMAIN = ethers.id("e3-decryption-domain");
const CIPHERTEXT_COMMITMENT = fieldHash("ciphertext-commitment");

/** Must match `BfvDecryptionVerifier.threshold` / default circuit `T`. */
const THRESHOLD = BFV_THRESHOLD_T;

/** Exact `publicInputs.length` for the configured threshold. */
const EXPECTED_PUBLIC_INPUTS_LEN = bfvDecExpectedPublicInputsLen(THRESHOLD);

/** Indices for committee hash limbs (fixed layout). */
const COMMITTEE_HASH_HI_IDX = 2;
const COMMITTEE_HASH_LO_IDX = 3;
const DECRYPTION_DOMAIN_HI_IDX = 4;
const DECRYPTION_DOMAIN_LO_IDX = 5;

/** `party_ids`/`expected_sk`/`expected_esm` column start indices for `THRESHOLD`. */
const {
  partyId: PARTY_ID_COL_OFFSET,
  sk: SK_COL_OFFSET,
  esm: ESM_COL_OFFSET,
} = bfvDecPartyColOffsets(THRESHOLD);

/**
 * Default DKG anchors for `THRESHOLD + 1` reconstructing parties, consistent across
 * circuit-side (1-indexed) and registry-side (0-indexed) party id conventions.
 */
const DEFAULT_REGISTRY_PARTY_IDS = Array.from(
  { length: THRESHOLD + 1 },
  (_, i) => i,
); // 0-indexed, matches `dkgPartyIds`/`topNodes`
const DEFAULT_CIRCUIT_PARTY_IDS = DEFAULT_REGISTRY_PARTY_IDS.map(
  (id) => id + 1,
); // 1-indexed Shamir x-coordinates, as emitted by `decryption_aggregator`
const DEFAULT_SK_COMMITS = DEFAULT_REGISTRY_PARTY_IDS.map((id) =>
  fieldHash(`sk-${id}`),
);
const DEFAULT_ESM_COMMITS = DEFAULT_REGISTRY_PARTY_IDS.map((id) =>
  fieldHash(`esm-${id}`),
);

function committeeHashHi(committeeHash: string): string {
  const v = BigInt(committeeHash);
  return "0x" + (v >> 128n).toString(16).padStart(64, "0");
}

function committeeHashLo(committeeHash: string): string {
  const mask = (1n << 128n) - 1n;
  const v = BigInt(committeeHash);
  return "0x" + (v & mask).toString(16).padStart(64, "0");
}

function buildPublicInputsWithMessage(
  messageCoeffs: bigint[],
  totalInputs = EXPECTED_PUBLIC_INPUTS_LEN,
  subCircuitHashes: [string, string] = [
    EXPECTED_C6_FOLD_KEY_HASH,
    EXPECTED_C7_KEY_HASH,
  ],
  committeeHash = ethers.ZeroHash,
  // Circuit-side (1-indexed) party_ids and their sk/esm commitments. Defaults
  // match `DEFAULT_REGISTRY_PARTY_IDS`'s anchors as configured by `deployWithMockCircuit`,
  // so tests unrelated to DKG-anchor binding pass that check transparently.
  partyIds: bigint[] = DEFAULT_CIRCUIT_PARTY_IDS.map(BigInt),
  skCommits: string[] = DEFAULT_SK_COMMITS,
  esmCommits: string[] = DEFAULT_ESM_COMMITS,
  decryptionDomain = DECRYPTION_DOMAIN,
): string[] {
  const arr: string[] = new Array(totalInputs);
  arr[0] = subCircuitHashes[0];
  arr[1] = subCircuitHashes[1];
  for (let i = 2; i < totalInputs; i++) {
    arr[i] = "0x" + "00".repeat(32);
  }
  arr[COMMITTEE_HASH_HI_IDX] = committeeHashHi(committeeHash);
  arr[COMMITTEE_HASH_LO_IDX] = committeeHashLo(committeeHash);
  arr[6] = CIPHERTEXT_COMMITMENT;
  for (let i = 0; i < partyIds.length; i++) {
    arr[PARTY_ID_COL_OFFSET + i] =
      "0x" + partyIds[i].toString(16).padStart(64, "0");
  }
  for (let i = 0; i < skCommits.length; i++) {
    arr[SK_COL_OFFSET + i] = skCommits[i];
  }
  for (let i = 0; i < esmCommits.length; i++) {
    arr[ESM_COL_OFFSET + i] = esmCommits[i];
  }
  arr[DECRYPTION_DOMAIN_HI_IDX] = committeeHashHi(decryptionDomain);
  arr[DECRYPTION_DOMAIN_LO_IDX] = committeeHashLo(decryptionDomain);
  const offset = totalInputs - MESSAGE_COEFFS_COUNT;
  for (let i = 0; i < messageCoeffs.length && i < MESSAGE_COEFFS_COUNT; i++) {
    arr[offset + i] = "0x" + messageCoeffs[i].toString(16).padStart(64, "0");
  }
  return arr;
}

function plaintextToHash(messageCoeffs: bigint[]): string {
  const buf = new Uint8Array(MESSAGE_COEFFS_COUNT * 8);
  for (
    let i = 0;
    i < Math.min(messageCoeffs.length, MESSAGE_COEFFS_COUNT);
    i++
  ) {
    const c = messageCoeffs[i];
    for (let j = 0; j < 8; j++) {
      buf[i * 8 + j] = Number((c >> BigInt(j * 8)) & 0xffn);
    }
  }
  const hex =
    "0x" +
    Array.from(buf)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
  return ethers.keccak256(hex);
}

function encodeProof(rawProof: string, publicInputs: string[]): string {
  const abiCoder = ethers.AbiCoder.defaultAbiCoder();
  return abiCoder.encode(["bytes", "bytes32[]"], [rawProof, publicInputs]);
}

describe("BfvDecryptionVerifier", function () {
  const E3_ID = 7n;

  const deployWithMockCircuit = async () => {
    const [owner] = await ethers.getSigners();
    const { mockCircuitVerifier } = await ignition.deploy(
      MockCircuitVerifierModule,
    );
    const mockAddr = await mockCircuitVerifier.getAddress();

    const { mockCiphernodeRegistry } = await ignition.deploy(
      MockCiphernodeRegistryModule,
    );
    const registryAddr = await mockCiphernodeRegistry.getAddress();
    const registry = MockCiphernodeRegistryFactory.connect(registryAddr, owner);
    await registry.setDkgAnchors(
      E3_ID,
      DEFAULT_REGISTRY_PARTY_IDS,
      DEFAULT_SK_COMMITS,
      DEFAULT_ESM_COMMITS,
    );

    const bfvDecryptionVerifier = await (
      await ethers.getContractFactory("BfvDecryptionVerifier")
    ).deploy(
      mockAddr,
      registryAddr,
      EXPECTED_C6_FOLD_KEY_HASH,
      EXPECTED_C7_KEY_HASH,
      THRESHOLD,
    );

    await bfvDecryptionVerifier.waitForDeployment();
    const dv = BfvDecryptionVerifierFactory.connect(
      await bfvDecryptionVerifier.getAddress(),
      owner,
    );
    const mc = MockCircuitVerifierFactory.connect(mockAddr, owner);
    return {
      bfvDecryptionVerifier: dv,
      mockCircuit: mc,
      mockCiphernodeRegistry: registry,
    };
  };

  /** Domain supplied by Interfold after hashing the full E3 context. */
  const ctx = () => {
    return { e3Id: E3_ID, decryptionDomain: DECRYPTION_DOMAIN };
  };

  describe("reverts", function () {
    it("rejects zero, EOA, and zero-hash trust anchors at deployment", async function () {
      const factory = await ethers.getContractFactory("BfvDecryptionVerifier");
      const { mockCiphernodeRegistry } = await loadFixture(
        deployWithMockCircuit,
      );
      const registryAddress = await mockCiphernodeRegistry.getAddress();

      await expect(
        factory.deploy(
          ethers.ZeroAddress,
          registryAddress,
          EXPECTED_C6_FOLD_KEY_HASH,
          EXPECTED_C7_KEY_HASH,
          THRESHOLD,
        ),
      )
        .to.be.revertedWithCustomError(factory, "InvalidCircuitVerifier")
        .withArgs(ethers.ZeroAddress);
      await expect(
        factory.deploy(
          testSigner.address,
          registryAddress,
          EXPECTED_C6_FOLD_KEY_HASH,
          EXPECTED_C7_KEY_HASH,
          THRESHOLD,
        ),
      )
        .to.be.revertedWithCustomError(factory, "InvalidCircuitVerifier")
        .withArgs(testSigner.address);

      const { mockCircuit } = await loadFixture(deployWithMockCircuit);
      await expect(
        factory.deploy(
          await mockCircuit.getAddress(),
          registryAddress,
          ethers.ZeroHash,
          EXPECTED_C7_KEY_HASH,
          THRESHOLD,
        ),
      ).to.be.revertedWithCustomError(factory, "InvalidVerificationKeyHash");
      await expect(
        factory.deploy(
          await mockCircuit.getAddress(),
          registryAddress,
          EXPECTED_C6_FOLD_KEY_HASH,
          ethers.ZeroHash,
          THRESHOLD,
        ),
      ).to.be.revertedWithCustomError(factory, "InvalidVerificationKeyHash");
    });

    it("reverts on invalid proof encoding", async function () {
      const { bfvDecryptionVerifier } = await loadFixture(
        deployWithMockCircuit,
      );
      const { decryptionDomain } = ctx();
      const plaintextHash = ethers.keccak256("0x1234");

      await expect(
        bfvDecryptionVerifier.verify.staticCall(
          E3_ID,
          decryptionDomain,
          plaintextHash,
          ethers.ZeroHash,
          CIPHERTEXT_COMMITMENT,
          "0xdeadbeef",
        ),
      ).to.be.revert(ethers);
    });

    it("reverts InvalidPublicInputsLength when length differs from expected (M-34)", async function () {
      const { bfvDecryptionVerifier, mockCircuit } = await loadFixture(
        deployWithMockCircuit,
      );
      await mockCircuit.setReturnValue(true);
      const { decryptionDomain } = ctx();

      const messageCoeffs = [1n, 2n, 3n];
      const publicInputs = buildPublicInputsWithMessage(messageCoeffs).slice(
        0,
        EXPECTED_PUBLIC_INPUTS_LEN - 1,
      );
      const plaintextHash = plaintextToHash(messageCoeffs);
      const proof = encodeProof("0x01", publicInputs);

      await expect(
        bfvDecryptionVerifier.verify.staticCall(
          E3_ID,
          decryptionDomain,
          plaintextHash,
          ethers.ZeroHash,
          CIPHERTEXT_COMMITMENT,
          proof,
        ),
      ).to.be.revertedWithCustomError(
        bfvDecryptionVerifier,
        "InvalidPublicInputsLength",
      );
    });

    it("reverts InvalidPublicInputsLength when length exceeds expected", async function () {
      const { bfvDecryptionVerifier, mockCircuit } = await loadFixture(
        deployWithMockCircuit,
      );
      await mockCircuit.setReturnValue(true);
      const { decryptionDomain } = ctx();

      const messageCoeffs = [1n, 2n, 3n];
      const publicInputs = buildPublicInputsWithMessage(
        messageCoeffs,
        EXPECTED_PUBLIC_INPUTS_LEN + 1,
      );
      const plaintextHash = plaintextToHash(messageCoeffs);
      const proof = encodeProof("0x01", publicInputs);

      await expect(
        bfvDecryptionVerifier.verify.staticCall(
          E3_ID,
          decryptionDomain,
          plaintextHash,
          ethers.ZeroHash,
          CIPHERTEXT_COMMITMENT,
          proof,
        ),
      ).to.be.revertedWithCustomError(
        bfvDecryptionVerifier,
        "InvalidPublicInputsLength",
      );
    });

    it("rejects every in-range BN254 alias of a message coefficient", async function () {
      const { bfvDecryptionVerifier } = await loadFixture(
        deployWithMockCircuit,
      );
      const { decryptionDomain } = ctx();
      const messageOffset = EXPECTED_PUBLIC_INPUTS_LEN - MESSAGE_COEFFS_COUNT;
      const verifyAlias = (alias: bigint) => {
        const publicInputs = buildPublicInputsWithMessage([]);
        publicInputs[messageOffset] = ethers.toBeHex(alias, 32);
        return bfvDecryptionVerifier.verify.staticCall(
          E3_ID,
          decryptionDomain,
          plaintextToHash([BigInt.asUintN(64, alias)]),
          ethers.ZeroHash,
          CIPHERTEXT_COMMITMENT,
          encodeProof("0x01", publicInputs),
        );
      };

      for (let multiplier = 1n; multiplier <= 5n; multiplier++) {
        const alias = 21n + multiplier * BN254_SCALAR_MODULUS;
        await expect(verifyAlias(alias))
          .to.be.revertedWithCustomError(
            bfvDecryptionVerifier,
            "NonCanonicalPublicInput",
          )
          .withArgs(messageOffset);
      }
    });

    it("rejects a non-canonical value outside the message coefficients", async function () {
      const { bfvDecryptionVerifier } = await loadFixture(
        deployWithMockCircuit,
      );
      const { decryptionDomain } = ctx();
      const publicInputs = buildPublicInputsWithMessage([]);
      publicInputs[0] = ethers.toBeHex(BN254_SCALAR_MODULUS, 32);

      await expect(
        bfvDecryptionVerifier.verify.staticCall(
          E3_ID,
          decryptionDomain,
          plaintextToHash([]),
          ethers.ZeroHash,
          CIPHERTEXT_COMMITMENT,
          encodeProof("0x01", publicInputs),
        ),
      )
        .to.be.revertedWithCustomError(
          bfvDecryptionVerifier,
          "NonCanonicalPublicInput",
        )
        .withArgs(0);
    });

    it("reverts VkHashMismatch when c6_fold key hash does not match (M-34)", async function () {
      const { bfvDecryptionVerifier, mockCircuit } = await loadFixture(
        deployWithMockCircuit,
      );
      await mockCircuit.setReturnValue(true);
      const { decryptionDomain } = ctx();

      const messageCoeffs = [1n, 2n, 3n];
      const publicInputs = buildPublicInputsWithMessage(
        messageCoeffs,
        EXPECTED_PUBLIC_INPUTS_LEN,
        [fieldHash("wrong-c6"), EXPECTED_C7_KEY_HASH],
      );
      const plaintextHash = plaintextToHash(messageCoeffs);
      const proof = encodeProof("0x01", publicInputs);

      await expect(
        bfvDecryptionVerifier.verify.staticCall(
          E3_ID,
          decryptionDomain,
          plaintextHash,
          ethers.ZeroHash,
          CIPHERTEXT_COMMITMENT,
          proof,
        ),
      ).to.be.revertedWithCustomError(bfvDecryptionVerifier, "VkHashMismatch");
    });

    it("reverts VkHashMismatch when c7 key hash does not match (M-34)", async function () {
      const { bfvDecryptionVerifier, mockCircuit } = await loadFixture(
        deployWithMockCircuit,
      );
      await mockCircuit.setReturnValue(true);
      const { decryptionDomain } = ctx();

      const messageCoeffs = [1n, 2n, 3n];
      const publicInputs = buildPublicInputsWithMessage(
        messageCoeffs,
        EXPECTED_PUBLIC_INPUTS_LEN,
        [EXPECTED_C6_FOLD_KEY_HASH, fieldHash("wrong-c7")],
      );
      const plaintextHash = plaintextToHash(messageCoeffs);
      const proof = encodeProof("0x01", publicInputs);

      await expect(
        bfvDecryptionVerifier.verify.staticCall(
          E3_ID,
          decryptionDomain,
          plaintextHash,
          ethers.ZeroHash,
          CIPHERTEXT_COMMITMENT,
          proof,
        ),
      ).to.be.revertedWithCustomError(bfvDecryptionVerifier, "VkHashMismatch");
    });

    it("rejects an independent mismatch in either committee-hash limb (C-08)", async function () {
      const { bfvDecryptionVerifier, mockCircuit } = await loadFixture(
        deployWithMockCircuit,
      );
      await mockCircuit.setReturnValue(true);
      const { decryptionDomain } = ctx();

      const committeeHash = ethers.id("real-committee");
      const messageCoeffs = [1n, 2n, 3n];
      const publicInputs = buildPublicInputsWithMessage(
        messageCoeffs,
        EXPECTED_PUBLIC_INPUTS_LEN,
        [EXPECTED_C6_FOLD_KEY_HASH, EXPECTED_C7_KEY_HASH],
        committeeHash,
      );
      const plaintextHash = plaintextToHash(messageCoeffs);
      for (const index of [COMMITTEE_HASH_HI_IDX, COMMITTEE_HASH_LO_IDX]) {
        const mismatchedInputs = [...publicInputs];
        mismatchedInputs[index] = ethers.toBeHex(
          BigInt(mismatchedInputs[index]!) ^ 1n,
          32,
        );
        const proof = encodeProof("0x01", mismatchedInputs);

        await expect(
          bfvDecryptionVerifier.verify.staticCall(
            E3_ID,
            decryptionDomain,
            plaintextHash,
            committeeHash,
            CIPHERTEXT_COMMITMENT,
            proof,
          ),
        ).to.be.revertedWithCustomError(
          bfvDecryptionVerifier,
          "DomainBindingMismatch",
        );
      }
    });

    it("rejects an independent mismatch in either decryption-domain limb (C-03)", async function () {
      const { bfvDecryptionVerifier, mockCircuit } = await loadFixture(
        deployWithMockCircuit,
      );
      await mockCircuit.setReturnValue(true);

      const messageCoeffs = [1n, 2n, 3n];
      const publicInputs = buildPublicInputsWithMessage(messageCoeffs);
      const plaintextHash = plaintextToHash(messageCoeffs);
      for (const index of [
        DECRYPTION_DOMAIN_HI_IDX,
        DECRYPTION_DOMAIN_LO_IDX,
      ]) {
        const mismatchedInputs = [...publicInputs];
        mismatchedInputs[index] = ethers.toBeHex(
          BigInt(mismatchedInputs[index]!) ^ 1n,
          32,
        );
        const proof = encodeProof("0x01", mismatchedInputs);

        await expect(
          bfvDecryptionVerifier.verify.staticCall(
            E3_ID,
            DECRYPTION_DOMAIN,
            plaintextHash,
            ethers.ZeroHash,
            CIPHERTEXT_COMMITMENT,
            proof,
          ),
        ).to.be.revertedWithCustomError(
          bfvDecryptionVerifier,
          "DomainBindingMismatch",
        );
      }
    });

    it("reverts when the stored SAFE ciphertext commitment differs from the proof", async function () {
      const { bfvDecryptionVerifier, mockCircuit } = await loadFixture(
        deployWithMockCircuit,
      );
      await mockCircuit.setReturnValue(true);
      const { decryptionDomain } = ctx();

      const messageCoeffs = [1n, 2n, 3n];
      const publicInputs = buildPublicInputsWithMessage(messageCoeffs);
      const plaintextHash = plaintextToHash(messageCoeffs);
      const proof = encodeProof("0x01", publicInputs);

      await expect(
        bfvDecryptionVerifier.verify.staticCall(
          E3_ID,
          decryptionDomain,
          plaintextHash,
          ethers.ZeroHash,
          ethers.id("wrong-ciphertext-commitment"),
          proof,
        ),
      ).to.be.revertedWithCustomError(
        bfvDecryptionVerifier,
        "CiphertextCommitmentMismatch",
      );
    });

    it("reverts PlaintextHashMismatch when message coeffs don't hash to plaintextHash", async function () {
      const { bfvDecryptionVerifier, mockCircuit } = await loadFixture(
        deployWithMockCircuit,
      );
      await mockCircuit.setReturnValue(true);
      const { decryptionDomain } = ctx();

      const messageCoeffs = [1n, 2n, 3n];
      const wrongHash = ethers.keccak256("0x0000");
      const publicInputs = buildPublicInputsWithMessage(messageCoeffs);
      const proof = encodeProof("0x01", publicInputs);

      await expect(
        bfvDecryptionVerifier.verify.staticCall(
          E3_ID,
          decryptionDomain,
          wrongHash,
          ethers.ZeroHash,
          CIPHERTEXT_COMMITMENT,
          proof,
        ),
      ).to.be.revertedWithCustomError(
        bfvDecryptionVerifier,
        "PlaintextHashMismatch",
      );
    });

    it("reverts InvalidProof when circuit verifier returns false (M-35)", async function () {
      const { bfvDecryptionVerifier, mockCircuit } = await loadFixture(
        deployWithMockCircuit,
      );
      await mockCircuit.setReturnValue(false);
      const { decryptionDomain } = ctx();

      const messageCoeffs = [1n, 2n, 3n];
      const publicInputs = buildPublicInputsWithMessage(messageCoeffs);
      const plaintextHash = plaintextToHash(messageCoeffs);
      const proof = encodeProof("0x01", publicInputs);

      await expect(
        bfvDecryptionVerifier.verify.staticCall(
          E3_ID,
          decryptionDomain,
          plaintextHash,
          ethers.ZeroHash,
          CIPHERTEXT_COMMITMENT,
          proof,
        ),
      ).to.be.revertedWithCustomError(bfvDecryptionVerifier, "InvalidProof");
    });

    it("reverts VkHashMismatch when constructor expected hashes do not match proof", async function () {
      const { mockCircuit, mockCiphernodeRegistry } = await loadFixture(
        deployWithMockCircuit,
      );
      await mockCircuit.setReturnValue(true);
      const mockAddr = await mockCircuit.getAddress();
      const registryAddr = await mockCiphernodeRegistry.getAddress();
      const { decryptionDomain } = ctx();

      const bfvDecryptionVerifier = await (
        await ethers.getContractFactory("BfvDecryptionVerifier")
      ).deploy(
        mockAddr,
        registryAddr,
        ethers.id("wrong-c6"),
        ethers.id("wrong-c7"),
        THRESHOLD,
      );
      await bfvDecryptionVerifier.waitForDeployment();

      const messageCoeffs = [1n, 2n, 3n];
      const publicInputs = buildPublicInputsWithMessage(messageCoeffs);
      const plaintextHash = plaintextToHash(messageCoeffs);
      const proof = encodeProof("0x0102", publicInputs);

      await expect(
        bfvDecryptionVerifier.verify.staticCall(
          E3_ID,
          decryptionDomain,
          plaintextHash,
          ethers.ZeroHash,
          CIPHERTEXT_COMMITMENT,
          proof,
        ),
      ).to.be.revertedWithCustomError(bfvDecryptionVerifier, "VkHashMismatch");
    });

    it("reverts DkgAnchorMismatch when a party's sk commitment doesn't match the stored DKG anchor", async function () {
      const { bfvDecryptionVerifier, mockCircuit } = await loadFixture(
        deployWithMockCircuit,
      );
      await mockCircuit.setReturnValue(true);
      const { e3Id, decryptionDomain } = ctx();

      const messageCoeffs = [1n, 2n, 3n];
      const forgedSkCommits = [fieldHash("forged-sk-0"), DEFAULT_SK_COMMITS[1]];
      const publicInputs = buildPublicInputsWithMessage(
        messageCoeffs,
        EXPECTED_PUBLIC_INPUTS_LEN,
        [EXPECTED_C6_FOLD_KEY_HASH, EXPECTED_C7_KEY_HASH],
        ethers.ZeroHash,
        DEFAULT_CIRCUIT_PARTY_IDS.map(BigInt),
        forgedSkCommits,
        DEFAULT_ESM_COMMITS,
      );
      const plaintextHash = plaintextToHash(messageCoeffs);
      const proof = encodeProof("0x01", publicInputs);

      await expect(
        bfvDecryptionVerifier.verify.staticCall(
          e3Id,
          decryptionDomain,
          plaintextHash,
          ethers.ZeroHash,
          CIPHERTEXT_COMMITMENT,
          proof,
        ),
      ).to.be.revertedWithCustomError(
        bfvDecryptionVerifier,
        "DkgAnchorMismatch",
      );
    });

    it("reverts DkgAnchorMismatch when a party's esm commitment doesn't match the stored DKG anchor", async function () {
      const { bfvDecryptionVerifier, mockCircuit } = await loadFixture(
        deployWithMockCircuit,
      );
      await mockCircuit.setReturnValue(true);
      const { e3Id, decryptionDomain } = ctx();

      const messageCoeffs = [1n, 2n, 3n];
      const forgedEsmCommits = [
        DEFAULT_ESM_COMMITS[0],
        fieldHash("forged-esm-1"),
      ];
      const publicInputs = buildPublicInputsWithMessage(
        messageCoeffs,
        EXPECTED_PUBLIC_INPUTS_LEN,
        [EXPECTED_C6_FOLD_KEY_HASH, EXPECTED_C7_KEY_HASH],
        ethers.ZeroHash,
        DEFAULT_CIRCUIT_PARTY_IDS.map(BigInt),
        DEFAULT_SK_COMMITS,
        forgedEsmCommits,
      );
      const plaintextHash = plaintextToHash(messageCoeffs);
      const proof = encodeProof("0x01", publicInputs);

      await expect(
        bfvDecryptionVerifier.verify.staticCall(
          e3Id,
          decryptionDomain,
          plaintextHash,
          ethers.ZeroHash,
          CIPHERTEXT_COMMITMENT,
          proof,
        ),
      ).to.be.revertedWithCustomError(
        bfvDecryptionVerifier,
        "DkgAnchorMismatch",
      );
    });

    it("reverts DkgAnchorNotFound when a party_id is not present in the stored DKG anchors", async function () {
      const { bfvDecryptionVerifier, mockCircuit } = await loadFixture(
        deployWithMockCircuit,
      );
      await mockCircuit.setReturnValue(true);
      const { e3Id, decryptionDomain } = ctx();

      // Registry only has anchors for 0-indexed party ids [0, 1] (circuit-side [1, 2]).
      // Circuit-side id 99 has no corresponding registry entry at any offset.
      const messageCoeffs = [1n, 2n, 3n];
      const unknownPartyIds = [
        99n,
        ...DEFAULT_CIRCUIT_PARTY_IDS.slice(1).map(BigInt),
      ];
      const publicInputs = buildPublicInputsWithMessage(
        messageCoeffs,
        EXPECTED_PUBLIC_INPUTS_LEN,
        [EXPECTED_C6_FOLD_KEY_HASH, EXPECTED_C7_KEY_HASH],
        ethers.ZeroHash,
        unknownPartyIds,
        DEFAULT_SK_COMMITS,
        DEFAULT_ESM_COMMITS,
      );
      const plaintextHash = plaintextToHash(messageCoeffs);
      const proof = encodeProof("0x01", publicInputs);

      await expect(
        bfvDecryptionVerifier.verify.staticCall(
          e3Id,
          decryptionDomain,
          plaintextHash,
          ethers.ZeroHash,
          CIPHERTEXT_COMMITMENT,
          proof,
        ),
      ).to.be.revertedWithCustomError(
        bfvDecryptionVerifier,
        "DkgAnchorNotFound",
      );
    });

    it("does not reuse DKG anchors from another E3", async function () {
      const { bfvDecryptionVerifier, mockCircuit } = await loadFixture(
        deployWithMockCircuit,
      );
      await mockCircuit.setReturnValue(true);

      const messageCoeffs = [1n, 2n, 3n];
      const publicInputs = buildPublicInputsWithMessage(messageCoeffs);
      const plaintextHash = plaintextToHash(messageCoeffs);
      const proof = encodeProof("0x01", publicInputs);

      await expect(
        bfvDecryptionVerifier.verify.staticCall(
          E3_ID + 1n,
          DECRYPTION_DOMAIN,
          plaintextHash,
          ethers.ZeroHash,
          CIPHERTEXT_COMMITMENT,
          proof,
        ),
      ).to.be.revertedWithCustomError(
        bfvDecryptionVerifier,
        "DkgAnchorNotFound",
      );
    });

    it("reverts (arithmetic underflow) when circuit party_id is 0 -- x=0 is the secret's own point, never a valid share", async function () {
      const { bfvDecryptionVerifier, mockCircuit } = await loadFixture(
        deployWithMockCircuit,
      );
      await mockCircuit.setReturnValue(true);
      const { e3Id, decryptionDomain } = ctx();

      const messageCoeffs = [1n, 2n, 3n];
      const zeroPartyIds = [
        0n,
        ...DEFAULT_CIRCUIT_PARTY_IDS.slice(1).map(BigInt),
      ];
      const publicInputs = buildPublicInputsWithMessage(
        messageCoeffs,
        EXPECTED_PUBLIC_INPUTS_LEN,
        [EXPECTED_C6_FOLD_KEY_HASH, EXPECTED_C7_KEY_HASH],
        ethers.ZeroHash,
        zeroPartyIds,
        DEFAULT_SK_COMMITS,
        DEFAULT_ESM_COMMITS,
      );
      const plaintextHash = plaintextToHash(messageCoeffs);
      const proof = encodeProof("0x01", publicInputs);

      await expect(
        bfvDecryptionVerifier.verify.staticCall(
          e3Id,
          decryptionDomain,
          plaintextHash,
          ethers.ZeroHash,
          CIPHERTEXT_COMMITMENT,
          proof,
        ),
      ).to.be.revert(ethers);
    });
  });

  describe("success", function () {
    it("returns true with mock ICircuitVerifier and matching plaintext hash", async function () {
      const { bfvDecryptionVerifier, mockCircuit } = await loadFixture(
        deployWithMockCircuit,
      );
      await mockCircuit.setReturnValue(true);
      const { decryptionDomain } = ctx();

      const messageCoeffs = [1n, 2n, 3n, 42n, 100n];
      const publicInputs = buildPublicInputsWithMessage(messageCoeffs);
      expect(publicInputs.length).to.equal(EXPECTED_PUBLIC_INPUTS_LEN);
      const plaintextHash = plaintextToHash(messageCoeffs);
      const proof = encodeProof("0x0102", publicInputs);

      const result = await bfvDecryptionVerifier.verify.staticCall(
        E3_ID,
        decryptionDomain,
        plaintextHash,
        ethers.ZeroHash,
        CIPHERTEXT_COMMITMENT,
        proof,
      );
      expect(result).to.equal(true);
    });

    it("returns true when committee hash matches proof slots 2/3 (hi/lo)", async function () {
      const { bfvDecryptionVerifier, mockCircuit } = await loadFixture(
        deployWithMockCircuit,
      );
      await mockCircuit.setReturnValue(true);
      const { decryptionDomain } = ctx();

      const committeeHash = ethers.id("the-committee");
      const messageCoeffs = [10n, 20n, 30n];
      const publicInputs = buildPublicInputsWithMessage(
        messageCoeffs,
        EXPECTED_PUBLIC_INPUTS_LEN,
        [EXPECTED_C6_FOLD_KEY_HASH, EXPECTED_C7_KEY_HASH],
        committeeHash,
      );
      const plaintextHash = plaintextToHash(messageCoeffs);
      const proof = encodeProof("0x01", publicInputs);

      const result = await bfvDecryptionVerifier.verify.staticCall(
        E3_ID,
        decryptionDomain,
        plaintextHash,
        committeeHash,
        CIPHERTEXT_COMMITMENT,
        proof,
      );
      expect(result).to.equal(true);
    });

    it("verifies all-zero message coefficients", async function () {
      const { bfvDecryptionVerifier, mockCircuit } = await loadFixture(
        deployWithMockCircuit,
      );
      await mockCircuit.setReturnValue(true);
      const { decryptionDomain } = ctx();

      const messageCoeffs: bigint[] = [];
      const publicInputs = buildPublicInputsWithMessage(messageCoeffs);
      const plaintextHash = plaintextToHash(messageCoeffs);
      const proof = encodeProof("0x01", publicInputs);

      const result = await bfvDecryptionVerifier.verify.staticCall(
        E3_ID,
        decryptionDomain,
        plaintextHash,
        ethers.ZeroHash,
        CIPHERTEXT_COMMITMENT,
        proof,
      );
      expect(result).to.equal(true);
    });

    it("verifies all 100 message coefficients", async function () {
      const { bfvDecryptionVerifier, mockCircuit } = await loadFixture(
        deployWithMockCircuit,
      );
      await mockCircuit.setReturnValue(true);
      const { decryptionDomain } = ctx();

      const messageCoeffs = Array.from(
        { length: MESSAGE_COEFFS_COUNT },
        (_, i) => BigInt(i + 1),
      );
      const publicInputs = buildPublicInputsWithMessage(messageCoeffs);
      const plaintextHash = plaintextToHash(messageCoeffs);
      const proof = encodeProof("0x01", publicInputs);

      const result = await bfvDecryptionVerifier.verify.staticCall(
        E3_ID,
        decryptionDomain,
        plaintextHash,
        ethers.ZeroHash,
        CIPHERTEXT_COMMITMENT,
        proof,
      );
      expect(result).to.equal(true);
    });
  });

  describe("immutables (M-34)", function () {
    it("exposes correct threshold", async function () {
      const { bfvDecryptionVerifier } = await loadFixture(
        deployWithMockCircuit,
      );
      expect(await bfvDecryptionVerifier.threshold()).to.equal(THRESHOLD);
    });

    it("exposes correct expectedC6FoldKeyHash", async function () {
      const { bfvDecryptionVerifier } = await loadFixture(
        deployWithMockCircuit,
      );
      expect(await bfvDecryptionVerifier.expectedC6FoldKeyHash()).to.equal(
        EXPECTED_C6_FOLD_KEY_HASH,
      );
    });

    it("exposes correct expectedC7KeyHash", async function () {
      const { bfvDecryptionVerifier } = await loadFixture(
        deployWithMockCircuit,
      );
      expect(await bfvDecryptionVerifier.expectedC7KeyHash()).to.equal(
        EXPECTED_C7_KEY_HASH,
      );
    });

    it("exposes correct ciphernodeRegistry", async function () {
      const { bfvDecryptionVerifier, mockCiphernodeRegistry } =
        await loadFixture(deployWithMockCircuit);
      expect(await bfvDecryptionVerifier.ciphernodeRegistry()).to.equal(
        await mockCiphernodeRegistry.getAddress(),
      );
    });
  });
});
