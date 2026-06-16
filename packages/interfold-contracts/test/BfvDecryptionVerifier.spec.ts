// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
import { expect } from "chai";
import { network } from "hardhat";

import MockCircuitVerifierModule from "../ignition/modules/mockSlashingVerifier";
import {
  BFV_THRESHOLD_T,
  bfvDecExpectedPublicInputsLen,
} from "../scripts/utils";
import {
  BfvDecryptionVerifier__factory as BfvDecryptionVerifierFactory,
  MockCircuitVerifier__factory as MockCircuitVerifierFactory,
} from "../types";

const { ethers, ignition, networkHelpers } = await network.connect();
const { loadFixture } = networkHelpers;
const [testSigner] = await ethers.getSigners();

/** Must match `BfvDecryptionVerifier.MESSAGE_COEFFS_COUNT` / circuit `MAX_MSG_NON_ZERO_COEFFS`. */
const MESSAGE_COEFFS_COUNT = 100;

const EXPECTED_C6_FOLD_KEY_HASH = ethers.id("c6_fold");
const EXPECTED_C7_KEY_HASH = ethers.id("c7");

/** Must match `BfvDecryptionVerifier.threshold` / default circuit `T`. */
const THRESHOLD = BFV_THRESHOLD_T;

/** Exact `publicInputs.length` for the configured threshold. */
const EXPECTED_PUBLIC_INPUTS_LEN = bfvDecExpectedPublicInputsLen(THRESHOLD);

/** Indices for committee hash limbs (fixed layout). */
const COMMITTEE_HASH_HI_IDX = 2;
const COMMITTEE_HASH_LO_IDX = 3;

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
): string[] {
  const arr: string[] = new Array(totalInputs);
  arr[0] = subCircuitHashes[0];
  arr[1] = subCircuitHashes[1];
  for (let i = 2; i < totalInputs; i++) {
    arr[i] = "0x" + "00".repeat(32);
  }
  arr[COMMITTEE_HASH_HI_IDX] = committeeHashHi(committeeHash);
  arr[COMMITTEE_HASH_LO_IDX] = committeeHashLo(committeeHash);
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
  const deployWithMockCircuit = async () => {
    const [owner] = await ethers.getSigners();
    const { mockCircuitVerifier } = await ignition.deploy(
      MockCircuitVerifierModule,
    );
    const mockAddr = await mockCircuitVerifier.getAddress();

    const bfvDecryptionVerifier = await (
      await ethers.getContractFactory("BfvDecryptionVerifier")
    ).deploy(
      mockAddr,
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
    return { bfvDecryptionVerifier: dv, mockCircuit: mc };
  };

  /** Contextual params forwarded to verify; not checked against circuit outputs (future domain binding). */
  const ctx = () => {
    const e3Id = 7n;
    const root = BigInt(ethers.id("test-root"));
    const nodes = [testSigner.address];
    const ciphertextHash = ethers.id("ct-hash");
    const committeePk = ethers.id("committee-pk");
    return { e3Id, root, nodes, ciphertextHash, committeePk };
  };

  describe("reverts", function () {
    it("reverts on invalid proof encoding", async function () {
      const { bfvDecryptionVerifier } = await loadFixture(
        deployWithMockCircuit,
      );
      const { e3Id, root, nodes, ciphertextHash, committeePk } = ctx();
      const plaintextHash = ethers.keccak256("0x1234");

      await expect(
        bfvDecryptionVerifier.verify.staticCall(
          e3Id,
          root,
          nodes,
          ciphertextHash,
          committeePk,
          plaintextHash,
          ethers.ZeroHash,
          "0xdeadbeef",
        ),
      ).to.be.revert(ethers);
    });

    it("reverts InvalidPublicInputsLength when length differs from expected (M-34)", async function () {
      const { bfvDecryptionVerifier, mockCircuit } = await loadFixture(
        deployWithMockCircuit,
      );
      await mockCircuit.setReturnValue(true);
      const { e3Id, root, nodes, ciphertextHash, committeePk } = ctx();

      const messageCoeffs = [1n, 2n, 3n];
      const publicInputs = buildPublicInputsWithMessage(messageCoeffs).slice(
        0,
        EXPECTED_PUBLIC_INPUTS_LEN - 1,
      );
      const plaintextHash = plaintextToHash(messageCoeffs);
      const proof = encodeProof("0x01", publicInputs);

      await expect(
        bfvDecryptionVerifier.verify.staticCall(
          e3Id,
          root,
          nodes,
          ciphertextHash,
          committeePk,
          plaintextHash,
          ethers.ZeroHash,
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
      const { e3Id, root, nodes, ciphertextHash, committeePk } = ctx();

      const messageCoeffs = [1n, 2n, 3n];
      const publicInputs = buildPublicInputsWithMessage(
        messageCoeffs,
        EXPECTED_PUBLIC_INPUTS_LEN + 1,
      );
      const plaintextHash = plaintextToHash(messageCoeffs);
      const proof = encodeProof("0x01", publicInputs);

      await expect(
        bfvDecryptionVerifier.verify.staticCall(
          e3Id,
          root,
          nodes,
          ciphertextHash,
          committeePk,
          plaintextHash,
          ethers.ZeroHash,
          proof,
        ),
      ).to.be.revertedWithCustomError(
        bfvDecryptionVerifier,
        "InvalidPublicInputsLength",
      );
    });

    it("reverts VkHashMismatch when c6_fold key hash does not match (M-34)", async function () {
      const { bfvDecryptionVerifier, mockCircuit } = await loadFixture(
        deployWithMockCircuit,
      );
      await mockCircuit.setReturnValue(true);
      const { e3Id, root, nodes, ciphertextHash, committeePk } = ctx();

      const messageCoeffs = [1n, 2n, 3n];
      const publicInputs = buildPublicInputsWithMessage(
        messageCoeffs,
        EXPECTED_PUBLIC_INPUTS_LEN,
        [ethers.id("wrong-c6"), EXPECTED_C7_KEY_HASH],
      );
      const plaintextHash = plaintextToHash(messageCoeffs);
      const proof = encodeProof("0x01", publicInputs);

      await expect(
        bfvDecryptionVerifier.verify.staticCall(
          e3Id,
          root,
          nodes,
          ciphertextHash,
          committeePk,
          plaintextHash,
          ethers.ZeroHash,
          proof,
        ),
      ).to.be.revertedWithCustomError(bfvDecryptionVerifier, "VkHashMismatch");
    });

    it("reverts VkHashMismatch when c7 key hash does not match (M-34)", async function () {
      const { bfvDecryptionVerifier, mockCircuit } = await loadFixture(
        deployWithMockCircuit,
      );
      await mockCircuit.setReturnValue(true);
      const { e3Id, root, nodes, ciphertextHash, committeePk } = ctx();

      const messageCoeffs = [1n, 2n, 3n];
      const publicInputs = buildPublicInputsWithMessage(
        messageCoeffs,
        EXPECTED_PUBLIC_INPUTS_LEN,
        [EXPECTED_C6_FOLD_KEY_HASH, ethers.id("wrong-c7")],
      );
      const plaintextHash = plaintextToHash(messageCoeffs);
      const proof = encodeProof("0x01", publicInputs);

      await expect(
        bfvDecryptionVerifier.verify.staticCall(
          e3Id,
          root,
          nodes,
          ciphertextHash,
          committeePk,
          plaintextHash,
          ethers.ZeroHash,
          proof,
        ),
      ).to.be.revertedWithCustomError(bfvDecryptionVerifier, "VkHashMismatch");
    });

    it("reverts DomainBindingMismatch when committee hash hi limb mismatches (C-08)", async function () {
      const { bfvDecryptionVerifier, mockCircuit } = await loadFixture(
        deployWithMockCircuit,
      );
      await mockCircuit.setReturnValue(true);
      const { e3Id, root, nodes, ciphertextHash, committeePk } = ctx();

      const committeeHash = ethers.id("real-committee");
      const wrongCommitteeHash = ethers.id("wrong-committee");
      const messageCoeffs = [1n, 2n, 3n];
      // proof built with real committeeHash in slots 2/3
      const publicInputs = buildPublicInputsWithMessage(
        messageCoeffs,
        EXPECTED_PUBLIC_INPUTS_LEN,
        [EXPECTED_C6_FOLD_KEY_HASH, EXPECTED_C7_KEY_HASH],
        committeeHash,
      );
      const plaintextHash = plaintextToHash(messageCoeffs);
      const proof = encodeProof("0x01", publicInputs);

      // pass wrong committeeHash to verify — hi/lo check should fail
      await expect(
        bfvDecryptionVerifier.verify.staticCall(
          e3Id,
          root,
          nodes,
          ciphertextHash,
          committeePk,
          plaintextHash,
          wrongCommitteeHash,
          proof,
        ),
      ).to.be.revertedWithCustomError(
        bfvDecryptionVerifier,
        "DomainBindingMismatch",
      );
    });

    it("reverts PlaintextHashMismatch when message coeffs don't hash to plaintextHash", async function () {
      const { bfvDecryptionVerifier, mockCircuit } = await loadFixture(
        deployWithMockCircuit,
      );
      await mockCircuit.setReturnValue(true);
      const { e3Id, root, nodes, ciphertextHash, committeePk } = ctx();

      const messageCoeffs = [1n, 2n, 3n];
      const wrongHash = ethers.keccak256("0x0000");
      const publicInputs = buildPublicInputsWithMessage(messageCoeffs);
      const proof = encodeProof("0x01", publicInputs);

      await expect(
        bfvDecryptionVerifier.verify.staticCall(
          e3Id,
          root,
          nodes,
          ciphertextHash,
          committeePk,
          wrongHash,
          ethers.ZeroHash,
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
      const { e3Id, root, nodes, ciphertextHash, committeePk } = ctx();

      const messageCoeffs = [1n, 2n, 3n];
      const publicInputs = buildPublicInputsWithMessage(messageCoeffs);
      const plaintextHash = plaintextToHash(messageCoeffs);
      const proof = encodeProof("0x01", publicInputs);

      await expect(
        bfvDecryptionVerifier.verify.staticCall(
          e3Id,
          root,
          nodes,
          ciphertextHash,
          committeePk,
          plaintextHash,
          ethers.ZeroHash,
          proof,
        ),
      ).to.be.revertedWithCustomError(bfvDecryptionVerifier, "InvalidProof");
    });

    it("reverts VkHashMismatch when constructor expected hashes do not match proof", async function () {
      const { mockCircuit } = await loadFixture(deployWithMockCircuit);
      await mockCircuit.setReturnValue(true);
      const mockAddr = await mockCircuit.getAddress();
      const { e3Id, root, nodes, ciphertextHash, committeePk } = ctx();

      const bfvDecryptionVerifier = await (
        await ethers.getContractFactory("BfvDecryptionVerifier")
      ).deploy(
        mockAddr,
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
          e3Id,
          root,
          nodes,
          ciphertextHash,
          committeePk,
          plaintextHash,
          ethers.ZeroHash,
          proof,
        ),
      ).to.be.revertedWithCustomError(bfvDecryptionVerifier, "VkHashMismatch");
    });
  });

  describe("success", function () {
    it("returns true with mock ICircuitVerifier and matching plaintext hash", async function () {
      const { bfvDecryptionVerifier, mockCircuit } = await loadFixture(
        deployWithMockCircuit,
      );
      await mockCircuit.setReturnValue(true);
      const { e3Id, root, nodes, ciphertextHash, committeePk } = ctx();

      const messageCoeffs = [1n, 2n, 3n, 42n, 100n];
      const publicInputs = buildPublicInputsWithMessage(messageCoeffs);
      const plaintextHash = plaintextToHash(messageCoeffs);
      const proof = encodeProof("0x0102", publicInputs);

      const result = await bfvDecryptionVerifier.verify.staticCall(
        e3Id,
        root,
        nodes,
        ciphertextHash,
        committeePk,
        plaintextHash,
        ethers.ZeroHash,
        proof,
      );
      expect(result).to.equal(true);
    });

    it("returns true with exact-length public inputs", async function () {
      const { bfvDecryptionVerifier, mockCircuit } = await loadFixture(
        deployWithMockCircuit,
      );
      await mockCircuit.setReturnValue(true);
      const { e3Id, root, nodes, ciphertextHash, committeePk } = ctx();

      const messageCoeffs = [1n, 2n, 3n];
      const publicInputs = buildPublicInputsWithMessage(
        messageCoeffs,
        EXPECTED_PUBLIC_INPUTS_LEN,
      );
      const plaintextHash = plaintextToHash(messageCoeffs);
      const proof = encodeProof("0x01", publicInputs);

      const result = await bfvDecryptionVerifier.verify.staticCall(
        e3Id,
        root,
        nodes,
        ciphertextHash,
        committeePk,
        plaintextHash,
        ethers.ZeroHash,
        proof,
      );
      expect(result).to.equal(true);
    });

    it("returns true when committee hash matches proof slots 2/3 (hi/lo)", async function () {
      const { bfvDecryptionVerifier, mockCircuit } = await loadFixture(
        deployWithMockCircuit,
      );
      await mockCircuit.setReturnValue(true);
      const { e3Id, root, nodes, ciphertextHash, committeePk } = ctx();

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
        e3Id,
        root,
        nodes,
        ciphertextHash,
        committeePk,
        plaintextHash,
        committeeHash,
        proof,
      );
      expect(result).to.equal(true);
    });

    it("verifies all-zero message coefficients", async function () {
      const { bfvDecryptionVerifier, mockCircuit } = await loadFixture(
        deployWithMockCircuit,
      );
      await mockCircuit.setReturnValue(true);
      const { e3Id, root, nodes, ciphertextHash, committeePk } = ctx();

      const messageCoeffs: bigint[] = [];
      const publicInputs = buildPublicInputsWithMessage(messageCoeffs);
      const plaintextHash = plaintextToHash(messageCoeffs);
      const proof = encodeProof("0x01", publicInputs);

      const result = await bfvDecryptionVerifier.verify.staticCall(
        e3Id,
        root,
        nodes,
        ciphertextHash,
        committeePk,
        plaintextHash,
        ethers.ZeroHash,
        proof,
      );
      expect(result).to.equal(true);
    });

    it("verifies all 100 message coefficients", async function () {
      const { bfvDecryptionVerifier, mockCircuit } = await loadFixture(
        deployWithMockCircuit,
      );
      await mockCircuit.setReturnValue(true);
      const { e3Id, root, nodes, ciphertextHash, committeePk } = ctx();

      const messageCoeffs = Array.from(
        { length: MESSAGE_COEFFS_COUNT },
        (_, i) => BigInt(i + 1),
      );
      const publicInputs = buildPublicInputsWithMessage(messageCoeffs);
      const plaintextHash = plaintextToHash(messageCoeffs);
      const proof = encodeProof("0x01", publicInputs);

      const result = await bfvDecryptionVerifier.verify.staticCall(
        e3Id,
        root,
        nodes,
        ciphertextHash,
        committeePk,
        plaintextHash,
        ethers.ZeroHash,
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
  });
});
