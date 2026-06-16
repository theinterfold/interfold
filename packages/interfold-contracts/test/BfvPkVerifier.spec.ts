// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
import { expect } from "chai";
import { network } from "hardhat";

import MockCircuitVerifierModule from "../ignition/modules/mockSlashingVerifier";
import { BFV_DKG_H, bfvPkExpectedPublicInputsLen } from "../scripts/utils";
import {
  BfvPkVerifier__factory as BfvPkVerifierFactory,
  MockCircuitVerifier__factory as MockCircuitVerifierFactory,
} from "../types";

const { ethers, ignition, networkHelpers } = await network.connect();
const { loadFixture } = networkHelpers;
const [testSigner] = await ethers.getSigners();

const EXPECTED_NODES_FOLD_KEY_HASH = ethers.id("nodes_fold");
const EXPECTED_C5_KEY_HASH = ethers.id("c5");
/** Must match `BfvPkVerifier.h` / default circuit `H`. */
const H = BFV_DKG_H;
/** Aggregator return slots after committee hash: `2*H + 1` padding + `pkCommitment`. */
const DKG_RETURN_FIELD_COUNT = 2 * H + 2;

/** Exact `publicInputs.length` for the configured H. */
const EXPECTED_PUBLIC_INPUTS_LEN = bfvPkExpectedPublicInputsLen(H);

function committeeHashLimbs(committeeHash: string): [string, string] {
  const bn = BigInt(committeeHash);
  const hi = ethers.toBeHex(bn >> 128n, 32);
  const lo = ethers.toBeHex(bn & ((1n << 128n) - 1n), 32);
  return [hi, lo];
}

function minimalDkgPublicInputs(
  pkCommitment: string,
  committeeHash: string = ethers.ZeroHash,
): string[] {
  const [hi, lo] = committeeHashLimbs(committeeHash);
  return [
    EXPECTED_NODES_FOLD_KEY_HASH,
    EXPECTED_C5_KEY_HASH,
    ...Array(H).fill(ethers.ZeroHash),
    hi,
    lo,
    ...Array(DKG_RETURN_FIELD_COUNT - 1).fill(ethers.ZeroHash),
    pkCommitment,
  ];
}

function encodeProof(rawProof: string, publicInputs: string[]): string {
  const abiCoder = ethers.AbiCoder.defaultAbiCoder();
  return abiCoder.encode(["bytes", "bytes32[]"], [rawProof, publicInputs]);
}

describe("BfvPkVerifier", function () {
  const deployWithMockCircuit = async () => {
    const [owner] = await ethers.getSigners();
    const { mockCircuitVerifier } = await ignition.deploy(
      MockCircuitVerifierModule,
    );
    const mockAddr = await mockCircuitVerifier.getAddress();

    const bfvPkVerifier = await (
      await ethers.getContractFactory("BfvPkVerifier")
    ).deploy(mockAddr, EXPECTED_NODES_FOLD_KEY_HASH, EXPECTED_C5_KEY_HASH, H);

    await bfvPkVerifier.waitForDeployment();
    const pk = BfvPkVerifierFactory.connect(
      await bfvPkVerifier.getAddress(),
      owner,
    );
    const mc = MockCircuitVerifierFactory.connect(mockAddr, owner);
    return { bfvPkVerifier: pk, mockCircuit: mc };
  };

  /** Contextual params forwarded to verify; not checked against circuit outputs (future domain binding). */
  const ctx = () => ({
    e3Id: 7n,
    root: BigInt(ethers.id("test-root")),
    nodes: [testSigner.address],
  });

  describe("reverts", function () {
    it("reverts on invalid proof encoding", async function () {
      const { bfvPkVerifier } = await loadFixture(deployWithMockCircuit);
      const { e3Id, root, nodes } = ctx();
      const pkCommitment = ethers.keccak256("0x1234");
      const invalidProof = "0xdeadbeef";

      await expect(
        bfvPkVerifier.verify.staticCall(
          e3Id,
          root,
          nodes,
          pkCommitment,
          ethers.ZeroHash,
          invalidProof,
        ),
      ).to.be.revert(ethers);
    });

    it("reverts InvalidPublicInputsLength when publicInputs is empty (M-34)", async function () {
      const { bfvPkVerifier } = await loadFixture(deployWithMockCircuit);
      const { e3Id, root, nodes } = ctx();
      const pkCommitment = ethers.keccak256("0x1234");
      const proof = encodeProof("0x01", []);

      await expect(
        bfvPkVerifier.verify.staticCall(
          e3Id,
          root,
          nodes,
          pkCommitment,
          ethers.ZeroHash,
          proof,
        ),
      ).to.be.revertedWithCustomError(
        bfvPkVerifier,
        "InvalidPublicInputsLength",
      );
    });

    it("reverts InvalidPublicInputsLength when below expected length (M-34)", async function () {
      const { bfvPkVerifier } = await loadFixture(deployWithMockCircuit);
      const { e3Id, root, nodes } = ctx();
      const pkCommitment = ethers.keccak256("0xabcd");
      const proof = encodeProof(
        "0x01",
        minimalDkgPublicInputs(pkCommitment).slice(
          0,
          EXPECTED_PUBLIC_INPUTS_LEN - 1,
        ),
      );

      await expect(
        bfvPkVerifier.verify.staticCall(
          e3Id,
          root,
          nodes,
          pkCommitment,
          ethers.ZeroHash,
          proof,
        ),
      ).to.be.revertedWithCustomError(
        bfvPkVerifier,
        "InvalidPublicInputsLength",
      );
    });

    it("reverts InvalidPublicInputsLength when above expected length (M-34)", async function () {
      const { bfvPkVerifier } = await loadFixture(deployWithMockCircuit);
      const { e3Id, root, nodes } = ctx();
      const pkCommitment = ethers.keccak256("0xabcd");
      const proof = encodeProof("0x01", [
        ...minimalDkgPublicInputs(pkCommitment),
        ethers.ZeroHash,
      ]);

      await expect(
        bfvPkVerifier.verify.staticCall(
          e3Id,
          root,
          nodes,
          pkCommitment,
          ethers.ZeroHash,
          proof,
        ),
      ).to.be.revertedWithCustomError(
        bfvPkVerifier,
        "InvalidPublicInputsLength",
      );
    });

    it("reverts VkHashMismatch when nodes_fold key hash does not match (M-34)", async function () {
      const { bfvPkVerifier } = await loadFixture(deployWithMockCircuit);
      const { e3Id, root, nodes } = ctx();
      const pkCommitment = ethers.keccak256("0xabcd");
      const publicInputs = minimalDkgPublicInputs(pkCommitment).map((v, i) =>
        i === 0 ? ethers.id("wrong-nodes-fold") : v,
      );
      const proof = encodeProof("0x01", publicInputs);

      await expect(
        bfvPkVerifier.verify.staticCall(
          e3Id,
          root,
          nodes,
          pkCommitment,
          ethers.ZeroHash,
          proof,
        ),
      ).to.be.revertedWithCustomError(bfvPkVerifier, "VkHashMismatch");
    });

    it("reverts VkHashMismatch when c5 key hash does not match (M-34)", async function () {
      const { bfvPkVerifier } = await loadFixture(deployWithMockCircuit);
      const { e3Id, root, nodes } = ctx();
      const pkCommitment = ethers.keccak256("0xabcd");
      const publicInputs = minimalDkgPublicInputs(pkCommitment).map((v, i) =>
        i === 1 ? ethers.id("wrong-c5") : v,
      );
      const proof = encodeProof("0x01", publicInputs);

      await expect(
        bfvPkVerifier.verify.staticCall(
          e3Id,
          root,
          nodes,
          pkCommitment,
          ethers.ZeroHash,
          proof,
        ),
      ).to.be.revertedWithCustomError(bfvPkVerifier, "VkHashMismatch");
    });

    it("reverts DomainBindingMismatch when committeeHash hi/lo does not match public inputs (C-08)", async function () {
      const { bfvPkVerifier, mockCircuit } = await loadFixture(
        deployWithMockCircuit,
      );
      await mockCircuit.setReturnValue(true);
      const { e3Id, root, nodes } = ctx();

      const realCommitteeHash = ethers.id("real-committee");
      const wrongCommitteeHash = ethers.id("wrong-committee");
      const pkCommitment = ethers.keccak256("0xabcd");
      // proof encodes real committeeHash in hi/lo slots
      const publicInputs = minimalDkgPublicInputs(
        pkCommitment,
        realCommitteeHash,
      );
      const proof = encodeProof("0x01", publicInputs);

      // pass wrong committeeHash — hi/lo mismatch
      await expect(
        bfvPkVerifier.verify.staticCall(
          e3Id,
          root,
          nodes,
          pkCommitment,
          wrongCommitteeHash,
          proof,
        ),
      ).to.be.revertedWithCustomError(bfvPkVerifier, "DomainBindingMismatch");
    });

    it("reverts PkCommitmentMismatch when last slot != pkCommitment (M-34)", async function () {
      const { bfvPkVerifier, mockCircuit } = await loadFixture(
        deployWithMockCircuit,
      );
      await mockCircuit.setReturnValue(true);
      const { e3Id, root, nodes } = ctx();

      const pkCommitment = ethers.keccak256("0xabcd");
      const wrongCommitment = ethers.keccak256("0xbeef");
      const publicInputs = minimalDkgPublicInputs(wrongCommitment);
      const proof = encodeProof("0x01", publicInputs);

      await expect(
        bfvPkVerifier.verify.staticCall(
          e3Id,
          root,
          nodes,
          pkCommitment,
          ethers.ZeroHash,
          proof,
        ),
      ).to.be.revertedWithCustomError(bfvPkVerifier, "PkCommitmentMismatch");
    });

    it("reverts InvalidProof when underlying circuit verifier returns false (M-35)", async function () {
      const { bfvPkVerifier, mockCircuit } = await loadFixture(
        deployWithMockCircuit,
      );
      await mockCircuit.setReturnValue(false);
      const { e3Id, root, nodes } = ctx();

      const pkCommitment = ethers.keccak256("0xabcd");
      const publicInputs = minimalDkgPublicInputs(pkCommitment);
      const proof = encodeProof("0x01", publicInputs);

      await expect(
        bfvPkVerifier.verify.staticCall(
          e3Id,
          root,
          nodes,
          pkCommitment,
          ethers.ZeroHash,
          proof,
        ),
      ).to.be.revertedWithCustomError(bfvPkVerifier, "InvalidProof");
    });

    it("reverts VkHashMismatch when constructor expected hashes do not match proof (M-34)", async function () {
      const { mockCircuit } = await loadFixture(deployWithMockCircuit);
      await mockCircuit.setReturnValue(true);
      const mockAddr = await mockCircuit.getAddress();
      const { e3Id, root, nodes } = ctx();

      const bfvPkVerifier = await (
        await ethers.getContractFactory("BfvPkVerifier")
      ).deploy(
        mockAddr,
        ethers.id("wrong-nodes-fold"),
        ethers.id("wrong-c5"),
        H,
      );
      await bfvPkVerifier.waitForDeployment();

      const pkCommitment = ethers.keccak256("0xabcd");
      const proof = encodeProof("0x0102", minimalDkgPublicInputs(pkCommitment));

      await expect(
        bfvPkVerifier.verify.staticCall(
          e3Id,
          root,
          nodes,
          pkCommitment,
          ethers.ZeroHash,
          proof,
        ),
      ).to.be.revertedWithCustomError(bfvPkVerifier, "VkHashMismatch");
    });
  });

  describe("success", function () {
    it("returns true when commitment matches and circuit verifier passes", async function () {
      const { bfvPkVerifier, mockCircuit } = await loadFixture(
        deployWithMockCircuit,
      );
      await mockCircuit.setReturnValue(true);
      const { e3Id, root, nodes } = ctx();

      const pkCommitment = ethers.keccak256("0xabcd");
      const publicInputs = minimalDkgPublicInputs(pkCommitment);
      const proof = encodeProof("0x0102", publicInputs);

      const result = await bfvPkVerifier.verify.staticCall(
        e3Id,
        root,
        nodes,
        pkCommitment,
        ethers.ZeroHash,
        proof,
      );
      expect(result).to.equal(true);
    });

    it("returns true with exact-length public inputs", async function () {
      const { bfvPkVerifier, mockCircuit } = await loadFixture(
        deployWithMockCircuit,
      );
      await mockCircuit.setReturnValue(true);
      const { e3Id, root, nodes } = ctx();

      const pkCommitment = ethers.id("committee-pk");
      const publicInputs = minimalDkgPublicInputs(pkCommitment);
      expect(publicInputs.length).to.equal(EXPECTED_PUBLIC_INPUTS_LEN);
      const proof = encodeProof("0x0102", publicInputs);

      const result = await bfvPkVerifier.verify.staticCall(
        e3Id,
        root,
        nodes,
        pkCommitment,
        ethers.ZeroHash,
        proof,
      );
      expect(result).to.equal(true);
    });

    it("returns true when committee hash matches proof slots hi/lo", async function () {
      const { bfvPkVerifier, mockCircuit } = await loadFixture(
        deployWithMockCircuit,
      );
      await mockCircuit.setReturnValue(true);
      const { e3Id, root, nodes } = ctx();

      const committeeHash = ethers.id("the-committee");
      const pkCommitment = ethers.keccak256("0xabcd");
      const publicInputs = minimalDkgPublicInputs(pkCommitment, committeeHash);
      const proof = encodeProof("0x0102", publicInputs);

      const result = await bfvPkVerifier.verify.staticCall(
        e3Id,
        root,
        nodes,
        pkCommitment,
        committeeHash,
        proof,
      );
      expect(result).to.equal(true);
    });
  });

  describe("immutables (M-34)", function () {
    it("exposes correct h", async function () {
      const { bfvPkVerifier } = await loadFixture(deployWithMockCircuit);
      expect(await bfvPkVerifier.h()).to.equal(H);
    });

    it("exposes correct expectedNodesFoldKeyHash", async function () {
      const { bfvPkVerifier } = await loadFixture(deployWithMockCircuit);
      expect(await bfvPkVerifier.expectedNodesFoldKeyHash()).to.equal(
        EXPECTED_NODES_FOLD_KEY_HASH,
      );
    });

    it("exposes correct expectedC5KeyHash", async function () {
      const { bfvPkVerifier } = await loadFixture(deployWithMockCircuit);
      expect(await bfvPkVerifier.expectedC5KeyHash()).to.equal(
        EXPECTED_C5_KEY_HASH,
      );
    });
  });
});
