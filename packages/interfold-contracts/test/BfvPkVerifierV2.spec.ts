// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
import { expect } from "chai";

import dkgAggregatorV2VerifierModule from "../ignition/modules/dkgAggregatorV2Verifier";
import { ethers, ignition } from "./fixtures/connection";

const abiCoder = ethers.AbiCoder.defaultAbiCoder();
const NODES_FOLD_KEY_HASH = ethers.id("v2-nodes-fold");
const C5_KEY_HASH = ethers.id("v2-c5");
const SK_C2_CHUNK_KEY_HASH = ethers.id("v2-sk-c2-chunk");
const ESM_C2_CHUNK_KEY_HASH = ethers.id("v2-esm-c2-chunk");
const LEGACY_VK_BINDING = Array.from({ length: 16 }, (_, index) =>
  ethers.id(`v2-legacy-vk-${index}`),
);
const V2_VK_BINDING = Array.from({ length: 12 }, (_, index) =>
  ethers.id(`v2-vk-${index}`),
);
const SECURE_16384_CONFIG_ID =
  "0xde3c303973a0bf2b841cd0e7266ae68a7e48f8b271ffd629b245485e52dc8cd8";

function limbs(hash: string): [string, string] {
  const value = BigInt(hash);
  return [
    ethers.toBeHex(value >> 128n, 32),
    ethers.toBeHex(value & ((1n << 128n) - 1n), 32),
  ];
}

function committeeHash(nodes: string[]): string {
  return ethers.keccak256(
    ethers.concat(nodes.map((node) => ethers.getBytes(node))),
  );
}

function acceptedSetHash(first: number, second: number): string {
  return ethers.keccak256(
    ethers.solidityPacked(
      ["bytes32", "uint32", "uint32", "uint32"],
      [ethers.id("interfold.lbfv.accepted-party-set:v1"), 2, first, second],
    ),
  );
}

function sessionId(
  chainId: bigint,
  interfold: string,
  e3Id: bigint,
  finalizedCommitteeHash: string,
): string {
  return ethers.keccak256(
    abiCoder.encode(
      [
        "bytes32",
        "uint256",
        "uint256",
        "uint256",
        "address",
        "uint256",
        "bytes32",
        "bytes32",
        "uint256",
        "uint256",
        "uint256",
      ],
      [
        ethers.id("interfold.lbfv.proof-domain:v1"),
        1,
        4,
        chainId,
        interfold,
        e3Id,
        SECURE_16384_CONFIG_ID,
        finalizedCommitteeHash,
        1,
        0,
        0,
      ],
    ),
  );
}

function publicInputs(
  nodes: string[],
  interfold: string,
  e3Id: bigint,
  pkCommitment: string,
): string[] {
  const inputs = Array.from({ length: 63 }, () => ethers.ZeroHash);
  const hash = committeeHash(nodes);
  const [committeeHi, committeeLo] = limbs(hash);
  const [acceptedHi, acceptedLo] = limbs(acceptedSetHash(0, 2));
  const [sessionHi, sessionLo] = limbs(
    sessionId(31337n, interfold, e3Id, hash),
  );

  inputs[0] = NODES_FOLD_KEY_HASH;
  inputs[1] = C5_KEY_HASH;
  inputs[2] = ethers.toBeHex(0, 32);
  inputs[3] = ethers.toBeHex(2, 32);
  inputs[4] = committeeHi;
  inputs[5] = committeeLo;
  inputs.splice(6, LEGACY_VK_BINDING.length, ...LEGACY_VK_BINDING);
  inputs[23] = SK_C2_CHUNK_KEY_HASH;
  inputs[24] = ESM_C2_CHUNK_KEY_HASH;
  inputs[29] = pkCommitment;
  inputs[31] = sessionHi;
  inputs[32] = sessionLo;
  inputs[33] = ethers.toBeHex(0, 32);
  inputs[34] = acceptedHi;
  inputs[35] = acceptedLo;
  inputs.splice(51, V2_VK_BINDING.length, ...V2_VK_BINDING);
  return inputs;
}

function encodeProof(publicInputValues: string[]): string {
  return abiCoder.encode(["bytes", "bytes32[]"], ["0x1234", publicInputValues]);
}

describe("BfvPkVerifierV2", function () {
  it("deploys the linked V2 circuit verifier", async function () {
    const { dkgAggregatorV2Verifier } = await ignition.deploy(
      dkgAggregatorV2VerifierModule,
    );

    expect(await dkgAggregatorV2Verifier.getAddress()).to.be.properAddress;
  });

  async function deployFixture() {
    const circuit = await ethers.deployContract("MockCircuitVerifier");
    await circuit.waitForDeployment();
    await circuit.setReturnValue(true);

    const registry = await ethers.deployContract("MockCiphernodeRegistry");
    await registry.waitForDeployment();
    const interfold = await ethers.deployContract("MockBfvV2Interfold", [2]);
    await interfold.waitForDeployment();
    await registry.setInterfold(await interfold.getAddress());

    const verifier = await ethers.deployContract("BfvPkVerifierV2", [
      await circuit.getAddress(),
      await registry.getAddress(),
      NODES_FOLD_KEY_HASH,
      C5_KEY_HASH,
      SK_C2_CHUNK_KEY_HASH,
      ESM_C2_CHUNK_KEY_HASH,
      LEGACY_VK_BINDING,
      V2_VK_BINDING,
    ]);
    await verifier.waitForDeployment();

    return { circuit, registry, interfold, verifier };
  }

  it("accepts the secure-16384 V2 layout and context", async function () {
    const { interfold, verifier } = await deployFixture();
    const [signer, second, third] = await ethers.getSigners();
    const nodes = [signer.address, second.address, third.address];
    const e3Id = 7n;
    const pkCommitment = ethers.id("v2-pk");
    const proof = encodeProof(
      publicInputs(nodes, await interfold.getAddress(), e3Id, pkCommitment),
    );

    expect(
      await verifier.verify.staticCall(
        e3Id,
        0,
        nodes,
        pkCommitment,
        committeeHash(nodes),
        proof,
      ),
    ).to.equal(true);
  });

  it("rejects a proof bound to another committee", async function () {
    const { interfold, verifier } = await deployFixture();
    const [first, second, third, fourth] = await ethers.getSigners();
    const proofNodes = [second.address, third.address, fourth.address];
    const callNodes = [first.address, third.address, fourth.address];
    const e3Id = 7n;
    const pkCommitment = ethers.id("v2-pk");
    const proof = encodeProof(
      publicInputs(
        proofNodes,
        await interfold.getAddress(),
        e3Id,
        pkCommitment,
      ),
    );

    await expect(
      verifier.verify.staticCall(
        e3Id,
        0,
        callNodes,
        pkCommitment,
        committeeHash(callNodes),
        proof,
      ),
    ).to.be.revertedWithCustomError(verifier, "DomainBindingMismatch");
  });
});
