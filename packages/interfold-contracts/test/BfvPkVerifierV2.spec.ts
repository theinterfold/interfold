// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
import { expect } from "chai";

import { currentNodeRelease } from "../scripts/protocol/nodeRelease";
import {
  INSECURE_LBFV_MINIMUM_BFV_CONFIG,
  INSECURE_LBFV_PARAM_SET,
  SECURE_16384_MINIMUM_BFV_CONFIG,
  bfvPkV2PublicInputLayout,
} from "../scripts/utils";
import { ethers } from "./fixtures/connection";

const abiCoder = ethers.AbiCoder.defaultAbiCoder();
const NODES_FOLD_KEY_HASH = ethers.id("v2-nodes-fold");
const SK_C2_CHUNK_KEY_HASH = ethers.id("v2-sk-c2-chunk");
const ESM_C2_CHUNK_KEY_HASH = ethers.id("v2-esm-c2-chunk");
const LEGACY_VK_BINDING = Array.from({ length: 15 }, (_, index) =>
  ethers.id(`v2-legacy-vk-${index}`),
);
const V2_VK_BINDING = Array.from({ length: 11 }, (_, index) =>
  ethers.id(`v2-vk-${index}`),
);
const SECURE_16384_CONFIG_ID = SECURE_16384_MINIMUM_BFV_CONFIG.configId;
const INSECURE_CONFIG_ID = INSECURE_LBFV_MINIMUM_BFV_CONFIG.configId;
const LBFV_PROTOCOL_VERSION = currentNodeRelease().protocolVersion;

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
  protocolVersion = LBFV_PROTOCOL_VERSION,
  configId = SECURE_16384_CONFIG_ID,
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
        protocolVersion,
        chainId,
        interfold,
        e3Id,
        configId,
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
  protocolVersion = LBFV_PROTOCOL_VERSION,
  configId = SECURE_16384_CONFIG_ID,
  lbfvRows = 6,
): string[] {
  const inputs = Array.from(
    { length: 45 + 3 * lbfvRows },
    () => ethers.ZeroHash,
  );
  const hash = committeeHash(nodes);
  const [committeeHi, committeeLo] = limbs(hash);
  const [acceptedHi, acceptedLo] = limbs(acceptedSetHash(0, 2));
  const [sessionHi, sessionLo] = limbs(
    sessionId(31337n, interfold, e3Id, hash, protocolVersion, configId),
  );

  inputs[0] = NODES_FOLD_KEY_HASH;
  inputs[1] = ethers.toBeHex(0, 32);
  inputs[2] = ethers.toBeHex(2, 32);
  inputs[3] = committeeHi;
  inputs[4] = committeeLo;
  inputs.splice(5, LEGACY_VK_BINDING.length, ...LEGACY_VK_BINDING);
  inputs[21] = SK_C2_CHUNK_KEY_HASH;
  inputs[22] = ESM_C2_CHUNK_KEY_HASH;
  inputs[27] = pkCommitment;
  inputs[29] = sessionHi;
  inputs[30] = sessionLo;
  inputs[31] = ethers.toBeHex(0, 32);
  inputs[32] = acceptedHi;
  inputs[33] = acceptedLo;
  inputs.splice(34 + 3 * lbfvRows, V2_VK_BINDING.length, ...V2_VK_BINDING);
  return inputs;
}

function encodeProof(publicInputValues: string[]): string {
  return abiCoder.encode(["bytes", "bytes32[]"], ["0x1234", publicInputValues]);
}

describe("BfvPkVerifierV2", function () {
  async function deployFixture(
    paramSet: number = SECURE_16384_MINIMUM_BFV_CONFIG.paramSet,
    e3ParamSet: number = paramSet,
  ) {
    const circuit = await ethers.deployContract("MockCircuitVerifier");
    await circuit.waitForDeployment();
    await circuit.setReturnValue(true);

    const registry = await ethers.deployContract("MockCiphernodeRegistry");
    await registry.waitForDeployment();
    const interfold = await ethers.deployContract("MockBfvV2Interfold", [
      e3ParamSet,
      0,
    ]);
    await interfold.waitForDeployment();
    await registry.setInterfold(await interfold.getAddress());

    const verifier = await ethers.deployContract("BfvPkVerifierV2", [
      await circuit.getAddress(),
      await registry.getAddress(),
      paramSet,
      2,
      3,
      NODES_FOLD_KEY_HASH,
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
    expect(
      await verifier.getFunction("LBFV_PROTOCOL_VERSION").staticCall(),
    ).to.equal(LBFV_PROTOCOL_VERSION);
  });

  it("accepts the insecure three-row V2 layout and context", async function () {
    const { interfold, verifier } = await deployFixture(
      INSECURE_LBFV_PARAM_SET,
    );
    const [signer, second, third] = await ethers.getSigners();
    const nodes = [signer.address, second.address, third.address];
    const e3Id = 7n;
    const pkCommitment = ethers.id("insecure-v2-pk");
    const proof = encodeProof(
      publicInputs(
        nodes,
        await interfold.getAddress(),
        e3Id,
        pkCommitment,
        LBFV_PROTOCOL_VERSION,
        INSECURE_CONFIG_ID,
        3,
      ),
    );

    expect(await verifier.expectedPublicInputsLen()).to.equal(54n);
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

  it("rejects a proof from another protocol version", async function () {
    const { interfold, verifier } = await deployFixture();
    const [first, second, third] = await ethers.getSigners();
    const nodes = [first.address, second.address, third.address];
    const e3Id = 7n;
    const pkCommitment = ethers.id("v2-pk");
    const proof = encodeProof(
      publicInputs(
        nodes,
        await interfold.getAddress(),
        e3Id,
        pkCommitment,
        LBFV_PROTOCOL_VERSION + 1,
      ),
    );

    await expect(
      verifier.verify.staticCall(
        e3Id,
        0,
        nodes,
        pkCommitment,
        committeeHash(nodes),
        proof,
      ),
    ).to.be.revertedWithCustomError(verifier, "DomainBindingMismatch");
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

  it("pins the public-input length of the TypeScript layout", async function () {
    for (const config of [
      SECURE_16384_MINIMUM_BFV_CONFIG,
      INSECURE_LBFV_MINIMUM_BFV_CONFIG,
    ]) {
      const { verifier } = await deployFixture(config.paramSet);
      expect(await verifier.expectedPublicInputsLen()).to.equal(
        BigInt(
          bfvPkV2PublicInputLayout(config.h, Number(await verifier.lbfvRows()))
            .length,
        ),
      );
    }
    expect(
      await (
        await deployFixture(SECURE_16384_MINIMUM_BFV_CONFIG.paramSet)
      ).verifier.lbfvRows(),
    ).to.equal(6n);
    expect(
      await (await deployFixture(INSECURE_LBFV_PARAM_SET)).verifier.lbfvRows(),
    ).to.equal(3n);
  });

  describe("verify() rejections", function () {
    const e3Id = 7n;
    const pkCommitment = ethers.id("v2-pk");

    async function validCase(paramSet?: number, e3ParamSet?: number) {
      const fixture = await deployFixture(paramSet, e3ParamSet);
      const [first, second, third] = await ethers.getSigners();
      const nodes = [first.address, second.address, third.address];
      const inputs = publicInputs(
        nodes,
        await fixture.interfold.getAddress(),
        e3Id,
        pkCommitment,
      );
      const call = (
        overrides: {
          inputs?: string[];
          callNodes?: string[];
          root?: bigint;
          commitment?: string;
        } = {},
      ) => {
        const callNodes = overrides.callNodes ?? nodes;
        return fixture.verifier.verify.staticCall(
          e3Id,
          overrides.root ?? 0n,
          callNodes,
          overrides.commitment ?? pkCommitment,
          committeeHash(callNodes),
          encodeProof(overrides.inputs ?? inputs),
        );
      };
      return { ...fixture, nodes, inputs, call };
    }

    const withInput = (inputs: string[], index: number, value: string) => {
      const copy = [...inputs];
      copy[index] = value;
      return copy;
    };

    it("rejects a changed nodes-fold, C2 chunk, legacy binding or V2 binding hash", async function () {
      const { verifier, inputs, call } = await validCase();
      const v2BindingStart = 34 + 3 * 6;
      for (const index of [
        0,
        21,
        22,
        5,
        19,
        v2BindingStart,
        v2BindingStart + 10,
      ]) {
        await expect(
          call({ inputs: withInput(inputs, index, ethers.id("other")) }),
          `input ${index}`,
        ).to.be.revertedWithCustomError(verifier, "VkHashMismatch");
      }
    });

    it("rejects a public-input vector of the wrong length", async function () {
      const { verifier, inputs, call } = await validCase();
      await expect(
        call({ inputs: inputs.slice(0, -1) }),
      ).to.be.revertedWithCustomError(verifier, "InvalidPublicInputsLength");
    });

    it("rejects a pk commitment that the proof does not carry", async function () {
      const { verifier, call } = await validCase();
      await expect(
        call({ commitment: ethers.id("other-pk") }),
      ).to.be.revertedWithCustomError(verifier, "PkCommitmentMismatch");
    });

    it("rejects an E3 on another parameter set", async function () {
      const { verifier, call } = await validCase(
        SECURE_16384_MINIMUM_BFV_CONFIG.paramSet,
        INSECURE_LBFV_PARAM_SET,
      );
      await expect(call()).to.be.revertedWithCustomError(
        verifier,
        "DomainBindingMismatch",
      );
    });

    it("rejects party IDs that are out of range or not ascending", async function () {
      const { verifier, inputs, call } = await validCase();
      for (const [first, second] of [
        [2, 0],
        [1, 1],
        [0, 3],
      ]) {
        const tampered = withInput(
          withInput(inputs, 1, ethers.toBeHex(first, 32)),
          2,
          ethers.toBeHex(second, 32),
        );
        await expect(
          call({ inputs: tampered }),
          `${first},${second}`,
        ).to.be.revertedWithCustomError(verifier, "DomainBindingMismatch");
      }
    });

    it("rejects a wrong accepted-set hash, committee root or committee size", async function () {
      const { verifier, inputs, nodes, call } = await validCase();
      await expect(
        call({ inputs: withInput(inputs, 32, ethers.id("other-set")) }),
      ).to.be.revertedWithCustomError(verifier, "DomainBindingMismatch");
      await expect(call({ root: 1n })).to.be.revertedWithCustomError(
        verifier,
        "DomainBindingMismatch",
      );
      await expect(
        call({ callNodes: nodes.slice(0, 2) }),
      ).to.be.revertedWithCustomError(verifier, "DomainBindingMismatch");
    });

    it("rejects a proof that the circuit verifier refuses", async function () {
      const { verifier, circuit, call } = await validCase();
      await circuit.setReturnValue(false);
      await expect(call()).to.be.revertedWithCustomError(
        verifier,
        "InvalidProof",
      );
    });
  });

  describe("constructor", function () {
    async function deployWith(overrides: Record<number, unknown>) {
      const circuit = await ethers.deployContract("MockCircuitVerifier");
      const registry = await ethers.deployContract("MockCiphernodeRegistry");
      const args: unknown[] = [
        await circuit.getAddress(),
        await registry.getAddress(),
        SECURE_16384_MINIMUM_BFV_CONFIG.paramSet,
        2,
        3,
        NODES_FOLD_KEY_HASH,
        SK_C2_CHUNK_KEY_HASH,
        ESM_C2_CHUNK_KEY_HASH,
        LEGACY_VK_BINDING,
        V2_VK_BINDING,
      ];
      for (const [index, value] of Object.entries(overrides)) {
        args[Number(index)] = value;
      }
      const factory = await ethers.getContractFactory("BfvPkVerifierV2");
      return { factory, deploy: () => factory.deploy(...args) };
    }

    it("rejects a verifier or registry without code", async function () {
      const [eoa] = await ethers.getSigners();
      for (const [index, error] of [
        [0, "InvalidCircuitVerifier"],
        [1, "InvalidRegistry"],
      ] as const) {
        const { factory, deploy } = await deployWith({ [index]: eoa.address });
        await expect(deploy()).to.be.revertedWithCustomError(factory, error);
      }
    });

    it("rejects a trBFV parameter set and an inverted committee", async function () {
      for (const overrides of [{ 2: 4 }, { 2: 3 }, { 3: 4, 4: 3 }, { 3: 0 }]) {
        const { factory, deploy } = await deployWith(overrides);
        await expect(deploy()).to.be.revertedWithCustomError(
          factory,
          "InvalidParamSet",
        );
      }
    });

    it("rejects a zero verification key hash", async function () {
      const zero = ethers.ZeroHash;
      for (const overrides of [
        { 5: zero },
        { 6: zero },
        { 7: zero },
        { 8: [zero, ...LEGACY_VK_BINDING.slice(1)] },
        { 9: [...V2_VK_BINDING.slice(0, 10), zero] },
      ]) {
        const { factory, deploy } = await deployWith(overrides);
        await expect(deploy()).to.be.revertedWithCustomError(
          factory,
          "InvalidVerificationKeyHash",
        );
      }
    });
  });
});
