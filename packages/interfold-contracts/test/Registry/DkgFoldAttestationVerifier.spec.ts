// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
import { expect } from "chai";

import {
  buildMockDkgAttestationFixtureData,
  deployInterfoldSystem,
  ethers,
  networkHelpers,
} from "../fixtures";

const { loadFixture } = networkHelpers;

describe("DkgFoldAttestationVerifier", function () {
  const e3Id = 7;

  const setup = async () => {
    const sys = await deployInterfoldSystem({
      useMockCiphernodeRegistry: true,
      setupOperators: 0,
      wireSlashingManager: false,
    });
    const verifier = await ethers.deployContract("DkgFoldAttestationVerifier");
    const signers = await ethers.getSigners();
    const operators = [signers[2], signers[3], signers[4]];
    return {
      owner: sys.owner,
      mockRegistry: sys.mockCiphernodeRegistry!,
      verifier,
      operators,
    };
  };

  it("verifies a valid bundle and returns anchors", async function () {
    const { owner, mockRegistry, verifier, operators } =
      await loadFixture(setup);
    const { ordered, proof, bundle, skCommits, esmCommits } =
      await buildMockDkgAttestationFixtureData(
        operators,
        e3Id,
        ethers.id(`pk-${e3Id}`),
        await verifier.getAddress(),
      );
    await mockRegistry.connect(owner).setCommitteeNodes(
      e3Id,
      ordered.map((o) => o.addr),
    );

    const [partyIds, skAggCommits, esmAggCommits] = await verifier.verify(
      await mockRegistry.getAddress(),
      31337,
      e3Id,
      proof,
      bundle,
    );

    expect(partyIds.map((v: bigint) => Number(v))).to.deep.equal([0, 1, 2]);
    expect(skAggCommits).to.deep.equal(skCommits);
    expect(esmAggCommits).to.deep.equal(esmCommits);
  });

  it("reverts on out-of-order attestations", async function () {
    const { owner, mockRegistry, verifier, operators } =
      await loadFixture(setup);
    const { ordered, proof, attestations, bindings } =
      await buildMockDkgAttestationFixtureData(
        operators,
        e3Id,
        ethers.id(`pk-${e3Id}`),
        await verifier.getAddress(),
      );
    await mockRegistry.connect(owner).setCommitteeNodes(
      e3Id,
      ordered.map((o) => o.addr),
    );

    const badAttestations = [...attestations];
    [badAttestations[0], badAttestations[1]] = [
      badAttestations[1],
      badAttestations[0],
    ];
    const badBundle = ethers.AbiCoder.defaultAbiCoder().encode(
      [
        "tuple(uint256 partyId, bytes32 skAggCommit, bytes32 esmAggCommit, bytes signature)[]",
        "tuple(uint256 partyId, address node)[]",
      ],
      [badAttestations, bindings],
    );

    await expect(
      verifier.verify(
        await mockRegistry.getAddress(),
        31337,
        e3Id,
        proof,
        badBundle,
      ),
    ).to.be.revertedWithCustomError(mockRegistry, "InvalidFoldAttestation");
  });

  it("reverts on duplicate binding partyId", async function () {
    const { owner, mockRegistry, verifier, operators } =
      await loadFixture(setup);
    const { ordered, proof, attestations, bindings } =
      await buildMockDkgAttestationFixtureData(
        operators,
        e3Id,
        ethers.id(`pk-${e3Id}`),
        await verifier.getAddress(),
      );
    await mockRegistry.connect(owner).setCommitteeNodes(
      e3Id,
      ordered.map((o) => o.addr),
    );

    const badBindings = [...bindings];
    badBindings[1] = { ...badBindings[1], partyId: badBindings[0].partyId };
    const badBundle = ethers.AbiCoder.defaultAbiCoder().encode(
      [
        "tuple(uint256 partyId, bytes32 skAggCommit, bytes32 esmAggCommit, bytes signature)[]",
        "tuple(uint256 partyId, address node)[]",
      ],
      [attestations, badBindings],
    );

    await expect(
      verifier.verify(
        await mockRegistry.getAddress(),
        31337,
        e3Id,
        proof,
        badBundle,
      ),
    ).to.be.revertedWithCustomError(mockRegistry, "InvalidFoldAttestation");
  });

  it("reverts when signatures are bound to the wrong verifyingContract", async function () {
    const { owner, mockRegistry, verifier, operators } =
      await loadFixture(setup);
    const wrongVerifyingContract = "0x0000000000000000000000000000000000000002";
    const { ordered, proof, bundle } = await buildMockDkgAttestationFixtureData(
      operators,
      e3Id,
      ethers.id(`pk-${e3Id}`),
      wrongVerifyingContract,
    );
    await mockRegistry.connect(owner).setCommitteeNodes(
      e3Id,
      ordered.map((o) => o.addr),
    );

    await expect(
      verifier.verify(
        await mockRegistry.getAddress(),
        31337,
        e3Id,
        proof,
        bundle,
      ),
    ).to.be.revertedWithCustomError(mockRegistry, "InvalidFoldAttestation");
  });

  it("reverts when attestation and binding counts mismatch", async function () {
    const { owner, mockRegistry, verifier, operators } =
      await loadFixture(setup);
    const { ordered, proof, attestations, bindings } =
      await buildMockDkgAttestationFixtureData(
        operators,
        e3Id,
        ethers.id(`pk-${e3Id}`),
        await verifier.getAddress(),
      );
    await mockRegistry.connect(owner).setCommitteeNodes(
      e3Id,
      ordered.map((o) => o.addr),
    );

    const shortBundle = ethers.AbiCoder.defaultAbiCoder().encode(
      [
        "tuple(uint256 partyId, bytes32 skAggCommit, bytes32 esmAggCommit, bytes signature)[]",
        "tuple(uint256 partyId, address node)[]",
      ],
      [attestations.slice(0, 2), bindings],
    );

    await expect(
      verifier.verify(
        await mockRegistry.getAddress(),
        31337,
        e3Id,
        proof,
        shortBundle,
      ),
    ).to.be.revertedWithCustomError(
      mockRegistry,
      "AttestationBindingCountMismatch",
    );
  });

  it("reverts with typed error on malformed proof encoding", async function () {
    const { owner, mockRegistry, verifier, operators } =
      await loadFixture(setup);
    const { ordered, bundle } = await buildMockDkgAttestationFixtureData(
      operators,
      e3Id,
      ethers.id(`pk-${e3Id}`),
      await verifier.getAddress(),
    );
    await mockRegistry.connect(owner).setCommitteeNodes(
      e3Id,
      ordered.map((o) => o.addr),
    );

    await expect(
      verifier.verify(
        await mockRegistry.getAddress(),
        31337,
        e3Id,
        "0x1234",
        bundle,
      ),
    ).to.be.revertedWithCustomError(mockRegistry, "InvalidFoldAttestation");
  });

  it("reverts with typed error on malformed bundle encoding", async function () {
    const { owner, mockRegistry, verifier, operators } =
      await loadFixture(setup);
    const { ordered, proof } = await buildMockDkgAttestationFixtureData(
      operators,
      e3Id,
      ethers.id(`pk-${e3Id}`),
      await verifier.getAddress(),
    );
    await mockRegistry.connect(owner).setCommitteeNodes(
      e3Id,
      ordered.map((o) => o.addr),
    );

    await expect(
      verifier.verify(
        await mockRegistry.getAddress(),
        31337,
        e3Id,
        proof,
        "0xabcd",
      ),
    ).to.be.revertedWithCustomError(mockRegistry, "InvalidFoldAttestation");
  });
});
