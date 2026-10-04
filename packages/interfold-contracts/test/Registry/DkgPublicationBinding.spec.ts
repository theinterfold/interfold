// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
import { expect } from "chai";
import type { Signer } from "ethers";

import MockCircuitVerifierModule from "../../ignition/modules/mockSlashingVerifier";
import { BFV_DKG_H } from "../../scripts/utils";
import {
  ENCRYPTION_SCHEME_ID,
  buildRequestParams,
  deployInterfoldSystem,
  ethers,
  ignition,
  makeRequest,
  networkHelpers,
  signFoldAttestation,
} from "../fixtures";

const { loadFixture, time } = networkHelpers;
const abiCoder = ethers.AbiCoder.defaultAbiCoder();

const NODES_FOLD_KEY_HASH = ethers.id("nodes_fold");
const C5_KEY_HASH = ethers.id("c5");

// `BfvPkVerifier` checks the committee hash but not the E3 or the chain, and two E3s with the same
// committee share that hash. The fold attestations bind a publication to one E3 on one chain: each
// signer signs the registry, the E3 ID, and the chain ID of the EIP-712 domain.
describe("DKG publication binding", function () {
  const setup = async () => {
    const sys = await deployInterfoldSystem({
      wireMockDkgFoldAttestationVerifier: false,
    });
    const { ciphernodeRegistry: registry, interfold } = sys;

    const attestationVerifier = await ethers.deployContract(
      "DkgFoldAttestationVerifier",
    );
    await attestationVerifier.waitForDeployment();
    await registry.setInitialDkgFoldAttestationVerifier(
      await attestationVerifier.getAddress(),
    );

    const { mockCircuitVerifier } = await ignition.deploy(
      MockCircuitVerifierModule,
    );
    // The circuit verifier accepts every proof, so only the wrapper and attestation checks decide.
    await mockCircuitVerifier.setReturnValue(true);
    const pkVerifier = await ethers.deployContract("BfvPkVerifier", [
      await mockCircuitVerifier.getAddress(),
      NODES_FOLD_KEY_HASH,
      C5_KEY_HASH,
      BFV_DKG_H,
    ]);
    await pkVerifier.waitForDeployment();
    await interfold.setPkVerifier(
      ENCRYPTION_SCHEME_ID,
      await pkVerifier.getAddress(),
    );

    // Two E3s whose committees hold the same three operators.
    const firstE3Id = await interfold.nexte3Id();
    const e3Ids = [firstE3Id, firstE3Id + 1n];
    for (let i = 0; i < e3Ids.length; i++) {
      const params = await buildRequestParams(
        sys.mocks.e3Program,
        sys.mocks.decryptionVerifier,
        { windowDuration: 3600 },
      );
      await makeRequest(interfold, sys.usdcToken, params);
      await time.increase(1);
    }
    for (const e3Id of e3Ids) {
      for (const operator of sys.operators) {
        await registry.connect(operator).submitTicket(e3Id, 1);
      }
    }
    const deadline = await registry.getCommitteeDeadline(e3Ids[1]!);
    await time.setNextBlockTimestamp(deadline + 1n);
    for (const e3Id of e3Ids) {
      await registry.finalizeCommittee(e3Id);
    }

    const signers = new Map<string, Signer>();
    for (const operator of sys.operators) {
      signers.set((await operator.getAddress()).toLowerCase(), operator);
    }
    return {
      registry,
      attestationVerifier,
      pkVerifier,
      signers,
      committeeSize: sys.operators.length,
      e3Ids: e3Ids as [bigint, bigint],
    };
  };

  /** The finalized committee in canonical order: the `topNodes` that `publishCommittee` hashes. */
  const committeeNodes = async (
    fixture: Awaited<ReturnType<typeof setup>>,
    e3Id: bigint,
  ): Promise<string[]> => {
    const nodes = [];
    for (let partyId = 0; partyId < fixture.committeeSize; partyId++) {
      nodes.push(
        await fixture.registry.canonicalCommitteeNodeAt(e3Id, partyId),
      );
    }
    return nodes;
  };

  /**
   * A DKG proof for the committee of `e3Id` that passes `BfvPkVerifier`, with fold attestations
   * from the first `BFV_DKG_H` canonical members, signed for `signedE3Id` on `signedChainId`.
   */
  const buildPublication = async (
    fixture: Awaited<ReturnType<typeof setup>>,
    e3Id: bigint,
    pkCommitment: string,
    signedE3Id: bigint,
    signedChainId: bigint,
  ) => {
    const { registry, attestationVerifier, signers } = fixture;
    const nodes = await committeeNodes(fixture, e3Id);
    const committeeHash = BigInt(ethers.keccak256(ethers.concat(nodes)));
    const h = BFV_DKG_H;
    const publicInputs: string[] = Array.from(
      { length: 3 * h + 6 },
      () => ethers.ZeroHash,
    );
    publicInputs[0] = NODES_FOLD_KEY_HASH;
    publicInputs[1] = C5_KEY_HASH;
    publicInputs[2 + h] = ethers.toBeHex(committeeHash >> 128n, 32);
    publicInputs[3 + h] = ethers.toBeHex(
      committeeHash & ((1n << 128n) - 1n),
      32,
    );
    publicInputs[3 * h + 5] = pkCommitment;

    const attestations = [];
    const bindings = [];
    for (let partyId = 0; partyId < h; partyId++) {
      const node = nodes[partyId]!;
      const skAggCommit = ethers.id(`sk-${e3Id}-${partyId}`);
      const esmAggCommit = ethers.id(`esm-${e3Id}-${partyId}`);
      publicInputs[2 + partyId] = ethers.toBeHex(partyId, 32);
      publicInputs[5 + h + partyId] = skAggCommit;
      publicInputs[5 + 2 * h + partyId] = esmAggCommit;
      attestations.push({
        partyId,
        skAggCommit,
        esmAggCommit,
        signature: await signFoldAttestation(
          signers.get(node.toLowerCase())!,
          signedChainId,
          await attestationVerifier.getAddress(),
          await registry.getAddress(),
          signedE3Id,
          partyId,
          skAggCommit,
          esmAggCommit,
        ),
      });
      bindings.push({ partyId, node });
    }

    return {
      nodes,
      committeeHash: ethers.toBeHex(committeeHash, 32),
      proof: abiCoder.encode(["bytes", "bytes32[]"], ["0x", publicInputs]),
      bundle: abiCoder.encode(
        [
          "tuple(uint256 partyId, bytes32 skAggCommit, bytes32 esmAggCommit, bytes signature)[]",
          "tuple(uint256 partyId, address node)[]",
        ],
        [attestations, bindings],
      ),
    };
  };

  it("rejects a publication replayed into another E3 with the same committee", async function () {
    const fixture = await loadFixture(setup);
    const { registry, pkVerifier, e3Ids } = fixture;
    const [first, second] = e3Ids;
    const { chainId } = await ethers.provider.getNetwork();
    const pkCommitment = ethers.id("first-e3-public-key");
    const firstPublication = await buildPublication(
      fixture,
      first,
      pkCommitment,
      first,
      chainId,
    );
    expect(await committeeNodes(fixture, second)).to.deep.equal(
      firstPublication.nodes,
    );

    // The PK verifier alone accepts the first E3's proof for the second E3.
    expect(
      await pkVerifier.verify(
        second,
        0,
        firstPublication.nodes,
        pkCommitment,
        firstPublication.committeeHash,
        firstPublication.proof,
      ),
    ).to.equal(true);
    await expect(
      registry.publishCommittee(
        second,
        pkCommitment,
        firstPublication.proof,
        firstPublication.bundle,
      ),
    ).to.be.revertedWithCustomError(registry, "InvalidFoldAttestation");

    await expect(
      registry.publishCommittee(
        first,
        pkCommitment,
        firstPublication.proof,
        firstPublication.bundle,
      ),
    ).to.emit(registry, "CommitteeProofPublished");
    const secondPkCommitment = ethers.id("second-e3-public-key");
    const secondPublication = await buildPublication(
      fixture,
      second,
      secondPkCommitment,
      second,
      chainId,
    );
    await expect(
      registry.publishCommittee(
        second,
        secondPkCommitment,
        secondPublication.proof,
        secondPublication.bundle,
      ),
    ).to.emit(registry, "CommitteeProofPublished");
  });

  it("rejects attestations signed for another chain", async function () {
    const fixture = await loadFixture(setup);
    const { registry, e3Ids } = fixture;
    const [first] = e3Ids;
    const { chainId } = await ethers.provider.getNetwork();
    const pkCommitment = ethers.id("first-e3-public-key");
    const otherChain = await buildPublication(
      fixture,
      first,
      pkCommitment,
      first,
      chainId + 1n,
    );

    await expect(
      registry.publishCommittee(
        first,
        pkCommitment,
        otherChain.proof,
        otherChain.bundle,
      ),
    ).to.be.revertedWithCustomError(registry, "InvalidFoldAttestation");

    const thisChain = await buildPublication(
      fixture,
      first,
      pkCommitment,
      first,
      chainId,
    );
    await expect(
      registry.publishCommittee(
        first,
        pkCommitment,
        thisChain.proof,
        thisChain.bundle,
      ),
    ).to.emit(registry, "CommitteeProofPublished");
  });
});
