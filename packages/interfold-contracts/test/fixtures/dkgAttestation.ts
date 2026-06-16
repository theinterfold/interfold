// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
import type { Signer } from "ethers";

import { ethers } from "./connection";

export type DkgFoldAttestation = {
  partyId: number;
  skAggCommit: string;
  esmAggCommit: string;
  signature: string;
};

export type DkgPartySlotBinding = {
  partyId: number;
  node: string;
};

/** Public inputs layout expected by `DkgFoldAttestationVerifier` for honest count `h`. */
export function encodeMockDkgProofForAttestation(
  pkCommitment: string,
  partyIds: number[],
  skCommits: string[],
  esmCommits: string[],
): string {
  const h = partyIds.length;
  const publicInputs: string[] = Array.from(
    { length: 6 + 3 * h },
    () => ethers.ZeroHash,
  );
  publicInputs[publicInputs.length - 1] = pkCommitment;
  for (let i = 0; i < h; i++) {
    publicInputs[2 + i] = ethers.zeroPadValue(ethers.toBeHex(partyIds[i]), 32);
    publicInputs[5 + h + i] = skCommits[i];
    publicInputs[5 + 2 * h + i] = esmCommits[i];
  }
  return ethers.AbiCoder.defaultAbiCoder().encode(
    ["bytes", "bytes32[]"],
    ["0x", publicInputs],
  );
}

/** Sign one EIP-712 fold-attestation tuple. */
export async function signFoldAttestation(
  signer: Signer,
  chainId: bigint,
  verifyingContract: string,
  e3Id: number,
  partyId: number,
  skAggCommit: string,
  esmAggCommit: string,
): Promise<string> {
  const domain = {
    name: "InterfoldDkgFoldAttestation",
    version: "1",
    chainId,
    verifyingContract,
  };
  const types = {
    DkgFoldAttestation: [
      { name: "e3Id", type: "uint256" },
      { name: "partyId", type: "uint256" },
      { name: "skAggCommit", type: "bytes32" },
      { name: "esmAggCommit", type: "bytes32" },
    ],
  };
  return signer.signTypedData(domain, types, {
    e3Id,
    partyId,
    skAggCommit,
    esmAggCommit,
  });
}

/**
 * Build mock proof + bundle payloads for `publishCommittee`/verifier tests.
 * Operators are sorted by address to match on-chain canonical `topNodes`.
 */
export async function buildMockDkgAttestationFixtureData(
  operators: Signer[],
  e3Id: number,
  pkCommitment: string,
  signingVerifierAddress: string,
): Promise<{
  ordered: { op: Signer; addr: string }[];
  proof: string;
  bundle: string;
  partyIds: number[];
  skCommits: string[];
  esmCommits: string[];
  attestations: DkgFoldAttestation[];
  bindings: DkgPartySlotBinding[];
}> {
  const ordered = await Promise.all(
    operators.map(async (op) => ({ op, addr: await op.getAddress() })),
  );
  ordered.sort((a, b) =>
    a.addr.toLowerCase() < b.addr.toLowerCase()
      ? -1
      : a.addr.toLowerCase() > b.addr.toLowerCase()
        ? 1
        : 0,
  );

  const partyIds = ordered.map((_, idx) => idx);
  const skCommits = partyIds.map((i) => ethers.id(`sk-${e3Id}-${i}`));
  const esmCommits = partyIds.map((i) => ethers.id(`esm-${e3Id}-${i}`));
  const proof = encodeMockDkgProofForAttestation(
    pkCommitment,
    partyIds,
    skCommits,
    esmCommits,
  );

  const { chainId } = await ethers.provider.getNetwork();
  const attestations: DkgFoldAttestation[] = [];
  const bindings: DkgPartySlotBinding[] = [];
  for (let i = 0; i < ordered.length; i++) {
    attestations.push({
      partyId: i,
      skAggCommit: skCommits[i],
      esmAggCommit: esmCommits[i],
      signature: await signFoldAttestation(
        ordered[i].op,
        chainId,
        signingVerifierAddress,
        e3Id,
        i,
        skCommits[i],
        esmCommits[i],
      ),
    });
    bindings.push({ partyId: i, node: ordered[i].addr });
  }

  const bundle = ethers.AbiCoder.defaultAbiCoder().encode(
    [
      "tuple(uint256 partyId, bytes32 skAggCommit, bytes32 esmAggCommit, bytes signature)[]",
      "tuple(uint256 partyId, address node)[]",
    ],
    [attestations, bindings],
  );

  return {
    ordered,
    proof,
    bundle,
    partyIds,
    skCommits,
    esmCommits,
    attestations,
    bindings,
  };
}

/** Convenience helper for Interfold tests with a plaintext public key input. */
export async function buildMockAggregationPublishArgs(
  operators: Signer[],
  e3Id: number,
  publicKey: string,
  signingVerifierAddress: string,
): Promise<{ proof: string; bundle: string }> {
  const fixture = await buildMockDkgAttestationFixtureData(
    operators,
    e3Id,
    ethers.keccak256(publicKey),
    signingVerifierAddress,
  );
  return { proof: fixture.proof, bundle: fixture.bundle };
}
