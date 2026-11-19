// SPDX-License-Identifier: LGPL-3.0-only
import type { TypedDataDomain } from "ethers";

export const synchronizedDkgAttestationTypes = {
  SynchronizedDkgAttestation: [
    { name: "registry", type: "address" },
    { name: "e3Id", type: "uint256" },
    { name: "cryptoConfigId", type: "bytes32" },
    { name: "setupBinding", type: "bytes32" },
    { name: "rosterHash", type: "bytes32" },
    { name: "dealerBatch", type: "bytes32" },
    { name: "pkCommitment", type: "bytes32" },
    { name: "partyId", type: "uint256" },
    { name: "skAggCommit", type: "bytes32" },
    { name: "keyBundleCommit", type: "bytes32" },
  ],
};

export function synchronizedDkgAttestationDomain(
  chainId: bigint,
  verifyingContract: string,
): TypedDataDomain {
  return {
    name: "InterfoldSynchronizedDkgAttestation",
    version: "1",
    chainId,
    verifyingContract,
  };
}
