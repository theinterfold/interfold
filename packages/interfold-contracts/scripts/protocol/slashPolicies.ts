// SPDX-License-Identifier: LGPL-3.0-only
import { ethers } from "ethers";

/** Proof types 0–7 and 11–14 belong to DKG. */
export const DKG_PROOF_TYPES = [
  0, 1, 2, 3, 4, 5, 6, 7, 11, 12, 13, 14,
] as const;

/** Proof types C5 through C7 belong to aggregation and decryption. */
export const DECRYPTION_PROOF_TYPES = [8, 9, 10] as const;

/** All protocol proof types that have deterministic slash-policy reasons. */
export const PROOF_TYPES = [
  ...DKG_PROOF_TYPES,
  ...DECRYPTION_PROOF_TYPES,
] as const;

export function slashReasonForProofType(proofType: number): string {
  return ethers.keccak256(ethers.solidityPacked(["uint256"], [proofType]));
}
