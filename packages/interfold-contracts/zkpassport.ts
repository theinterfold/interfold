// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
//
// What off-chain code must agree on with ZKPassportIdentityVerifier and BondOwnerCapacityLib, and
// the identity panel's proof download. The contract tests check it against the contracts. The
// dashboard bundles it (@interfold/contracts/zkpassport), so it uses no Node.js or ethers APIs.
import config from "./deploy/protocol/example.protocol.config.json";

type Hex = `0x${string}`;

/** ZKPassport's verification method for a proof that reads the document's chip. */
export const ICAO_CHIP = 100;

/** ZKPassportIdentityVerifier.IDENTITY_TAG. */
export const IDENTITY_TAG = "interfold.identity.zkpassport.v1";

/** BondOwnerCapacityLib.IDENTITY_CAPACITY_WINDOW. */
export const CAPACITY_WINDOW = 30n * 86_400n;

/** The identity settings of the example protocol config: the planned deployment. */
export const PLANNED_IDENTITY = {
  rootVerifier: config.identity.zkPassportRootVerifier,
  domain: config.identity.domain,
  scope: config.identity.scope,
  faceMatchRequired: config.identity.faceMatchRequired,
  proofValidity: BigInt(config.identity.proofValidity),
  maxValidity: BigInt(config.identity.maxValidity),
} as const;

export const PROOF_BUNDLE_KIND = "interfold.identity.zkpassport-proof";

/** The identity panel's proof download, as the proof replay reads it. */
export type ProofBundle = {
  kind: typeof PROOF_BUNDLE_KIND;
  chainId: number;
  owner: string;
  domain: string;
  scope: string;
  faceMatch: boolean;
  /** Unix seconds. */
  validUntil: string;
  proofDate: string;
  nullifierType: number;
  oprfKeyHash: Hex;
  version: Hex;
  evidence: Hex;
  params: { proofVerificationData: { publicInputs: readonly string[] } };
};

/** ZKPassport's version word: major, minor and patch as big-endian uint16 values at the start of a bytes32. */
export function zkPassportVersion(
  major: number,
  minor: number,
  patch: number,
): Hex {
  const word =
    (BigInt(major) << 240n) | (BigInt(minor) << 224n) | (BigInt(patch) << 208n);
  return `0x${word.toString(16).padStart(64, "0")}`;
}

/**
 * Where a version's public inputs hold the values that identity code reads: the proof date by index,
 * the rest by position from the end. From 0.23, the public inputs end with the verification method.
 * Null for a version that ZKPassportIdentityVerifier refuses to deploy with.
 */
export function publicInputLayout(version: string) {
  const word = BigInt(version);
  const minor = Number((word >> 224n) & 0xffffn);
  if (
    word >> 240n !== 0n ||
    minor < 20 ||
    minor > 23 ||
    (word & ((1n << 208n) - 1n)) !== 0n
  ) {
    return null;
  }
  const method = minor >= 23 ? 1 : 0;
  return {
    proofDate: 2,
    nullifierTypeFromEnd: 3 + method,
    scopedNullifierFromEnd: 2 + method,
    oprfKeyHashFromEnd: 1 + method,
    verificationMethodFromEnd: method === 1 ? 1 : null,
  };
}

/** Throws for a version that ZKPassportIdentityVerifier refuses to deploy with. */
export function readPublicInputs(version: string, inputs: readonly string[]) {
  const layout = publicInputLayout(version);
  if (!layout) {
    throw new Error(
      `The identity verifier does not read ZKPassport version ${version}`,
    );
  }
  const fromEnd = (position: number) => inputs[inputs.length - position];
  return {
    proofDate: BigInt(inputs[layout.proofDate]),
    nullifierType: Number(BigInt(fromEnd(layout.nullifierTypeFromEnd))),
    scopedNullifier: fromEnd(layout.scopedNullifierFromEnd) as Hex,
    oprfKeyHash: fromEnd(layout.oprfKeyHashFromEnd) as Hex,
    // Before 0.23, ZKPassport proves only chips.
    verificationMethod:
      layout.verificationMethodFromEnd === null
        ? ICAO_CHIP
        : Number(BigInt(fromEnd(layout.verificationMethodFromEnd))),
  };
}

/** The credential end that ZKPassportIdentityVerifier sets. */
export function credentialEnd(
  validUntil: bigint,
  proofDate: bigint,
  maxValidity: bigint,
): bigint {
  const capped = proofDate + maxValidity;
  return validUntil < capped ? validUntil : capped;
}

/** The last second of the capacity window that contains `timestamp` (BondOwnerCapacityLib._windowEnd). */
export function capacityWindowEnd(timestamp: bigint): bigint {
  return (timestamp / CAPACITY_WINDOW + 1n) * CAPACITY_WINDOW - 1n;
}
