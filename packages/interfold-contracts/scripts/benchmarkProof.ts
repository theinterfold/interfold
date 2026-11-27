// SPDX-License-Identifier: LGPL-3.0-only
import { getBytes, hexlify } from "ethers";

/** Decode the same nonempty proof and whole public fields as Rust's artifact_measures. */
export function decodeBenchmarkProof(
  proofHex: string,
  publicInputsHex: string,
) {
  const bytes = (hex: string) =>
    getBytes(hex.startsWith("0x") ? hex : `0x${hex}`);
  const proof = bytes(proofHex);
  const inputs = bytes(publicInputsHex);
  if (proof.length === 0) throw new Error("Empty folded proof");
  if (inputs.length === 0 || inputs.length % 32 !== 0)
    throw new Error("Expected nonempty 32-byte-aligned public inputs");
  const fields: string[] = [];
  for (let i = 0; i < inputs.length; i += 32)
    fields.push(hexlify(inputs.subarray(i, i + 32)));
  return { proof, fields };
}
